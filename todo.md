我希望实现一套mesh vpn的控制程序（控制平面）。整个网络运行在三层p2p互联网络，之上运行路由协议。目前的初步设计如下：

底层传输协议：
1. wireguard 
2. strongswan udp ikev2

可选的兼容层：
1. vxlan (用于实现二层网络)
2. seg6 用于封装复杂

上层路由协议：
1. babeld: babel
2. bird: babel 或者 bgp

控制平面主要功能：
1. 节点之间建立起一套去中心话的最终一致的配置同步机制。权限通过ed25519密钥签名实现，权限细分为：准入（主签名节点的子密钥），核准ip（主密钥签名ip分配记录，子密钥继续签名分配），公布自己节点的信息（节点的子密钥签名自己的内容）。
2. 节点之间建立底层传输协议
3. 当节点信息更改时调整传输协议
4. 对应调整路由协议，filter，准入，防火墙等等。
5. 配置seg6等

需要一些特殊的点：
1. 底层传输协议可以有线路并行，例如既有wg，又有ikev2，还可以加上gre等
2. 为了防止流量被劣化，考虑到“跳频”的功能，既如果是udp+port协议（例如wg），动态建立监听多个端口，约定好时间切换，有点像证书的rotate，不过是端口的rotate。

实现： go语言
平台： linux

---

# 可执行实施方案

## 一、架构调整建议

### 1.1 核心问题与风险
| 问题 | 风险 | 建议 |
|------|------|------|
| 配置同步机制未细化 | 这是整个系统的基石，直接决定项目成败 | 采用 **DNS 式层级作用域 (Zone) + Signed Merkle DAG + Gossip** 方案 |
| 同时支持 WG/IKEv2/VXLAN/SRv6/Babel/BGP | 工作量巨大，MVP 周期过长 | 第一阶段只保留 **WireGuard + Babeld** |
| 跳频/多线路并行 | 属于高级对抗/优化特性 | 放到 Phase 3 |
| 与系统服务交互方式未定 | 代码无法开始写 | 明确区分 `netlink`/`exec`/`配置文件` 三种模式 |

### 1.2 推荐总体架构（核心 + 插件）

```
┌─────────────────────────────────────────────┐
│                 higgs (control plane)         │
├─────────────┬───────────────┬───────────────┤
│    core     │  transport    │    routing    │
│             │   drivers     │   adapters    │
├─────────────┼───────────────┼───────────────┤
│ • Identity  │ • wireguard   │ • babeld      │
│ • Gossip    │ • ipsec(later│ • bird/bgp    │
│ • ZoneStore │ • gre(later)  │   (later)     │
│ • MerkleDAG │               │               │
│ • Signature │               │               │
│ • StateDB   │               │               │
├─────────────┴───────────────┴───────────────┤
│              overlay (later)                  │
│         • vxlan  • seg6                       │
└─────────────────────────────────────────────┘
```

---

## 二、核心设计：DNS 式层级作用域（Zone）K-V 配置系统

这是整个 higgs 控制平面最本质的创新点。**全网配置呈现为一组层级化的 K-V 数据库，权限通过 Zone 委派实现，配置支持向下覆盖继承。**

### 2.1 核心概念

**Zone（作用域）**
- 类似 DNS 域名，如 `.`（根）、`catofes.`、`pek.catofes.`、`node1.pek.catofes.`
- 每个 Zone 是一个独立的命名空间，内部包含 K-V 记录和子 Zone 委派声明
- Zone `A.B.` 的创建必须由 Zone `B.` 的当前持有者签名授权

**Delegation（委派）**
- 记录在某个 Zone 下，声明子 Zone 由哪个公钥管理
- 例：在 `catofes.` 下有一条 delegation：
  - `zone: pek.catofes.`
  - `delegate_key: 0xAABBCC...`（被委派者的 ed25519 公钥）
  - `permissions: ["delegate", "write", "allocate-ip"]`
  - `signature: 0x...`（由 `catofes.` 的当前持有者签名）

**Authority（权限持有者）**
- 每个 Zone 的实际写权限主体不是单 key，而是可扩展的 `ZoneAuthority`（keyset + threshold + epoch）
- Phase 1 可先退化为 `threshold=1`，但数据模型从第一天保留多 key/轮换能力
- 根 key 仅用于签发/轮换 authority；日常写入使用 operational key

**Record（K-V 记录）**
- Zone 内的任意键值对，key 形如 `nodes/node1/wg/pubkey`、`ips/10.0.1.0/24`
- 每条 Record 必须由该 Zone 的当前持有者签名
- Record 必须带类型与版本链，禁止仅靠时间戳裁决冲突
- 特殊保留 key：
  - `@delegation`：本 Zone 自身的委派信息（即"我是谁授权的"）

**@delegation 权威性规则（必须固定）**
- 父 Zone 中 `delegations/<child>` 是唯一权威授权来源
- 子 Zone 中 `@delegation` 仅作为缓存/证明材料，不单独产生授权
- 如父 Zone delegation 与子 Zone `@delegation` 不一致，视为冲突并拒绝激活该 Zone 更新

**配置向下覆盖（Fallback/继承）**
- 查询 `pek.catofes./policy/mtu` 时，先在该 Zone 查找
- 若不存在，去掉最左一级，在 `catofes.` 中继续查找 `policy/mtu`
- 直到根 Zone `.` 或找到为止
- 这与 DNS 查询不同，更接近配置系统的 override/继承模型

### 2.2 一个完整的配置示例

```
. (根 Zone，由创世主密钥持有)
├── @delegation
│   └── {zone: ".", delegate_key: <root-pubkey>, signed_by: <root-pubkey>}
├── records/
│   ├── policy/allowed-transports  → "wireguard"
│   ├── policy/default-ip-pool     → "10.0.0.0/8"
│   └── policy/mtu                 → "1420"
│
└── delegations/
    └── catofes. → {delegate_key: <alice-pubkey>, permissions: ["delegate","write","allocate-ip"], signed_by: <root>}

catofes.
├── @delegation
│   └── {zone: "catofes.", delegate_key: <alice-pubkey>, signed_by: <root>}
├── records/
│   ├── policy/mtu                 → "1400"          ← 覆盖根的 1420
│   └── ips/10.0.1.0/24            → {delegated_to: "pek.catofes."}
│
└── delegations/
    ├── pek.catofes.  → {delegate_key: <bob-pubkey>, signed_by: <alice>}
    └── node1.catofes. → {delegate_key: <node1-pubkey>, permissions: ["write-self"], signed_by: <alice>}

pek.catofes.
├── @delegation
│   └── {zone: "pek.catofes.", delegate_key: <bob-pubkey>, signed_by: <alice>}
└── records/
    └── ips/10.0.1.1/32            → {assigned_to: "node1.pek.catofes."}  ← bob 分配的 IP

node1.catofes.
├── @delegation
│   └── {zone: "node1.catofes.", delegate_key: <node1-pubkey>, signed_by: <alice>}
└── records/
    ├── wg/pubkey                   → "0xnode1wgpubkey..."
    ├── wg/endpoint                 → "1.2.3.4:51820"
    ├── wg/listen-port              → "51820"
    └── local-routes                → "10.0.1.1/32, fd00::1/128"
```

**验证签名链示例：**
- 读取 `node1.catofes./wg/pubkey` 时：
  1. 取出 Record，验证其签名者 = `node1.catofes.` 的 delegate_key
  2. 验证 `node1.catofes.` 的 delegation 签名者 = `catofes.` 的 delegate_key
  3. 验证 `catofes.` 的 delegation 签名者 = `.` 的 delegate_key（根自签）
  4. 全部通过 → 配置可信

**查询与覆盖示例：**
- `Get("node1.catofes./wg/pubkey")` → 命中 `node1.catofes.` 的 `wg/pubkey`
- `Get("pek.catofes./policy/mtu")` → `pek.catofes.` 无此 key → 查 `catofes./policy/mtu` → 命中 `"1400"`
- `Get("node1.catofes./policy/allowed-transports")` → 一路回退到 `.` → 命中 `"wireguard"`

### 2.3 与 Mesh VPN 各功能的映射

| 原需求 | Zone K-V 映射 |
|--------|--------------|
| 节点准入 | 父 Zone 签发一个 `nodeX.parent.` 的 delegation |
| 节点自宣告信息 | 节点用自身私钥在 `nodeX.parent.` 下写 `wg/*`、`endpoint` 等 Record |
| IP 分配 | 在 Zone 下写 `ips/<prefix>` Record，值指明 delegated_to 或 assigned_to |
| 路由宣告 | `nodeX.parent./local-routes` Record |
| 全局策略 | 在 `.` 或中间 Zone 设置 `policy/*` Record，被子 Zone 继承 |
| 传输层参数 | `nodeX.parent./wg/*`、`nodeX.parent./ipsec/*` 等 Record |

### 2.4 Merkle DAG + Gossip 在此模型下的实现

**Merkle Tree 组织：**
- 每个 Zone 维护自己的独立 Merkle Tree，包含两部分：
  1. `delegations_tree`: 所有子 Zone 的 delegation 记录
  2. `records_tree`: 本 Zone 的所有 K-V 记录
- Zone 的 Root Hash = Hash(delegations_root + records_root + @delegation_hash)
- 全局状态 = 所有 Zone Root Hash 的集合（可再包一层 Merkel Tree）

**Gossip 协议：**
- `PING`: 携带 `map[zone_name]zone_root_hash`（类似交换各自持有的 zone 版本摘要）
- `PONG`: 返回对方缺失/过时的 zone 列表
- `FETCH_ZONE`: 请求某个 Zone 的完整内容（或按 Merkle path 请求差异分支）
- `FETCH_RECORD`: 请求单条 record 内容
- `ANNOUNCE`: 主动广播某个 Zone 的更新（低频次）

**Gossip 安全边界（Phase 1 必需）**
- 仅接受 bootstrap 列表、已验证节点、显式 allowlist 节点的同步连接
- `FETCH_ZONE` 前先验证 zone path 是否位于可信根树下
- 限制单次同步资源：最大 Zone 数、最大 Record 数、最大字节数
- 收到的数据先进入 `quarantine store`，签名链通过后再提升到 `active store`
- 状态分层必须明确：`untrusted received data` -> `verified candidate state` -> `active network state`

**同步流程：**
1. 节点 A 连接节点 B，交换各自的 zone hash 映射表
2. A 发现 B 有更新的 `catofes.`（hash 不同）
3. A 向 B 请求 `catofes.` 的 Merkle Tree 顶层
4. 通过 Merkle diff 快速定位变化的子分支（可能是新 delegation 或 record 变更）
5. 只拉取变化的叶子节点
6. 本地验证签名链 → 验证通过 → 应用更新 → 重新计算本地 hash → 继续 Gossip

**并发与冲突：**
- Zone 天然有单一持有者，同一 Zone 内的写入冲突应由该持有者避免。
- 若检测到同一 Zone 同一 key 的冲突，采用版本链规则：
  1. `Version` 更高者胜；
  2. `Version` 相同但内容不同，进入 `fork/conflict`；
  3. `fork/conflict` 不自动裁决，需 Zone owner（或上级 Zone）签发修正记录。
- `Timestamp` 仅作为审计字段，不参与最终裁决。

**Merkle 实施分层（降低 Phase 1 风险）**
- Phase 1A: `ZoneRoot = hash(sorted(records + delegations))`，hash 不同直接拉完整 Zone
- Phase 1B: 引入 per-record hash diff
- Phase 2+: 再上完整 Merkle path/proof 增量同步

---

## 三、核心数据结构（Phase 1 必须定义）

```go
// ZonePath 作用域路径，如 "pek.catofes."
type ZonePath string

func (zp ZonePath) Parent() ZonePath   // "pek.catofes." → "catofes."
func (zp ZonePath) IsRoot() bool      // "."

// Delegation 委派记录：谁被授权管理某个子 Zone
type Delegation struct {
    ZoneName    ZonePath          // 被委派的 Zone，如 "pek.catofes."
    DelegateKey ed25519.PublicKey // 被委派者的公钥
    Permissions []Permission      // [PermDelegate, PermWrite, PermAllocateIP, ...]
    ExpiresAt   *time.Time        // 可选过期时间
    
    SignedBy    ed25519.PublicKey // 签名者的公钥（即父 Zone 的当前持有者）
    Signature   []byte            // 签名
}

  // ZoneAuthority Zone 的写权限主体（支持轮换、多 key、门限）
  type ZoneAuthority struct {
    Zone      ZonePath
    Epoch     uint64
    Keys      []AuthorizedKey
    Threshold uint8
  }

  type AuthorizedKey struct {
    Key         ed25519.PublicKey
    Capabilities []Permission
    NotBefore   int64
    NotAfter    int64
  }

// Record K-V 记录
type Record struct {
    Zone      ZonePath
    Key       string            // 如 "wg/pubkey", "ips/10.0.1.0/24"
  Type      string            // 如 "wireguard.public_key", "policy.uint"
  Value     []byte
    
  Version   uint64
  PrevHash  []byte
  Timestamp int64             // 审计字段，不参与最终冲突裁决
    SignedBy  ed25519.PublicKey // 签名者的公钥（必须是该 Zone 的当前持有者）
    Signature []byte            // 对 (Zone+Key+Value+Timestamp) 的签名
}

// ZoneState 一个 Zone 的完整本地状态
type ZoneState struct {
    Path        ZonePath
    SelfDelegation *Delegation     // @delegation：本 Zone 是如何被授权的
  Authority   *ZoneAuthority
    Delegations map[ZonePath]*Delegation // 子 Zone 的委派
    Records     map[string]*Record // 本 Zone 的 K-V，key 为 record key
    
    MerkleRoot  []byte            // 缓存的 Merkle Root Hash
}

// NetworkState 全局网络状态（所有 Zone 的集合）
type NetworkState struct {
    Zones map[ZonePath]*ZoneState
    // 可选：全局 Merkle Root = MerkleTree(Hash(每个 Zone.MerkleRoot))
    GlobalRoot []byte
}

// NodeIdentity 本节点身份
type NodeIdentity struct {
    PrivateKey ed25519.PrivateKey
    PublicKey  ed25519.PublicKey
    
    // 本节点被授权管理的 Zone 列表（通常只有一个，如 node1.catofes.）
    ManagedZones []ZonePath
}

// Endpoint 网络端点
type Endpoint struct {
    IP       net.IP
    Port     uint16
    Scope    string // "global", "site", "link"
    Priority int
}

// TransportLink 传输层链路定义
type TransportLink struct {
    Type       string // "wireguard", "ipsec", "gre"
    LocalPort  uint16
    RemotePort uint16
    Params     map[string]string
}

  // LinkInstance 路由适配器消费的链路实例，不直接耦合 PeerView
  type LinkInstance struct {
    ID         string
    Peer       ZonePath
    Transport  string
    Interface  string
    LocalAddr  netip.Addr
    RemoteAddr netip.Addr
    Metric     uint32
    State      string
  }

// PeerView 从配置系统推导出的对等节点视图（用于生成 WG/路由配置）
type PeerView struct {
    NodeID      []byte        // blake2b(pubkey) 或直接用 pubkey
    Zone        ZonePath      // 如 "node1.catofes."
    PublicKey   []byte        // wg pubkey
    AllowedIPs  []net.IPNet   // 从 Zone 的 local-routes + 分配到的 IPs 汇总
    Endpoints   []Endpoint
    Links       []TransportLink
}

  // 建议的内置记录类型（用于 schema 约束）
  // node.identity
  // node.endpoint
  // wireguard.public_key
  // wireguard.listen_port
  // ipam.assignment
  // route.announcement
  // policy.uint
  // policy.string
  // policy.string_list
```

---

## 四、分阶段实施计划

### Phase 1.0: 单机配置模型（建议先做，预计 1-2 周）
**目标：** 在单机完成可验证的配置状态机，不依赖网络。

- [ ] identity 生成、存储与签名验证
- [ ] zone/delegation/record/authority/version-chain 基础模型
- [ ] bbolt 持久化与加载恢复
- [ ] CLI: `init`, `zone show`, `record put`, `verify`

### Phase 1.1: 两节点同步（建议拆分，预计 1-2 周）
**目标：** 跑通安全边界明确的同步流程。

- [ ] bootstrap peer 连接
- [ ] whole-zone 同步（先不做复杂 Merkle diff）
- [ ] `quarantine -> verify -> active` 状态晋升
- [ ] CLI: `sync status`

### Phase 1: 核心骨架 + Zone K-V + WireGuard + Babeld（预计 5-7 周）
**目标：** 让两个节点能自动发现、同步 Zone 配置、建立 WG 隧道、运行 Babeld 互相学习路由、ping 通。

- [ ] **1.1 项目结构与工具链**
  - 目录：`cmd/higgs/`, `pkg/core/{identity,zone,merkle,gossip}`, `pkg/transport/wireguard/`, `pkg/routing/babeld/`, `pkg/crypto/`
  - 升级 Go 至 1.22+
  - 引入依赖：`golang.zx2c4.com/wireguard/wgctrl`, `github.com/vishvananda/netlink`, `go.etcd.io/bbolt`, `google.golang.org/protobuf`

- [ ] **1.2 身份与密钥系统**
  - ED25519 主密钥生成与本地加密存储（OS keyring 或 passphrase + bcrypt）
  - NodeID = blake2b(pubkey)
  - 子密钥/Zone 委派关系存储

- [ ] **1.3 Zone K-V 存储引擎**
  - 内存中的 `ZoneState` 管理（map[ZonePath]*ZoneState）
  - 本地持久化：bbolt，按 Zone 分 bucket
  - `Get(fqkey)` 实现：解析 Zone + Key → 本 Zone 查找 → 向上 fallback 直到根
  - `Put(record)` 实现：验证签名者是否属于 ZoneAuthority 且满足权限 → 写入 → 更新 ZoneRoot
  - 冲突处理：`Version + PrevHash`，同版本冲突进入 fork，禁止自动时间戳覆盖

- [ ] **1.4 Merkle Tree**
  - Phase 1A: `ComputeZoneRoot()`（sorted hash）
  - Phase 1B: `GetZoneDiff()`（per-record hash）
  - Phase 2+: 完整 Merkle tree diff

- [ ] **1.5 Gossip 传输层**
  - UDP socket 监听（固定端口，如 33434）
  - Protobuf 消息定义：`Ping`, `Pong`, `FetchZone`, `FetchRecord`, `Announce`
  - Anti-replay：消息带 64-bit nonce + 时间戳窗口（±5分钟）
  - 节点发现：通过配置文件中的 bootstrap 列表启动
  - 限流与配额：每 peer 限制速率/字节/对象数
  - 未验证状态隔离存储：禁止直接写 active StateDB

- [ ] **1.6 签名验证链**
  - `VerifyDelegation(d, parentZone)`：检查签名者 = parentZone 的当前持有者
  - `VerifyRecord(r, zone)`：检查签名者 = zone 的当前持有者
  - `VerifyChain(zonePath)`：从该 Zone 一路回溯到根，验证每个 @delegation

- [ ] **1.7 WireGuard 控制模块**
  - 通过 `wgctrl-go` 操作内核 WG 接口
  - 监听 `*.<parent_zone>./wg/*` Record 变更
  - 自动生成 PeerView 与 LinkInstance → 应用 WG 配置（add/remove/update peer）
  - 增加拓扑策略：`policy/topology`、`policy/max-active-links`

- [ ] **1.8 Babeld 路由适配器**
  - 启动 babeld 并通过控制 socket（`-G` Unix/TCP socket）发送命令
  - 命令封装：`add interface wg0`、`flush interface wg0`
  - 当 WG 接口建立/拆除时，动态通知 babeld 添加/移除接口
  - 可选：通过 `redistribute` 或 `install` 注入本地路由

- [ ] **1.9 最小闭环验证**
  - 节点 A（`node1.catofes.`）和节点 B（`node2.catofes.`）启动
  - 各自加载本地私钥，读取/写入自己的 Zone Record
  - 通过 Gossip 交换 Zone 配置
  - 为对方添加 WG Peer，隧道建立
  - babeld 在 wg0 上发现邻居，交换路由
  - 互相 ping 通 tunnel IP

### Phase 2: 动态拓扑 + 多节点 + IP 分配（预计 3-4 周）
**目标：** 支持 3+ 节点、自动准入、IP 分配、链路健康检测。

- [ ] **2.1 准入流程**
  - 新节点生成密钥对 → 向管理员申请 delegation
  - 管理员在父 Zone 创建 `nodeX.parent.` delegation
  - Gossip 全网传播后，新节点自动被所有节点识别并建立 WG Peer

- [ ] **2.2 IP 分配管理**
  - 拆分语义：`ipam/pools/*`、`ipam/assignments/*`、`routes/announcements/*`
  - 节点查询自己的 Zone fallback 路径，汇总所有分配到的 IPs
  - 冲突检测：按 ownership + version-chain 裁决，禁止仅按时间戳

- [ ] **2.3 链路健康检测**
  - 在 WG 隧道上周期性发送 ICMP/自定义 keepalive
  - 检测 RTT、丢包率
  - 链路异常时标记 down，从 babeld 接口中移除或降低优先级

- [ ] **2.4 动态 Peer 管理**
  - 节点离线超时后，保留配置但标记 stale
  - 长期离线后自动清理 WG Peer 和路由
  - 节点信息变更（endpoint、pubkey rotate）自动更新 WG 配置

- [ ] **2.5 防火墙规则同步（基础）**
  - 基于已同步的 Zone 中所有合法节点的 AllowedIPs
  - 通过 `nftables` netlink 接口生成 accept 规则，默认 drop

### Phase 3: 健壮性与高级特性（预计 4-6 周）
**目标：** 生产可用，支持多线路、跳频、扩展传输协议。

- [ ] **3.1 多线路并行（Multipath）**
  - 一个 Peer 可建立多条 TransportLink（WG over 公网 + WG over 内网 + GRE）
  - 每条链路独立运行 babeld 接口
  - babeld 自动进行多路径负载均衡（Babel 原生支持 ECMP）

- [ ] **3.2 UDP 端口跳频（Port Hopping）**
  - 先实现多 endpoint / 多 port probe 与质量选择
  - 如需 rotate，必须包含：old-port grace period、clock skew 容忍、fallback static port、失联恢复路径

- [ ] **3.3 IKEv2 (StrongSwan) 传输驱动**
  - 通过 vici 协议控制 StrongSwan
  - 复用 Zone K-V 中的 `ipsec/*` Record

- [ ] **3.4 VXLAN Overlay**
  - 在 WG 三层网络上封装 VXLAN
  - 通过 Zone Record 同步 VNI、VTEP 信息

- [ ] **3.5 SRv6 支持（实验性）**
  - 通过 netlink 配置 SRv6 SID、End.DT4/End.DX6 行为
  - 与 BIRD/FRR 的 SRv6 扩展联动（如后续引入 BGP）

- [ ] **3.6 运维与可观测性**
  - Prometheus metrics 导出（节点数、链路状态、Gossip 流量、Zone 数量）
  - 结构化日志（slog）
  - CLI 调试工具：`higgs status`, `higgs zones`, `higgs peers`, `higgs sync`

---

## 五、关键技术选型建议

| 组件 | 推荐方案 | 备选 | 理由 |
|------|----------|------|------|
| Go 版本 | 1.22+ | - | 泛型、slog、标准库增强 |
| WG 控制 | `wgctrl-go` | exec `wg` | 直接 netlink，性能更好 |
| netlink | `vishvananda/netlink` | `mdlayher/netlink` | 生态成熟 |
| 本地存储 | `bbolt` | `badger` | KV 足够，纯 Go 无 CGO |
| 序列化 | `protobuf` | `msgpack` | Gossip 消息用 pb，本地/Record 值可用 msgpack |
| 配置格式 | `TOML` | YAML | 已有依赖，人类可读 |
| 路由协议 | `babeld` + 控制 socket | BIRD/BGP | Babel 更适合 mesh，自动邻居发现，无需 AS 号 |
| 防火墙 | `nftables` netlink | exec `iptables` | 现代 Linux 趋势 |

---

## 六、下一步行动（推荐立即开始）

1. **确认 Zone K-V 设计细节：** 上述 DNS 式作用域 + K-V + 向下覆盖的方案是否完全符合预期？有无需要调整的术语或行为？
2. **细化 Merkle DAG 算法：** 是否需要我先写一份 Zone Merkle Tree 的伪代码/流程图？
3. **开始写代码：** 从 `pkg/core/zone.go`（Zone/Delegation/Record 定义）、`pkg/crypto/identity.go`（ED25519 密钥+签名）开始。
