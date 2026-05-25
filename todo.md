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
| 跳频/多线路并行 | 属于高级对抗/优化特性 | 放到 Phase 5 |
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

**ZoneAuthority（Zone 的写权限主体）**
- 每个 Zone 的实际写权限主体不是单 key，而是可扩展的 `ZoneAuthority`（keyset + threshold + epoch）
- Phase 0 可先退化为 `threshold=1`，但数据模型从第一天保留多 key/轮换能力
- 根 key 仅用于签发/轮换 authority；日常写入使用 operational key
- `ZoneAuthority` 变更（epoch 递增）时，父 Zone 的 `Delegation` 必须同步更新 `AuthorityEpoch` + `AuthorityHash`

**Delegation（委派）**
- 父 Zone 授权的不是"某个 key"，而是"某个 ZoneAuthority"
- `Delegation` 包含：
  - `zone: pek.catofes.`
  - `authority_epoch: 3`
  - `authority_hash: 0x...`（blake2b(ZoneAuthority)）
  - `authority: ZoneAuthority{Keys: [...], Threshold: 1, Epoch: 3}`
  - `signature: 0x...`（由父 Zone 的当前持有者签名）
- 子 Zone 的 `ParentProof` 只是该 `Delegation` 的缓存副本，**唯一权威来源始终是父 Zone 中的 `delegations/<child>` 记录**

**Record（K-V 记录）**
- Zone 内的任意键值对，key 形如 `wireguard/public_key`、`routes/announcements/10.0.1.1_32`
- 每条 Record 必须由该 Zone 当前有效的 `ZoneAuthority` 中的某个 key 签名
- Record 必须带类型与版本链，`Timestamp` 仅作为审计字段，**禁止用于冲突裁决**
- 建议内置类型：
  - `node.identity`
  - `node.endpoint`
  - `wireguard.public_key`
  - `wireguard.listen_port`
  - `ipam.assignment`
  - `route.announcement`
  - `policy.uint`
  - `policy.string`
  - `policy.string_list`

**配置向下覆盖（Fallback/继承）**
- 查询 `pek.catofes./policy/mtu` 时，先在该 Zone 查找
- 若不存在，去掉最左一级，在 `catofes.` 中继续查找 `policy/mtu`
- 直到根 Zone `.` 或找到为止
- 这与 DNS 查询不同，更接近配置系统的 override/继承模型

### 2.2 一个完整的配置示例

```
. (根 Zone，由创世主密钥持有)
├── authority
│   └── ZoneAuthority{Epoch: 1, Keys: [<root-pubkey>], Threshold: 1}
├── records/
│   ├── policy/allowed-transports  → "wireguard"
│   ├── policy/default-ip-pool     → "10.0.0.0/8"
│   └── policy/mtu                 → "1420"
│
└── delegations/
    └── catofes. → Delegation{
        AuthorityEpoch: 1,
        AuthorityHash: 0x...,
        Authority: ZoneAuthority{Keys: [<alice-pubkey>], Threshold: 1, Epoch: 1},
        SignedBy: <root-pubkey>
    }

catofes.
├── authority
│   └── ZoneAuthority{Epoch: 1, Keys: [<alice-pubkey>], Threshold: 1}
├── records/
│   ├── policy/mtu                 → "1400"          ← 覆盖根的 1420
│   └── ipam/pools/10.0.1.0/24    → {delegated_to: "pek.catofes."}
│
└── delegations/
    ├── pek.catofes.  → Delegation{Authority: ZoneAuthority{Keys: [<bob-pubkey>], ...}, SignedBy: <alice>}
    └── node1.catofes. → Delegation{Authority: ZoneAuthority{Keys: [<node1-pubkey>], ...}, SignedBy: <alice>}

pek.catofes.
├── authority
│   └── ZoneAuthority{Epoch: 1, Keys: [<bob-pubkey>], Threshold: 1}
└── records/
    └── ipam/assignments/10.0.1.1/32 → {assigned_to: "node1.pek.catofes."}  ← bob 分配的 IP

node1.catofes.
├── authority
│   └── ZoneAuthority{Epoch: 1, Keys: [<node1-pubkey>], Threshold: 1}
└── records/
    ├── identity                    → {name: "node1"}
    ├── endpoints/public            → "1.2.3.4:51820"
    ├── wireguard/public_key        → "0xnode1wgpubkey..."
    ├── wireguard/listen_port       → "51820"
    └── routes/announcements/10.0.1.1_32 → "10.0.1.1/32"
```

**验证签名链示例：**
- 读取 `node1.catofes./wireguard/public_key` 时：
  1. 取出 Record，验证 `SignedBy` 是否属于 `node1.catofes.` 的 `ZoneAuthority.Keys`
  2. 验证该 key 的 `Capabilities` 包含 `write`（或更细粒度的 `write:wireguard`）
  3. 验证 `node1.catofes.` 的 `ParentProof`（Delegation）签名者属于 `catofes.` 的 `ZoneAuthority.Keys`
  4. 验证 `catofes.` 的 `ParentProof` 签名者属于 `.` 的 `ZoneAuthority.Keys`
  5. 全部通过 → 配置可信

**查询与覆盖示例：**
- `Get("node1.catofes./wireguard/public_key")` → 命中 `node1.catofes.` 的 `wireguard/public_key`
- `Get("pek.catofes./policy/mtu")` → `pek.catofes.` 无此 key → 查 `catofes./policy/mtu` → 命中 `"1400"`
- `Get("node1.catofes./policy/allowed-transports")` → 一路回退到 `.` → 命中 `"wireguard"`

### 2.3 与 Mesh VPN 各功能的映射

| 原需求 | Zone K-V 映射 |
|--------|--------------|
| 节点准入 | 父 Zone 签发一个 `nodeX.parent.` 的 delegation（委派 ZoneAuthority） |
| 节点自宣告信息 | 节点用自身 operational key 在 `nodeX.parent.` 下写 `wireguard/*`、`endpoints/*`、`routes/*` 等 Record |
| IP 分配 | 在 Zone 下写 `ipam/pools/*` 或 `ipam/assignments/*` Record |
| 路由宣告 | `nodeX.parent./routes/announcements/<prefix>` Record |
| 全局策略 | 在 `.` 或中间 Zone 设置 `policy/*` Record，被子 Zone 继承 |
| 传输层参数 | `nodeX.parent./wireguard/*`、`nodeX.parent./ipsec/*` 等 Record |

### 2.4 签名规范（必须无歧义）

**Domain Separator（防止跨对象签名重放）：**
- Record: `"higgs.record.v1"`
- Delegation: `"higgs.delegation.v1"`
- ZoneAuthority: `"higgs.authority.v1"`
- Gossip message: `"higgs.gossip.v1"`

**Record 签名内容（canonical serialization）：**
```text
Sign(
  "higgs.record.v1",
  zone,       // e.g. "node1.catofes."
  key,        // e.g. "wireguard/public_key"
  type,       // e.g. "wireguard.public_key"
  value_hash, // blake2b(value)
  version,    // uint64, per-zone-per-key
  prev_hash,  // blake2b(prev_record) or nil
  timestamp,  // int64, audit only
  signer_key_id // blake2b(signer_pubkey), for lookup
)
```

**Delegation 签名内容：**
```text
Sign(
  "higgs.delegation.v1",
  parent_zone,
  child_zone,
  authority_epoch,
  authority_hash, // blake2b(ZoneAuthority)
  expires_at,
  signer_key_id
)
```

### 2.5 Merkle DAG + Gossip 在此模型下的实现

**Merkle Tree 组织：**
- 每个 Zone **独立维护一棵 Merkle Tree**，包含三部分：
  1. `authority_hash`: 本 Zone 的 ZoneAuthority hash
  2. `delegations_tree`: 所有子 Zone 的 delegation 记录
  3. `records_tree`: 本 Zone 的所有 K-V 记录（每条 key 只取最新 active record）
- Zone 的 Root Hash = Hash(authority_hash + delegations_root + records_root)
- **全局状态** = 所有 Zone Root Hash 再组成一棵顶层 Merkle Tree（或简单排序后的哈希链）
- 这样设计的好处：Gossip 时只需交换顶层全局 hash 和变更 Zone 的 hash，同步粒度最细

**Version 链模型（per-zone-per-key）：**
- `Version` 是 **per-zone-per-key** 的版本号，不是整个 Zone 的全局版本
- `PrevHash` 指向同一个 Zone + Key 的上一版本 Record hash
- 同 key 冲突时：Version 更高者胜；Version 相同但内容不同 → 进入 `fork/conflict`，不自动裁决，需 Zone owner（或上级 Zone）签发修正记录
- `Timestamp` 仅作为审计字段，不参与最终裁决
- ZoneRoot 由每个 key 的 latest active record 计算：
  ```text
  ZoneRoot = Hash(authority_hash + delegations_root + sorted(latest_record_hashes))
  ```
- 旧版本记录保留在 `RecordHistory` 中作为审计 log，但 active state 只使用每个 key 的 latest non-conflict record

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
3. A 向 B 请求 `catofes.` 的完整内容（Phase 1 先 whole-zone sync，不先做 Merkle diff）
4. 数据进入 quarantine store
5. 本地逐条验证签名链（Delegation → Authority → Record）
6. 验证通过 → 提升到 active store → 重新计算本地 hash → 继续 Gossip

**并发与冲突：**
- Zone 天然有单一持有者，同一 Zone 内的写入冲突应由该持有者避免。
- 若因网络分区恢复等原因检测到同一 Zone 同一 key 的冲突：
  1. `Version` 更高者胜；
  2. `Version` 相同但内容不同，进入 `fork/conflict`；
  3. `fork/conflict` 不自动裁决，需 Zone owner（或上级 Zone）签发修正记录。
- `Timestamp` 仅作为审计字段，不参与最终裁决。

**Merkle 实施分层（降低 Phase 1 风险）**
- Phase 1A: `ZoneRoot = hash(sorted(records + delegations + authority))`，hash 不同直接拉完整 Zone
- Phase 1B: 引入 per-record hash diff
- Phase 2+: 再上完整 Merkle path/proof 增量同步

---

## 三、核心数据结构（Phase 0 必须定义）

```go
// ZonePath 作用域路径，如 "pek.catofes."
type ZonePath string

func (zp ZonePath) Parent() ZonePath   // "pek.catofes." → "catofes."
func (zp ZonePath) IsRoot() bool      // "."

// Permission 能力枚举
type Permission string
const (
    PermWrite       Permission = "write"
    PermWriteWireGuard Permission = "write:wireguard"
    PermWriteRoute  Permission = "write:route"
    PermDelegate    Permission = "delegate"
    PermAllocateIP  Permission = "allocate-ip"
)

// Capability key 的能力声明
type Capability struct {
    Permissions []Permission
    KeyPrefix   string // 可选：限制只能写特定 key 前缀
}

// AuthorizedKey ZoneAuthority 中的授权 key
type AuthorizedKey struct {
    Key          ed25519.PublicKey
    NotBefore    int64
    NotAfter     int64
    Capabilities []Capability
}

// ZoneAuthority Zone 的写权限主体（支持轮换、多 key、门限）
type ZoneAuthority struct {
    Zone      ZonePath
    Epoch     uint64
    Keys      []AuthorizedKey
    Threshold uint8
}

// Delegation 委派记录：父 Zone 授权子 Zone 由哪个 ZoneAuthority 管理
type Delegation struct {
    ZoneName       ZonePath
    AuthorityEpoch uint64
    AuthorityHash  []byte      // blake2b(ZoneAuthority)
    Authority      ZoneAuthority
    ExpiresAt      *time.Time

    SignedBy       ed25519.PublicKey // 父 Zone Authority 中的某个 key
    Signature      []byte
}

// Record K-V 记录
type Record struct {
    Zone      ZonePath
    Key       string
    Type      string
    Value     []byte
    ValueHash []byte        // blake2b(value)
    Version   uint64        // per-zone-per-key version chain
    PrevHash  []byte        // 指向同 zone+key 上一版本
    Timestamp int64         // 审计字段，不参与冲突裁决

    SignedBy  ed25519.PublicKey // 必须是该 Zone 当前 ZoneAuthority.Keys 中的某个 key
    Signature []byte            // domain + zone + key + type + value_hash + version + prev_hash + timestamp + signer_key_id
}

// ZoneState 一个 Zone 的完整本地状态
type ZoneState struct {
    Path           ZonePath
    Authority      *ZoneAuthority         // 本 Zone 当前 authority
    ParentProof    []*Delegation          // 父级到根的 proof chain（缓存，非权威）
    Delegations    map[ZonePath]*Delegation // 子 Zone 的委派
    Records        map[string]*Record     // key → latest active record
    RecordHistory  map[string][]*Record   // key → version chain（审计）
    MerkleRoot     []byte                 // 缓存的 Merkle Root Hash
}

// NetworkState 全局网络状态（所有 Zone 的集合）
type NetworkState struct {
    Zones map[ZonePath]*ZoneState
    // 全局 Merkle Root = MerkleTree(sorted(每个 Zone.MerkleRoot))
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

// PeerView 从配置系统推导出的对等节点视图
type PeerView struct {
    NodeID           []byte
    Zone             ZonePath
    PublicKey        []byte         // wg pubkey
    TunnelAllowedIPs []netip.Prefix // WG 只放 tunnel IP /32 或 /128
    AnnouncedRoutes  []netip.Prefix // 业务路由，交给 Babeld
    Endpoints        []Endpoint
    Links            []TransportLink
}
```

---

## 四、验证逻辑（必须精确定义）

### 4.1 VerifyRecord(r, zone)

```text
1. 找到 zone 当前有效的 ZoneAuthority
2. 检查 r.SignedBy 是否属于 authority.Keys（按 key_id 匹配）
3. 找到匹配的 AuthorizedKey，检查其 Capabilities：
   a. 是否包含全局 PermWrite；或
   b. 是否包含 PermWrite<Type>（如 write:wireguard）；或
   c. 是否包含匹配 r.Key 前缀的 Capability
4. 检查 AuthorizedKey 的 NotBefore <= now <= NotAfter
5. 重新计算 value_hash = blake2b(r.Value)，与 r.ValueHash 比对
6. 验证 Signature：
   domain="higgs.record.v1" + zone + key + type + value_hash + version + prev_hash + timestamp + signer_key_id
7. 检查 Version：
   a. 如果是同 key 的新版本，Version 必须 > current_version
   b. 如果 Version == current_version 但 hash 不同，标记为 fork/conflict
   c. 如果 Version < current_version，拒绝（旧版本攻击）
8. 检查 PrevHash：
   a. 如果 Version == 1，PrevHash 必须为 nil
   b. 如果 Version > 1，PrevHash 必须匹配当前 active record 的 hash
```

### 4.2 VerifyDelegation(d, parentZone)

```text
1. 找到 parentZone 当前有效的 ZoneAuthority
2. 检查 d.SignedBy 是否属于 parentZone.Authority.Keys
3. 检查签名者的 Capabilities 是否包含 PermDelegate
4. 检查签名者的 NotBefore/NotAfter
5. 重新计算 authority_hash = blake2b(d.Authority)，与 d.AuthorityHash 比对
6. 验证 Signature：
   domain="higgs.delegation.v1" + parent_zone + child_zone + authority_epoch + authority_hash + expires_at + signer_key_id
7. 检查 d.ZoneName 的 Parent() == parentZone（防路径欺骗）
```

### 4.3 VerifyChain(zonePath)

```text
1. 从 zonePath 开始向上回溯：
   current = zonePath
   while current != ".":
     a. 获取 current 的 ParentProof[0]（即父 Zone 对 current 的 Delegation）
     b. 验证该 Delegation 的 VerifyDelegation(d, current.Parent())
     c. current = current.Parent()
2. 根 Zone "." 的 Authority 必须自签（或通过本地可信配置锚定）
3. 任何一环验证失败 → 整个 Zone 树不可信
```

---

## 五、分阶段实施计划

### Phase 0: 单机可信状态机（预计 1-2 周）
**目标：** 在单机完成可验证的配置状态机，不依赖网络。

- [ ] **0.1 项目结构**
  - 目录：`cmd/higgs/`, `pkg/core/{identity,zone,merkle,gossip}`, `pkg/transport/wireguard/`, `pkg/routing/babeld/`, `pkg/crypto/`
  - 升级 Go 至 1.22+
  - 引入依赖：`golang.zx2c4.com/wireguard/wgctrl`, `github.com/vishvananda/netlink`, `go.etcd.io/bbolt`

- [ ] **0.2 身份与密钥系统**
  - ED25519 主密钥生成与本地加密存储（passphrase + bcrypt）
  - NodeID = blake2b(pubkey)

- [ ] **0.3 Zone / Authority / Delegation / Record 基础模型**
  - 定义上述数据结构
  - 实现 `Get(fqkey)`：解析 Zone + Key → 本 Zone 查找 → 向上 fallback 直到根
  - 实现 `Put(record)`：本地写入（暂不验证网络签名，只验证本地 authority）

- [ ] **0.4 签名与验证**
  - 实现 Record / Delegation / ZoneAuthority 的 Sign 和 Verify
  - 实现 VerifyChain
  - 定义并使用 domain separator

- [ ] **0.5 bbolt 持久化**
  - 按 Zone 分 bucket 存储
  - 加载/恢复/版本链审计

- [ ] **0.6 CLI 调试**
  - `higgs init`
  - `higgs zone show <zone>`
  - `higgs record put <zone> <key> <value>`
  - `higgs verify <zone>`

### Phase 1: 两节点 Zone 同步（预计 1-2 周）
**目标：** 跑通安全边界明确的同步流程。

- [ ] **1.1 Gossip 传输层**
  - UDP socket 监听（固定端口，如 33434）
  - Protobuf 消息定义：`Ping`, `Pong`, `FetchZone`, `FetchRecord`, `Announce`
  - Anti-replay：64-bit nonce + 时间戳窗口（±5分钟）
  - 限流与配额：每 peer 限制速率/字节/对象数

- [ ] **1.2 节点发现**
  - 通过配置文件中的 bootstrap 列表启动
  - 仅接受已知 peer 的连接

- [ ] **1.3 Whole-Zone 同步**
  - Phase 1A 先不做 Merkle diff，hash 不同直接拉完整 Zone
  - 数据进入 `quarantine store`
  - 逐条验证签名链（VerifyDelegation → VerifyRecord → VerifyChain）
  - 验证通过后提升到 `active store`

- [ ] **1.4 闭环验证**
  - 节点 A 修改本地 Zone Record
  - Gossip 到节点 B
  - B 验证通过后 active store 可见
  - CLI: `higgs sync status`

### Phase 2: WireGuard 建链（预计 2-3 周）
**目标：** 两个节点能根据同步后的 Zone 配置自动建立 WG 隧道。

- [ ] **2.1 WireGuard 控制模块**
  - 通过 `wgctrl-go` 操作内核 WG 接口
  - 监听 `*.<parent_zone>./wireguard/*` Record 变更
  - 从 Zone 推导 PeerView：
    - `PublicKey` = `wireguard/public_key`
    - `Endpoints` = `endpoints/*`
    - `TunnelAllowedIPs` = 节点自身的 tunnel IP /32（从 `ipam/assignments/*` 推导）
    - `AnnouncedRoutes` = `routes/announcements/*`
  - 应用 WG 配置（add/remove/update peer）
  - **安全原则：WG AllowedIPs 只放 tunnel /32 或 /128，业务路由不经过 WG allowed-ips**

- [ ] **2.2 链路实例管理**
  - 当 WG peer 建立后，生成 LinkInstance
  - 跟踪链路状态：up/down/stale

- [ ] **2.3 最小闭环验证**
  - 节点 A 和 B 同步配置
  - 自动为对方添加 WG Peer
  - `wg show` 看到握手成功
  - 互相 ping 通 tunnel IP

### Phase 3: Babeld 路由 + Route Authorization Filter（预计 2-3 周）
**目标：** babeld 在 WG 接口上发现邻居、学习路由，且只接受被授权的前缀。

- [ ] **3.1 Babeld 路由适配器**
  - 启动 babeld 并通过控制 socket（`-G` Unix/TCP socket）发送命令
  - 命令封装：`add interface wg0`、`flush interface wg0`
  - 当 WG 接口建立/拆除时，动态通知 babeld 添加/移除接口

- [ ] **3.2 Route Authorization Filter（核心安全任务）**
  - 根据 active state 中的 `routes/announcements/*` 和 `ipam/assignments/*` 生成 prefix whitelist
  - 为每个 peer/interface 生成 babeld `import filter`：
    - 只允许来自该 peer 的、被其 Zone 宣告过的前缀
    - 拒绝 `0.0.0.0/0`、未授权前缀、他人网段
  - **原则：控制平面验证了节点"可以加入网络"，但路由协议层面还要防止它乱宣告**

- [ ] **3.3 本地路由注入**
  - 通过 babeld 控制 socket 的 `install` / `uninstall` 注入本节点 AnnouncedRoutes
  - 或通过 `redistribute` 配置让 babeld 自动学习

- [ ] **3.4 闭环验证**
  - 3+ 节点组网
  - Babeld 在 wg0 上发现邻居，交换路由
  - 验证 route filter：节点 A 尝试宣告未授权前缀 → 被其他节点过滤掉

### Phase 4: 多节点/IPAM/准入/防火墙（预计 3-4 周）
**目标：** 支持动态准入、IP 分配、链路健康、防火墙规则。

- [ ] **4.1 准入流程**
  - 新节点生成密钥对 → 向管理员申请 delegation
  - 管理员在父 Zone 创建 `nodeX.parent.` delegation
  - Gossip 全网传播后，新节点自动被所有节点识别并建立 WG Peer

- [ ] **4.2 IP 分配管理（IPAM）**
  - 拆分语义：`ipam/pools/*`、`ipam/assignments/*`、`routes/announcements/*`
  - 节点查询自己的 Zone fallback 路径，汇总所有分配到的 IPs
  - 冲突检测：按 ownership + version-chain 裁决，禁止仅按时间戳

- [ ] **4.3 链路健康检测**
  - 在 WG 隧道上周期性发送 ICMP/自定义 keepalive
  - 检测 RTT、丢包率
  - 链路异常时标记 down，从 babeld 接口中移除或降低优先级

- [ ] **4.4 动态 Peer 管理**
  - 节点离线超时后，保留配置但标记 stale
  - 长期离线后自动清理 WG Peer 和路由
  - 节点信息变更（endpoint、pubkey rotate）自动更新 WG 配置

- [ ] **4.5 防火墙规则同步**
  - 基于已同步的 Zone 中所有合法节点的 TunnelAllowedIPs
  - 通过 `nftables` netlink 接口生成 accept 规则，默认 drop

### Phase 5: 健壮性与高级特性（预计 4-6 周）
**目标：** 生产可用，支持多线路、跳频、扩展传输协议。

- [ ] **5.1 多线路并行（Multipath）**
  - 一个 Peer 可建立多条 TransportLink（WG over 公网 + WG over 内网 + GRE）
  - 每条链路独立运行 babeld 接口
  - babeld 自动进行多路径负载均衡（Babel 原生支持 ECMP）

- [ ] **5.2 UDP 端口跳频（Port Hopping）**
  - 先实现多 endpoint / 多 port probe 与质量选择
  - 如需 rotate，必须包含：old-port grace period、clock skew 容忍、fallback static port、失联恢复路径

- [ ] **5.3 IKEv2 (StrongSwan) 传输驱动**
  - 通过 vici 协议控制 StrongSwan
  - 复用 Zone K-V 中的 `ipsec/*` Record

- [ ] **5.4 VXLAN Overlay**
  - 在 WG 三层网络上封装 VXLAN
  - 通过 Zone Record 同步 VNI、VTEP 信息

- [ ] **5.5 SRv6 支持（实验性）**
  - 通过 netlink 配置 SRv6 SID、End.DT4/End.DX6 行为
  - 与 BIRD/FRR 的 SRv6 扩展联动（如后续引入 BGP）

- [ ] **5.6 运维与可观测性**
  - Prometheus metrics 导出（节点数、链路状态、Gossip 流量、Zone 数量）
  - 结构化日志（slog）
  - CLI 调试工具：`higgs status`, `higgs zones`, `higgs peers`, `higgs sync`

---

## 六、关键技术选型建议

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

## 七、下一步行动

1. **开始写 `pkg/core/zone.go`**：`ZonePath`、`ZoneAuthority`、`AuthorizedKey`、`Delegation`、`Record`、`ZoneState` 的定义与基础方法
2. **开始写 `pkg/crypto/signer.go`**：domain separator 常量、Sign/Verify 函数、VerifyRecord/VerifyDelegation/VerifyChain 逻辑
3. **Phase 0 闭环验证**：单机完成 `init` → `record put` → `verify chain` 的 CLI 流程
