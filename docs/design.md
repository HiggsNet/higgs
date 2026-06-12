# Higgs Mesh VPN 控制平面设计

> **文档状态（2026-06）**
> Phase 0–3 已落地实现。本文档同时承担设计规格说明与实现参考的角色。
> 各 Phase 完成情况见 `../todo.md`；Phase 4（StrongSwan/IKEv2 + XFRM interface 建链）已进入实现阶段：record / ContactPoint / planner / LinkInstance reconcile / dry-run driver / XFRM preflight 已落地，driver 层真实 StrongSwan/VICI IKE/CHILD_SA + tunnel ping 已在 4.3 验证，daemon `Run` 循环级 gossip 同步后的真实 VICI/XFRM bring-up 和 tunnel ping 已进入 root/container smoke。

## 原始需求摘要

目标是实现一套 mesh vpn 的控制程序（控制平面）。整个网络运行在三层 p2p 互联网络，之上运行路由协议。目前的初步设计如下：

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
1. 节点之间建立起一套去中心化的最终一致的配置同步机制。权限通过ed25519密钥签名实现，权限细分为：准入（主签名节点的子密钥），核准ip（主密钥签名ip分配记录，子密钥继续签名分配），公布自己节点的信息（节点的子密钥签名自己的内容）。
2. 节点之间建立底层传输协议
3. 当节点信息更改时调整传输协议
4. 对应调整路由协议，filter，准入，防火墙等等。
5. 配置seg6等

需要一些特殊的点：
1. 底层传输协议可以有线路并行，例如既有wg，又有ikev2，还可以加上gre等
2. 为了防止流量被劣化，考虑到“跳频”的功能，即如果是udp+port协议（例如wg），动态建立监听多个端口，约定好时间切换，有点像证书的rotate，不过是端口的rotate。

实现： go语言
平台： linux

## 一、架构

### 1.1 核心决策
| 方向 | 决策 | 说明 |
|------|------|------|
| 配置同步机制 | **DNS 式层级作用域 (Zone) + Signed Merkle DAG + Gossip** | 整个系统的基石 |
| 第一阶段传输 | **StrongSwan/IKEv2 + XFRM interface + Babeld** | 动态路由、多 peer、namespace 和撤销清理作为主线；WireGuard 后移为可选轻量传输驱动 |
| 跳频/多线路 | Phase 6 | 高级对抗/优化特性，待控制平面稳定后再做 |
| 系统服务交互 | `vici`（StrongSwan）/ `netlink`（XFRM/路由/WG）/ `控制 socket`（babeld）/ `exec`（兜底） | 按组件分层 |

### 1.2 总体架构（核心 + 插件）

```
┌──────────────────────────────────────────────────┐
│             app/higgs/  (CLI / daemon 入口)       │
│  init · keygen · join · delegate · record        │
│  verify · daemon · sync · debug · db             │
├──────────────┬───────────────┬───────────────────┤
│  pkg/core/   │ pkg/transport/│  pkg/routing/     │
│              │   drivers     │    adapters        │
├──────────────┼───────────────┼───────────────────┤
│ ✅ identity  │ 🟨 ipsec      │ 🔲 babeld         │
│ ✅ gossip    │   (Phase 4)   │   (Phase 5)        │
│ ✅ zone      │               │                   │
│ 🔲 merkle   │               │                   │
│ ✅ crypto    │               │                   │
├──────────────┴───────────────┴───────────────────┤
│           overlay (Phase 6 规划)                  │
│       vxlan (🔲)    seg6 (🔲)                    │
└──────────────────────────────────────────────────┘

✅ = 已实现   🟨 = 部分实现/系统闭环扩展中   🔲 = 已建目录/存根，待实现
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
- Phase 0 明确只接受 `threshold=1`；遇到 `threshold>1` 的 ZoneAuthority 必须拒绝并返回 `unsupported threshold`，避免把多签数据误按单签验证
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
    └── ipam/assignments/10.0.1.1/32 → {assigned_to: "node1.catofes."}  ← bob 分配的 IP

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

### 2.4 Overlay / Provider / Link Policy（Phase 4+）

Phase 4 进入 StrongSwan/IKEv2 + XFRM interface 后，控制平面的核心不应退化成“发现一个节点后，管理员手写一条 VPN link”。Higgs 的目标是用已同步的 Zone 状态、节点公开能力和本地规则快速构建 mesh。因此必须把“选择哪些节点互联”和“用 StrongSwan 具体怎么建链”分层：

```text
Local MeshPolicy
        ↓
Verified NodeProfile / IPsec records
        ↓
LinkPlanner
        ↓
TransportLinkSpec
        ↓
OverlayProvider(strongswan)
        ↓
VICI + XFRM apply
```

**MeshPolicy（本地策略，不 gossip 公开）**
- 描述本节点希望连接哪些 peer、使用哪个 overlay/provider、方向、地址族、候选来源、path mode 和数量限制。
- 默认持久化在本机 daemon 配置或本地 DB policy 中；它是本节点的拓扑和安全策略，不应作为普通 public record 向全网广播。
- 支持手工 override，但第一目标是规则驱动 mesh，而不是给每个 peer 手写 link。

**Public NodeProfile / IPsec profile（可 gossip 公开）**
- 节点可以公开“我支持 IPsec，我愿意被哪些类型的 peer 尝试连接，我有哪些候选地址/端口”。
- 公开的是能力和 accept intent，不是完整连接清单。这样可让远端自动决定是否匹配自己的 MeshPolicy，同时避免泄露完整拓扑。

**OverlayProvider（具体系统驱动）**
- `provider=strongswan` 是 Phase 4 唯一实现目标，负责把 `TransportLinkSpec` 转成 VICI connection/secret、XFRM interface、地址和清理动作。
- 后续可以增加 `wireguard`、`vxlan`、`gre`、`seg6`。高层 mesh 选择规则不应依赖 StrongSwan 内部字段。
- 更高层 overlay 可以声明 underlay，例如 `vxlan` 跑在 `strongswan` overlay 之上；Phase 4 只保留模型兼容性，不实现 VXLAN。

#### 2.4.1 Public IPsec records

Phase 4 已实现以下 signed record 的模型、解析和 planner 消费路径。所有记录都由节点自身 Zone authority 签名，通过普通 gossip 同步，远端只在 `VerifyChain` / `VerifyRecord` 通过后使用。

```text
node-a.catofes./ipsec/profile
node-a.catofes./ipsec/addresses
node-a.catofes./ipsec/ports
node-a.catofes./ipsec/transport-key
```

`ipsec/profile` 示例：

```json
{
  "version": 1,
  "enabled": true,
  "provider": "strongswan",
  "ike_identity": "node-a.catofes.",
  "transport_key_fingerprint": "b2:...",
  "accept": "inbound",
  "address_families": ["ipv6", "ipv4"],
  "path_modes": ["family-redundant", "exhaustive"],
  "nat": {
    "hint": "unknown",
    "inbound_reachable": "unknown"
  },
  "updated_at": 1717171717
}
```

`accept` 的含义：
- `none`：不接受自动 mesh 拨入；仍可被本地手工 override 使用。
- `inbound`：本节点愿意接受匹配 policy 的远端主动拨入。
- `bidirectional`：本节点既可接受拨入，也可主动拨出；双方都是 `bidirectional` 时必须用稳定 tie-break 避免重复拨号。

NAT 字段只是 hint，不是安全事实。远端必须结合地址来源、端口公告、连接结果和本地策略判断是否可达。

#### 2.4.2 地址与端口分离

IPsec endpoint 不应直接建模为单个 `ip:port`。端口后续可能在配置范围内动态选择、短期保留旧端口、甚至做较快 rotate；地址也可能来自 DNS、discovery、reflector 或本地接口扫描。Phase 4 使用三层模型：

```text
AddressCandidate      # 当前可用地址或域名解析结果
PortAdvertisement     # 当前可用 IKE/NAT-T 端口公告
ContactPoint          # AddressCandidate + PortAdvertisement 组合出的实际拨号目标
```

`ipsec/addresses` 示例：

```json
{
  "version": 1,
  "addresses": [
    {
      "id": "dns-main",
      "source": "manual-dns",
      "host": "node-a.example.com",
      "families": ["ipv6", "ipv4"],
      "refresh_seconds": 60,
      "priority": 90,
      "reachability": "public",
      "ttl_seconds": 300
    },
    {
      "id": "reflector-v4",
      "source": "reflector",
      "address": "203.0.113.10",
      "family": "ipv4",
      "priority": 60,
      "reachability": "nat-observed",
      "last_observed": 1717171717,
      "ttl_seconds": 600
    }
  ],
  "updated_at": 1717171717
}
```

地址来源：
- `manual-address`：管理员明确配置的 IP。
- `manual-dns`：管理员明确配置的域名；daemon 保存原始域名，并定期 refresh A/AAAA。
- `discovery`：可选 discovery server 返回的候选地址或域名。
- `reflector`：reflector 观察到的外部地址；主要用于 NAT/公网变化场景。
- `local`：本机接口扫描结果；适合 LAN/实验，公网默认应允许禁用。

Go 实现里 DNS/discovery host 被建模为运行时候选展开，而不是 signed record 里的固定 endpoint：`manual-dns` / `discovery` record 保留原始域名；planner 通过 resolver 把 A/AAAA 结果展开成 `AddressCandidate`，再与 `PortAdvertisement` 组合为 `ContactPoint`。这样 DNS refresh 或 discovery 返回变化只影响本地 desired-state 计算，不改变 Zone 签名记录本身。

DNS、discovery、reflector 的优先级不能写死。动态 DNS 本质上也可能只是公网反射/发现机制的包装，因此本地配置应允许指定顺序，例如：

```yaml
ipsec_address_source_order:
  - manual-address
  - manual-dns
  - discovery
  - reflector
  - local
```

当前 `AddressCandidateOptions.SourceOrder` / `AllowedSources` 已经把 source order 和本地 rule 过滤作为运行时输入；排序先看来源顺序，再看单条 `priority`。`local` 来源默认不使用 private/link-local/interface-scan 候选，只有 LAN/实验或管理员显式启用时才通过 `AllowPrivateLocal` 放行，避免公网 IPsec 误连内网地址。

`ipsec/ports` 示例：

```json
{
  "version": 1,
  "mode": "range",
  "range": {"from": 30000, "to": 30999},
  "current": {
    "generation": 42,
    "ike": {"local": 30412, "advertised": 30412, "observed": 30412},
    "natt": {"local": 30413, "advertised": 30413, "observed": 30413},
    "valid_until": 1717175317
  },
  "previous": [
    {
      "generation": 41,
      "ike": {"advertised": 30100},
      "natt": {"advertised": 30101},
      "valid_until": 1717172017
    }
  ],
  "updated_at": 1717171717
}
```

端口语义：
- `local`：本机 StrongSwan/charon 实际监听端口。
- `advertised`：希望远端拨入的端口。
- `observed`：reflector/discovery 从外部看到的端口；NAT 后可能与 local 不同。
- `current`：首选当前端口。
- `previous`：端口轮换 grace 窗口内可回退的旧端口。
- `range`：daemon 可在该范围内选择端口；也可配置固定端口。

Phase 4 当前把端口作为独立公告对象建模，并支持固定/范围/current/previous grace 的规划与 dry-run。`PlanPortRecord` 负责把本地策略、上一代公告和 grace window 转成待签名的 `ipsec/ports` payload；peer 侧继续通过 `ContactPoint` 组合当前地址候选和未过期端口候选。这里需要区分两层能力：当前已实现的是“公告 + planner fallback”，即远端可以优先尝试 current，current 失败/backoff 时在 grace 内回退 previous；这不代表本机 StrongSwan 已经同时监听新旧两组端口，也不代表系统层已经做到无损 rotate。StrongSwan 自定义端口的第一版边界是 `charon.port` / `charon.port_nat_t` + connection `remote_port` + 必要时 reestablish；低频生产可用的平滑 rotate 提前到 Phase 4.4 设计和实现，高频/对抗性 port hopping、复杂多实例策略留到 Phase 7。

平滑 rotate 的 Phase 4.4 目标是把 current/previous grace 变成系统可执行的 staged transition，而不只是远端选择候选端口。当前优先考虑三种实现路径：

- 外层 DNAT/redirect grace：charon 保持稳定监听端口，系统防火墙在 grace 窗口内把新旧 advertised 端口都转发到当前监听端口，grace 后清理旧规则。
- 双 connection / staged reestablish：为新旧端口加载可区分的临时 StrongSwan connection，先确认新 SA，再终止旧 SA。
- 多 charon/socket 实例：新旧监听端口并行，grace 后清理旧实例；部署成本最高，作为后备方案。

无论选择哪条路径，`LinkInstance` 都需要记录 selected ContactPoint、port generation、rotate phase、旧/新端口 owner、rollback deadline 和最近 rotate error；`higgs debug links` 应能说明当前处于 preparing、dual-running、cutover、rollback 还是 cleanup，避免端口轮换变成不可解释的连接抖动。

#### 2.4.3 本地 MeshPolicy rule DSL

为了避免复杂 YAML selector，第一版 MeshPolicy 可以使用小型 URI rule 语言。URI 只用于本地配置，不作为签名协议格式；解析后内部仍落为结构化对象。

```yaml
overlays:
  - name: ipsec-main
    provider: strongswan
    connect:
      - "strongswan://*.catofes.?accept=inbound&family=dual&source=manual-dns,discovery&mode=family-redundant&direction=outbound"
      - "strongswan://edge.catofes.?accept=bidirectional&family=dual"
    deny:
      - "strongswan://*.lab.catofes."
```

第一版 predicate 集合应保持克制：
- zone glob / exact：`*.catofes.`、`node-a.catofes.`
- label selector：`role=edge`、`tag=lab`，仅在本机已有 peer label/tag 来源后使用；示例默认使用 zone glob，避免把未实现的 tag 来源误认为远端声明。
- 远端公开意图：`accept=inbound|bidirectional`
- 本地方向：`direction=outbound|inbound|bidirectional`
- 地址族：`family=ipv4|ipv6|dual`
- 地址来源：`source=manual-address|manual-dns|discovery|reflector|local`
- 路径模式：`mode=family-redundant|exhaustive`
- 数量限制：`max_peers=N`

规则评估顺序为 deny 优先，然后按 connect 顺序匹配。正则表达式可后续作为高级能力加入，但默认使用 glob/suffix/label，便于审计。

当前 planner 已把 zone glob/exact connect/deny rule 接入 `TransportLinkSpec` 推导：rule 可按远端 `accept`、地址族、地址来源、path mode、direction 和 `max_peers` 过滤或覆盖 group 默认值；`role` / `tag` selector 已解析但在本地 peer label 来源接入前不会匹配。

#### 2.4.4 方向、双栈与 NAT 处理

实际建链由“本地 direction”和“远端 accept intent”共同决定：

| 本地 direction | 远端 accept | 行为 |
|----------------|-------------|------|
| `outbound` | `inbound` / `bidirectional` | 本节点可主动拨远端 |
| `inbound` | 任意 | 本节点只加载接收配置，不主动拨 |
| `bidirectional` | `inbound` | 本节点可主动拨远端 |
| `bidirectional` | `bidirectional` | 双方可拨；用稳定 tie-break 决定首拨方 |
| `outbound` | `none` | 不自动建链，除非本地手工 override |

双栈 path mode：
- `family-redundant`：每个地址族最多选择一条 ContactPoint。两个双栈节点之间目标是 IPv6 一条 + IPv4 一条；如果某个地址族不可用，则只建可用族。
- `exhaustive`：尽量连接所有允许来源和端口组合，主要用于调试或特殊高可用场景。
- 不使用语义模糊的 `single-best` 作为第一版名称；如果后续需要单条路径，可增加 `preferred-only`，并把排序规则写清楚。

NAT 处理原则：
- IKEv2/StrongSwan 支持 NAT-T，但“能穿 NAT”不等于“任意方向都能主动拨入”。
- NAT 后节点主动连接公网 inbound 节点通常是第一版应支持的主路径。
- 公网节点主动拨入 NAT 后节点需要 IPv6、静态端口映射、已验证 observed external port、打洞或 relay；不能仅凭 `behind_nat` hint 假装可达。
- 两端都在 NAT 后时，若无可验证公网 ContactPoint，应进入 `degraded`，debug 输出明确不可达原因。

#### 2.4.5 远端公告到本机 reconcile 的运行流程

远端节点从“不支持/未广播 StrongSwan”变成“广播可连接”时，本机不会因为收到某个字符串就立即修改系统网络。当前 daemon 的处理路径是：

```text
gossip announce
  -> SyncRuntime.handleAnnounceUntil
  -> VerifyChain / VerifyRecord / ApplySnapshot 或 ApplyRecordSnapshot
  -> verified active state digest 发生变化
  -> DaemonService.handleRemoteAppliedEvent
  -> notifyStateChanged
  -> PlanTransportLinks(active state + 本地 LinkGroupSpec)
  -> ReconcileLinkInstances(desired + persisted LinkInstance + driver ListSAs)
  -> ApplyReconcileAction(create/update/repair/teardown)
```

因此，远端新发布 `ipsec/profile`、`ipsec/addresses`、`ipsec/ports`、`ipsec/transport-key` 后，只有这些记录已经通过 Zone trust chain 验证并进入本地 active state，才会被 LinkPlanner 使用。LinkPlanner 会重新扫描所有 verified peer zone：缺少任一 `ipsec/*` 记录、profile disabled、本地 connect/deny rule 不匹配、accept intent 不允许、地址族/path mode 不支持、没有可拨 ContactPoint、NAT 后缺少可验证公网证据，都会变成结构化 skip reason，而不是进入 apply。

如果远端记录从“缺失/不匹配”变成“完整且匹配本地 MeshPolicy”，planner 会输出新的 `TransportLinkSpec`。reconciler 随后根据本地是否已有 `LinkInstance`、driver 是否已经能从 `ListSAs` 看到匹配 SA、desired spec hash 是否变化、是否处于 apply backoff，决定 `create`、`adopt`、`update`、`repair` 或 `noop`。daemon event drain 期间多次 state change 会合并为一次 IPsec `ListSAs` + reconcile/apply，所以同一轮收到 profile/address/port/key 多条 record 时不会对同一个 peer/group 重复加载 connection/interface。

当前默认 daemon 使用 `ipsec.driver: dry-run`，因此可在非 root 环境验证 desired-state、action 和 debug 输出。测试机显式设置 `ipsec.driver: strongswan` 后，daemon 会创建真实 `GoviciClient`、通过 VICI 控制 StrongSwan，并使用 `SystemXFRMDriver` 管理 XFRM/netns；`ipsec.vici_socket` 可覆盖 charon VICI socket 路径。root/container smoke 已覆盖两个 daemon service 在 `Run` 循环中自动发布 `ipsec/*` records、经 UDP gossip 同步后触发真实 StrongSwan/VICI + XFRM bring-up，并完成 tunnel ping；daemon reconcile 级 smoke 还覆盖启动恢复观测现有 SA、唯一 SA 断言、revocation teardown、VICI SA 消失、XFRM interface 删除和 tunnel ping 失败。外部 `build/higgs daemon` 双进程验证和 gossip revocation 传播仍作为后续 hardening。

#### 2.4.6 LinkPlanner 输出

LinkPlanner 的输入：
- 本地 `MeshPolicy`。
- verified active state 中的 peer Zone、`ipsec/profile`、`ipsec/addresses`、`ipsec/ports`、`ipsec/transport-key`。
- 本地地址来源优先级、端口策略、历史连接成功/失败分数。
- revocation/tombstone 状态。

输出 `TransportLinkSpec`，供 provider 消费：

```go
type AddressCandidate struct {
    ID           string
    Source       string // manual-address, manual-dns, discovery, reflector, local
    Family       string // ipv4, ipv6
    Address      string // resolved IP, if known
    Host         string // original DNS name, if any
    Reachability string // public, nat-observed, private, unknown
    Priority     int
    ExpiresAt    int64
}

type PortAdvertisement struct {
    Generation uint64
    Kind       string // current, previous
    IKE        PortTuple
    NATT       PortTuple
    ValidUntil int64
}

type PortTuple struct {
    Local      uint16
    Advertised uint16
    Observed   uint16
}

type ContactPoint struct {
    Address AddressCandidate
    Ports   PortAdvertisement
}

type TransportLinkSpec struct {
    OverlayID    string
    Provider     string // strongswan
    LocalZone    ZonePath
    PeerZone     ZonePath
    Direction    string
    PathMode     string
    ContactPoints []ContactPoint
    IKEIdentity  string
    TransportKeyFingerprint string
    XFRMIfID     uint32
    Interface    string
    LocalTunnelAddr  netip.Addr
    RemoteTunnelAddr netip.Addr
    NetNS        string
}
```

`LinkGroupSpec` 是 daemon 的 desired-state 边界，而不是 gossip 公开记录。一个 group 描述 overlay id/name、provider、目标 netns、默认 path mode、方向、address source 优先级、最大 peer/link 数、`tunnel_address` 分配策略（`derived-link-local`、`derived-pool`、`sequential-pool`、`disabled`）以及 reconcile/backoff 策略；当前 daemon 已从一个 group 推导多条 `TransportLinkSpec`，避免把每个 peer link 都变成手工配置。

netns 属于本机 overlay data-plane 配置，不进入 gossip。`config.yaml` 的 `overlay.default_netns` 默认是 `kind=name, name=h2, create=true`；`ipsec.default_netns` 只作为旧配置兼容别名。link group 可覆盖为 `host`、named netns 或 netns path。provider apply 时先 `EnsureNamespace`，再创建/移动 XFRM interface 和分配 tunnel address；Phase 5 babeld 应运行在对应 `LinkGroupSpec.NetNS` 中，和 XFRM interface 看到同一张 overlay data-plane；只有显式声明且带 Higgs 归属边界的 named ns 会被自动创建，path/host 不隐式创建。

`pkg/transport/ipsec.ApplyTransportLink` 固化了第一版 apply 顺序：ensure namespace -> load StrongSwan connection -> ensure XFRM interface -> assign local tunnel address，并返回 `ApplyPlan` 供 dry-run、debug 和失败审计使用。StrongSwan provider 通过 VICI command 控制 charon：`load-conn` 加载 connection，`terminate` / `unload-conn` 做撤销清理，`list-sas` 做运行态观测；`swanctl` 只作为人工 debug 对照，不作为核心控制面的输出解析依赖。

`pkg/transport/ipsec.PlanTransportLinks` / `ReconcileLinkInstances` 提供 Phase 4.2 的纯函数核心。主路径是：verified active state + 本地 `LinkGroupSpec` 先被 planner 转成 desired `TransportLinkSpec` 和 skip reason；reconciler 再把 desired spec、持久化 `LinkInstance`、driver `ListSAs` 快照和 revocation 输入放在一起，判定 create/update/adopt/repair/teardown/noop。

daemon 已接入这条 reconcile 链路：
- state 变化后，从 active state + overlay 配置生成 desired links，查询 IPsec driver `ListSAs`，读取/保存本地 `LinkInstance`，并记录最近 action/skip 摘要。
- 启动进入主循环前，会主动执行一次 IPsec reconcile，用 active state、本地 `LinkGroupSpec`、已持久化 `LinkInstance` 和 driver SA 快照恢复 link state，而不是等待下一次 record/reload 事件。
- `reload` control event 会重新读取本地 `config.yaml`，刷新 `overlays:`、`connect/deny`、`overlay.default_netns`、`ipsec.driver` / `ipsec.vici_socket`、sync/log 配置并触发 reconcile；如果 reload 会改变当前 state DB 路径或 control socket 路径，则拒绝并要求重启。
- daemon drain event 队列时会合并多次 state change，同一轮 record/admin/remote apply 或 config reload 只触发一次 IPsec `ListSAs` + reconcile/apply，避免同一个 peer/group 被短时间重复加载。
- daemon sync tick 后也会做一次 IPsec observe/reconcile，用 driver `ListSAs` 把已由 StrongSwan 建立的 `connecting` link 推进到 `up`；默认频率跟随 daemon interval，root smoke 可用更短 interval 加速验证。

`LinkInstance` 是这条链路的持久化锚点，保存 desired spec hash、实际状态、XFRM `if_id`、IKE/CHILD_SA 名称、endpoint、owner、failure count、backoff 和最近错误。provider apply 成功后 create/update/repair 会把实例推进到 `connecting`，表示配置已经应用、正在等待 IKE_SA/CHILD_SA；只有后续 `ListSAs` 观测到匹配 SA 时才进入 `up`。apply 失败会写入 failure/backoff，backoff 未到期时 reconcile 不重复 apply，到期后 error/degraded link 再进入 repair。teardown 成功后 daemon 会删除本地持久化实例，因此 link group 删除、record 过期或 peer 不再可信不会留下 `removing` 状态并在下一轮重复清理。

reconcile 摘要会持久化最近 desired `TransportLinkSpec` 快照和 driver SA 快照；`higgs debug links` 重新按当前 active state + `LinkGroupSpec` 规划 desired links，再与已落盘 `LinkInstance`、上次 daemon 看到的 SA、CHILD_SA、endpoint、spec hash、local/remote identity、local/remote endpoint、reqid、if_id、backoff 和错误并排展示；link-local 地址会带 interface scope（如 `fe80::...%hgsxxxx`）展示。默认 daemon 仍使用 dry-run driver；显式 root/container smoke 已覆盖真实 VICI/XFRM apply、双 daemon service gossip 同步、`LinkInstance=up`、启动恢复观测、撤销 teardown、link-local scoped tunnel ping 和 IPv4 derived-pool tunnel ping。

`LinkInstance.Owner` 是 daemon 自动清理资源的归属边界。新建实例会保存 `manager=higgs`、group id、instance id、transport id 和派生 owner token；reconcile 对“不再 desired”的旧实例只在 owner 字段与实例字段匹配、transport id 使用 `ipsec-*`、interface 使用 `hgs*` 命名时生成 teardown。apply 层对只有 persisted instance、没有 desired spec 的 teardown 再做一次同样校验，避免 daemon 误删管理员手工创建的 StrongSwan connection 或 XFRM interface。旧状态没有 token 时仍可通过 manager/group/instance/transport/name 校验迁移，带 token 的新状态会额外校验 token。

StrongSwan connection 渲染为 route-based VPN：每条 `TransportLinkSpec` 对应一条 IKE connection 和一个 CHILD_SA，CHILD_SA 使用稳定 XFRM `if_id_in` / `if_id_out`，traffic selector 保持宽泛（IPv4 tunnel link 使用 `0.0.0.0/0`，IPv6 tunnel link 使用 `::/0`）。Phase 4 只证明 peer-to-peer tunnel link 可用；多前缀授权、route filter 和 Babel import/export 留给 Phase 5。

撤销或删除 link 时使用 `TeardownTransportLink` 的可审计顺序：先 terminate IKE_SA/CHILD_SA，再 unload StrongSwan connection，最后删除通过 `LinkInstance.Owner` 校验的 Higgs 管理 XFRM interface。daemon 在 teardown 成功后删除本地持久化 `LinkInstance`，让后续 state-change 或 restart reconcile 看到一个干净的 no-desired/no-instance 状态，而不是重复执行同一个 teardown。

撤销优先级最高：peer Zone 或父 delegation tombstone 后，LinkPlanner 必须立即停止输出该 peer 的 specs，并要求 provider teardown 已存在 SA/interface；teardown 成功后本地 `LinkInstance` 被移除，避免 endpoint fallback、rekey 或下一轮 reconcile 把撤销 peer 重新拉起。

### 2.5 签名规范（必须无歧义）

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

### 2.6 Merkle DAG + Gossip 在此模型下的实现

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
- `PrevHash` 指向同一个 Zone + Key 的上一版本 Record hash；普通同步把它作为审计/调试字段，而不是冷启动接受最新状态的硬依赖
- 同 key 冲突时：Version 更高者胜；Version 相同但内容不同 → 进入 `fork/conflict`，不自动裁决，需 Zone owner（或上级 Zone）签发修正记录
- 如果收到更高版本且签名有效的 Record，可直接提升为 active；只有本地正好持有直接前驱且对方提供了 `PrevHash` 时，才检查 `PrevHash` 是否匹配
- `Timestamp` 仅作为审计字段，不参与最终裁决
- ZoneRoot 由每个 key 的 latest active record 计算：
  ```text
  ZoneRoot = Hash(authority_hash + delegations_root + sorted(latest_record_hashes))
  ```
- 旧版本记录在 `RecordHistory` 中保留有限窗口作为审计/调试 log，但 active state 只使用每个 key 的 latest non-conflict record；普通同步主路径不维护 pending 补前驱状态

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

type DelegationScope string
const (
    DelegationScopeDirectChild DelegationScope = "direct-child"
    DelegationScopeSubtree     DelegationScope = "subtree" // 预留，Phase 0 拒绝
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
    Scope          DelegationScope // Phase 0 只接受 direct-child；subtree 为后续跨层委派预留
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
   a. 如果本地当前 active record 正好是 `Version-1`，且新 Record 携带了 PrevHash，则 PrevHash 必须匹配当前 active record 的 hash
   b. 如果本地缺少直接前驱，但新 Record 签名有效且 Version 更高，则直接 fast-forward；完整历史审计由保留窗口或后续 archive/checkpoint 机制承担
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
7. 检查 Scope：
   a. Phase 0 只接受 `direct-child`，并要求 d.ZoneName 的 Parent() == parentZone（防路径欺骗）
   b. `subtree` 为后续跨层委派预留；Phase 0 必须拒绝并返回 unsupported delegation scope，避免把跨层数据误按直接子委派验证
```

### 4.3 VerifyChain(zonePath)

```text
1. 从 zonePath 开始向上回溯：
   current = zonePath
   while current != ".":
     a. 获取 current 的直接父委派（ParentProof 按“当前 Zone → 根 Zone”的顺序缓存，因此 ParentProof[0] 是父 Zone 对 current 的 Delegation）
     b. 验证该 Delegation 的 VerifyDelegation(d, current.Parent())
     c. current = current.Parent()
2. ParentProof 只是缓存，权威来源始终是父 Zone 中的 `delegations/<child>` 记录；两者不一致时以父 Zone active state 为准
3. 根 Zone "." 的 Authority 必须自签（或通过本地可信配置锚定）
4. 任何一环验证失败 → 整个 Zone 树不可信
```

---

## 五、关键技术选型

| 组件 | 当前实现 | Phase 4+ 规划 | 备注 |
|------|----------|--------------|------|
| Go 版本 | 1.25+ | — | 泛型、slog、标准库增强 |
| 序列化（Gossip） | MessagePack（`higgs.gossip.m1\n...`），短期兼容旧 JSON magic | Protobuf 可选后续优化 | Phase 3.6 已切 MessagePack + 1200-byte UDP budget；proto 文件仅作协议形状参考 |
| 序列化（Record 值） | JSON | — | 具体 record 格式（endpoint、policy 等）均为 JSON |
| 配置文件 | YAML（`config.yaml`） | — | 默认 `./config.yaml`，可用 `HIGGS_CONFIG` 覆盖 |
| 本地存储 | `bbolt` | — | 纯 Go，无 CGO；按 Zone 分 bucket |
| 哈希 | `blake2b-256`（`golang.org/x/crypto`） | — | 用于 KeyID、RecordHash、ZoneRoot |
| 签名 | ED25519（标准库） | — | 密钥加密存储：AES-GCM + bcrypt |
| Daemon / 单 writer | `higgs daemon` + Unix control socket | systemd / 远程管理预留 | Phase 3 最小形态已实现 |
| StrongSwan / IKEv2 控制 | 🟨 VICI driver 边界、dry-run apply、`list-sas` snapshot、root/container daemon-run gossip smoke 已实现 | CLI 进程级 smoke、重启恢复、撤销闭环 | 动态路由主线传输；`swanctl` 只做人肉 debug 对照 |
| XFRM / netns 控制 | 🟨 exec-based `SystemXFRMDriver` + preflight + dry-run apply 已实现 | 后续可替换/增强为 netlink provider | 管理 XFRM interface、地址和 namespace；系统 smoke 显式 root 运行 |
| WG 控制 | _未实现_（Phase 7 可选） | `wgctrl-go` | 轻量 fallback，不作为动态路由主线 |
| 路由协议 | _未实现_（Phase 5） | `babeld` + 控制 socket | Babel 更适合 mesh，自动邻居发现 |
| 防火墙 | _未实现_（Phase 6） | `nftables` netlink | 现代 Linux 趋势 |

---

## 六、当前实现现状（Phase 0–4.2）

### 已落地

| 模块 | 包路径 | 状态 |
|------|--------|------|
| 核心数据结构（Zone / Authority / Delegation / Record） | `pkg/core/zone/` | ✅ 完整 |
| 签名与验证（VerifyRecord / VerifyDelegation / VerifyChain） | `pkg/crypto/` | ✅ 完整 |
| blake2b 哈希 / KeyID / RecordHash / ZoneRoot | `pkg/crypto/` | ✅ 完整 |
| 身份管理（ED25519 生成、加密存储、NodeID） | `pkg/core/identity/` | ✅ 完整 |
| bbolt 持久化（LoadNetwork / SaveNetwork / 元数据） | `pkg/core/zone/` | ✅ 完整 |
| NetworkState：Get（fallback 继承）/ Put / PutAt | `pkg/core/zone/` | ✅ 完整 |
| 配置化身份初始化 | `app/higgs/identity_bootstrap.go` | ✅ `managed_zone` / `identity.key_path` identity overlay、空 DB pending bootstrap state、reload 不可变校验和 pending 签名 gating 已实现 |
| Gossip 传输层（UDP、magic frame、MessagePack codec，短期兼容旧 JSON magic） | `pkg/core/gossip/` | ✅ 完整 |
| Anti-replay（nonce + 时间戳 ±5min 窗口） | `pkg/core/gossip/` | ✅ 完整 |
| 速率配额（每 peer 字节 + 对象 token bucket） | `pkg/core/gossip/` | ✅ 完整 |
| Zone 摘要与快照同步 | `pkg/core/gossip/` | ✅ 完整 |
| Relay fanout（变更后对其他 peer 触发轻量 sync） | `app/higgs/sync.go` | ✅ 完整 |
| Peer 动态发现（endpoint record 扫描、TTL/grace 管理） | `pkg/core/gossip/` | ✅ 完整 |
| Bootstrap 准入 / 新节点首次接入死锁修复 | `pkg/core/gossip/transport.go` | ✅ 完整 |
| Daemon 单 writer（长期 gossip、事件队列、control socket） | `app/higgs/daemon.go` | ✅ 已实现，admin 写入和 IPsec state-change hook 已接入 |
| CLI（init / join / keygen / delegate / record / verify / daemon / sync / debug / db） | `app/higgs/` | ✅ 完整 |
| 配置文件（YAML + 环境变量覆盖） | `app/higgs/config.go` | ✅ 完整 |

### 进行中/预留（Phase 4+）

| 模块 | 包路径 | 状态 |
|------|--------|------|
| StrongSwan / XFRM 建链 | `pkg/transport/ipsec/` + `app/higgs/ipsec_reconcile.go` | 🟨 record / ContactPoint / planner / LinkInstance reconcile / dry-run driver / VICI boundary / XFRM preflight / daemon debug / daemon-run gossip + IKE/CHILD_SA/tunnel ping smoke 已创建；重启恢复和撤销闭环待补强 |
| WireGuard 建链 | `pkg/transport/wireguard/` | 🔲 仅 doc.go，后移为可选 fallback |
| Babeld 路由适配器 | `pkg/routing/babeld/` | 🔲 仅 doc.go |
| Merkle DAG 增量同步 | `pkg/core/merkle/` | 🔲 仅 doc.go |
| 多签 Authority（Threshold > 1） | `pkg/core/zone/types.go` | ⚠️ 数据结构已定义，运行时拒绝 |
| Delegation 撤销（tombstone） | `pkg/core/zone/` + `app/higgs/` | ✅ 已实现 |
| 细粒度 Capability 执行 | `pkg/crypto/sign.go` | ⚠️ 结构已定义，校验仅检查 PermDelegate/PermWrite |
| Public IP Reflector | `pkg/core/gossip/discovery.go` | ✅ HTTP client + local smoke |

---

实施路线与各 Phase 任务见 `../todo.md`。
