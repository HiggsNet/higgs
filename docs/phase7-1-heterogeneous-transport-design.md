# Phase 7.1：异构 TransportLink 并行共存设计

> **状态：** 模型决策已冻结，待验证性实验与实现拆分  
> **创建日期：** 2026-07-11  
> **关联：** `todo.md` 7.1、`docs/phase5-7-per-netns-bird-design.md`、`docs/phase6-link-health-design.md`

## 1. 背景

Higgs 当前已经形成以下数据面主线：

```text
signed ipsec records + 本地 LinkGroupSpec
  -> PlanTransportLinks
  -> TransportLinkSpec
  -> StrongSwan/IKEv2 + XFRM interface
  -> 目标 netns 中的 per-netns BIRD/Babel
```

现有模型已经允许一个 netns 中的多个 link group 共享同一个 BIRD，但
`pkg/transport/ipsec`、daemon reconcile、运行态和诊断结构仍以 IPsec/XFRM 为中心。
Phase 7.1 的主要问题不再是“同一种 IPsec 因多个公网 IP 建立多条并线连接”，而是：

```text
同一个 peer
  ├── strongswan
  ├── wireguard-gre
  └── 未来的其他 provider

所有 provider 同时向同一个目标 netns 暴露独立的 Babel 接口。
```

provider 不固化为主用或 fallback。是否形成等价路径、较高 cost 的备用路径，
或者因不同目的前缀选择不同链路，由 LinkGroup 静态 base cost 和 Babel 协议自身决定。
Higgs health 第一版不主动接管 BIRD 选路。

## 2. 本阶段目标与非目标

### 2.1 目标

1. 冻结单 peer 多条异构 TransportLink 的 identity、配置、运行态和资源 ownership。
2. 定义 transport provider 必须向 routing/health/readmodel 提供的统一接口契约。
3. 冻结 signed capability record 与本地选择 policy 的边界。
4. 定义 per-netns BIRD 如何发现多种接口，并允许每条链路拥有不同基础 cost。
5. 定义独立 health、失败隔离、cleanup 和 operator readmodel。
6. 给出可分阶段实现的代码切口和真实 smoke 验收条件。

### 2.2 非目标

1. 7.1 设计冻结不要求立即完成 WireGuard/GRE/VXLAN runtime provider。
2. 第一版不要求 Babel ECMP；先保证多链路并存和确定性的优先/故障切换。
3. 不在第一轮冻结 WG 上层最终必须使用 GRE 还是 VXLAN。
4. 不设计 Higgs 自有 ESP 密钥交换协议；IPsec 生产路径继续使用 IKEv2/StrongSwan。
5. 不把多个公网 endpoint 自动展开成多条 Babel link。endpoint 是 provider 内部的
   建链候选；只有最终暴露独立 tunnel interface 时才是独立 TransportLink。
6. 第一版不让 Higgs health 状态自动修改 BIRD metric、interface policy 或管理状态；
   Babel 路由收敛继续由协议自身负责。

## 3. 已冻结原则

以下原则来自 7.1 前置讨论，不再作为开放问题：

1. **provider 不代表主备角色。** `strongswan` 和 `wireguard-gre` 都可以同时
   active；fallback 只是本地 Babel cost/policy 的一种结果。
2. **业务前缀不进入 WG AllowedIPs。** WG AllowedIPs 只包含直连 peer 的 transit
   `/32` 或 `/128`，业务前缀始终由 Babel 和 route authorization 管理。
3. **Babel 不直接运行在共享裸 WG mesh interface 上。** WG 上层必须向每个 peer
   提供独立普通接口，隔离 Babel 下一跳选择与 WG AllowedIPs peer 选择。
4. **默认使用同一目标 netns。** WG、GRE/VXLAN、XFRM interface 和 BIRD 原则上
   位于同一个 overlay/data-plane netns。跨 netns underlay 不是默认拓扑。
5. **每条 link 独立失败。** 一个 peer 的一条 link down/degraded 不改变 peer 身份，
   也不应 teardown 该 peer 的其他 link。
6. **一个 overlay 列表项就是一个 LinkGroup，且只有一个 provider。** provider 表示
   生成完整 Babel-facing 接口的数据面实现；`wireguard-gre` 是一个组合 provider，
   WireGuard 和 GRE 不是同一 LinkGroup 下两个独立 provider。
7. **Babel link cost 属于 LinkGroup。** 第一版只实现静态 `base_cost`，表达本机对该
   group/provider 链路的基础评价；per-netns routing instance 只提供全局默认值，并将
   各 group 的设置合并成 BIRD per-interface policy blocks。动态 penalty 留作扩展。
8. **Link ID 显式包含 provider，但不引入 ID version。** provider 原地变化必须产生
   不同 Link ID；升级时通过现有 legacy ID lookup + owner guard adopt/cleanup，不增加
   `v2` 字段或 `hgl2-*` 前缀。
9. **WG device 按 LinkGroup 和 underlay 地址族共享。** 一个 `wireguard-gre` group
   默认拥有一个 IPv4-underlay WG device 和一个 IPv6-underlay WG device；每个 device
   由该 group 对应地址族的所有 peer/link 共享，而不是每个 peer 创建一个 WG device。
10. **双方一致的非秘密参数从稳定 Link ID 派生。** GRE key、成对 transit address、
    interface/runtime 派生输入等使用明确 domain separator 从 Link ID 确定性生成，不再
    通过 signed record 同步逐 link 随机值。密码学私钥是例外：不得从公开 Link ID 直接
    派生，必须随机生成并持久化，或从本机秘密 master key 经 KDF 派生；record 只发布公钥。
11. **端口 rotate 是通用 endpoint-generation 能力，但 apply 语义属于 provider。**
    通用层保留 current/previous generation、grace、状态和观测接口；StrongSwan 可以使用
    per-link staged SA/XFRM；WG 按共享 device scope 创建 staged WG device，并为 peer
    创建可独立观测的 staged GRE/VXLAN interface。两者共享通用 rotate 状态，但资源
    scope 和具体 apply action 不相同。

## 4. 现有实现盘点

### 4.1 已经可以复用的边界

| 能力 | 当前实现 | 7.1 可复用程度 |
|------|----------|--------------|
| 本地 link group policy | `pkg/transport/ipsec.LinkGroupSpec` | 保留“一个 overlay/link group 一个 provider” |
| desired planner | `PlanTransportLinks` | 规划流程可复用，类型和 record 输入需解耦 |
| 稳定 link identity | `StableLinkID(local, peer, overlay, pathKey)` | 算法可扩展，但必须纳入 provider identity |
| runtime reconcile | `ReconcileLinkInstances` | 状态机和 owner guard 可抽为通用层 |
| owner token | `ResourceOwner` | 结构可复用，token 必须覆盖 provider scope |
| per-netns BIRD | `routing.instances[]` | 可直接承载多个 provider 的接口 |
| 多 interface pattern | `BirdInstanceSpec.InterfacePatterns` | 可发现多类接口，但当前 cost 仍是全局统一值 |
| per-link health | `ProbeTarget.InstanceID` | 主键和 probe 模型可复用 |
| online readmodel | `links_status` / `internal/inspect` | 聚合路径可复用，但 DTO 含大量 IPsec 专属字段 |

### 4.2 当前需要解除的 IPsec 假设

当前 `TransportLinkSpec` 位于 `pkg/transport/ipsec`，同时包含通用字段和：

- IKE identity、认证引用和 contact points；
- XFRM `if_id`；
- IKE local port；
- transport private/public key material；
- StrongSwan initiator/takeover/rotate 字段。

`LinkInstance`、持久化 state 和 inspect readmodel 也直接包含 IKE SA、CHILD SA、
XFRM、port generation 和 rotate 字段。这些字段不能成为所有 provider 的必填契约。

当前 BIRD generator 将所有 `InterfacePatterns` 渲染到同一个 Babel interface block，
共用一个 `rxcost`。因此它只能表达“这一组匹配接口使用同一个基础 cost”，不能表达：

```text
hgs-ipsec-*  rxcost 96
hgs-wggre-*  rxcost 160
```

7.1 实现前必须补成多个有序 interface policy block，或提供等价的 per-interface cost
生成模型。

## 5. 术语与分层

### 5.1 Routing domain

`routing domain` 是一个由同一 netns、同一 BIRD 实例和同一授权路由集合构成的
路由域。现有实现中它实际上由 netns 界定，不新增持久化实体。

### 5.2 Link group

`LinkGroup` 是本地 policy 和 desired-state 边界。第一版建议继续保持：

> 一个 `overlays[]` 列表项就是一个 LinkGroup，且只配置一个 provider；多个 group 可以连接同一批 peer，
> 并因引用同一 netns 而进入同一个 routing domain。

例如：

```yaml
overlays:
  - id: mesh-ipsec
    provider: strongswan
    netns: h2

  - id: mesh-wggre
    provider: wireguard-gre
    netns: h2
```

这样不需要把 `LinkGroupSpec.Provider string` 改造成嵌套 provider 数组，也能自然得到
同一 peer 两条 desired link。未来如需共享 connect/deny rules，可再增加可复用 policy
模板，而不是让一个 group 同时拥有多个 provider lifecycle。

### 5.3 Transport provider

这里的 `provider` 表示生成一条 Babel-facing link 所需的完整数据面实现，而不是必须
等同于单个内核驱动：

| Provider | 安全/underlay 层 | Babel-facing 层 |
|------------|------------------|-----------------|
| `strongswan` | IKEv2 + ESP | XFRM interface |
| `wireguard-gre` | WireGuard | GRE/IP6GRE interface |
| `wireguard-vxlan` | WireGuard | VXLAN interface |

因此 `wireguard-gre` 是一个组合 provider。它在内部管理 WG device/peer 和 GRE interface，
但对 planner/reconcile 只产出一条 Babel-facing TransportLink。无需再增加与 provider
平行的 `stack`/`StackKind` 概念。

### 5.4 TransportLink

TransportLink 是 Babel-facing 的最小独立链路：

- 对应一个 peer；
- 对应一个目标 netns 中的独立接口；
- 有独立 tunnel address、MTU、health、desired hash、owner token 和 lifecycle；
- 可以独立进入、退出；LinkGroup 配置变化可以改变其静态 Babel base cost；
- underlay endpoint 变化不必改变 link identity。

## 6. 统一接口契约

每个 provider 必须输出以下通用 desired spec：

```go
type LinkSpec struct {
    ID             string
    GroupID        string
    LocalZone      zone.ZonePath
    PeerZone       zone.ZonePath
    Provider       string
    PathKey        string
    RuntimeID      string
    NetNS          string
    InterfaceName  string
    LocalLinkAddr  netip.Addr
    PeerLinkAddr   netip.Addr
    MTU            uint32
    BabelBaseCost  uint
    DesiredHash    string
    ResourceRefs   []string

    ProviderSpec   ProviderLinkSpec
}
```

上面是设计结构，不要求第一步按原样落地。`ProviderLinkSpec` 在实现中必须是可验证、
可稳定序列化和参与 desired hash 的 tagged union，不能用未约束的 `map[string]any`。
候选 Go 表达如下：

```go
type ProviderLinkSpec struct {
    StrongSwanXFRM *StrongSwanXFRMSpec `json:"strongswan_xfrm,omitempty"`
    WireGuardGRE   *WireGuardGRESpec   `json:"wireguard_gre,omitempty"`
    WireGuardVXLAN *WireGuardVXLANSpec `json:"wireguard_vxlan,omitempty"`
}
```

必须校验恰好一个 provider spec 非空，且与 `Provider` 一致。

### 6.1 Provider runtime 契约

通用 reconcile 不应了解 IKE SA、WG handshake 或 FDB。由于 WG device 是多条 link 的
共享前置资源，provider planner 必须输出 desired resource graph，而不只是扁平 links：

```go
type ProviderPlan struct {
    Resources []ProviderResourceSpec
    Links     []LinkSpec
}

type LinkProvider interface {
    Kind() string
    Plan(LinkPlanInput) (ProviderPlan, []PlanSkip, error)
    InspectResource(context.Context, ProviderResourceSpec) (ProviderObservation, error)
    ApplyResource(context.Context, ProviderResourceSpec) (ApplyResult, error)
    TeardownResource(context.Context, ProviderResourceSpec, ResourceOwner) (ApplyResult, error)
    InspectLink(context.Context, LinkSpec) (ProviderObservation, error)
    ApplyLink(context.Context, LinkSpec) (ApplyResult, error)
    TeardownLink(context.Context, LinkSpec, ResourceOwner) (ApplyResult, error)
}
```

通用 reconcile 按依赖顺序 apply `Resources -> Links`，按反向顺序 teardown
`Links -> unreferenced Resources`。`strongswan` adapter 第一版可以只输出 link resources；
`wireguard-gre` 输出 group/family WG device resource、device peer membership 和引用这些
resource IDs 的 per-peer GRE links。staged generation 也是同一张 resource graph 的另一组
runtime resources。

`ProviderObservation` 包含统一状态和 provider-specific details：

```go
type ProviderObservation struct {
    InterfacePresent bool
    CarrierReady      bool
    SessionReady      bool
    Endpoint          string
    LastHandshakeUnix int64
    Details           ProviderRuntimeDetails
}
```

第一轮重构可以先把现有 IPsec planner/apply 包装为现有 `strongswan` provider，保持
既有 rotate/takeover 状态机不变；不要为了通用化重写已验证的 StrongSwan lifecycle。

### 6.2 Endpoint generation 与 rotate 契约

端口公告的通用语义是：

```go
type EndpointGeneration struct {
    Generation uint64
    Current    []AdvertisedEndpoint
    Previous   []PreviousEndpoint // 带 ValidUntil
}
```

通用 planner/readmodel 必须理解“优先 current、grace 内允许 previous、generation 单调
变化”，但不规定 provider 必须创建一条新的 Babel-facing interface。provider 额外声明
rotate scope 和能力：

```go
type RotateCapability struct {
    Scope            string // link | shared-device
    GraceMode        string // staged-runtime+redirect | redirect | break-before-make
    ParallelRuntime  bool
}
```

通用状态保留：

- active/staged generation；
- preparing/testing/dual-running/cutover/rollback/cleanup；
- grace/retention deadline；
- provider readiness 和最近 rotate error。

provider-specific details 再记录 IKE/CHILD/XFRM、WG device/listen port/firewall redirect 等
实际资源。这样 `debug rotate` 可以跨 provider 使用同一视图，同时不会把 IPsec 字段平铺
成所有 provider 的必填字段。

## 7. Identity、generation 与 ownership

### 7.1 稳定 Link ID

当前 `StableLinkID` 没有显式 provider 输入。异构并行后推荐派生：

```text
link_id = H(
  ordered(local_zone, peer_zone),
  group_id,
  provider,
  path_key
)
```

不为这个变化新增 ID version。当前已有 IPsec instance 的兼容通过旧公式计算 legacy ID，
再使用现有 migratable-instance lookup 和 owner guard 完成 adopt/cleanup。provider 原地
改变时，新公式自然产生不同 Link ID，旧 provider 资源必须进入受保护 teardown，不能
被新 provider adopt。

说明：

- `group_id` 已经通常能区分 provider，但仍显式加入 `provider`，防止 group 原地改
  provider 时误 adopt 旧资源；
- endpoint、当前端口、WG handshake 和健康状态不进入稳定 ID；
- provider rotate generation 不改变 Link ID，只改变 Runtime ID；
- 两端可以派生相同逻辑 Link ID，接口名和本地 runtime resource 仍可按方向派生。

### 7.2 Runtime ID

```text
runtime_id = H(link_id, provider_generation, provider_runtime_role)
```

它用于 StrongSwan connection、WG device/peer scope、临时 staged interface 等运行资源。
不同 provider 可以解释自己的 generation，但必须把当前和 staged generation 暴露到
统一 readmodel。

### 7.3 Owner token

owner token 至少覆盖：

```text
manager + group_id + link_id + provider + runtime_id + resource_kind
```

teardown 必须同时满足：

1. persisted owner token 匹配；
2. provider-specific resource marker 匹配；
3. interface/device/name 位于 Higgs 保留命名空间；
4. 当前 desired state 已删除、被 revoke，或显式进入 cleanup。

一个 provider link 的 teardown 不得按 peer 或 netns 粗粒度删除其他 provider 的资源。

## 8. Signed record 与本地 policy

### 8.1 Signed record 只表达远端事实和能力

建议的能力边界：

| 数据 | signed record | 本地 policy |
|------|---------------|--------------|
| transport public key/fingerprint | 是 | 否 |
| 可联系 endpoint 与 generation | 是 | 本地选择候选 |
| 支持的 provider/component 和地址族 | 是 | 选择是否启用 |
| peer WG transit address | 否，按 Link ID 稳定派生 | 本地提供双方一致的 pool policy |
| link group/connect/deny | 否 | 是 |
| 目标 netns | 否 | 是 |
| Babel base cost | 否 | 是 |
| health threshold/gate | 否 | 是 |
| 本地 interface name | 否 | 是/稳定派生 |
| MTU policy | 公告能力上限 | 本地取安全下限 |
| GRE key/VNI | 仅双方必须协商时 | 优先从 link identity 派生 |

不新增一个全能 `transport/capabilities` record 来替代现有 IPsec/WG 专用记录。WG
provider 对应的最小 record family 为：

```text
wireguard/profile
wireguard/addresses
wireguard/ports
wireguard/transport-keys
wireguard/overlays/<overlay_id>
```

其中 `wireguard/transport-keys` 按 `overlay_id + underlay_family` 公告 device public key
和 fingerprint；private key 只保存在本地 state。`wireguard/ports` 同样按
`overlay_id + underlay_family` 公告 generation。overlay intent 引用相应 device/key
capability，并确认 path 和 transit pool 派生规则。

provider 分别解析自己的 signed records，再输出统一 `PeerTransportCapability`：

```go
type PeerTransportCapability struct {
    PeerZone      zone.ZonePath
    Provider      string
    AddressFamily string
    PublicKeyRef  string // group/family device key fingerprint
    Endpoints     []Endpoint
    TransitAddrs  []netip.Addr
    MaxMTU        uint32
    Generation    uint64
}
```

### 8.2 双方 policy 不对称

本地 policy 不通过 gossip 强制对称。若 A 启用 `wireguard-gre` 而 B 未启用，A planner
必须产生结构化 skip/degraded reason，例如：

```text
peer_provider_capability_missing
peer_transit_address_missing
peer_policy_not_observed
provider_record_invalid
```

仅看到远端 capability 不等于远端一定已经 apply。provider session、接口存在和 Babel
neighbor 分别确认数据面与 routing readiness；health 是独立观测维度，只参与告警和既有
rotate cutover gate，不是普通 link-up 或 route selection 的必要条件。

## 9. WireGuard + GRE 边界

### 9.1 AllowedIPs

一个共享 WG device 可以持有多个 peer，但每个 peer 的 AllowedIPs 只包含 transport
transit address：

```text
peer B -> fd00:wg::b/128
peer C -> fd00:wg::c/128
```

GRE/IP6GRE endpoint 使用这些 transit address。业务包先由 Babel 选择 per-peer GRE
interface，再封装到 peer transit address；WG 只根据该 transit address 选择加密 peer。

以下内容禁止进入 WG AllowedIPs：

- peer 被授权发布的业务前缀；
- Babel learned route；
- default route；
- 需要经 peer 多跳转发的其他节点前缀。

每一对 peer 的 transit address 从 Link ID 和配置的 transit pool 稳定派生，并按排序后的
zone 端点确定两端地址归属。IPv4/IPv6 family path 使用不同 domain separator，避免跨
family 或与业务 tunnel-address pool 混用。双方只要得到相同 Link ID 和 pool policy，
即可得到相同地址对；signed record 无需携带逐 link transit address。

### 9.2 Device 与 link ownership

共享 WG device 是 LinkGroup + underlay family 级资源，GRE interface 是 link 级资源：

```text
LinkGroup wireguard-gre
  ├── WG device v4 owner: (group_id, netns, family:ipv4)
  │     ├── peer B
  │     └── peer C
  └── WG device v6 owner: (group_id, netns, family:ipv6)
        ├── peer B
        └── peer C

WireGuard peer owner: (device runtime owner, peer zone)
GRE interface owner:  Link ID
```

因此删除一条 GRE link 不能直接删除共享 WG device；只有最后一个 owned peer/link 退出且
device owner scope 确认无引用时，才能清理 device。IPv4/IPv6 device 必须有各自可用的
listen socket/port。每个 `(group_id, netns, underlay_family)` **逻辑 device** 默认使用
独立、随机生成并持久化的 WG private key；old/staged runtime devices 默认复用该逻辑
identity。对应 public key 通过 signed provider record 公告。未来若要减少 key 数量，可以
显式选择复用 node-level WG identity，但不能从公开 Link ID 直接生成 private key。

使用两个 device 的原因不是 WG interface 本身不能承载双栈 transit address，而是一个
WG peer 在一个 device 上只有一个当前 endpoint。若希望公网 IPv4 和 IPv6 path 同时存在，
必须把它们放入不同 device/peer runtime。provider 以 `path_key=family:ipv4` /
`family:ipv6` 为同一 peer 生成独立 TransportLink 和 GRE interface。

### 9.3 GRE 与 VXLAN

第一轮优先用 GRE 验证 point-to-point 三层模型。VXLAN 仅在明确需要二层时进入实现，
并必须额外解决 VNI、FDB、广播/多播复制和更高 MTU 开销。共享 VNI 不能假设 WG 自动
把广播/多播复制到所有 peer。

### 9.4 WireGuard 端口 rotate

WG 监听端口属于共享 device，而不是某一条 GRE link：

```text
rotate scope = (group_id, netns, underlay_family, wg_device)
```

因此一次 IPv4 WG device 端口 rotate 会为该 device 上所有当前 desired peer 准备同一
generation 的 staged runtime。IPv6 WG device 有独立 generation，可以单独 rotate。
逻辑 Link ID 保持不变，但 staged runtime 必须拥有 generation-specific resource ID、
transit address epoch 和 GRE/VXLAN interface，才能与旧 generation 真正并行并被 Babel
独立观测。

WG provider 的推荐低频平滑路径是：

1. 为 group/family device 选择新 listen port，generation 递增；
2. 创建 staged WG device，复用该逻辑 device 的持久化 WG identity，并监听新端口；
3. 把该 group/family 当前 desired peers 加入 staged device；
4. 每个 peer 使用 `address_epoch=<generation>` 派生 staged transit address，并创建独立
   staged GRE/VXLAN interface，避免新旧 WG device 上相同 AllowedIPs/route 产生歧义；
5. 发布 current + previous/valid-until signed port advertisement，远端对称准备 staged
   runtime；
6. 观察 staged WG handshake、GRE/VXLAN interface、Babel neighbor/selected route 和既有
   rotate cutover gate；达到 per-link readiness 的 peer 可以进入 dual-running/cutover；
7. retention 到期后逐 link 清理旧 GRE/VXLAN runtime；旧 WG device 采用引用计数，直到
   没有仍依赖旧 generation 的 active peer/link 才删除；
8. firewall 同时放行 old/current 真实 listener；如 advertised alias/NAT 映射与实际
   listener 不同，或旧 listener 已退出但仍处于 previous grace，再使用 owned UDP
   redirect 补足入口窗口。

这与当前 IPsec rotate 的分层一致：staged SA/XFRM/interface 负责验证新数据面，firewall
redirect 负责入口 advertised/current/previous grace；redirect 不是 staged runtime 的
替代品。WG 只是在 shared-device scope 一次准备多个 peers，再把 readiness/cutover 投影到
各个稳定 Link ID。

需要真实 smoke 验证 Linux 是否允许在同一 netns 的 old/staged WG devices 上复用逻辑
device private key并配置相同 peer public keys，以及 generation-specific transit/GRE 路由
是否完全隔离；不满足时才考虑 staged generation 使用独立 WG key record。

高频/对抗性 port hopping 仍属于 7.2，不因 7.1 抽象 rotate 而自动承诺。

## 10. netns 与 MTU

### 10.1 默认拓扑

```text
target netns
  ├── BIRD
  ├── XFRM interfaces
  ├── WG devices (IPv4/IPv6 underlay)
  └── per-peer GRE interfaces
```

provider 必须在 apply 前验证目标 netns 内的 underlay 可达性。若 WG 放在 host netns、
GRE 放在 overlay netns，则必须显式配置跨 netns veth/route/forward/firewall ownership；
第一版直接拒绝这种隐式拓扑，而不是尝试自动猜测。

### 10.2 MTU

`LinkSpec.MTU` 必须是 planner 的显式结果，并进入 desired hash。计算输入至少包括：

- 实际 underlay family 和 MTU；
- 加密层开销；
- GRE/VXLAN 层开销；
- provider 要求的安全余量；
- IPv6 最小 MTU 下限。

第一版不依赖内核自动继承得到“碰巧可用”的 MTU。若无法证明安全 MTU，则 planner
应 skip 或使用明确配置的保守默认值，并在 readmodel 标记来源。

## 11. BIRD/Babel 行为

### 11.1 接口发现

每种 provider 使用稳定且不冲突的接口名前缀，例如：

```text
hgsx*   strongswan
hgsg*   wireguard-gre
hgsv*   wireguard-vxlan
```

实际前缀需要在实现时结合 Linux 15 字符接口名限制确定。BIRD instance 继续按 netns
聚合所有相关 patterns。

### 11.2 Per-link base cost

当前单一 `metric_base` 不足以表达异构链路。目标生成模型为有序 policy blocks：

```yaml
routing:
  instances:
    - id: h2
      netns: h2
      interfaces:
        - pattern: "hgsx*"
          rxcost: 96
        - pattern: "hgsg*"
          rxcost: 160
```

生成的 BIRD 配置应保留每个 block 的独立 `rxcost`。更精细到单 link 的 override 可由
精确 interface name block 实现，且精确规则必须在通配规则之前，避免匹配歧义。

需要注意：Babel `rxcost` 是本机对接收方向链路的评价。BIRD 官方文档特别指出，
它主要影响**邻居**的 route selection，而不是直接给本机从该接口学到的 route 加 cost。
双方本地 policy 可以不对称，但不能把“提高本机接口 rxcost”误当成“强制本机绕开该
接口”。debug 必须展示这是本机公告/配置的 RX cost，不能误报成双方共同权重或本机
强制 preference。

### 11.3 Health 与 metric

第一版明确保持松耦合：Higgs health 负责观测、告警、readmodel 和既有 rotate cutover
gate，不自动修改 BIRD `rxcost`，不从 Babel policy 排除接口，也不执行 interface
admin-down。路由稳定和故障收敛主要依赖 Babel 自己的 Hello/IHU、neighbor timeout、
metric 和 route selection；provider/session down 后接口或邻居失效，Babel 自然收敛。

预留一个默认关闭的扩展接口即可，例如：

```go
type HealthRoutingPolicy interface {
    Evaluate(LinkHealth, LinkRoutingObservation) RoutingInfluence
}

type RoutingInfluence struct {
    Mode      string // none | cost-penalty | exclude
    CostDelta uint
    Reason    string
}
```

第一版唯一实现返回 `Mode=none`，且 routing reconcile 不因普通 health sample 或 state
transition 触发 BIRD configure。未来如开启动态影响，必须先通过真实 BIRD/netns 实验
确认方向语义、收敛效果，并加入迟滞、最小保持时间和 configure 合并。

### 11.4 ECMP

第一版验收不要求 ECMP。原因是仓库现有 root smoke 已记录部分 BIRD 2.x 版本不接受
当前尝试的 `ecmp` directive。第一版只要求：

1. 两条 link 可同时建立 Babel neighbor；
2. 不同 base cost 时确定性选择低 cost link；
3. 首选 link 失效后收敛到另一条 link；
4. 接口恢复后由 Babel 自身重新收敛和回切。

等价 cost 的内核 multipath 安装作为独立后续实验，不与异构 link 模型绑定。

## 12. Lifecycle 与失败隔离

### 12.1 通用状态

保留现有状态词汇，统一含义：

```text
pending -> configuring -> connecting -> up
                                |        |
                                v        v
                              error   degraded
                                         |
desired removed/revoked -> removing -> down
```

provider-specific 子状态放在 details 中，例如：

- StrongSwan：IKE/CHILD SA、rotate、takeover；
- WireGuard：device/peer、last handshake、key generation；
- GRE/VXLAN：interface、endpoint、FDB。

共享 provider resource 需要独立于 per-link instance 的运行态，例如：

```go
type ProviderResourceInstance struct {
    ID               string
    GroupID          string
    Provider         string
    NetNS            string
    Family           string
    ActiveGeneration uint64
    StagedGeneration uint64
    RotatePhase      string
    RotateDeadline   int64
    Owner            ResourceOwner
}
```

WG device rotate 写入这个 shared-resource state；各 peer LinkInstance 只引用 device resource
ID，并在 readmodel 中投影其 active generation。这样一次 device rotate 不会为 N 个 peer
重复执行 N 次 listener/firewall apply。

### 12.2 Readiness

一条 link 的通用观测至少分层展示：

```text
provider session ready
interface ready
Babel neighbor ready
health ready
```

不能将“WG device up”或“XFRM interface 存在”直接等同于 link up。前三层用于判断
provider/data-plane/routing readiness；health 单独展示，不默认阻断普通 link-up，只在
既有 rotate cutover gate 中作为附加条件。

### 12.3 Cleanup

- revoke peer：teardown 该 peer 的所有 owned link，但逐条执行 owner guard；
- 删除一个 group：只清理该 group 的 links 和无引用的 group/provider 共享资源；
- provider capability 消失：进入 degraded/stale grace，再按 policy teardown；
- daemon restart：从 persisted instance + provider inspect adopt，不能因 readmodel 缺失重建；
- 一条 link apply 失败：只更新该 instance backoff，不阻塞同 peer 其他 provider reconcile。

## 13. Readmodel 与运维输出

`links_status` 继续是在线 daemon-owned truth，不允许 CLI 在 control socket 可用时自行重新
规划并代替 runtime snapshot。通用视图建议为：

```text
peer node-b.catofes.
  mesh-ipsec/strongswan
    state=up interface=hgsx... cost=96 mtu=1400
    session=ready babel=neighbor health=healthy endpoint=[...]:4500

  mesh-wggre/wireguard-gre
    state=degraded interface=hgsg... cost=160 mtu=1360
    session=ready babel=neighbor health=degraded endpoint=[...]:51820
```

通用字段：

- peer、group、provider、link/runtime ID；
- netns、interface、local/peer link address、MTU；
- desired/actual state、base/effective cost；
- provider/interface/Babel/health 四层 readiness；
- endpoint、last transition、backoff、last error；
- owner token 摘要。

provider details 使用 tagged 子对象保留现有 IKE/XFRM/rotate 信息，并新增 WG/GRE 详情，
而不是把所有 provider 字段继续平铺到 `LinkView` 顶层。

## 14. 配置草案

以下只表达目标语义，字段名尚未全部冻结：

```yaml
netns:
  default:
    kind: name
    name: h2
    create: true

overlays:
  - id: mesh-ipsec
    provider: strongswan
    netns: default
    babel:
      base_cost: 96

  - id: mesh-wggre
    provider: wireguard-gre
    netns: default
    babel:
      base_cost: 160
    wireguard:
      ipv4:
        listen_port: 51820
        transit_pool: 10.77.0.0/16
      ipv6:
        listen_port: 51821
        transit_pool: fd00:77:1::/64
      port_mode: range
      port_range: 30000-30999
      rotate_retention: 1h
    gre:
      mtu: auto

routing:
  instances:
    - id: h2
      netns: default
      mode: managed
```

这里将 base cost 写在 link group，是因为“某个 provider 在本机的偏好”属于本地 link
policy；routing reconcile 再把各 group 的 link/cost 合并为同一个 per-netns BIRD 配置。

## 15. 实现切口

建议按以下顺序推进，完成一个切口不要求同时实现 WG runtime：

### 7.1.1 通用模型和 provider adapter

- 新增通用 `LinkSpec` / `LinkInstance` / owner/readiness 结构；
- 将现有 IPsec spec/instance 通过 adapter 接入；
- 保持 StrongSwan rotate/takeover 行为和现有 state 兼容迁移；
- Link ID 显式包含 provider，并兼容查找旧 IPsec ID，不增加 ID version。
- 抽出通用 endpoint generation/readmodel，并增加 provider shared-resource state；
  不把 WG device rotate 复制成 per-peer action。

### 7.1.2 Readmodel 多 provider 化

- `internal/inspect` 顶层只保留通用字段；
- IPsec 字段移入 tagged details；
- `debug links`、observer `/api/v1/links` 支持按 peer/group/provider 展示多 link。

### 7.1.3 BIRD per-interface policy blocks

- `BirdInstanceSpec` 支持多个 interface policy block；
- group base cost 合并到 per-netns BIRD spec；
- reload 去抖和精确/通配 pattern 优先级测试。

### 7.1.4 Fake provider + dry-run

- fake provider 为同一 peer 生成两条普通 interface link；
- 验证 planner identity、独立 reconcile、owner cleanup 和 readmodel；
- 不依赖 root/WG/StrongSwan。

### 7.1.5 真实 netns/BIRD 验证性实验

- [x] 两节点、每端两条独立 veth/tunnel-like interface；
- [x] BIRD 同时建立两个 Babel neighbor；
- [x] 不同 cost 选路、首选 link down 后切换、恢复回切；
- [x] 由 `pkg/routing/bird.TestBabelDualInterfaceCostFailoverRootSmoke` 在 BIRD 2.19.1
  root/netns lane 记录 `rxcost` 方向性：A 配置的低 `rxcost` 让 B 偏好对应链路，B
  配置的低 `rxcost` 让 A 偏好对应链路。实验未接入 Higgs health 动态 metric 或
  interface exclusion。该实验较慢，只通过 `sudo make phase7-1-bird-experiment` 显式运行，
  不纳入 `bird-babel-smoke` 或聚合 `root-smoke`。

### 7.1.6 WireGuard transit + GRE provider

- netns 内 WG device/peer ownership；
- AllowedIPs 仅 transit `/32`/`/128`；
- per-peer GRE/IP6GRE interface；
- MTU 派生、inspect、teardown 和 key generation。
- group/family device-scoped port advertisement、current/previous grace、owned UDP redirect
  和 staged WG device + staged GRE/VXLAN interface 的低频 rotate。

### 7.1.7 联合 root/container smoke

- 同一 peer 的真实 IPsec/XFRM 与 WG/GRE 同时 active；
- 同一 per-netns BIRD 建立两条邻接；
- 验证业务前缀不在 WG AllowedIPs；
- 分别中断 IPsec、WG、GRE，确认失败隔离和 Babel 收敛；
- 删除单个 group 和 revoke peer，验证资源粒度 cleanup。

## 16. 进入实现前的验证验收

7.1 设计冻结的文档决策已经完成；进入正式 runtime provider 实现前还需满足：

1. 本文冻结规则与代码切口保持一致，实验后若有修订必须记录原因；
2. 数据模型、配置和 readmodel 示例足以指导实现，不依赖实现者重新发明边界；
3. BIRD 双接口/不同 cost 的真实验证性实验有记录；
4. WG AllowedIPs/transit/GRE 数据路径通过最小真实 netns smoke；
5. `todo.md` 将实现工作拆成可以独立验证和归档的切口。

这些验证不要求先完成正式 WG/GRE daemon provider；可以使用独立 root smoke 原型。

## 17. 决策记录

D1-D7 的模型方向已经冻结。进入实现前仍需通过第 15、16 节列出的真实 BIRD/netns 和
WG/GRE smoke 验证内核行为、MTU 与 lifecycle 细节；实验结论只能补充机制，不应重新
引入一个 group 多 provider、业务前缀进入 WG AllowedIPs 或 health 主动接管 Babel 选路。

| 决策 | 冻结结论 |
|------|----------|
| D1 | 一个 `overlays[]` 项就是一个 LinkGroup，一个 LinkGroup 只有一个 provider |
| D2 | 静态 Babel base cost 属于 LinkGroup，per-netns routing instance 负责合并 |
| D3 | Link ID 显式包含 provider，不新增 ID version；旧 ID 通过 legacy lookup 迁移 |
| D4 | WG device 按 LinkGroup + underlay family 共享，peer link 引用 shared resource |
| D5 | health 第一版只做观测、告警和 rotate gate，不自动修改 BIRD routing policy |
| D6 | GRE key/transit address 等非秘密参数从 Link ID 派生；WG private key 安全持久化 |
| D7 | IPsec/WG 保留 provider-specific ports record 和 overlay intent，内部共享 generation DTO |

### 17.1 D7：provider port advertisement 与 overlay intent

record 不合并，保持 provider-specific：

```text
ipsec/ports
ipsec/overlays/<overlay_id>

wireguard/ports
wireguard/overlays/<overlay_id>
```

代码内部可以共享 `EndpointGeneration` DTO，但不迁移现有 IPsec wire record，也不新增
一个把所有 provider 混在一起的 `transport/ports` record。`wireguard/ports` payload 需要
按 `overlay_id + family` 列出 device port generation，因为 WG listener 的实际 owner 是
group/family device。第一版使用一个 record 内的 `devices[]`，与现有单一
`wireguard/ports` key 保持一致；若未来 record 规模或写放大成为实际问题，再迁移为子 key。

目标 payload 形状为：

```json
{
  "version": 1,
  "devices": [
    {
      "overlay_id": "mesh-wggre",
      "family": "ipv4",
      "current": {"generation": 42, "advertised": 30412},
      "previous": [{"generation": 41, "advertised": 30100, "valid_until": 1717172017}]
    }
  ],
  "updated_at": 1717171717
}
```

overlay intent 的作用不是“广播一个 ID 以生成稳定 Link ID”，而是 signed opt-in 和兼容
声明。节点级 profile/address/ports/key 只说明“我具备这种 transport 能力”；
`<provider>/overlays/<overlay_id>` 进一步声明“我愿意把这些能力用于这个 overlay/path，
并同意这些 path keys、tunnel/transit address 派生规则”。没有 intent 时，本地不能因为
看到了远端 transport key 和公网 endpoint 就擅自为任意本地 LinkGroup 建链。

它同时避免两端 overlay ID、path family 或地址池规则不一致时出现“加密 session 看似 up，
但 Link ID、transit/tunnel address 和 Babel 数据面不一致”。ports record 频繁随 rotate
变化，overlay intent 相对稳定，因此二者保持分离。

现有 `routing/netns` record 与 overlay intent 不冲突。它公告本节点运行 routing/Babel
实例所使用的稳定 netns label，供其他节点或控制面按：

```text
StableRouterID(zone, root_trust, netns_label)
```

重新计算并审计该节点的 Babel Router-ID。它不是让多个节点形成相同 Router-ID；不同
节点因 `zone` 不同仍得到不同 ID。三个 identity 各自解决不同问题：

| Identity/record | 作用 |
|-----------------|------|
| `overlay_id` / overlay intent | 对齐双方参与的逻辑 overlay、provider、path 和地址派生规则 |
| `LinkID` | 标识同一 overlay 中一对节点的一条稳定逻辑链路 |
| `routing/netns` / Babel Router-ID | 标识并审计某节点某个 netns 中的 BIRD/Babel 实例 |
