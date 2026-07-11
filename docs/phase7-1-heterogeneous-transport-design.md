# Phase 7.1：StrongSwan/XFRM 与 WG/GRE 并行链路设计

本文定义 Higgs 同时运行 StrongSwan/XFRM 与 WireGuard/GRE 两套 TransportLink 的最终边界。
它只保留已经冻结、能够直接指导实现的内容；执行队列见 [`todo.md`](../todo.md)。

## 1. 状态与目标

已完成验证：

- 7.1.a：真实 BIRD 双接口、不同静态 cost、故障切换和恢复回切；
- 7.1.b：三节点共享 WG device、transit-only AllowedIPs、per-peer GRE/Babel 数据面；
- 7.1.c：old/staged WG device、generation-specific transit/GRE、Babel cutover 和零引用 cleanup；
- 7.1.d：确认只维护两套 provider lifecycle，撤销通用 planner/action/resource graph 的过度抽象。

剩余实现：

1. 7.1.e：公共 Babel-facing `LinkOutput` 与 routing/firewall/health/readmodel 消费边界；
2. 7.1.f：WG/GRE 正式 provider；
3. 7.1.g：BIRD per-interface policy、双 provider readmodel 和联合 smoke。

目标拓扑：

```text
same peer, same routing domain/netns
  ├── StrongSwan/IKEv2 + ESP -> XFRM interface -> Babel
  └── WireGuard              -> GRE interface  -> Babel
```

provider 不表示主用或备用。两条 link 可以同时 active；实际选择由本地 LinkGroup cost、Babel
邻接和路由收敛决定。

非目标：

- 不建设可无限扩展的 transport 插件框架；
- 不把 StrongSwan 迁移到通用 desired/runtime/action 模型；
- 不让业务前缀进入 WG AllowedIPs；
- 不让 Babel 直接运行在共享裸 WG device 上；
- 不让 health 第一版动态修改 BIRD cost 或 admin-down 接口；
- 不在 7.1 承诺高频/对抗性 port hopping、VXLAN 或 SRv6。

## 2. 冻结决策

| 决策 | 结论 |
|---|---|
| D1 | 一个 `overlays[]` 项就是一个 LinkGroup，一个 LinkGroup 只有一个 provider |
| D2 | 静态 Babel base cost 属于 LinkGroup；per-netns routing instance 负责合并 |
| D3 | 最终 Link ID 包含 provider，不增加 ID version；旧 StrongSwan ID 通过 legacy lookup adopt |
| D4 | WG device 按 LinkGroup + netns + underlay family 共享；GRE link 是 per-peer |
| D5 | health 第一版只做观测、告警和既有 rotate gate，不主动接管 Babel 选路 |
| D6 | GRE key、transit address 等非秘密参数从稳定 Link ID 派生；WG private key 随机生成并持久化 |
| D7 | StrongSwan/WG 保留各自的 ports record 与 overlay intent；只复用 generation/grace DTO/helper |
| D8 | 两个 provider 各自管理 planner、hash、state、action、resource graph；daemon 只统一调度和 `LinkOutput` |

## 3. 最终代码边界

```text
Daemon single-writer/event-loop
  |
  +-- reconcileIPsecLinks
  |     -> existing IPsec planner/reconcile/apply/state
  |     -> project base []LinkOutput
  |
  +-- reconcileWireGuardGRELinks
  |     -> WG device/peer/GRE planner/reconcile/apply/state
  |     -> project base []LinkOutput
  |
  +-- enrich and aggregate []LinkOutput
        +-- LinkGroup base cost
        +-- BIRD neighbor/routing readiness
        +-- health snapshot
        +-- routing/firewall/inspect consumers
```

第一版可以由 daemon 显式调用两个 reconcile 方法，不要求 registry。若以后出现真实的第三个
provider 或重复调度代码，再考虑提取只有 `Kind()`/`Reconcile()` 的窄接口。

### 3.1 StrongSwan 保持现有生命周期

StrongSwan 保持现有 **desired 规划 → 实际观测 → reconcile action → VICI/XFRM apply → state
commit** 闭环；完整输入、操作图和 create/teardown 顺序见
[`Transport-IPsec`](new/transport-ipsec.md#reconcile-主循环)。本阶段只关心它最终能投影一条
Babel-facing `LinkOutput`。

```text
IPsec records + local policy + persisted state + SA/XFRM observation
  -> existing IPsec reconcile/apply lifecycle
  -> committed LinkInstances/IPsecReconcileState
  -> base LinkOutput(session/interface facts)
```

必须保留：

- signed IPsec record、policy、contact selection 和 tunnel address 语义；
- SA/XFRM observation、restart/adopt 和缺失接口修复；
- owner guard、backoff、revision-aware commit；
- initiator/secondary takeover；
- per-link staged rotate、cutover、rollback 和 cleanup。

不增加 `AdaptStrongSwanLinkSpec` 生产转换，不引入通用 `ProviderPlan`/`ProviderAction`，也不为
匹配 WG 而制造 no-op shared resource。

### 3.2 WG/GRE 使用独立生命周期

建议内部模型：

```text
wireguardgre.Plan
  DeviceSpec(group, netns, family, generation)
    -> PeerSpec(peer, public key, transit AllowedIP, endpoint)
       -> GRESpec(peer, transit endpoints, GRE key, MTU, link addresses)
  -> wireguardgre.Reconcile
  -> wireguardgre.Action
  -> wgctrl + netlink + firewall
  -> wireguardgre.State
```

WG/GRE 独立持久化：

- logical device identity 与 private-key reference；
- active/staged WG device generation 和 listener；
- peer membership、public key、endpoint、transit AllowedIP、last handshake；
- per-peer GRE/IP6GRE interface、key、address、MTU；
- 引用、owner marker、rotate phase/deadline、error/backoff。

WG 的 device → peer → GRE resource graph 只存在于 WG/GRE 包内。删除一条 GRE link 不得删除
其他 peer 仍在使用的 WG device。

## 4. 公共 `LinkOutput`

`LinkOutput` 是 provider runtime 向公共消费者发布的只读投影，不是 desired spec，不参与
provider desired hash，也不能反向生成 apply/teardown action。

```go
type LinkOutput struct {
    ID             string
    GroupID        string
    PeerZone       zone.ZonePath
    Provider       string
    PathKey        string
    NetNS          string
    InterfaceName  string
    LocalAddr      netip.Addr
    PeerAddr       netip.Addr
    MTU            uint32
    BabelBaseCost  uint
    Generation     uint64
    RuntimeRole    string // active | staged | draining
    State          string
    Readiness      LinkReadiness
    Endpoint       string
    LastError      string
    LastTransition int64
}

type LinkReadiness struct {
    Session   string
    Interface string
    Routing   string
    Health    string
}
```

投影与 enrichment：

```text
IPsec state + SA/XFRM observation
  -> base LinkOutput(session/interface)

WG/GRE state + wgctrl/netlink observation
  -> base LinkOutput(session/interface)

LinkGroup policy + BIRD snapshot + health snapshot
  -> BabelBaseCost + routing/health readiness
```

公共消费者：

- routing：按 netns/interface 生成 BIRD policy；
- firewall：收集有效 live interfaces；
- health：生成 per-link probe target；
- inspect/observer：按 peer/group/provider 展示多 link。

公共消费者不得读取 provider action/resource state，也不得凭 `LinkOutput` 执行 teardown。

## 5. Identity、generation 与 ownership

### 5.1 Link ID

最终公式：

```text
link_id = H(
  ordered(local_zone, peer_zone),
  group_id,
  provider,
  path_key
)
```

endpoint、port、handshake、health 和 generation 不进入稳定 Link ID。provider 原地变化会产生
新 ID，从而禁止新 provider adopt 旧 provider 资源。

当前上个实验 commit 仍使用旧 StrongSwan ID。provider-aware helper 必须在 WG/GRE 正式接入
时一次性完成，并覆盖所有 StrongSwan planner/constructor 路径；不允许只修改部分 constructor。
迁移测试必须证明：

- 新 StrongSwan ID 能关联旧 Link ID/transport ID；
- owner guard 仍能 adopt/cleanup legacy state；
- WG/GRE 不会 adopt StrongSwan resource；
- daemon restart 不会误 teardown/recreate 正常 SA。

### 5.2 Generation

generation 表示 provider runtime 代次，不改变稳定 Link ID：

- StrongSwan：per-link IKE/CHILD/XFRM generation；
- WG/GRE：group/netns/family shared-device generation，并投影到该 device 的 peer links。

`EndpointGeneration` 的 current/previous/valid-until 表达和 grace helper 可以复用，但 signed
record、状态机和 apply 语义分别属于 provider。

### 5.3 Ownership

公共 owner scope 可以共享以下字段概念：

```text
manager + provider + group_id + link/resource_id + runtime_id + kind
```

destructive cleanup 必须同时满足：

1. persisted owner/token 匹配；
2. provider-specific live marker 匹配；
3. resource name 位于 Higgs 保留命名空间；
4. desired 已删除、peer 已 revoke，或 lifecycle 明确进入 cleanup。

具体校验由 provider 实现：StrongSwan 检查 IKE/XFRM identity 与 legacy owner；WG/GRE 检查
WG device、peer membership、GRE key/interface 和 firewall marker。

## 6. LinkGroup、records 与本地 policy

一个 group 只选择一个 provider：

```yaml
overlays:
  - id: mesh-ipsec
    provider: strongswan
    netns: h2

  - id: mesh-wggre
    provider: wireguard-gre
    netns: h2
```

signed record 只表达远端事实/能力，本地配置表达是否启用和如何使用：

| 数据 | signed record | 本地 policy |
|---|---|---|
| public key/fingerprint | 是 | 否 |
| endpoint + generation | 是 | 本地选择 |
| provider/path/address-family capability | 是 | 选择是否启用 |
| overlay intent | 是 | 本地 group 必须匹配 |
| target netns | 否 | 是 |
| Babel base cost | 否 | 是 |
| MTU policy | 能力上限 | 本地取安全结果 |
| transit address/GRE key | 否，稳定派生 | pool/算法 policy |

records 保持 provider-specific：

```text
ipsec/profile
ipsec/addresses
ipsec/ports
ipsec/transport-key
ipsec/overlays/<overlay_id>

wireguard/profile
wireguard/addresses
wireguard/ports
wireguard/transport-keys
wireguard/overlays/<overlay_id>
```

看到远端 capability 不等于远端已经 apply。没有匹配 overlay intent 时，不得仅凭 key 和
endpoint 自动建链。双方 policy 可以不对称；planner 应返回结构化 skip/degraded reason。

## 7. WG/GRE 数据面约束

### 7.1 AllowedIPs 与 GRE

共享 WG device 的每个 peer 只安装 transport transit address：

```text
peer B -> 10.200.0.2/32 或 fd00:wg::b/128
peer C -> 10.200.0.3/32 或 fd00:wg::c/128
```

禁止进入 AllowedIPs：

- peer 公告的业务前缀；
- Babel learned routes；
- default route；
- 经该 peer 多跳转发的其他节点前缀。

业务包先由 Babel 选择 per-peer GRE interface，GRE 外层目的为 peer transit address，WG 再按
transit AllowedIP 选择加密 peer。

第一版只实现 GRE/IP6GRE。VXLAN 需要 VNI、FDB、广播/多播复制和额外 MTU 设计，不属于本切口。

### 7.2 Shared device scope

```text
LinkGroup wireguard-gre
  ├── WG device ipv4
  │     ├── peer B -> GRE B -> Babel
  │     └── peer C -> GRE C -> Babel
  └── WG device ipv6
        ├── peer B -> IP6GRE B -> Babel
        └── peer C -> IP6GRE C -> Babel
```

device scope 为 `(group_id, netns, underlay_family)`。分 IPv4/IPv6 device 的原因是同一 WG peer
在一个 device 上只有一个当前 endpoint；若希望两个公网 family 同时 active，需要独立
device/peer runtime。

logical device private key 随机生成并持久化；old/staged runtime 默认复用该 identity。不得从
公开 Link ID 派生 private key。

### 7.3 Staged rotate

WG rotate 属于 shared-device lifecycle：

```text
active WG device generation 12
  ├── peer B -> GRE B generation 12
  └── peer C -> GRE C generation 12

staged WG device generation 13
  ├── peer B -> staged GRE B generation 13
  └── peer C -> staged GRE C generation 13
```

流程：

1. 创建新 listener 与 staged WG device，复用 logical device key；
2. 加入该 scope 的 desired peers；
3. 使用 generation-specific transit address epoch，避免 old/staged AllowedIPs 和路由冲突；
4. 为每个 peer 创建 staged GRE/IP6GRE interface；
5. 发布 current + previous/valid-until port advertisement；
6. 观察 WG handshake、GRE interface、Babel neighbor/route 和既有 cutover gate；
7. per-link 完成 cutover 后清理 old GRE；
8. 最后一个 old-generation 引用退出后才删除 old WG device/listener/firewall rule。

旧/新 listener grace 与 staged 数据面是两个层次；firewall redirect 不能替代 staged runtime。

## 8. netns、MTU、BIRD 与 health

默认所有数据面对象位于同一目标 netns：

```text
target netns
  ├── BIRD
  ├── XFRM interfaces
  ├── WG devices
  └── per-peer GRE/IP6GRE interfaces
```

隐式 host-WG + overlay-netns-GRE 拓扑第一版拒绝；若以后支持，必须显式设计 veth、route、
forwarding、firewall 和 ownership。

MTU 是 provider planner 的明确结果。WG/GRE 第一版沿用真实实验通过的保守 GRE MTU 1360，
后续自动派生需考虑 underlay family、WG、GRE、IPv6 下限和安全余量。

BIRD 需要多个有序 interface policy blocks：

```text
interface "hgs*"  { rxcost 96;  } // StrongSwan/XFRM
interface "hgsg*" { rxcost 160; } // WG/GRE
```

实际命名前缀必须满足 Linux 15 字符限制。精确 interface 规则应优先于通配规则。

注意：Babel `rxcost` 是本机向邻居公告的接收方向评价，主要影响邻居的 route selection，
不能描述成“强制本机绕开该接口”。

health 第一版只补充 `LinkOutput.Readiness.Health`、告警和 rotate gate；不自动改 BIRD cost、
排除接口或触发 BIRD configure。普通故障收敛依赖 provider interface/邻接消失和 Babel 自身机制。

## 9. 状态、失败隔离与 cleanup

两套持久化 state 分开：

```text
existing LinkInstances/IPsecReconcileState  // StrongSwan
WireGuardGREState                           // WG device/peer/GRE
```

不为 readmodel 统一而改成 tagged generic instance。基础状态词可以在输出层统一为：

```text
pending -> configuring -> connecting -> up
                                |        |
                                v        v
                              error   degraded
desired removed/revoked -> removing -> down
```

失败隔离：

- 一条 StrongSwan link 失败不阻塞 WG/GRE；
- 一个 WG peer/GRE 失败不阻塞同 device 的其他 peer，也不阻塞 StrongSwan；
- provider 单边 commit 失败不得覆盖另一边已提交 state；
- 聚合只能读取已提交 runtime snapshot。

cleanup：

- revoke peer：分别触发 IPsec teardown 与 WG peer/GRE teardown；
- 删除 group：只清理该 provider/group scope；
- WG shared device：仅零引用且 owner/live marker 通过时删除；
- daemon restart：各 provider 从自身 persisted state + live inspect adopt；
- hard purge：在 provider cleanup 完成后才删除对应 runtime state，不能只删 readmodel。

## 10. 运维输出

在线 `links_status` 继续是 daemon-owned truth；control socket 可用时，CLI 不得自行重新规划并
替代 runtime snapshot。

建议默认文本：

```text
peer node-b.catofes.
  mesh-ipsec/strongswan
    state=up interface=hgs... cost=96 mtu=1400
    session=ready babel=neighbor health=healthy endpoint=[...]:4500

  mesh-wggre/wireguard-gre
    state=degraded interface=hgsg... cost=160 mtu=1360
    session=ready babel=pending health=degraded endpoint=[...]:51820
```

公共列表使用 `LinkOutput`。详细视图分别追加 provider section：

- StrongSwan：IKE/CHILD/XFRM、initiator/takeover、rotate；
- WG/GRE：device/peer、last handshake、transit AllowedIP、GRE、shared rotate/refcount。

private key、完整 owner token 和其他秘密不得进入输出。

## 11. 实现切口

### 11.1 7.1.e：公共 LinkOutput 与消费者收口

- 在窄 `pkg/transport` 或 `internal/state` 边界定义 `LinkOutput`/`LinkReadiness`；
- 从现有 StrongSwan committed state 投影基础输出，不改变 IPsec lifecycle；
- 聚合 LinkGroup、BIRD 和 health snapshot；
- firewall、routing、health、inspect 逐步改为消费聚合输出；
- 保持 online daemon snapshot 为真值。

验收：StrongSwan 现有测试无语义变化；聚合/enrichment 单测覆盖 active/staged、多 group、
missing BIRD/health 和稳定排序。

### 11.2 7.1.f：WG/GRE 正式 provider

- 一次性落地 provider-aware Link ID helper 与 StrongSwan legacy migration tests；
- 实现 WG records、overlay intent 和本地 policy；
- 实现 device/peer/GRE planner、state、inspect、reconcile、apply 和 teardown；
- AllowedIPs 只允许 transit `/32`/`/128`；
- 实现 private key 持久化、owner/live marker 和 restart/adopt；
- 实现 shared-device staged rotate、listener/firewall grace 和零引用 cleanup；
- 投影基础 `LinkOutput`。

验收：fake-driver 单测、state round-trip/restart、shared device 引用、错误隔离、rotate/rollback/
cleanup，以及现有 WG/GRE root experiment 的正式 provider 等价验证。

### 11.3 7.1.g：联合收口

- BIRD per-interface policy blocks 和 LinkGroup base cost；
- `debug links`/observer 按 peer/group/provider 展示；
- 同一 peer 的真实 IPsec/XFRM 与 WG/GRE 同时 active；
- 同一 per-netns BIRD 建立两条邻接；
- 分别中断 IPsec、WG、GRE，验证失败隔离与 Babel 收敛；
- 删除单 group、revoke peer、restart，验证 provider 粒度 cleanup/adopt；
- 验证业务前缀未进入 WG AllowedIPs。

## 12. 已验证实验

### 12.1 BIRD 双接口

`pkg/routing/bird.TestBabelDualInterfaceCostFailoverRootSmoke` 在真实 BIRD 2.19.1 中验证：

- 两节点每端两条接口和两个 Babel neighbor；
- 不同 `rxcost` 的确定性选路；
- 首选接口 down 后切换，恢复后回切；
- `rxcost` 的方向性符合第 8 节说明。

入口：`sudo make phase7-1-bird-experiment`，不进入默认 smoke。

### 12.2 WG/GRE 三节点

`pkg/transport/wireguard.TestWireGuardGREThreeNodeRootSmoke` 验证：

- 中心节点一个共享 WG device 承载两个 peers；
- AllowedIPs 只有 transit `/32`；
- 每个 peer 有独立 GRE/Babel interface；
- B/C 业务前缀经 A 学习并双向转发；
- GRE MTU 1360 和 cleanup 无残留。

### 12.3 WG staged rotate

`pkg/transport/wireguard.TestWireGuardGREStagedRotateRootSmoke` 验证：

- old/staged WG devices 可以复用 logical private key 和 peer public keys；
- 两代 listener、transit epoch 和 GRE interfaces 可并行；
- Babel 可在 old withdraw 后切到 staged；
- old/current firewall listener grace 可并存；
- 最后一个 old link 引用释放后才删除旧 shared device。

WG/GRE 两项入口：`sudo make phase7-1-wg-gre-experiment`，不进入默认 smoke。

## 13. 完成条件

7.1 只有在以下条件全部满足时完成：

1. StrongSwan 主链路、state、takeover 和 rotate 未因 WG 抽象发生语义回归；
2. WG/GRE 正式 provider 具备完整 owner、restart/adopt、rotate 和零引用 cleanup；
3. 两个 provider 都能发布公共 `LinkOutput`，消费者不读取 provider 内部 action/resource；
4. BIRD 支持按 interface/group 设置 cost，同一 peer 两条邻接可共存和独立收敛；
5. readmodel 能区分 peer/group/provider/link/runtime generation；
6. `make check`、focused tests、双 provider dry-run 和联合 root/container smoke 通过；
7. revoke、group removal、restart 和单边故障不影响另一 provider 的 owned resources。
