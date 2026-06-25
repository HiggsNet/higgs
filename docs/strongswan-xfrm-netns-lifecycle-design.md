# StrongSwan XFRM / netns lifecycle design

## 背景

Higgs 当前 StrongSwan/XFRM 主线是单 host charon + VICI 控制面 + per-netns
overlay data plane。`TransportLinkSpec` 里保存目标 netns、XFRM `if_id`、
interface name 和 tunnel address，daemon/reconcile 负责加载 StrongSwan
connection、创建 XFRM interface、分配地址、观测 `ListSAs` 并维护
`LinkInstance`。

近期排障暴露出一个 namespace 错位风险：charon 安装的 XFRM state/policy 在
host netns，而 Higgs 的 `SystemXFRMDriver` 第一版在目标 overlay netns 里直接
`ip link add ... type xfrm`。这种形态下，目标 netns 能看到 interface，但看不到
host 里的 state/policy，流量可能在 XFRM interface 上 TX dropped。

`6-6-6/swan-updown` 证明了更适合单 charon 多 netns 的模式：XFRM interface
先在 charon 所在 netns 创建，再 move 到目标 netns。StrongSwan 官方 route-based
VPN 文档也说明，XFRM interface 可以移动到其它 network namespace，让那里的进程
访问另一个 namespace 中创建的 SA/policy；目标 namespace 只看到 interface，
看不到 SA key/state。

Higgs 要借鉴这个实现原理，但不直接依赖外部 `updown` 脚本。接口生命周期应内嵌在
daemon 的 VICI/reconcile 控制面里，继续受 Higgs owner、restart recovery、
revocation 和 staged rotate 状态机约束。

## 目标

- host charon 继续负责 IKE/NAT-T socket、VICI、XFRM state/policy 和密钥材料。
- overlay netns 只承载明文 overlay data plane：XFRM interface、tunnel address、
  BIRD/Babel、overlay firewall。
- XFRM interface 必须在 charon/state/policy 所在 netns 创建，然后 move 到
  `TransportLinkSpec.NetNS` / `LinkGroupSpec.NetNS` 指定的 overlay netns。
- Higgs daemon 内嵌生命周期管理，不把核心状态交给外部 script。
- 保持现有 VICI-first 边界：`swanctl` 仍只做人肉 debug，对 daemon 核心控制面没有
  解析依赖。

## 非目标

- 不引入多个 charon 实例作为第一步。多 charon 只保留给极端部署或后续多 listener
  需求。
- 不配置 `connections.<conn>.children.<child>.updown = ...` 调用 Higgs helper 作为
  主线。这样会把生命周期切成 daemon 和 forked helper 两个 writer。
- 不把 Babel、route authorization 或 firewall policy 混入 XFRM driver。它们继续由
  Phase 5/6 各自 manager 处理。

## 目标运行形态

```
host netns:
  charon / VICI
  UDP 500/4500 or configured NAT-T ingress
  XFRM state/policy installed by StrongSwan
  XFRM interface is created here first

overlay netns (for example h2):
  moved XFRM interface hgs...
  tunnel address on hgs...
  BIRD/Babel process and overlay routes
  overlay firewall rules
```

关键点不是 interface 最终在哪里，而是它的出生点：它要先出生在 charon 的
state/policy namespace，再 move 到 overlay netns。

## 内嵌生命周期方案

### 第一阶段：reconcile 驱动的 host-born interface

先改 `SystemXFRMDriver.EnsureInterface` 的真实 apply 语义：

1. `EnsureNamespace(target)` 确保目标 overlay netns 存在。
2. 如果 interface 已在目标 netns，直接 set up。
3. 如果 interface 已在 host netns，move 到目标 netns 后 set up。
4. 如果 interface 不存在，在 host netns 执行：
   `ip link add <iface> type xfrm if_id <if_id>`。
5. 对非 host 目标执行：
   `ip link set <iface> netns <target>`。
6. 在目标 netns 内执行：
   `ip link set dev <iface> up`。
7. `AssignAddress` 继续在目标 netns 内执行：
   `ip addr replace <prefix> dev <iface>`。

这样不改变现有 `ApplyTransportLink` 的高层顺序：ensure namespace -> load key ->
load connection -> ensure interface -> assign address。只是 `EnsureInterface` 内部把
XFRM interface 的创建点从目标 netns 改回 host netns。

### 第二阶段：VICI event 辅助收敛

在第一阶段跑通后，再把 strongSwan CHILD_SA 事件纳入 daemon：

- 订阅 VICI event，例如 `child-updown` / `ike-updown`，获取 child name、connection
  name、`if_id_in` / `if_id_out`、reqid、local/remote identity 和 endpoint。
- 事件处理只标记 IPsec/XFRM dirty，或调用同一套幂等 lifecycle manager；不能绕过
  `LinkInstance` owner 和 desired-state 校验。
- 事件里的 child/if_id 必须能匹配当前 desired `TransportLinkSpec` 或已有
  `LinkInstance`，否则只记录 unmanaged observation，不自动创建/删除资源。
- `down` 事件不能单独决定 teardown。revocation、policy deny、desired removal 才能
  触发强制清理；临时 rekey/down 事件应交给 reconcile + `ListSAs` 判断 repair/backoff。

VICI event 的价值是缩短“SA 已建立但 interface 尚未准备好”或“SA down 需要修复”的
观测延迟；权威状态仍是 Higgs desired state + persisted `LinkInstance` + current
`ListSAs`。

## 删除与恢复语义

- `DeleteInterface` 应优先在 `LinkInstance` / `TransportLinkSpec` 对应的目标 netns
  删除 interface；找不到时再检查 host netns 并删除残留。
- 对 path netns 第一版仍保守处理：建议 bind 到 `/var/run/netns` 后按 named netns
  管理；直接 move 到 path netns 需要单独设计 fd/setns 实现。
- daemon restart 后，reconcile 先从 active state + config 重新生成 desired spec，再用
  `ListSAs` 和系统 link inspection 采用已有 interface/SA。host 残留且 owner 匹配时可
  move 到目标 netns；目标 netns 残留且 if_id/name 匹配时直接 set up/address。
- revocation/policy deny/transport key mismatch 仍强制 terminate/unload/delete，并且
  不能被 backoff/retry 重新拉起。

## 与 staged rotate 的关系

staged generation 已经要求独立 `TransportID`、XFRM `if_id` 和 interface name。新的
host-born 规则同样适用于 staged interface：

- base generation 和 staged generation 都在 host 创建各自 XFRM interface，然后 move 到
  overlay netns。
- `dual_running` 期间 overlay netns 同时存在两个 `hgs*` interface，BIRD/Babel 通过
  metric 和 cutover gate 决定流量迁移。
- rollback 只删除 staged connection/interface，不触碰旧 generation。
- revocation 需要清理 base 和 staged 两套 owner-managed interface。

## 与 firewall/routing 的关系

- host firewall 继续只管 IKE/NAT-T ingress、range-mode redirect grace 等 host 入口。
- overlay firewall 继续在目标 netns 里按 `hgs*` 或具体 live interface 放行/限制明文
  mesh traffic。
- BIRD/Babel 必须运行在 overlay netns，观察 move 后的 `hgs*` interface。BIRD 不需要
  知道 interface 是在 host 出生的。

## 验证计划

1. 增加 `SystemXFRMDriver` 单元测试，断言 named netns 目标下命令顺序为 host
   `ip link add ... type xfrm` -> host `ip link set <iface> netns <ns>` ->
   target `ip link set dev <iface> up`。
2. 更新 preflight：除了检查目标 netns 内 `ip link add type xfrm` 能力，还要检查
   host-born XFRM interface move 到 named netns 的能力。
3. 增加 root/container smoke：host netns 中手工或 StrongSwan 安装 XFRM state/policy，
   host 创建 interface 后 move 到 overlay netns，目标 netns 内分配 tunnel address 并
   ping 通。
4. 更新现有 StrongSwan daemon smoke：失败诊断同时输出 host `ip xfrm state/policy`、
   host XFRM link、每个 overlay netns 的 `ip link/addr/route`。
5. VICI event 阶段增加 fake VICI event 单测和 root smoke，验证 child-up/down 只触发
   幂等 reconcile，不绕过 owner guard。

## 参考

- https://github.com/6-6-6/swan-updown
- https://docs.strongswan.org/docs/5.9/features/routeBasedVpn.html
- https://docs.strongswan.org/docs/5.9/plugins/updown.html
