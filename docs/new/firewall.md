# Higgs Firewall 设计与实现

> **本文档状态：2026-07**
> 描述 Higgs firewall 子系统的当前实现：`pkg/firewall` 的 planner 与 backend driver、`app/higgs` 中的 reconcile 集成，以及 `higgs debug firewall` 等诊断命令。
> 旧设计参考见 `docs/phase6-firewall-design.md`，但本文以当前代码为准；文中会显式标注已实现行为与设计文档的差异或待完善项。

Firewall 是 Higgs overlay data-plane 的安全边界执行器。它把已通过 Zone trust chain 验证的 IPAM、route announcement、revocation state 和本地配置策略，收敛成 Linux 防火墙规则。它**不是**通用主机防火墙，不管理 SSH、Docker、Kubernetes 等发行版默认规则。

完整配置字段见 [config.md](config.md)，daemon reconcile 调度见 [daemon.md](daemon.md)，IPsec 端口与链路细节见 [transport-ipsec.md](transport-ipsec.md)。

---

## 目录

1. [范围与定位](#1-范围与定位)
2. [核心概念](#2-核心概念)
3. [配置模型](#3-配置模型)
4. [规则生成（Planner）](#4-规则生成planner)
5. [Backend 驱动](#5-backend-驱动)
6. [Reconcile 流程](#6-reconcile-流程)
7. [Debug 与诊断](#7-debug-与诊断)
8. [已知限制与实现缺口](#8-已知限制与实现缺口)

---

## 1. 范围与定位

### 1.1 职责边界

| 层面 | 做什么 | 不做什么 |
|---|---|---|
| overlay/data-plane netns | 默认 drop 未授权流量；放行 mesh 授权前缀、BIRD/Babel 控制流量、本地显式服务 | 不管理 host 全局防火墙、不处理 underlay 入口 |
| host netns | 仅管理 Higgs 必须的最小入口：IKE/NAT-T/WireGuard 端口 allow、端口 rotate 的 DNAT/redirect grace | 不接管 Docker、Kubernetes、发行版默认规则 |
| reconcile 语义 | 只增删 Higgs-owned 对象；启动时 adopt、运行时 diff apply | 停止时**不**自动清理 owned 规则（当前实现缺口，见第 8 节） |

### 1.2 命名空间边界

```text
host netns
  ├─ Higgs-owned host ingress allow (IKE/NAT-T/WG)
  ├─ optional old/current port redirect grace
  └─ non-Higgs firewall rules stay untouched

overlay netns (e.g. h2)
  ├─ XFRM tunnel interfaces: hgs*
  ├─ BIRD/Babel instance
  ├─ optional veth upstream: hgs-upstream*
  └─ Higgs-owned input/forward/output policy
```

Firewall 跟随 netns 隔离边界：一个 netns 对应一个 firewall instance。host 单独作为一个特殊 instance。

---

## 2. 核心概念

### 2.1 Owner

Higgs 所有防火墙对象通过 `Owner` 标记，以便与管理员规则区分：

```go
// pkg/firewall/types.go
type Owner struct {
    Manager     string // 始终为 "higgs"
    InstanceID  string // host 为 "host"，overlay 为实际 netns 名
    OwnerPrefix string // 默认 "higgs"
    Generation  uint64 // desired-state generation
    Token       string // prefix + scope + id 的 sha256 前 12 位
}
```

- 命名前缀决定 table/chain/set 名称。overlay 实例默认表名为 `higgs_<netns>`，如 `higgs_h2`；host 实例为 `higgs_host`。
- `Token` 由 `OwnerToken(spec)` 生成，用于稳定识别同一实例的历史对象。

### 2.2 Instance

一个 instance 对应一个 firewall 管理边界：

| 字段 | 含义 |
|---|---|
| `ID` | 配置里的实例标识 |
| `NetNS` | 实际 netns 名，或 `"host"` |
| `IsHost` | 是否为 host 实例；`host: true` 与 `netns` 互斥 |
| `Mode` | `managed` / `external` / `disabled` |
| `Backend` | `auto` / `nft` / `iptables` / `none` |
| `DefaultPolicy` | `drop` 或 `accept`，默认 `drop` |
| `OwnerPrefix` | 命名前缀，默认 `higgs` |

Instance scope（用于 owner 和命名）以实际 netns 名为准，而不是配置里的 `id`。例如 `id: host-ipsec, host: true` 归属到 `higgs_host`。

### 2.3 Mode

- `managed`：Higgs 拥有并管理该 netns 的防火墙规则。
- `external`：Higgs 不生成规则，保留给外部管理器；daemon 仍会读取配置但跳过 reconcile。
- `disabled`：完全禁用该 instance。

### 2.4 ForwardingPolicy

Firewall 与 BIRD 共享同一份 `ForwardingPolicy`，避免“路由允许但防火墙阻断”或相反：

```go
// pkg/firewall/types.go
type ForwardingPolicy struct {
    Transit       bool
    AllowPrefixes []netip.Prefix
    DenyPrefixes  []netip.Prefix
    AllowPeers    []string // zone globs or exact，当前未实际使用
    DenyPeers     []string // 当前未实际使用
    MetricHint    uint
}
```

- `Transit=false`：overlay forward chain 显式 drop XFRM→XFRM 流量。
- `Transit=true`：按 `AllowPrefixes`/`DenyPrefixes` 过滤后的 mesh 前缀允许 XFRM→XFRM transit。

> **注意**：当前代码只使用 `AllowPrefixes`/`DenyPrefixes`，`AllowPeers`/`DenyPeers` 字段存在但**未实际参与过滤**。

---

## 3. 配置模型

### 3.1 最小配置示例

```yaml
netns:
  default:
    kind: name
    name: h2

firewall:
  instances:
    - id: h2
      netns: default
      default_policy: drop

    - id: host-ipsec
      host: true
      host_ports:
        ike: true
        natt: true
      redirect_grace:
        enabled: true
```

### 3.2 字段说明

| 字段 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `id` | string | 必填 | 实例标识 |
| `netns` | string | `"default"` | 引用的 `netns` 段名字；非 host 实例必填 |
| `host` | bool | false | 是否为 host 实例；与 `netns` 互斥 |
| `enabled` / `disabled` | bool | true | 是否启用该 instance |
| `mode` | string | `managed` | `managed` / `external` / `disabled` |
| `backend` | string | `auto` | `auto` / `nft` / `iptables` / `none` |
| `default_policy` | string | `drop` | `drop` / `accept` |
| `owner_prefix` | string | `higgs` | 命名前缀 |
| `xfrm_tunnel_pattern` | string | `hgs*` | overlay XFRM 接口匹配模式 |
| `upstream_patterns` | string list | `["hgs-upstream*"]` | upstream veth 接口匹配模式 |
| `local_services` | list | `[]` | overlay 内显式开放的服务 |
| `host_ports.ike` | bool | 见下文 | host UDP 500 入口 |
| `host_ports.natt` | bool | 见下文 | host UDP 4500 入口 |
| `host_ports.wg` | bool | false | host WireGuard 入口（预留） |
| `redirect_grace.enabled` | bool | 见下文 | 端口 rotate 期间的 DNAT/redirect grace |
| `listen_addrs` | string list | `[]` | host 规则绑定的本地目的地址 |
| `hooks.*` | string | `""` | 管理员自定义 chain 挂载点 |

### 3.3 host 实例默认值

当 `ipsec.port_mode=range` 时，host 实例会自动启用 `host_ports.ike` 和 `host_ports.natt`，并启用 `redirect_grace`，以便端口范围模式正常工作。这些默认值可被显式配置覆盖。

```go
// app/higgs/firewall_config.go:189-214
rangeMode := isHost && ipsecCfg.PortMode == ipsec.PortModeRange
if rangeMode {
    hostPorts.IKE = true
    hostPorts.NATT = true
}
// ... 可被 yi.HostPorts.* 覆盖

if rangeMode {
    redirectGrace.Enabled = true
}
// ... 可被 yi.RedirectGrace.* 覆盖
```

### 3.4 local_services

显式开放 overlay netns 内的服务：

```yaml
local_services:
  - proto: tcp
    port: 8080
    sources:
      - 10.42.0.0/16
```

- `sources` 为空时，允许来源为所有 mesh 授权前缀。
- 只支持 `tcp` 或 `udp`。

### 3.5 hooks

Hook 用于挂载管理员自定义 chain。当前代码已解析并保留字段，但**生成的规则语法有误**，hook 实际无法生效（见第 8 节）。

```yaml
hooks:
  pre_input: higgs_h2_pre_user
  post_input: higgs_h2_post_user
  pre_forward: higgs_h2_pre_fwd
  post_forward: higgs_h2_post_fwd
  pre_output: higgs_h2_pre_out
  post_output: higgs_h2_post_out
  # host-only hooks
  host_pre_prerouting: ...
  host_post_prerouting: ...
  host_pre_input: ...
  host_post_input: ...
```

---

## 4. 规则生成（Planner）

Planner 是纯逻辑函数，不执行 I/O，不依赖 root。

### 4.1 入口与输入

```go
// pkg/firewall/planner.go:45
func BuildDesiredState(spec FirewallInstanceSpec, input FirewallPolicyInput) (*FirewallDesiredState, error)
```

`FirewallPolicyInput` 包含：

| 字段 | 来源 | 作用 |
|---|---|---|
| `LocalAssigned` | `AuthorizedRouteSet` 中本 Zone 被分配的前缀 | overlay 本地前缀 |
| `MeshAuthorized` | `AuthorizedRouteSet.Announced` 中所有授权前缀 | 可信 mesh 前缀 |
| `AssignmentPrefixes` | IPAM assignment 白名单 | 校验用 |
| `Forwarding` | 本 netns 的 forwarding policy | transit 决策 |
| `Revoked` | revocation state | deny-first：从 allow set 中剔除 |
| `LiveInterfaces` | 当前活跃 XFRM 接口 | 规则匹配 |
| `UpstreamInterfaces` | upstream veth 接口 | 规则匹配 |
| `AdvertisedCurrent/Previous*Ports` | 本地 signed `ipsec/ports` record | redirect grace |

### 4.2 PrefixSets

```go
// pkg/firewall/types.go
type PrefixSets struct {
    LocalAssignedV4  []netip.Prefix
    LocalAssignedV6  []netip.Prefix
    MeshAuthorizedV4 []netip.Prefix
    MeshAuthorizedV6 []netip.Prefix
    RevokedV4        []netip.Prefix // audit-only
    RevokedV6        []netip.Prefix // audit-only
}
```

`buildPrefixSets` 会把 `Revoked` 前缀从 `LocalAssigned` 和 `MeshAuthorized` 中剔除，同时把 revoked 前缀单独保留在 `RevokedV4/V6` 中用于审计。

### 4.3 overlay netns 规则顺序

overlay 实例生成 `input`、`forward`、`output` 三条 filter chain。

#### input chain（按生成顺序）

```text
1. loopback accept
2. pre_input hook（当前语法有误）
3. UDP 6696 (Babel) accept
4. ICMP / ICMPv6 accept
5. established/related accept（当前无 ct state 匹配）
6. local_services accept
7. mesh authorized -> local assigned accept
8. post_input hook（当前语法有误）
9. default policy (drop / accept)
```

#### forward chain

```text
1. established/related accept（当前无 ct state 匹配）
2. pre_forward hook（当前语法有误）
3. XFRM->XFRM：transit=false 则 drop；transit=true 则按 forwarding policy allow
4. XFRM->upstream：允许到 local assigned 前缀
5. upstream->XFRM：允许到 mesh authorized 前缀
6. post_forward hook（当前语法有误）
7. default policy (drop / accept)
```

#### output chain

```text
1. loopback accept
2. UDP 6696 (Babel) accept
3. ICMP / ICMPv6 accept
4. local assigned source accept
5. post_output hook（当前语法有误）
6. default accept（output 固定为 accept）
```

> **注意**：output chain 的默认策略当前硬编码为 `accept`，不受 `default_policy` 配置影响。

### 4.4 host netns 规则

host 实例生成以下规则：

#### Endpoint ACL（forward 链）

`EndpointACL` 通过 control API 应用，只允许匹配 Zone selector 的源访问指定目的端口。每个 endpoint 生成“允许+默认 drop”两条规则，实现 fail-closed。

```go
// app/higgs/endpoint_acl.go
if len(endpoint.Sources) > 0 {
    // accept rule
} else {
    // 不生成 accept；但始终生成 drop，保证 fail-closed
}
desired.ForwardRules = append(desired.ForwardRules, Rule{
    Action: ActionDrop, ...
})
```

#### Host ingress

`host_ports` 启用的端口生成 `HostIngressRule`：

| 端口 | 协议 | 说明 |
|---|---|---|
| 500 | UDP | IKE |
| 4500 | UDP | NAT-T |
| 51820 | UDP | WireGuard（预留） |

#### Redirect grace

当 `redirect_grace.enabled=true` 时，把当前或历史 advertised 端口重定向到当前 charon 监听端口（IKE 500 / NAT-T 4500）。同时生成 source-port rewrite 规则，使本机发出的传输流量源端口与 advertised 端口一致。

```go
// pkg/firewall/planner.go:332-353
addNatRedirects(desired, input.AdvertisedCurrentIKEPorts, ikePort, "redirect current", "ike", spec.ListenAddrs)
addNatRedirects(desired, input.AdvertisedPreviousIKEPorts, ikePort, "redirect grace", "ike", spec.ListenAddrs)
addNatRedirects(desired, input.AdvertisedCurrentNATTPorts, nattPort, "redirect current", "natt", spec.ListenAddrs)
addNatRedirects(desired, input.AdvertisedPreviousNATTPorts, nattPort, "redirect grace", "natt", spec.ListenAddrs)
addNatSourceRewrites(...)
```

WireGuard 的 previous port redirect 也已预留字段，但依赖 Phase 7 WireGuard transport driver 提供 advertised 端口。

---

## 5. Backend 驱动

### 5.1 Driver 接口

```go
// pkg/firewall/driver.go
type FirewallDriver interface {
    Preflight(ctx context.Context, spec FirewallInstanceSpec) (FirewallPreflight, error)
    Plan(ctx context.Context, desired *FirewallDesiredState, observed FirewallObservedState) (FirewallPlan, error)
    Apply(ctx context.Context, plan FirewallPlan, desired *FirewallDesiredState) (FirewallApplyResult, error)
    ListOwned(ctx context.Context, owner Owner) (FirewallObservedState, error)
    DeleteStale(ctx context.Context, refs []FirewallObjectRef) error
}
```

### 5.2 nftables 后端（`NFTDriver`）

- 使用 `nft` CLI（非 netlink API）。
- 所有对象放在 `inet` family 的表 `<owner_prefix>_<scope>` 中。
- overlay 创建 `input`、`forward`、`output` chain；host 额外创建 `prerouting`、`postrouting`。
- Mesh 前缀使用 `set`，命名如 `higgs_h2_mesh_v4`、`higgs_h2_mesh_v6`，带 `flags interval`。
- `Apply` 时如果观察到已存在同名 Higgs-owned table，先 `delete table` 再整体重建，避免 stale rule 累积。

### 5.3 iptables 后端（`IPTablesDriver`）

- 同时操作 `iptables` 与 `ip6tables`。
- 通过 chain 名前缀 `higgs_<scope>_INPUT/FORWARD/OUTPUT` 识别归属。
- 使用 `-m comment --comment higgs-<scope>` 标记 Higgs 规则。
- NAT redirect 用 `REDIRECT --to-ports`；source rewrite 用 `MASQUERADE --to-ports`。

### 5.4 dry-run 后端（`DryRunDriver`）

- 不修改系统，只记录 plan/apply 调用。
- 当 backend 探测不到 `nft` 或 `iptables`，或配置为 `none` 时使用。
- 用于单元测试和 smoke 场景。

### 5.5 Backend 探测

```go
// pkg/firewall/driver.go:65
func PreflightProbe(ctx context.Context) FirewallPreflight
```

探测逻辑：

1. 检查 `nft` 命令是否存在；存在则 `NFTNetlink=ok`，`Backend=nft`。
2. 检查 `iptables` 命令是否存在；存在则 `Iptables=available`，`Backend=iptables`（nft 不可用时）。
3. 都不可用时 `Backend=none`。
4. `CAP_NET_ADMIN` 通过 `nft list tables` 做尽力探测。

> **注意**：当前探测只检查命令存在性，不检测 netlink API、host NAT hook、ipset 等设计文档建议的能力。

### 5.6 Plan diff

```go
// pkg/firewall/driver.go:27
func PlanDiff(instanceID string, desired *FirewallDesiredState, observed FirewallObservedState) FirewallPlan
```

通用 diff 逻辑：

- desired 中有、observed 中无 → `create`
- desired 中有、observed 中也有 → `adopt`
- observed 中有、desired 中无 → `delete`（stale）

---

## 6. Reconcile 流程

### 6.1 触发时机

Firewall reconcile 在 `app/higgs/firewall_reconcile.go` 中实现，触发时机见 [daemon.md](daemon.md)：

- daemon 启动时 `recoverFirewallOnStart` 设置 `firewallDirty=true` 并 flush。
- `notifyStateChanged`（网络状态、Zone record、endpoint ACL 等变化）触发 flush。
- `processEvents` 每次事件 drain 后也会 `flushFirewallReconcile`。
- `endpoint_acl_apply` / `endpoint_acl_remove` 事件单独强制 flush。
- `reload_config` 重新加载配置后触发。

### 6.2 reconcileFirewall 主流程

```text
1. 获取当前 committed snapshot 与 config
2. 调用 routing.BuildAuthorizedRouteSet 生成授权路由集
3. PreflightProbe 探测 backend
4. 对每个 enabled instance：
   a. firewallInstanceSpecFromConfig 生成 spec
   b. host 实例：resolveEndpointServices 解析 EndpointACL
   c. buildFirewallPolicyInput 组装 planner 输入
   d. firewall.BuildDesiredState 生成期望状态
   e. 选择 driver（nft / iptables / dry-run）
   f. driver.ListOwned 读取当前 owned 对象
   g. driver.Plan 计算 diff
   h. driver.Apply 应用
   i. 记录 generation、policy_hash、owned_objects 到 reconcile state
5. commitFirewallReconcileResult 持久化结果
```

### 6.3 状态持久化

每个 instance 的 reconcile 结果持久化到 state：

```go
// internal/state/firewall.go
type FirewallReconcileInstance struct {
    Generation   uint64 `json:"generation,omitempty"`
    LastRunUnix  int64  `json:"last_run_unix,omitempty"`
    LastError    string `json:"last_error,omitempty"`
    PolicyHash   string `json:"policy_hash,omitempty"`
    OwnedObjects int    `json:"owned_objects,omitempty"`
}
```

> **注意**：当前 `Generation` 在 `NFTDriver` / `IPTablesDriver` / `DryRunDriver` 中均返回固定值 `1`，未实现真正的 generation 递增。

---

## 7. Debug 与诊断

### 7.1 higgs debug firewall

```bash
higgs debug firewall
```

输出每个 instance 的期望规则、owned 对象、reconcile 状态、backend 选择等信息。实现见：

- `internal/inspect/firewall.go`：构造 debug 视图
- `internal/inspect/text/firewall.go`：文本化输出
- `app/higgs/debug_firewall.go`：CLI 注册

### 7.2 higgs debug preflight

```bash
higgs debug preflight
```

输出 backend 探测结果：`nft` 是否可用、`iptables` 是否可用、`CAP_NET_ADMIN` 状态等。

### 7.3 单元测试与 smoke

- `pkg/firewall/*_test.go`：planner 与 driver 单元测试。
- `pkg/firewall/root_smoke_test.go`：需要 root / netns 的 backend smoke 测试。
- `app/higgs/firewall_test.go`：daemon 级 firewall 测试。

---

## 8. 已知限制与实现缺口

以下条款均以当前代码为准，与 `docs/phase6-firewall-design.md` 存在差异或尚未完成：

| 项 | 设计文档期望 | 当前实现 | 影响 |
|---|---|---|---|
| Hook 规则 | `jump <admin_chain>` | 把 hook chain 名填进 `IfaceIn`，渲染成 `iifname "<chain>" jump` | **管理员 hook 无法生效** |
| Invalid drop | overlay input 开头 drop invalid | 未生成 | 基础安全规则不完整 |
| Established/related conntrack | 基于 `ct state` 匹配 | 只生成 comment 为 "established related" 的 accept 规则，无 `ct state` | 语义退化为全 accept |
| Host hooks | host pre/post input/prerouting hook | host 规则未使用任何 hook | 未实现 |
| `peer_authorized_v4/v6` set | 按 peer 分组的前缀集合 | 未实现 | 无按 peer 分组 |
| Backend 探测粒度 | 检测 netlink API、`CAP_NET_ADMIN`、host NAT hook、ipset | 仅检测 `nft`/`iptables` 命令，`CAP_NET_ADMIN` 用 `nft list tables` 近似 | 探测较粗糙 |
| netlink API | nftables 优先使用 netlink | 实际使用 `nft` CLI | 实现方式不同 |
| Generation 递增 | 每次 apply 递增 | 各 driver 返回 `Generation: 1` | 无法按 generation 区分历史 |
| 停止清理 | shutdown 时回滚 owned rules | 停止时未调用 `DeleteStale` | daemon 退出后规则残留 |
| 周期 reconcile timer | 设计建议有周期 timer | 定义了 `defaultFirewallReconcileInterval` 但主循环未调度 | 只靠事件触发 |
| 冲突检测 | 检测非 Higgs 规则冲突 | `MergeConflicts` 直接返回 `nil` | 冲突检测未实现 |
| 优先级配置 | `priority.filter` / `priority.nat` | 未实现 | chain 优先级不可配置 |
| `AllowPeers`/`DenyPeers` | 按 peer zone 过滤 transit | 字段存在但**未实际使用** | 仅前缀过滤生效 |
| 命名约定 | 建议 `HIGGS-H2-INPUT` | 实际 `higgs_h2_INPUT` | 风格差异 |

### 8.1 Hook 语法问题详解

当前 overlay planner 生成的 hook 规则形如：

```go
// pkg/firewall/planner.go:142-143
addRule(ChainInput, Rule{Action: "jump", Comment: "pre_input hook", IfaceIn: spec.Hooks.PreInput})
```

`IfaceIn` 被后端渲染为接口匹配（`iifname`），而不是 `jump` 的目标 chain。因此 hook 规则会生成类似：

```text
iifname "higgs_h2_pre_user" jump
```

这是错误语法：既把 chain 名当接口名，又缺少 jump 目标。需要修复 planner 增加独立的 jump target 字段，并调整 backend 渲染逻辑。

### 8.2 使用建议

- 生产环境建议显式配置 `backend: nft` 或 `backend: iptables`，避免 `auto` 在命令缺失时落入 dry-run 而不自知。
- host 实例在 `ipsec.port_mode=range` 时默认启用 redirect grace；若使用固定端口，可关闭 `redirect_grace`。
- 不要依赖 hook 做关键安全策略，等待 hook 语法修复。
- daemon 升级或停止后，建议手动检查并清理残留的 Higgs-owned table/chain（`nft list tables` 或 `iptables -L | grep higgs_`）。
