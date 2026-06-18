# Phase 6.3 Firewall Rule Sync Design

## 1. 目标

Phase 6.3 的防火墙不是一个独立的“机器全局防火墙管理器”，而是 Higgs overlay data-plane 的安全边界执行器。它需要把已经通过 Zone trust chain 验证的 IPAM、route announcement、peer/link state、revocation state 和本地配置策略，收敛成可审计、可回滚的 Linux 防火墙规则。

主要目标：

- 在 overlay/data-plane netns 内默认 drop 未授权流量，只放行已授权的 overlay prefix、BIRD/Babel 控制流量、健康检查和本地显式开放服务。
- host netns 只管理 Higgs 必须拥有的入口规则，例如 IKE/NAT-T 端口 allow、端口 rotate 的 DNAT/redirect grace；不接管 host 全局防火墙。
- 防火墙策略与 BIRD forwarding policy 使用同一份来源，避免“路由允许但防火墙阻断”或“路由不允许但防火墙放行”。
- 所有规则都必须有 Higgs owner 边界，daemon 只增删自己拥有的 table/chain/set/rule。
- nftables 优先，iptables/ip6tables 作为老系统兜底；backend 选择必须可 preflight、可 dry-run、可诊断。

非目标：

- 第一版不实现通用主机防火墙产品能力，不管理 SSH、Docker、Kubernetes、发行版默认规则等非 Higgs 规则。
- 第一版不把自定义管理员规则内联进 Higgs 生成器；只提供 hook chain 和顺序约定。
- 防火墙不承担 IPsec SA 平滑切换语义；SA 生命周期仍由 StrongSwan/VICI reconcile 管理。

## 2. 边界模型

Higgs 同时涉及两个网络命名空间层面：

1. **overlay/data-plane netns**：XFRM interface、BIRD、veth upstream 的主要数据面所在位置。默认配置中的 `h2` 属于这一类。
2. **host netns**：外部 underlay 入口、StrongSwan/charon 监听端口、可能的 DNAT/redirect grace 所在位置。

防火墙主策略应放在 overlay/data-plane netns。host 侧只做最小入口处理。

```text
host netns
  ├─ Higgs-owned host ingress allow
  ├─ optional old/current port redirect grace
  └─ non-Higgs firewall rules stay untouched

overlay netns (for example h2)
  ├─ XFRM tunnel interfaces: hgs*
  ├─ BIRD Babel instance
  ├─ optional veth upstream: hgs-upstream*
  └─ Higgs-owned input/forward/output policy
```

这样做的原因：

- overlay 的路由和业务前缀已经按 netns 隔离，防火墙跟随该隔离边界最自然。
- host 可能已有管理员、发行版、容器运行时管理的防火墙，Higgs 不应默认覆盖。
- port rotate / NAT-T 入口规则无法完全留在 overlay netns，因此 host 能力只保留为明确的独立 plan。

## 3. Owner 与 generation

每个 Higgs 管理的对象必须带 owner 信息：

- `owner_prefix`：默认 `higgs`。
- `instance_id`：如 `h2`、`host-ipsec`。
- `generation`：daemon 每次成功 apply 的 desired-state generation。
- `manager=higgs` 标记：nftables 可用 comment/table 名称表达，iptables 用 chain 名称和 comment 表达。

建议命名：

```text
nft table inet higgs_h2
  set higgs_h2_overlay_v4
  set higgs_h2_overlay_v6
  chain higgs_h2_input
  chain higgs_h2_forward
  chain higgs_h2_output
  chain higgs_h2_pre_user
  chain higgs_h2_post_user

nft table inet higgs_host
  chain higgs_host_input
  chain higgs_host_prerouting
```

iptables backend 使用类似命名：

```text
HIGGS-H2-INPUT
HIGGS-H2-FORWARD
HIGGS-H2-OUTPUT
HIGGS-HOST-INPUT
HIGGS-HOST-PREROUTING
```

reconcile 原则：

1. 只读取和修改 owner 匹配的对象。
2. 发现非 Higgs 规则冲突时报告错误，不静默覆盖。
3. daemon 重启后先 `ListOwned()`，能匹配当前 desired state 的对象可以 adopt。
4. stale generation 只能在 owner token 匹配时删除。

## 4. 配置模型

建议新增 `firewall.instances[]`，与 `routing.instances[]` 一样以 netns 为主要维度。

```yaml
firewall:
  instances:
    - id: h2
      enabled: true
      mode: managed          # managed | external | disabled
      backend: auto          # auto | nft | iptables | none
      netns: h2
      default_policy: drop   # drop | accept
      owner_prefix: higgs
      priority:
        filter: 0
        nat: -100
      hooks:
        pre_input: higgs_h2_pre_user
        post_input: higgs_h2_post_user
        pre_forward: higgs_h2_pre_forward_user
        post_forward: higgs_h2_post_forward_user
      local_services:
        - proto: tcp
          port: 8080
          sources:
            - 10.42.0.0/16

    - id: host-ipsec
      enabled: true
      mode: managed
      backend: auto
      netns: host
      host_ports:
        ike: true
        natt: true
      redirect_grace:
        enabled: true
```

字段语义：

- `mode=managed`：Higgs 负责 plan/apply/recover owned rules。
- `mode=external`：Higgs 只生成 desired-state 和 dry-run diff，可校验 hook/owner chain 是否存在。
- `mode=disabled` 或 `backend=none`：不生成规则，可用于开发、非 Linux、或管理员完全手工管理场景。
- `default_policy=drop`：推荐生产默认；`accept` 仅用于迁移期或调试。
- `hooks`：管理员自定义 chain 的挂载点。Higgs 创建 hook jump，但不管理 hook chain 内部规则。
- `local_services`：显式开放 overlay netns 内的本机服务入口，避免 input 默认 drop 后服务不可达。

配置 reload 时，daemon 可以热更新 firewall policy；如果 backend、owner_prefix 或 netns 发生变化，必须先 dry-run 展示旧对象清理和新对象创建计划。

## 5. Policy Planner 输入

Firewall planner 不应直接扫描“所有同步到的记录然后放行”。它应消费已经验证过的派生状态：

| 输入 | 来源 | 用途 |
|---|---|---|
| `AuthorizedRouteSet.AllAssignments` | `pkg/routing/authorization.go` | 有效 IPAM assignment，包含 anycast/shared assignment |
| route announcements | `AuthorizedRouteSet.Routes` | 哪些 prefix 可以被哪些 Zone 宣告 |
| local assigned prefixes | assignment 中 `AssignedTo == managed_zone` | 本节点服务和 static route 放行 |
| live link state | `LinkInstances` / desired links / SA observations | 哪些 peer/interface 当前应允许流量 |
| revocation state | Zone tombstone / revoked subtree | 删除对应 set entries 和 exceptions |
| routing forwarding policy | 新增 record/config，见第 8 节 | 是否允许本节点作为 transit 转发 |
| local firewall config | `firewall.instances[]` | backend、hook、local service、default policy |

注意：旧的 `TunnelAllowedIPs` 不再作为唯一来源。StrongSwan/XFRM 的 traffic selector 可以较宽，真正的业务 prefix 授权由 IPAM + route authorization + firewall 共同约束。

## 6. overlay netns 规则结构

overlay netns 至少需要三类 chain：

```text
input:
  lo accept
  jump user-pre-input
  BIRD/Babel control traffic accept
  health/keepalive accept
  local_services accept
  established,related accept
  jump user-post-input
  default drop

forward:
  established,related accept
  jump user-pre-forward
  XFRM -> XFRM authorized transit accept
  XFRM -> veth upstream authorized egress accept
  veth upstream -> XFRM authorized ingress accept
  XFRM -> local assigned prefixes accept when policy allows
  jump user-post-forward
  default drop

output:
  lo accept
  BIRD/Babel control traffic accept
  health/keepalive accept
  local assigned/source prefixes accept
  default accept or drop according to policy
```

### 6.1 Prefix sets

Planner 生成以下集合：

- `local_assigned_v4/v6`：本节点被分配的业务前缀。
- `mesh_authorized_v4/v6`：所有已授权并有效的 mesh 业务前缀。
- `peer_authorized_v4/v6`：按 peer/subtree 分组的授权前缀，可用于更细的接口约束。
- `revoked_v4/v6`：可选审计集合；正常 apply 后不应继续被引用。

anycast/shared assignment 需要保留多个 assignment entry 的来源信息。set 可以按 prefix 去重，但 debug 输出必须能显示多个 owner Zone。

### 6.2 Interface roles

不同接口角色必须分开处理：

- `xfrm_tunnel`：如 `hgs*`，mesh peer 之间的数据面。
- `upstream_veth`：如 `hgs-upstream*`，overlay netns 与 host/main network 的出入口。
- `loopback`：本机服务。
- `underlay`：通常不在 overlay netns 内处理；host 入口另见第 9 节。

跨 `upstream_veth` 的流量必须有显式 policy。默认不把 mesh 学到的所有路由直接暴露给主网络。

## 7. Hook 设计

Hook 是管理员的扩展点，不能破坏 Higgs owner 边界。

推荐提供这些 hook：

- `pre_input`
- `post_input`
- `pre_forward`
- `post_forward`
- `pre_output`
- `post_output`
- `host_pre_prerouting`
- `host_post_prerouting`
- `host_pre_input`
- `host_post_input`

执行顺序：

1. Higgs 基础安全规则，例如 invalid drop、loopback accept。
2. `pre_*` hook。
3. Higgs authorized allow/drop 规则。
4. `post_*` hook。
5. 默认 policy。

hook chain 内部由管理员或外部系统管理。Higgs 只负责确保 jump 存在，并在 `debug firewall` 中显示 hook 是否存在、是否为空、是否缺失。

## 8. Forwarding Policy 与 BIRD 联动

当前 BIRD/Babel 的多跳传播能力意味着“学到路由”不等于“本节点应该替别人转发”。因此 Phase 6.3 需要引入明确的转发意图。

建议新增本地配置或 signed record：

```json
{
  "version": 1,
  "transit": false,
  "allow_prefixes": ["10.42.0.0/16"],
  "deny_prefixes": [],
  "allow_peers": ["*.catofes."],
  "deny_peers": [],
  "metric_hint": 200
}
```

第一版可以先用本地配置；后续再升级为 `routing/forwarding` signed record。语义：

- `transit=false`：只宣告本节点 local assigned prefixes，不替其他节点转发 learned routes。
- `transit=true`：允许在 policy 范围内转发 learned routes。
- `allow_prefixes/deny_prefixes`：约束可转发业务前缀。
- `allow_peers/deny_peers`：约束可作为来源或目的的 Zone/subtree。
- `metric_hint`：供 BIRD metric/rxcost 调整使用。

BIRD 与 firewall 必须共享同一份 forwarding policy：

```text
ForwardingPolicy
   ├─ BIRD export/import/static route policy
   └─ Firewall forward chain policy
```

规则：

- BIRD 不允许宣告的 transit path，firewall 也不得放行。
- BIRD 允许的 transit path，firewall 必须放行对应 prefix/interface 组合。
- 非 transit 节点的 firewall forward chain 默认 drop XFRM-to-XFRM transit。
- veth upstream 是否允许转发 learned routes，必须单独配置，不能随 `transit=true` 自动打开。

后续可以通过 gossip 增加“源节点不希望某些中继转发自己的路由”的控制信号，用于规避质量差、费用高或不可信链路。第一版先不做实时 gossip hint。

## 9. host 入口与 DNAT/redirect grace

host 侧只处理 Higgs 必须触碰的入口：

- IKE UDP 500。
- NAT-T UDP 4500 或配置的 current NAT-T port。
- `ipsec/ports.previous[]` grace 窗口内的旧 advertised port。
- 可选 TCP/UDP fallback transport 入口，后续 Phase 7 再扩展。

端口 rotate 场景：

```text
remote peer dials old advertised port
          │
          ▼
host prerouting redirect/DNAT grace
          │
          ▼
current charon listen port
```

边界：

- redirect grace 只解决 responder 入口端口兼容，不保证 CHILD_SA 无中断迁移。
- old/current port 的有效窗口必须来自 verified `ipsec/ports` record 和本地 port planner。
- grace 结束后必须删除旧端口规则。
- 如果 host 上已有非 Higgs owner 规则占用相同端口或 chain priority，apply 必须失败或降级为 dry-run，不覆盖。
- host rule 应绑定本地配置的 listen address / advertise address / protocol，避免无意开放全部地址。

### 9.1 为什么只需要 DNAT/redirect，不需要 SNAT/MASQUERADE（待 root smoke 验证）

> **状态：分析阶段，尚未在 root/container smoke 中实际验证。**

当前设计只对**入方向**（prerouting）做 DNAT/redirect grace，不对**出方向**做 SNAT/MASQUERADE。原因如下：

**StrongSwan (IKEv2/IPsec)：**

- **出方向** IKE 包由 charon 发起，源端口是 charon 选择的**临时本地端口**（通常不是 500，由内核/charon 随机选择）。
- 远端 peer 看到的是真实的源 IP + 临时源端口，不需要翻译。
- **入方向** IKE 包由远端 peer 发起，目标端口是本节点公告的 advertised port（500/4500 或 range 端口）。
- 端口 rotate 时，远端 peer 可能在 grace 窗口内仍向旧 advertised port 发包；本节点用 DNAT/redirect 把旧端口流量转到当前 charon 监听端口。
- 因此只需要 prerouting DNAT/redirect，不需要 postrouting SNAT。

**WireGuard：**

- **出方向** WG 包由内核发起，源端口是内核选择的临时端口。
- 远端 peer 同样看到真实源 IP + 临时端口。
- **入方向** WG 包目标端口是本节点公告的 listen port。
- 端口 rotate 时同理只需要 prerouting redirect。

**验证计划：**

- root/container smoke 中端口 rotate 时，抓包确认：
  1. 出方向包源端口确实是临时端口，不是 advertised port。
  2. DNAT/redirect 只影响入方向到旧 advertised port 的包。
  3. 不存在需要 SNAT 的场景。
- 如果发现某些 NAT 环境下出方向也需要端口翻译（例如对称 NAT 需要固定源端口），再补充 SNAT/MASQUERADE 规则。

### 9.2 WireGuard 端口轮换准备

防火墙模型已为 Phase 7 WireGuard 端口轮换做好准备：

- `HostPortConfig` 支持 `WG bool` 字段，控制是否开放 WireGuard 入口端口。
- `FirewallInstanceSpec` 支持 `WGPort uint16` 字段（默认 51820）。
- `FirewallPolicyInput` 支持 `AdvertisedPreviousWGPorts []uint16` 字段。
- `buildHostRules` 已实现 WireGuard ingress 规则生成和 WireGuard redirect grace 逻辑。

Phase 7 实现 WireGuard 端口轮换时，只需要：
1. 在 WireGuard 的 gossip record（如 `wireguard/ports`）中发布 current/previous 端口。
2. 在 daemon `buildFirewallPolicyInput` 中从该 record 提取 previous WG ports 填入 `AdvertisedPreviousWGPorts`。
3. planner 已自动处理 WG redirect grace。

## 10. Backend 兼容性

### 10.1 nftables

nftables 是主 backend。优先使用 netlink API，避免依赖解析 `nft` CLI 文本输出。

能力要求：

- 创建 table/chain/set/rule。
- 支持 inet family。
- 支持 IPv4/IPv6 prefix set。
- 支持 filter hook：input、forward、output。
- host 侧支持 nat prerouting/output redirect 或 dnat。
- 支持 comment 或等价 metadata 用于 owner/generation。

### 10.2 iptables/ip6tables

iptables 是兼容 backend，用于老系统或 nftables netlink 不可用场景。

限制：

- 需要同时管理 IPv4 和 IPv6。
- iptables-nft shim 与 nft backend 不应混用同一 owner。
- set 能力较弱时可以使用 ipset；没有 ipset 时只生成小规模规则或进入 degraded。
- 第一版只覆盖 filter 和 host NAT 所需的最小规则，不追求 nft backend 的完整表达能力。

### 10.3 backend auto

`backend=auto` 探测顺序：

1. nftables netlink 是否可用。
2. 当前 netns 是否有 `CAP_NET_ADMIN`。
3. host nat hook 是否可用。
4. iptables/ip6tables 是否可用。
5. ipset 是否可用。

输出应进入 `higgs debug preflight` 或 `higgs debug firewall`：

```text
firewall:
  backend: nft
  nft_netlink: ok
  iptables: available
  iptables_variant: nft
  cap_net_admin: ok
  netns_h2: ok
  host_nat: ok
  conflicts: []
```

## 11. Driver Interface

建议抽象：

```go
type FirewallDriver interface {
    Preflight(ctx context.Context, spec FirewallInstanceSpec) (FirewallPreflight, error)
    Plan(ctx context.Context, desired FirewallDesiredState) (FirewallPlan, error)
    Apply(ctx context.Context, plan FirewallPlan) (FirewallApplyResult, error)
    ListOwned(ctx context.Context, owner FirewallOwner) (FirewallObservedState, error)
    DeleteStale(ctx context.Context, stale []FirewallObjectRef) error
}
```

数据结构分层：

- `FirewallInstanceSpec`：来自配置。
- `FirewallPolicyInput`：来自 Zone/routing/link/revocation 派生状态。
- `FirewallDesiredState`：backend 无关的期望规则模型。
- `FirewallPlan`：包含 create/update/delete/adopt/noop。
- `FirewallObservedState`：从系统读取的 owner objects。
- `FirewallApplyResult`：成功 generation、部分失败、错误详情。

planner 必须是纯逻辑，可在非 root 单元测试和 dry-run smoke 中运行。

## 12. Reconcile 流程

```text
state/config/link/routing changed
        │
        ▼
BuildAuthorizedRouteSet
        │
        ▼
BuildForwardingPolicy
        │
        ▼
BuildFirewallDesiredState
        │
        ▼
driver.ListOwned
        │
        ▼
Plan diff: adopt/create/update/delete
        │
        ▼
Apply managed objects
        │
        ▼
Persist firewall reconcile snapshot
```

触发时机：

- daemon 启动。
- config reload。
- Zone/record digest 变化。
- route authorization/IPAM assignment/announcement 变化。
- LinkInstance up/down/staged/draining 变化。
- revocation/tombstone 变化。
- port rotate generation 变化。
- 周期 reconcile 兜底。

撤销优先级最高。Zone 或子树 revoked 后，不等待健康检查超时，立即触发 firewall reconcile 删除对应 allow entries、transit entries、rate-limit exceptions 和 host redirect grace。

## 13. Failure 与 rollback

apply 必须可恢复：

- `Plan` 失败：不改变系统规则，记录 last error。
- `Apply` 部分失败：保留旧 generation，可在下一轮继续收敛。
- backend 不可用：如果当前有旧 generation，保持旧规则并进入 degraded；如果没有旧规则，按配置进入 disabled/dry-run 或报错。
- owner 冲突：不覆盖，报告冲突对象。
- netns 不存在：managed netns 可由对应 netns manager 创建；external/path netns 不存在则报错。

daemon state 中应记录：

```json
{
  "backend": "nft",
  "instances": {
    "h2": {
      "generation": 12,
      "last_apply": "2026-06-18T10:00:00Z",
      "last_error": "",
      "owned_objects": 18,
      "policy_hash": "..."
    }
  }
}
```

## 14. Debug 与 dry-run

新增命令：

```bash
higgs debug firewall
higgs debug firewall --netns h2
higgs debug firewall --host
higgs debug firewall --dry-run
higgs debug firewall --json
```

输出应包含：

- backend 和 preflight 状态。
- 每个 instance 的 netns、mode、default policy、owner prefix、generation。
- owned table/chain/set/rule 摘要。
- 当前 policy summary：local prefixes、mesh authorized prefixes、transit enabled/disabled、upstream policy。
- pending diff：将新增、删除、adopt、跳过哪些对象。
- last apply error 和冲突对象。

dry-run 示例：

```text
firewall h2:
  backend: nft
  mode: managed
  default_policy: drop
  create:
    table inet higgs_h2
    set higgs_h2_mesh_v4: 10.42.0.0/16, 10.43.0.0/24
    chain higgs_h2_forward
  delete:
    set entry 10.99.0.0/24 reason=revoked zone node-b.catofes.
  keep:
    chain higgs_h2_pre_user reason=external hook
```

## 15. 验证计划

### 15.1 单元测试

- policy planner：IPAM assignment、route announcement、revocation、anycast/shared assignment。
- owner/stale 计算：只删除 owner 匹配对象。
- hook ordering：pre/post hook 顺序稳定。
- forwarding policy：BIRD export policy 与 firewall forward policy 一致。
- backend auto：nft、iptables、none 的选择和降级。
- host redirect grace：old/current port 窗口计算。

### 15.2 dry-run smoke

新增目标建议：

```bash
make firewall-dry-run-smoke
```

覆盖：

- 无 root 环境下生成 overlay netns filter plan。
- 生成 host NAT/redirect grace plan。
- 撤销节点后 plan 删除对应 allow set entry。
- backend 不可用时给出明确 preflight/degraded 输出。

### 15.3 root/container smoke

新增目标建议：

```bash
make firewall-container-smoke
```

覆盖：

- 创建 overlay netns + veth + BIRD。
- 默认 drop 非授权 prefix。
- 合法 assigned/announced prefix 可达。
- 非 transit 节点不转发第三方 learned route。
- transit 节点按 policy 转发。
- revocation 后对应流量立即断开。
- port rotate redirect grace 生效，grace 结束后旧端口失效。

## 16. 与现有文档的关系

- `todo.md` Phase 6.3 是可执行任务清单。
- `docs/phase6-ipam-design.md` 定义 IPAM assignment、route announcement 和 anycast/shared assignment，Firewall planner 消费其派生结果。
- `docs/phase5-7-per-netns-bird-design.md` 定义 per-netns BIRD 和 route authorization 边界，Firewall policy 必须与 BIRD policy 共用 forwarding decision。
- `docs/design.md` 保持总体架构与状态概览，本文件是 Phase 6.3 的细化设计。
