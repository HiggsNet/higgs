# StrongSwan / XFRM 交互测试方案

这份 runbook 用于 Phase 4 的系统集成验证。它刻意不放进
`make smoke-all`：该流程会接触宿主机网络、StrongSwan/charon、VICI、XFRM
interface，以及 root 或 `CAP_NET_ADMIN` 权限。

## 1. 前置检查

运行：

```sh
make ipsec-xfrm-preflight
```

真实 `ipsec-xfrm-smoke` 创建任何资源前，必须先通过 preflight。它检查：

- Linux 内核是否支持 XFRM。
- 当前进程是否是 root，或是否具备有效 `CAP_NET_ADMIN`。
- VICI socket 是否存在；默认是 `/run/charon.vici`，可用 `HIGGS_VICI_SOCKET` 覆盖。
- `ip`、`swanctl`、`charon` 是否可用。
- `ip link type xfrm` 是否可用。
- 当 `HIGGS_IPSEC_CHECK_UDP=1` 时，额外检查 IKE/NAT-T UDP 端口是否可绑定。

如果 preflight 失败，先修宿主机环境。不要让半途失败的 smoke 留下 connection 或
interface。

## 2. 最小手工 StrongSwan 健康检查

在接入 Higgs daemon reconcile 前，先确认宿主机能跑最小 route-based IPsec 链路：

1. 启动或 reload StrongSwan，并确认 VICI 可用：

```sh
swanctl --stats
```

2. 确认 XFRM interface 支持：

```sh
ip link help xfrm >/dev/null
```

3. 在 Higgs 之外创建一次性 namespace/interface 组合：

```sh
ip netns add h2-a
ip link add hgs-test-a type xfrm if_id 4242
ip link set hgs-test-a netns h2-a
ip netns exec h2-a ip addr replace fd00:1200::1/64 dev hgs-test-a
ip netns exec h2-a ip link set dev hgs-test-a up
ip netns exec h2-a ip link show hgs-test-a
```

清理：

```sh
ip netns exec h2-a ip link delete hgs-test-a || true
ip netns delete h2-a
```

这一步用于把 kernel/iproute2 问题和 Higgs 控制面问题分开排查。

## 3. Higgs Provider Apply 检查

第一个真正面向 Higgs 的检查，是先不接 VICI，只验证 XFRM/netns apply：

- 从 verified `ipsec/*` records 和本地 `LinkGroupSpec` 构造 `TransportLinkSpec`。
- 使用带默认 `overlay.default_netns` 的 `SystemXFRMDriver`；`ipsec.default_netns` 仅作为旧配置兼容别名。
- provider 预期按这个顺序执行：
  `EnsureNamespace -> LoadConnection -> EnsureInterface -> AssignAddress`.
- 真实 XFRM driver 只会在 `create=true` 时创建 named namespace；`host` 和 path
  namespace 必须已经存在。对于 path namespace，第一版 provider 建议先 bind 到
  `/var/run/netns` 下，再用 `kind=name` 管理。

执行任何变更前必须先记录 apply plan。失败时 daemon 应把 link 标记为
`degraded` 或 `error`，记录失败 operation，并且不能继续执行后续步骤。

## 4. 完整双节点 Smoke 形态

未来的 `make ipsec-xfrm-smoke` 只应在 preflight 通过后运行：

1. 创建两个 Higgs 数据目录和两个 named namespace，例如 `h2-a` 和
   `h2-b`.
2. 完成 root -> `catofes.` -> `node-a.catofes.` / `node-b.catofes.` join。
3. 每个节点发布已签名的 `ipsec/profile`、`ipsec/addresses`、`ipsec/ports`
   和 `ipsec/transport-key` records。
4. 启动两端 daemon，让 gossip 收敛。
5. link planner 从 verified active state 加本地 `LinkGroupSpec` 推导对称的
   `TransportLinkSpec`；不应需要为每个 peer 手写 link。
6. StrongSwan provider 通过 VICI 加载 connection 和 secret。`swanctl` 只作为人工
   debug / 交叉检查工具。
7. XFRM provider 创建 interface，移动到目标 namespace，并分配 tunnel address。
8. 断言 `LinkInstance` 进入 `up`。
9. 断言 VICI 和 `swanctl --list-sas` 能看到匹配的 IKE_SA/CHILD_SA identity、
   child name、reqid/if_id 和 endpoint。
10. 断言数据面能通过 tunnel IP 互相 `ping`。

失败输出应始终包含 daemon logs、VICI SA list、`swanctl --list-sas`、`ip link`、
`ip xfrm state`、`ip xfrm policy`、`ip route`，以及对应 namespace 内的
`ip addr`。

## 5. 恢复与撤销

happy path 通过后继续覆盖：

- 重启任意一端 daemon。daemon 必须 adopt 或 repair 已有 StrongSwan/XFRM state，
  不能重复创建资源。
- 从父 Zone 撤销其中一个 peer。另一端 daemon 必须 terminate IKE_SA/CHILD_SA、
  unload connection/secret、删除 XFRM interface 和 address，并阻止 reconnect/backoff
  再次把它拉起。

Phase 4 只做到 peer-to-peer tunnel link 可用。Babel routing 和 prefix authorization
仍属于 Phase 5。
