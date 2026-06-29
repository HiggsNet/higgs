# Higgs 测试入口

本文整理源码树里的验证命令和 smoke 目标。它面向开发、CI 和系统集成验证；日常部署、排障和恢复操作见 `docs/new/operations.md`。

## 基础验证

常规开发验证：

```bash
make check
```

`make check` 会执行格式化、`go vet`、`go test ./...` 和构建。Makefile 默认使用 `/tmp/higgs-gocache` 与 `/tmp/higgs-gomodcache`，便于在受限环境里复用缓存。

只构建：

```bash
make build
```

只运行 Go 测试：

```bash
make test
```

## 轻量 Smoke

轻量 smoke 不要求 root、真实 StrongSwan、真实 BIRD 或系统 firewall 数据面。部分目标会启动本地 UDP/TCP socket，因此受限 sandbox 里可能失败；失败时先区分产品回归和运行环境限制。

常用轻量 smoke：

```bash
make join-smoke
make phase2-smoke
make phase2-run-smoke
make phase3-daemon-smoke
make object-pull-smoke
make ipsec-dry-run-smoke
make routing-dry-run-smoke
make firewall-dry-run-smoke
make observer-smoke
```

常用目标说明：

| 目标 | 说明 |
|------|------|
| `join-smoke` | 不启动 UDP，只验证 root admin -> `catofes.` -> leaf node 的 join、bundle、密钥和本地 trust chain。 |
| `phase2-smoke` | 双节点手动同步，验证 A/B signed zone 和 record 双向收敛。 |
| `phase2-run-smoke` | 使用长期运行同步入口验证重连、恢复和后台收敛路径。 |
| `phase3-daemon-smoke` | 验证 CLI 通过 daemon control socket 写入、本机单 writer 和 daemon 驱动同步。 |
| `object-pull-smoke` | 验证大 record 不塞进超大 UDP 包，而是通过 object pull 收敛。 |
| `ipsec-dry-run-smoke` | 验证 IPsec planner、dry-run apply、fake driver reconcile 和 debug/read model 边界。 |
| `routing-dry-run-smoke` | 验证 route authorization、BIRD 配置生成和 routing dry-run reconcile。 |
| `firewall-dry-run-smoke` | 验证 firewall 配置解析、规则规划和 dry-run reconcile。 |
| `observer-smoke` | 验证 Observer API、SSE、static UI 和相关 inspect 输出。 |

完整轻量集合可以直接运行：

```bash
make smoke-all
```

`make smoke-all` 当前展开为：

```bash
make join-smoke
make phase1-smoke
make phase2-smoke
make phase2-run-smoke
make phase3-daemon-smoke
make phase3-daemon-fallback-smoke
make admin-daemon-smoke
make multi-node-smoke
make chain-relay-smoke
make discovery-smoke
make reflector-smoke
make bootstrap-join-smoke
make nat-observed-smoke
make nat-daemon-observed-smoke
make delegation-revoke-smoke
make object-pull-smoke
make chunk-fallback-smoke
make ipsec-policy-smoke
make ipsec-dry-run-smoke
make routing-dry-run-smoke
make firewall-dry-run-smoke
make peer-lifecycle-smoke
make revocation-cleanup-smoke
make observer-smoke
```

补充目标说明：

| 目标 | 说明 |
|------|------|
| `phase1-smoke` | 最小双 peer gossip 收敛，重点覆盖 summary/catalog fetch 基础路径。 |
| `phase3-daemon-fallback-smoke` | 验证 daemon 不在线时 CLI 直接写 DB 的开发/恢复 fallback，下一次 daemon 能加载并传播。 |
| `admin-daemon-smoke` | 验证管理端 daemon 运行时，delegation issue/revoke 经 control socket 写入。 |
| `multi-node-smoke` | 三节点传递同步，覆盖非直连节点通过中间 peer 收敛。 |
| `chain-relay-smoke` | 四节点链式拓扑，验证 relay fanout 能减少等待完整周期的时间。 |
| `discovery-smoke` | 验证 signed endpoint discovery 和 peer 地址更新。 |
| `reflector-smoke` | 验证 public IP reflector endpoint 路径。 |
| `bootstrap-join-smoke` | 验证新节点通过 bootstrap admission 加入并同步。 |
| `nat-observed-smoke` | 验证 NAT/outbound-only 场景下的 observed UDP path。 |
| `nat-daemon-observed-smoke` | daemon 版 NAT observed path 验证。 |
| `delegation-revoke-smoke` | 验证 delegation revocation 传播和下游状态失效。 |
| `chunk-fallback-smoke` | 验证 TCP object pull 不可达时，UDP chunk fallback 能补齐大对象。 |
| `ipsec-policy-smoke` | 验证 IPsec mesh policy URI 解析和 planner rule 匹配。 |
| `peer-lifecycle-smoke` | 验证 peer status、revoked peer 阻断和 peer lifecycle debug 输出。 |
| `revocation-cleanup-smoke` | 验证 deny-first revocation cleanup、peer cache 清理和 IPsec link teardown dry-run。 |

## 真实数据面 Smoke

真实数据面 smoke 会触碰宿主网络、network namespace、XFRM、StrongSwan/charon、BIRD、nftables 或 iptables。它们默认不放进 `make check`，也不放进 `make smoke-all`。

运行前先跑对应 preflight：

```bash
make ipsec-xfrm-preflight
sudo make ipsec-xfrm-smoke
make ipsec-xfrm-container-smoke

make bird-babel-preflight
sudo make bird-babel-smoke
make bird-babel-container-smoke

sudo make firewall-smoke
make firewall-container-smoke
sudo make revocation-data-plane-smoke
make revocation-data-plane-container-smoke
```

真实数据面目标说明：

| 目标 | 说明 |
|------|------|
| `ipsec-xfrm-preflight` | 检查 root/netns/XFRM/StrongSwan/VICI 等前置条件，避免半途创建系统资源后失败。 |
| `ipsec-xfrm-smoke` | 在真实系统能力下验证 StrongSwan/VICI + XFRM interface、daemon reconcile、SA 观测和 tunnel ping。 |
| `ipsec-xfrm-container-smoke` | 在 privileged container 中运行 StrongSwan/XFRM smoke，适合隔离宿主环境差异。 |
| `bird-babel-preflight` | 检查 root/netns/BIRD/Babel 相关前置条件。 |
| `bird-babel-smoke` | 验证 managed BIRD/Babel lifecycle、邻居和路由学习等真实 routing 数据面。 |
| `bird-babel-container-smoke` | 在 privileged container 中运行 BIRD/Babel smoke。 |
| `firewall-smoke` | 使用真实 nftables/iptables backend 验证 firewall 规则 apply 和清理。 |
| `firewall-container-smoke` | 在 privileged container 中运行 firewall 数据面 smoke。 |
| `revocation-data-plane-smoke` | 组合 firewall、BIRD 和 StrongSwan 的 revocation 数据面验证，需要 root。 |
| `revocation-data-plane-container-smoke` | 在 privileged container 中运行组合 revocation 数据面验证。 |

## 失败判断

smoke 失败时先看目标属于哪一层：

- `join-smoke` 这类纯本地目标失败，通常优先查 trust chain、bundle、record 写入和本地状态库。
- gossip smoke 失败，先看本地 UDP/TCP socket 是否被环境禁止，再看各节点日志和 `sync status`。
- object pull / chunk fallback 失败，区分 TCP object pull、UDP chunk repair 和外部端口阻断工具是否真的可用。
- dry-run 目标失败，通常是代码或测试 fixture 回归，不应归因于宿主系统能力。
- root/container smoke 失败，先看 preflight、容器权限、charon/VICI、BIRD、nftables/iptables 和 netns/XFRM 诊断输出。

如果一个 smoke 目标开始频繁失败，不要只按名称判断它过期。先用日志、状态库、generated config、系统规则和 runtime counters 判断是产品 bug、测试夹具不适合当前流程，还是运行环境能力不足。
