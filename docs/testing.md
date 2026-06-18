# Higgs 测试指南

本文档描述 Higgs 项目的测试分层、各类 smoke 测试的用途、运行方式和环境要求。

## 测试分层

```
make check
├── fmt        — go fmt
├── vet        — go vet
├── test       — go test ./...（单元测试 + 集成测试）
└── build      — 编译二进制

make smoke-all（不要求 root 的 smoke）
├── join-smoke               — 离线信任链生成/导入
├── phase1-smoke             — 双节点 UDP gossip 单向同步
├── phase2-smoke             — 双节点双向同步收敛
├── phase2-run-smoke         — sync run 自动重连/恢复
├── phase3-daemon-smoke      — daemon 控制面写入+同步
├── phase3-daemon-fallback-smoke — daemon 离线时直写 DB 恢复
├── admin-daemon-smoke       — 管理端 daemon 签发/撤销 delegation
├── multi-node-smoke         — 三节点传递同步
├── chain-relay-smoke        — 四节点链式 relay fanout
├── discovery-smoke          — endpoint record 动态发现
├── reflector-smoke          — public IP reflector
├── bootstrap-join-smoke     — 新节点首次接入
├── nat-observed-smoke       — NAT 后节点 observed UDP path
├── nat-daemon-observed-smoke — daemon 模式 NAT observed path
├── delegation-revoke-smoke  — delegation 撤销传播收敛
├── object-pull-smoke        — 大对象 TCP object pull
├── chunk-fallback-smoke     — TCP 不可达时 UDP chunk fallback
├── ipsec-policy-smoke       — IPsec mesh policy URI rule planner
├── ipsec-dry-run-smoke      — IPsec planner + fake driver reconcile
├── routing-dry-run-smoke    — Phase 5 路由授权 + BIRD config 生成
├── firewall-dry-run-smoke   — Phase 6.3 防火墙 planner + backend 选择 dry-run
├── peer-lifecycle-smoke     — Phase 6.4 peer 生命周期派生状态机
└── revocation-cleanup-smoke — Phase 6.5 撤销影响计算 + deny-first 清理

需要 root / privileged container（默认不在 smoke-all 中）
├── ipsec-xfrm-smoke         — 真实 StrongSwan/XFRM/netns/charon
├── ipsec-xfrm-container-smoke — 自动 privileged container 版
├── bird-babel-smoke         — 真实 BIRD/Babel/netns
└── bird-babel-container-smoke — 自动 privileged container 版
```

## 非 root smoke 测试（`make smoke-all`）

所有 `smoke-all` 目标都不需要 root 权限，只依赖本地 loopback UDP/TCP socket。
它们适合在 CI、开发机和受限环境中运行。

### 信任链与同步

| 目标 | 说明 |
|------|------|
| `make join-smoke` | 离线生成 root → catofes → node-b delegation chain |
| `make phase1-smoke` | A/B 双节点单向 gossip 同步：B serve, A sync once |
| `make phase2-smoke` | A/B 双节点双向同步：serve + sync once 两轮收敛 |
| `make multi-node-smoke` | A/B/C 三节点 transitive sync：B → A → C |

### 长期运行 / Daemon

| 目标 | 说明 |
|------|------|
| `make phase2-run-smoke` | sync run 模式：B 离线后重启，A 自动收到新 record |
| `make phase3-daemon-smoke` | daemon 控制面：CLI 通过 control socket 写 record，daemon 同步 |
| `make phase3-daemon-fallback-smoke` | daemon 不存在时 CLI 直接写 DB，后续 daemon 加载 |
| `make admin-daemon-smoke` | root/catofes daemon 签发 delegation bundle、撤销 node-b |

### Relay / Discovery

| 目标 | 说明 |
|------|------|
| `make chain-relay-smoke` | A-B-C-D 链式拓扑 relay fanout，验证 D 收到 A 的 record |
| `make discovery-smoke` | B 通过 A 同步发现 C 的 signed endpoint record |
| `make reflector-smoke` | public IP reflector 查询 + endpoint 候选生成 |
| `make bootstrap-join-smoke` | 新节点 B 只配置 bootstrap A，验证首次接入不死锁 |

### NAT / Observed Path

| 目标 | 说明 |
|------|------|
| `make nat-observed-smoke` | B 禁用 endpoint 发布，A 通过 observed UDP path 回复 |
| `make nat-daemon-observed-smoke` | daemon 模式下的 NAT observed path 传播 |

### 撤销 / 安全

| 目标 | 说明 |
|------|------|
| `make delegation-revoke-smoke` | catofes 撤销 node-b 后 A/C verify 失败、endpoint 移除 |

### 大对象 / MTU

| 目标 | 说明 |
|------|------|
| `make object-pull-smoke` | 3000-byte record 通过 TCP object pull 传输 |
| `make chunk-fallback-smoke` | TCP 不可达时 UDP chunk fallback 传输 |

### IPsec / Routing / Phase 6 Dry-Run

| 目标 | 说明 |
|------|------|
| `make ipsec-policy-smoke` | MeshPolicy URI rule 解析 + connect/deny rule planner |
| `make ipsec-dry-run-smoke` | IPsec planner + fake driver 完整 reconcile（不碰 root） |
| `make routing-dry-run-smoke` | 路由授权 + IPAM + BIRD config 生成 |
| `make firewall-dry-run-smoke` | Phase 6.3 防火墙 planner + nft/iptables driver + config reconcile dry-run |
| `make peer-lifecycle-smoke` | Phase 6.4 peer 生命周期派生状态机、阈值、`debug peers` |
| `make revocation-cleanup-smoke` | Phase 6.5 撤销影响计算、deny-first flush、`debug revoke-impact` |

### 调试命令

以下只读命令通过 control socket 与 daemon 交互：

```bash
higgs debug firewall          # backend、规则、generation、last error
higgs debug peers             # peer 派生生命周期状态
higgs debug revoke-impact     # 所有 revoked zone 的影响范围
higgs debug revoke-impact <zone>  # 单个 zone
```

## Root / Privileged Container Smoke

以下 smoke 测试需要真实的 Linux root 权限、named netns、XFRM 接口和/或
BIRD/StrongSwan 运行时。它们**不包含在 `make smoke-all` 中**。

### IPsec / XFRM / StrongSwan

**前置检查：**
```bash
make ipsec-xfrm-preflight
```

检查项：Linux、root/CAP_NET_ADMIN、charon VICI socket、`ip`/`swanctl`/`charon`/`ping`
可用性、kernel XFRM 支持、XFRM interface 支持、named netns create/delete。

**在 root 机器上直接运行：**
```bash
sudo make ipsec-xfrm-smoke
```

**在 privileged container 中自动运行（无需 root 机器）：**
```bash
make ipsec-xfrm-container-smoke
```

container smoke 会：
1. 构建 Ubuntu 24.04 镜像（安装 strongswan-swanctl/charon/plugins）
2. 用 Go cache volume 复用模块下载
3. 在 `--privileged` container 中启动 charon + 运行 `make ipsec-xfrm-smoke`
4. 复用 `ip` wrapper 处理 nested LXC netns 限制

**覆盖的测试：**
- `TestSystemXFRMDriverIntegrationSmoke` — XFRM interface lifecycle
- `TestSystemXFRMDriverPeerTunnelPingSmoke` — 双 netns veth + XFRM tunnel ping
  （container 中因 IPv6 邻居限制可能跳过）
- `TestStrongSwanDriverLoadsKeyAndConnection` — VICI key/conn 加载
- `TestStrongSwanDriverIKEBringupSmoke` — 双 charon netns IKE_SA/CHILD_SA + tunnel ping
- `TestStrongSwanBidirectionalTakeoverSmoke` — bidirectional secondary takeover
- `TestDaemonReconcileUsesSystemXFRMDriverSmoke` — daemon reconcile 创建 XFRM interface
- `TestDaemonStrongSwanReconcileBringupSmoke` — daemon + VICI + XFRM 完整建链 + 撤销 teardown（验证 Phase 6.5 IPsec/XFRM 清理路径）
- `TestDaemonStrongSwanPortRotationSmoke` — 端口轮换 bounded break-before-make
- `TestDaemonRunGossipStrongSwanBringupSmoke` — daemon Run 循环自动发布 + gossip + 建链
- `TestDaemonStrongSwanReconcileBringupDerivedPoolSmoke` — derived-pool tunnel address

**环境变量：**
- `HIGGS_IPSEC_XFRM_SMOKE=1` — gate Go 测试
- `HIGGS_IPSEC_XFRM_SMOKE_CONTAINER=1` — container 环境标记（跳过已知不兼容用例）
- `HIGGS_IPSEC_XFRM_IMAGE` — 基础镜像（默认 `ubuntu:24.04`）
- `HIGGS_IPSEC_XFRM_REBUILD_IMAGE=1` — 强制重建缓存镜像
- `HIGGS_CONTAINER_RUNTIME` — `docker` 或 `podman`

### BIRD / Babel

**前置检查：**
```bash
make bird-babel-preflight
```

检查项：Linux、root/CAP_NET_ADMIN、`bird`/`birdc`/`ip`/`ping` 可用性、
BIRD 版本 >= 2.0、named netns create/delete。

**在 root 机器上直接运行：**
```bash
sudo make bird-babel-smoke
```

**在 privileged container 中自动运行：**
```bash
make bird-babel-container-smoke
```

container smoke 会：
1. 构建 Ubuntu 24.04 镜像（安装 `bird2`）
2. 用 Go cache volume 复用模块下载
3. 在 `--privileged` container 中运行 `make bird-babel-smoke`

**覆盖的测试：**
- `TestExecProcessManagerRootSmoke` — managed BIRD lifecycle in named netns
  (`pkg/routing/bird/root_smoke_test.go`)
- `TestBabelTwoNodeRootSmoke` — 双 netns veth BIRD Babel 邻居建立 + 路由学习
  (`pkg/routing/bird/root_smoke_test.go`)
- `TestDaemonBIRDRoutingRootSmoke` — daemon routing reconcile 启动真实 BIRD
  (`app/higgs/bird_root_smoke_test.go`)
- `TestDaemonBIRDUpstreamRootSmoke` — veth upstream + BIRD config 验证
  (`app/higgs/bird_root_smoke_test.go`)
- `TestBIRDUpstreamBabelRootSmoke` — veth 跨 netns (host ← veth → overlay)
  BIRD Babel 邻居建立 + 前缀双向可达（6.1.7 场景）
  (`pkg/routing/bird/root_smoke_test.go`)

**环境变量：**
- `HIGGS_BIRD_SMOKE=1` — gate Go 测试
- `HIGGS_BIRD_SMOKE_CONTAINER=1` — container 环境标记
- `HIGGS_BIRD_IMAGE` — 基础镜像（默认 `ubuntu:24.04`）
- `HIGGS_BIRD_REBUILD_IMAGE=1` — 强制重建缓存镜像

## 常见问题

### NixOS / LXC 环境

即使 Docker 使用 `--privileged`，外层 LXC 可能仍然拦截 netns/XFRM/mount 能力。
preflight 会明确报告失败，而不是半途留下残留资源。

### 多公网接口测试机

在有多公网接口的测试机上，非 root smoke 可能因为 endpoint discovery 自动发布
公网地址而失败。项目已实现自动 loopback-only 检测（当所有 bootstrap peer 都是
loopback 地址时默认不发布公网 endpoint），大多数 smoke 不需要额外配置。

如果仍遇到问题，可在配置中显式设置 `publish_endpoints: false`。

### Go Cache Volume

container smoke 使用 Docker volume 缓存 Go module 和 build cache，避免每次
运行都重新下载。Volume 名称：
- IPsec: `higgs-ipsec-xfrm-gocache` / `higgs-ipsec-xfrm-gomodcache`
- BIRD: `higgs-bird-babel-gocache` / `higgs-bird-babel-gomodcache`

可以通过 `HIGGS_IPSEC_XFRM_GO_CACHE_VOLUME` / `HIGGS_BIRD_GO_CACHE_VOLUME`
等环境变量覆盖。

### 失败诊断

所有 smoke 在失败时会输出关键日志：
- Shell smoke：trap EXIT 打印相关 `.log` 文件
- IPsec root smoke：输出 netns、XFRM state/policy、charon log、`swanctl --list-sas`
- BIRD root smoke：输出 netns 内 `ip addr`、`birdc show protocols all`、`birdc show route`