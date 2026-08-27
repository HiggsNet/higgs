# `app/photon` Runtime 迁移盘点

> 盘点基线：`3aa43fb`（2026-08-27）  
> 范围：`app/photon` 下 76 个非测试 Go 文件  
> 目标：说明每个文件当前职责、最终归属，以及 verified state、gossip runtime、checkpoint、Linux platform runtime、observability 和 presentation 之间的边界。

## 1. 最终分层

| 层 | 所有权 |
|---|---|
| `app/photon` | Linux executable 入口、CLI 注册和依赖装配 |
| `pkg/core/host` | 公共事件队列、scheduler、唯一 writer、gossip action 执行、worker completion 和 ChangeSet dispatch |
| `pkg/core/gossip` | wire codec、同步 FSM/session、chunk、object-pull 协议和 endpoint discovery |
| `pkg/core/state` | verified state、`GossipCheckpoint`、typed intent、签名验证和公共事务 |
| `pkg/core/zone` | authority、delegation、revocation、record 和 Network 等最低层模型 |
| `internal/photonlinux` | Linux IPsec、routing、firewall、health、Unix control 和 platform runtime codec |
| `internal/observability` | 可丢失的实时统计和诊断 |
| `internal/inspect` | 只读 view；不拥有 mutable store |
| `internal/controlapi` | 平台无关 Command/Response DTO；Unix socket/named pipe 是平台 adapter |
| `internal/photoncli` | CLI 参数、文件导入导出、输出和显式离线调用 |
| `internal/photonlinux/migration` | 旧 Linux 数据库单向升级；不提供反向映射或兼容写入 |

固定依赖方向：

```text
app -> host -> gossip -> state -> zone
app -> Linux controllers
observer/CLI -> inspect/read model
```

迁移不能把当前大文件原样搬到另一个目录。`daemon.go`、`state.go`、`sync.go`、`ipam.go` 等文件同时包含多层职责，必须先按输入、输出和 owner 拆开。

## 2. Platform runtime 是否需要持久化

### 2.1 结论

Platform controller 必须满足幂等、可重试和最终收敛的 reconcile 合约。持久化不是默认要求：只要一个值能够从配置、verified record 和当前系统 Observe 唯一重建，就不应再在 platform runtime 中保存第二份。

当前字段应按以下规则重新分类：

| 内容 | 是否需要 platform 持久化 | 原因 |
|---|---|---|
| BIRD PID file/control socket/config path | 不需要 | 从 routing 配置和稳定目录规则直接推导 |
| BIRD config hash | 不需要 | 从本轮生成的配置重新计算，并与磁盘文件/运行实例比较 |
| StrongSwan connection/child name | 不需要 | 从 transport/link ID 和 generation 稳定推导 |
| resource owner/token | 不需要 | 从 manager、group、link、transport 等稳定输入推导 |
| XFRM if_id/interface name | 不需要 | 已有稳定 hash/命名函数；也可通过 XFRM Observe 验证 |
| reqid、实际 SA、实际进程状态 | 不需要 | 属于外部 observed state，每次启动重新查询 |
| port generation | 通常不需要 | 当前 verified port record 已包含 generation、range 和更新时间，可作为恢复输入 |
| 配置文件中的 Endpoint ACL | 不需要 | 配置文件是 desired source of truth |
| CLI 动态创建且要求跨重启保留的 Endpoint ACL | 需要，或者取消该持久语义 | 它不在配置和 gossip 中；产品必须明确“持久本机配置”或“重启丢失”二选一 |
| 随机生成的 IPsec transport private key | 可选 | gossip 只有公钥，不能反推出私钥；可以持久保持 transport identity，也可以规定每次启动重新生成并发布新 record |
| LastError、LastRun、action/skip、backoff | 不需要保证 | 属于 diagnostics/observability；可丢失，不参与 reconcile 正确性 |

因此目标不应是建立一个内容越来越多的 `PlatformCheckpoint`，而应尽量删除 platform runtime 字段。只有无法推导、无法 Observe、且产品明确要求跨重启连续的本机值才持久化。

如果最终所有 Linux 资源身份均可稳定推导、所有外部状态均可 Observe，并且 transport key 采用“重启即轮换”、动态 ACL 采用“仅内存”语义，那么 `photon:linux-runtime` 可以缩到没有 correctness-critical payload，甚至完全删除；这不影响公共 `VerifiedRevision`。

### 2.2 幂等是 controller 的硬性要求

每个 controller 应优先暴露收敛操作：

```text
Observe(current external state)
Plan(verified view, local desired state, observed state)
Ensure/Delete(stable resource identity)
Observe again
Commit completion(source verified revision)
```

`Ensure` 重复执行必须安全；`Delete` 对不存在资源也应成功；resource name、owner tag、if_id、netns 和 connection name 必须稳定推导。`reqid` 等由外部系统分配的值应通过 Observe 获取。外部系统和 bbolt 无法组成原子事务，因此数据库中的“已完成”标记不能代替重新 Observe。

### 2.3 BIRD PID 的具体处理

不应把数值 PID 当作持久真相，因为 PID 会复用；PID file 路径本身也不需要写进 runtime state，因为它已经由 routing 配置和稳定目录规则确定。control socket、config path、owner token 和 router ID 同理都可重算。

重启后 controller 应根据当前配置计算精确 PID file/control socket 路径，读取并校验进程、owner、netns 和 control socket；校验失败就清理该明确路径下的陈旧资源并重新 start。这里应按稳定 owner 和精确路径查找，而不是无边界扫描目录后接管名字相似的进程。

当前 `BirdInstanceState` 中的 `PIDFile`、`ControlSocket`、`Owner` 和 `LastConfigHash` 可以作为迁移期诊断缓存，但不应成为最终持久化依赖。

### 2.4 崩溃顺序

对于会公开到 gossip 的本机运行事实，使用以下顺序：

1. 从配置、verified record 和 Observe 重建 desired state；
2. 如存在明确要求跨重启连续、且无法推导的本机值，先持久化该最小值；
3. 幂等应用外部资源；
4. 重新 Observe 确认；
5. 发布或更新公共 record；
6. diagnostics 只写 observability，不能决定下次是否跳过 Observe。

IPsec transport key 有两种都正确的产品策略：持久化私钥以维持 transport identity；或者只保存在内存中，每次启动生成新 key 并立即替换公开 record。后一种会带来重启后的 SA 重建和传播窗口，但不要求 platform 持久化。port generation 则可直接从 verified port record 恢复。BIRD/路由规则始终以 Observe 为准。

### 2.5 建议拆分当前 Linux runtime payload

当前单一 JSON payload 可以继续作为迁移期实现，但目标应先删除所有可推导和可 Observe 字段，而不是马上把它们拆成更多持久 bucket。清理后如果仍存在跨重启连续值，只保留：

```text
local-desired        不在配置文件中、但产品要求跨重启保留的本机配置
continuity           无法推导、但产品要求保持的随机生成值
operations           极少数确实无法改造成幂等/可观察操作的 journal
```

`recovery` 和 `diagnostics` 默认不持久化；需要重启后展示时可以进入独立、可整体丢弃的 observability spool。若 transport key 选择重启轮换、动态 ACL 选择重启丢失，并且不存在不可安全重放操作，Linux runtime bucket 最终可以删除。

## 3. 逐文件迁移清单

### 3.1 Admission、authority、daemon

| 文件 | 当前作用 | 最终位置 / 层 |
|---|---|---|
| `admission_diagnostics.go` | auto-join 诊断和 admission 标记 | 诊断进 `internal/inspect`；状态转换进 `pkg/core/host` 的 admission runtime；CLI wrapper 进 `internal/photoncli` |
| `authority.go` | 权限解析、delegate grant、旧 direct 修改 | CLI 进 `internal/photoncli`；权限合并/epoch/父子 authority 更新成为 `pkg/core/state` intent；旧 direct writer 删除 |
| `bolt_state_store.go` | 组合公共 state 与 Linux runtime 的启动/提交 | 启动已优先读取新 schema，仅未初始化时进入旧 bootstrap/migration；最终迁入 `internal/photonlinux/persistence`，app 只负责构造和注入 |
| `cmd.go` | Linux CLI 命令树 | 留 `app/photon` 但缩成注册；handler 进 `internal/photoncli` |
| `config.go` | 混合解析 gossip、identity 和全部 Linux subsystem | 顶层 YAML 进 `internal/photonlinux/config`；公共参数转换为 host/gossip config；各 Linux 配置归各 controller |
| `control.go` | 私有 DTO、Unix socket client、命令 wrapper 和部分 view | DTO 进 `internal/controlapi`；Unix transport 进 `internal/photonlinux/control`；CLI/view 分别进 photoncli/inspect |
| `cpu_profile.go` | daemon CPU profile 生命周期 | `internal/runtimeprofile` 或薄 app helper；不属于状态层 |
| `daemon.go` | event loop、控制服务、timer、admin mutation、publisher、controller 生命周期 | 公共循环进 `pkg/core/host`；Unix control 和 Linux controller 下沉；最终只留 composition root |
| `daemon_common_intent.go` | control DTO 到公共 intent 的转换 | typed control command 落地后删除，不保留永久 adapter |
| `daemon_discovery.go` | common/Linux owner 到 discovery input 的组装与触发 | 规划、checkpoint patch、persist-before-publish 和地址簿更新已进 HostRuntime；地址簿是可重建的公共 transport runtime state。Runtime 直接持有 owner 后删除剩余文件 |
| `daemon_object_chunk.go` | chunk/NACK transport 与 checkpoint/观测 adapter | assembly 已由每个 host Runtime 独占；repair deadline/缺失索引在 gossip，timer/action 已进 host Scheduler |
| `daemon_runtime_commit.go` | Linux controller typed commit wrapper | 由 host 的 PlatformCompletion 流程取代后删除 |
| `daemon_state_projection.go` | 聚合 stateFile 的 controller/inspect 迁移期投影 | catalog、fetch-zone、object-pull、周期同步、relay 等 protocol projection 已全部删除；剩余展示进 inspect、controller 使用 typed input 后继续逐项删除，最终不保留该文件或通用 projection 层 |
| `daemon_state_store.go` | E1 唯一 writer 协调器和聚合读视图 | owner/排序进入 host；Linux persistence 进入 capability；聚合 view 消失后删除 |
| `daemon_sync.go` | Linux gossip event 预处理、snapshot capability、checkpoint、发送、relay、session 收尾 | 已退出完整 `stateFile` 读取，catalog/action/managed-zone/observed checkpoint 直接走 common Store/HostRuntime；继续迁走剩余 capability，FSM 保持在 `pkg/core/gossip` |

### 3.2 DB、debug 和 diagnostics

| 文件 | 当前作用 | 最终位置 / 层 |
|---|---|---|
| `db.go` | 离线 dump 公共、旧和 Linux runtime bucket | 公共 dump 进 `internal/stateinspect`；Linux dump 进 `internal/photonlinux/inspect`；CLI 进 photoncli |
| `debug_cmd.go` | debug 命令注册 | app 或 `internal/photoncli`，只注册命令 |
| `debug_endpoints.go` | 本机 endpoint discovery 展示 | discovery 留 gossip；view/text 进 inspect；CLI 进 photoncli |
| `debug_firewall.go` | firewall 实时诊断 | observe 进 Linux firewall；view 进 inspect；CLI 进 photoncli |
| `debug_format.go` | 时间/空值格式化 | 合并到 `internal/inspect/text` |
| `debug_links.go` | IPsec/BIRD link 展示 | Linux live query 进 controller；view 进 inspect；CLI 进 photoncli |
| `debug_peer.go` | 合并 verified/checkpoint/observability 的单 peer 诊断 | `internal/inspect`，从稳定 ReadModel 取数 |
| `debug_peers.go` | peer lifecycle 列表 | `internal/inspect` + photoncli |
| `debug_ping.go` | peer ping CLI | 执行继续由 `internal/ping`；本文件缩成 photoncli adapter |
| `debug_revoke_impact.go` | revocation 影响展示 | 公共 purge plan 来自 state，平台影响由 controller 补充，view 进 inspect |
| `debug_rotate.go` | IPsec port rotate 和诊断 | plan 进 IPsec publisher/controller；runtime mutation 进 Linux IPsec；展示进 inspect |
| `debug_routing.go` | BIRD/Babel/routes 查询和解析 | Linux BIRD adapter 进 routing controller；view/text 进 inspect |
| `debug_routing_ip.go` | netns 中执行 Linux `ip route` | `internal/photonlinux/routing` diagnostics |
| `debug_zone_records.go` | zone/record 展示 | Store read API + `internal/inspect`/text |
| `diagnostics.go` | gossip event 到日志 | 稳定事件名留 gossip；logger adapter 进 host/internal logging |

### 3.3 Firewall、health、identity、IPAM、IPsec、join

| 文件 | 当前作用 | 最终位置 / 层 |
|---|---|---|
| `endpoint_acl.go` | ACL CLI、验证、resolve 和 firewall runtime mutation | Linux firewall model/controller；CLI/control 留 adapter；属于 platform desired runtime |
| `firewall_config.go` | nftables/iptables/netns/hook 配置 | `internal/photonlinux/firewall/config` |
| `firewall_reconcile.go` | firewall plan/apply/completion | `internal/photonlinux/firewall` PlatformController |
| `forwarding_config.go` | Linux forwarding policy | Linux firewall/routing config |
| `gossip_checkpoint_migration.go` | 旧 SyncPeers 到 GossipCheckpoint | `internal/photonlinux/migration`；兼容窗口结束后删除 |
| `health_config.go` | probe/hysteresis/metrics 配置 | 通用类型留 `pkg/health`；Linux YAML 进 Linux health config |
| `health_reconcile.go` | probe target、manager、事件和状态 | 算法留 `pkg/health`；Linux target/observation 进 Linux health；事件回 host |
| `health_spool.go` | JSONL health 历史和查询 | `internal/observability/healthspool`；不属于 state/checkpoint |
| `identity_bootstrap.go` | identity key/config、auto-join adoption 和 refresh | 文件处理进 config/CLI；安装和 refresh 留 state；调度进 host；旧 stateFile mutation 删除 |
| `init.go` | root 初始化 | 公共初始化事务进 state；文件/CLI 进 photoncli |
| `inspect_links.go` | Linux link 到 inspect input | Linux controller 输出稳定 DTO，view 进 inspect |
| `inspect_peers.go` | verified/checkpoint/bootstrap/observability endpoint view | `internal/inspect`，不再依赖 stateFile |
| `ipam.go` | IPAM CLI、旧 mutation 和报告 | mutation 只调 state intent；报告进 inspect；CLI 进 photoncli；旧 apply 函数删除 |
| `ipsec_cleanup.go` | StrongSwan/XFRM cleanup | `internal/photonlinux/ipsec` controller |
| `ipsec_publish.go` | transport key/address/port/overlay record 和私有 runtime | record 构造进 transport/state publisher；key/port 本机事实进 platform runtime；排序由 host 保证 |
| `ipsec_reconcile.go` | StrongSwan/XFRM/SA/rotation reconcile | `internal/photonlinux/ipsec` PlatformController |
| `join.go` | join DTO、issue/revoke/accept、key/bundle、旧 direct writer | DTO/验证进 state admission；文件 CLI 进 photoncli；全部 mutation 复用 Store；旧 writer 删除 |

### 3.4 Key、link、logging、object-pull、observer、peer

| 文件 | 当前作用 | 最终位置 / 层 |
|---|---|---|
| `keygen.go` | Ed25519 key 文件生成 | `internal/photoncli/keygen`，底层复用 crypto |
| `link_outputs.go` | Linux link runtime 到 health/routing output | `internal/photonlinux/linkstate` 或 IPsec controller 输出 DTO |
| `linux_state_view.go` | 公共 view + Linux runtime 合成 stateFile | 迁移期读桥；consumer 改用 typed view 后删除 |
| `logging.go` | app logger 实现 | host 定义 Logger interface；Linux 实现进 internal logging |
| `main.go` | executable 入口 | 永久留 `app/photon`，只负责装配/退出码 |
| `objectpull.go` | TCP object-pull transport、quota、统计 | request/response 构造已进 gossip，在线 worker/completion、recovery lookup 和 peer 地址选择已进 host；继续把跨平台 dial/listen/deadline capability 迁入公共 transport，统计进 observability |
| `observer_config.go` | Observer 配置 | 模型进 observer；Linux YAML 进 Linux config |
| `observer_server.go` | HTTP/OpenMetrics/SSE provider wiring | server/read model 进 observer；Linux app 只注入 provider |
| `peer_lifecycle_cleanup.go` | peer 过期、checkpoint/observability/platform cleanup | policy/调度进 host；checkpoint 由 state 删除；平台资源通过 action 清理 |
| `peer_state.go` | peer lifecycle 状态推导 | view 进 inspect；参与调度的纯 policy 进 host |

### 3.5 Record、recovery、routing、state、sync 和基础 CLI

| 文件 | 当前作用 | 最终位置 / 层 |
|---|---|---|
| `record.go` | record CLI、旧 direct 签名和查询 | mutation 只调 state intent；查询进 inspect；CLI 进 photoncli；本地签名 helper 删除 |
| `recovery.go` | export/import/pull/purge 和 Linux cleanup | export/import/pull/purge 已通过唯一 BoltStore、common Store typed API 与 Linux runtime candidate 完成，不再读写旧 Network；继续把平台 cleanup 交 controller，CLI 进 photoncli |
| `revocation_cleanup.go` | impact、peer cache cleanup、purge plan | verified/checkpoint purge 留 state；平台 cleanup 变成 host action；view 进 inspect |
| `root.go` | root public key CLI | Store read API + photoncli |
| `route.go` | route CLI、旧 direct mutation、报告 | mutation进 state intent；授权计算留 routing；报告进 inspect；CLI 进 photoncli |
| `routing_config.go` | netns/BIRD/Babel/upstream config | `internal/photonlinux/routing/config` |
| `routing_reconcile.go` | BIRD/netns/veth/upstream、health、auto announce | Linux reconcile 进 routing controller；授权留 pkg/routing；公共 announce 用 state intent |
| `routing_upstream_routes.go` | Linux `ip` 安装 upstream 地址/路由 | `internal/photonlinux/routing` driver |
| `runtime_state_migration.go` | Linux runtime schema/codec 和旧 state 拆分 | codec/type 进 Linux state；旧转换进 migration，兼容结束后删除 |
| `service.go` | SOCKS5 CLI、旧 direct record mutation | intent 留 state/service；CLI 进 photoncli；展示进 inspect；旧 apply 删除 |
| `share.go` | base64 JSON 和文件 I/O | `internal/photoncli/encoding`；不是 state codec |
| `state.go` | stateFile、Linux aliases、CLI Runtime、旧 Load/Save、统计 helper | verified/checkpoint 已归 state；Linux runtime 归 Linux state；CLI context 归 photoncli；stateFile/旧 Load/Save 最终删除 |
| `state_clone.go` | aggregate 和 Linux runtime clone | 各 owner 自己 clone；aggregate clone 随 stateFile 删除 |
| `state_gc.go` | 孤儿 BIRD runtime GC | Linux routing controller；CLI 仅触发 platform action |
| `status.go` | status CLI | inspect read model + photoncli |
| `sync.go` | SyncRuntime、transport、endpoint publish、checkpoint helper、chunk、统计和 CLI | FSM/wire进 gossip；event/action/worker进 host；checkpoint进 state；统计进 observability；CLI进 photoncli；SyncRuntime 删除 |
| `verify.go` | chain 验证 CLI | 验证留 crypto/state；CLI 进 photoncli |
| `version.go` | build info | `internal/buildinfo` 供 Linux/Windows 复用 |
| `zone.go` | zone/record 列表 CLI | Store read API + inspect/text + photoncli |

## 4. 推荐迁移顺序

1. **删除剩余旧 direct writer**：`recovery.go` 已完成；`authority.go`、`join.go`、`record.go`、`ipam.go`、`route.go`、`service.go`、`state_gc.go` 的 `--direct` 路径继续统一改为打开 BoltStore 后调用同一个 typed Store/controller API。
2. **迁移公共 HostRuntime**：依次拆 `daemon_sync.go`、`daemon_object_chunk.go`、`daemon_discovery.go`、`objectpull.go`、`sync.go` 和 `daemon.go` 的 event loop。
3. **抽 Linux controllers**：IPsec、routing、firewall 三条独立迁移线，各自接收 detached input，返回 typed completion。
4. **删除聚合 stateFile**：先替换 protocol projection，再替换 controller input、inspect/observer 和离线 CLI read path；随后删除 `linux_state_view.go`、`daemon_state_store.go`、aggregate clone 和旧 state loader。
5. **收口 CLI/展示**：`debug_*.go`、`status.go`、`zone.go`、`db.go` 最终只做参数解析、control/read model 调用和 presenter 输出。

迁移过程中不再为单个调用点增加新的 stateFile wrapper。需要过渡时只允许 detached typed DTO，并在同一任务中写明删除条件。
