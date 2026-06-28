# Higgs Todo

设计文档见 [docs/design.md](docs/design.md)。本文件只保留可执行任务。

## 已完成里程碑归档

完整历史清单已拆到 [docs/roadmap-archive.md](docs/roadmap-archive.md)，主 TODO 只保留当前执行队列和后续计划。

- [x] Phase 0-2：可信状态机、join/delegation、gossip 同步、discovery、bounded history 和操作文档。
- [x] Phase 3-3.6：daemon/single-writer 基座、NAT/observed path、MTU-safe gossip 和 object-pull/chunk fallback。
- [x] Phase 4：StrongSwan/XFRM 主线、daemon admin 写入、auto-join、planner/reconcile、host-born XFRM、低频 rotate、bidirectional takeover。
- [x] Phase 5：BIRD Babel、route authorization、per-netns BIRD 配置模型、routing debug 和 dry-run smoke 基座。

## Phase 4: StrongSwan / XFRM interface 建链（归档后仅保留后续项）

**状态：** 主线能力已完成，完整展开清单见 [docs/roadmap-archive.md](docs/roadmap-archive.md)。当前只保留尚未彻底闭环的后续能力。

- [ ] **4.4.x 真正平滑 rotate / staged transition（后续重要工作）**
  - 目标：在不先打断当前可用 SA 的前提下，把 current/previous grace 变成系统层可执行的 staged transition；用户可见语义应是 zero-downtime 或接近 zero-downtime 的切换，而不是 bounded break-before-make。
  - 方案 A：为 staged generation 使用独立 XFRM interface/`if_id` 与独立 CHILD_SA，待新 SA established 且 tunnel/health check 通过后交给 Babel 层完成切换：新 link 以正常/更优 metric 加入，旧 link 在 grace 窗口内保留但调高 metric，等 Babel 邻居与路由收敛后再清理旧 generation。需要明确 route/interface ownership、BIRD interface pattern 自动发现语义、双 interface 期间的 metric/邻居收敛、daemon restart recovery 和 stale generation cleanup。
    - [x] IPsec staged generation 必须派生独立 `TransportID`、XFRM `if_id` 和 interface name；`prepare_rotate` 不再 terminate 旧 SA，旧 generation 在 staged 建立期间保持可用。
    - [x] `LinkInstance` 持久化 staged interface/`if_id`，用于 debug、daemon restart recovery、rollback、stale cleanup 和 revocation teardown。
    - [x] staged SA established 后进入 `dual_running`/cutover 语义：IPsec 层确认新旧 generation 并行承载；旧 generation 默认继续保留 1h，可通过 `overlays[].reconcile.rotate_retention` 配置；Babel/route manager 的 metric 纳入/调高/收敛回调仍由下一条接入。
    - [x] 旧 generation cleanup 由 retention 到期后的下一轮 reconcile 执行；daemon 重启后从落盘 `LinkInstance.rotate_deadline`、staged interface/`if_id` 和 `ListSAs` 恢复，若旧 SA 已不存在但 staged SA 已 established，则立即 promote staged generation 并清旧残留。
    - [x] 失败路径必须保持旧 generation：staged 建立超时、apply 失败或健康检查失败时只清 staged connection/interface，旧 SA/interface/route 继续保留并进入 backoff。
    - [x] 明确 accept-only initiator 规则：当前 primary 或 secondary-takeover owner 负责主动建立 staged generation；`accept=inbound` / `secondary-standby` 只准备 responder/trap staged config，不主动拨号，避免 rotate 触发双向同时拨号。
      - 2026-06-13 已在 `ReconcileLinkInstances` 中接入：secondary-standby/converged 观测到远端 port generation 变化时仍会生成 `prepare_rotate`，但 staged spec 被改写为无 ContactPoint 的 responder/trap，只加载 responder/trap；primary 和 secondary-takeover owner 保留主动 staged 建立语义。
    - [ ] inbound 端 rotate advertised/listen port 时，真正平滑依赖 responder 侧能在 retention/grace 窗口同时接收 old/current port；若 StrongSwan 单实例无法双 listen，则 A 只能保持旧 SA/XFRM link，不能单独保证新旧端口监听无断，需 DNAT/redirect grace 或多实例 listener 作为 Phase 6/7 能力。
    - [x] bidirectional 双端同时 rotate 时沿用 4.5 的 primary/secondary-takeover：primary 或 takeover owner 负责 staged initiate，standby 只加载 responder；takeover 不应在 `dual_running` 保留窗口内抢拨，除非当前 owner 超时且无 established staged SA。rotate 不再依赖本地 `direction`。
      - 2026-06-13 已补 reconcile 守卫：secondary-standby 在 staged/`dual_running` rotate deadline 未到期时返回 `rotate_staged_active` / `rotate_retention_active` noop，不触发 takeover；新增单测覆盖超过 takeover delay 但仍处于 retention 窗口时保持 standby。
    - [x] 后续 Phase 5 接 Babel 时增加 route manager 回调/状态输入，避免 IPsec reconcile 在 Babel 尚未收敛前过早清理旧 generation。
      - 2026-06-13 已在 `ReconcileInputs` 增加 `RotateCutoverReady` per-instance 门闩：默认未接 route manager 时沿用 retention 到期 commit；Phase 5 route/Babel manager 可显式置为 false，让 `dual_running` 即使 retention 到期也继续保留旧 generation，直到 Babel metric/邻居/路由收敛后再允许 `commit_rotate`。
  - 配置边界必须明确，避免把两类 rotate 混在一起：
    - `ipsec.port_mode` / `ipsec.port_range` / `ipsec.port_rotate_interval` / `ipsec.port_previous_grace` 是本节点公开的 IKE/NAT-T **入口端口 generation 策略**，决定本节点何时选择/公告 current port、previous port grace 多久；它主要影响 responder/inbound 入口和远端 planner 如何选择 ContactPoint。
    - `overlays[].reconcile.rotate_retention` 是本地 overlay link 的 **数据面旧 generation 保留窗口**，决定 staged CHILD_SA/XFRM link 已建立后，本机旧 SA/interface 继续保留多久给 Babel metric 收敛和回滚使用；默认 1h。它不负责让 charon 同时监听 old/current port。
    - 两者应满足：`port_previous_grace` 覆盖“远端还能尝试旧入口端口”的窗口；`rotate_retention` 覆盖“新旧 XFRM/Babel 数据面并行”的窗口。默认采用 `port_previous_grace=2h`、`rotate_retention=1h`；配置校验至少要求 `port_previous_grace >= rotate_retention`，生产推荐 previous grace 保持为 retention 的 2 倍或与 DNAT owner 规则生命周期绑定。
  - DNAT/redirect grace 作为 inbound 端口平滑 rotate 的主线后续能力，而不是普通可选项：charon 可以继续保持单实例/单当前监听端口，nftables/iptables owner 规则在 `port_previous_grace` 窗口把 previous/current advertised port 转发到当前 charon 监听端口，从而让 responder 在入口层同时接收 old/current port；需要规则 owner token、preflight、规则恢复、撤销清理、daemon restart adoption、端口冲突检测和与 NAT-T/MOBIKE 行为的边界说明。
  - 多 charon/socket/listener 暂不作为主线：只保留为极端部署 fallback。除非 DNAT/redirect grace 在 root/container smoke 中证明不可行，否则不要提前引入多 VICI socket、多 swanctl 配置树、多 charon 生命周期和 XFRM/policy 互扰问题。
  - 决策点：优先走 A + DNAT grace + Babel metric 三层组合。IPsec staged generation 负责并行承载新旧 CHILD_SA/XFRM link；DNAT/redirect grace 负责 inbound 入口端口平滑；Babel/route manager 负责 metric 提升与流量迁移。进入 DNAT 实现前需要 root/container smoke 证明 previous/current port redirect 到 charon 当前监听端口可用，并且不会破坏 NAT-T/MOBIKE 和现有 VICI SA 观测。
  - 验证要求：root/container smoke 必须覆盖旧 SA 保持可用、新 SA 并行建立、切换期间连续 tunnel ping 或允许的最大丢包窗口、失败回滚仍保持旧路径、daemon 重启恢复、revocation/policy deny 仍强制 teardown。

- [ ] **4.x IPsec 链路身份重新分层**
  - [ ] 引入无方向 `LinkID` / `PairID` 作为两节点同一逻辑 link 的唯一基础身份：`hash(sorted(local_zone, peer_zone), overlay_id, path_key)`；`path_key` 第一版为 `default` 或 `family:ipv4` / `family:ipv6`。
  - [ ] `LinkInstance`、routing/debug/health read model 以稳定 `LinkID` 为主键；runtime connection、generation、interface 作为观测 label，避免 rotate 后历史断裂。
  - [ ] 将 `TransportID` 降级为 runtime resource id：`RuntimeConnectionID = "ipsec-" + short(hash(LinkID, generation, provider, "runtime"))`，staged generation 使用 `-r<generation>` 短名；`ChildSAName = RuntimeConnectionID + "-child"`。
  - [ ] XFRM 与 interface 从 runtime 派生：`XFRMIfID = uint32(hash(LinkID, generation, provider, "xfrm-if-id"))`，0 改为 1；`InterfaceName = hgs<8hex>`，保持 Linux 15 字符限制。
  - [ ] owner token 从 `hash(LinkID, RuntimeConnectionID, "owner-token")` 派生，用于 create/adopt/cleanup/revocation 的 owner guard；兼容旧 `TransportID` owner token 的迁移/清理。
  - [ ] `derived-link-local` / `derived-pool` 地址改为从 `LinkID + address_epoch + mode + pool? + lower/higher` 派生；`address_epoch=0` 为稳定地址，staged old/new 同 family 双 running 时用 generation 作为 epoch，尤其避免 `derived-pool` 地址复用。
  - [ ] `derived-pool` 派生必须把 pool 纳入 hash：IPv4 跳过 network/broadcast/不可用 host，IPv6 跳过 pool base/不可用地址，通过 retry 处理候选不可用；两端 overlay intent 必须声明兼容 tunnel address mode/family/pool。
  - [ ] `sequential-pool` 标为 legacy：保留兼容和迁移测试，但新设计、示例和文档默认使用 `derived-link-local` 或 `derived-pool`。
  - [ ] 新增 overlay/link intent 记录层，例如 `ipsec/overlays/<overlay_id>` / `ipsec.overlay_intent.v1`：节点级 `ipsec/profile`、`ipsec/addresses`、`ipsec/ports`、`ipsec/transport-key` 只表达本节点 StrongSwan/IPsec 能力；overlay intent 记录表达本节点愿意把这些节点能力用于哪个 `overlay_id/path_key`。
  - [ ] planner 只有在远端 capability 完整可信、本地 `connect` 选择 peer、远端 overlay intent 与本地 `overlay_id/path_key` 兼容时才输出 desired link；当前兼容期若缺少 overlay intent，应显式输出 warning/skip reason 或受配置开关控制。
  - [ ] 补迁移策略：从旧 `TransportID`/directional address 状态恢复时能 adopt/cleanup 旧资源，重新写入 `LinkID`、runtime id、owner token、tunnel address；debug links 显示 old/new identity 对照。
  - [ ] 测试覆盖：双端同 overlay 得到相同 `LinkID` 和镜像 tunnel address；不同 overlay 不建链或给出明确 skip；family-redundant 产生不同 path_key；rotate gen N/N+1 runtime/if_id/interface/address_epoch 不冲突；derived-pool 双 running 不复用地址；daemon restart 可从 staged/current runtime 恢复。

## Phase 5: BIRD Babel 路由 + Route Authorization Filter（归档后仅保留后续项）

**状态：** 第一版 BIRD/Babel、route authorization、per-netns BIRD 和 dry-run smoke 已完成；完整展开清单见 [docs/roadmap-archive.md](docs/roadmap-archive.md)。

**剩余后续：**
- [ ] managed BIRD 崩溃恢复/backoff：`waitpid` + 崩溃重拉起。
- [ ] owner token 细化到 control socket/pid/route table/rule 的 teardown 清理规则。
- [ ] staged generation 接入 `RotateCutoverReady=true`：把 BIRD metric/邻居/路由观测反馈给 IPsec rotate cutover gate。
- [ ] route-table auditor 作为可选兜底。
- [ ] `ip rule` / fwmark / iif-oif 策略路由和 `/run/higgs/rt_tables.d` 诊断输出。
- [ ] 多 overlay 共享同一 netns 时的 table/rule 隔离。
- [ ] teardown/revocation 对 table routes/rules 的 owner-guarded 清理。
- [ ] `routing_reload` control method 和 `bird_dump`（完整 birdc 原始输出）。
- [ ] Higgs 侧 authorized route set 与 BIRD 侧 learned/installed routes 的交叉视图。
- [ ] negative smoke、rotate smoke、restart smoke 随真实 BIRD 数据面和策略路由一起补齐。

## Phase 6: IPAM / 准入 / 防火墙 / 链路健康（预计 4-5 周）

**状态：** 6.0 事件驱动控制面重构已完成（默认启用 event loop + SyncSession FSM，`go test -race` 全绿）。本章从 6.1 起进入 IPAM 闭环、防火墙同步、动态 peer 管理、撤销清理和链路健康检测；auto-join 准入基线已完成，后续只保留诊断补强。

**目标：** 在事件驱动 daemon 基座上，落地 IPAM/防火墙/链路健康等控制面特性。先补齐 IPAM 语义（6.1），再逐步补齐防火墙 apply 面、动态 peer 状态协调、撤销清理和链路健康检测。新节点是否建链仍由各节点本地 overlay/link group/MeshPolicy 配置决定，不由准入流程自动调整。

### 6.0 事件驱动控制面重构

- [x] **6.0.1 事件类型与事件循环改造**
  - [x] 在 `app/higgs/sync_session.go` 定义 `SyncEvent` 联合类型：`SyncTimerEvent`、`PacketEvent`、`UnsolicitedPacketEvent`、`PacketQuietTimeoutEvent`、`RoundTimeoutEvent`、`ObjectPullResultEvent`、`ObjectChunkEvent`、`FetchZoneReceivedEvent` 等（`StateFileChangedEvent` 留待 fsnotify 接入）
  - [x] 改造 `DaemonService.Run()`：统一 select `packetCh`、`d.Events`、内部 `syncEvents`、timer channel、object-pull result channel；保持 control/admin 事件走 `d.Events`，sync 内部事件走 `syncEvents`
  - [ ] 默认启用事件循环路径后移除 `sync.go` 中 `transport.Receive()` / `receiveWithContext` / `receiveWithDeadline`；当前旧路径仍保留在 `eventLoopSync=false` 模式下

- [x] **6.0.2 SyncSession 状态机**
  - [x] 新增 `app/higgs/sync_session.go`，定义 `SyncSession`：peerID、state、remoteDigests、pendingZones、localFetchZones、objectPullInflight、chunkFallbackZones、estimatedRTT、quietCount
  - [x] 状态定义：`Idle`、`PingSent`、`AwaitingAnnounce`、`FetchingLocal`、`ObjectPulling`、`ChunkFallback`、`Completed`、`Failed`
  - [x] 核心方法 `OnEvent(event SyncEvent, now time.Time) ([]SyncAction, error)`，纯状态转换：输入事件+当前状态 → 下一状态 + 动作列表
  - [x] 动作类型：`SendPingAction`、`SendPongAction`、`SendFetchZoneAction`、`SendAnnounceAction`、`StartObjectPullAction`、`ApplySnapshotAction`、`ApplyRecordSnapshotAction`、`SaveStateAction`、`RecordBackoffAction`、`StartTimerAction`、`CancelTimerAction`

- [x] **6.0.3 Packet Demuxer**
  - [x] 新增 `app/higgs/packet_demux.go`
  - [x] `routePacket(packet, sessions)`：若 `packet.PeerID` 命中活跃 `SyncSession` → 生成 `PacketEvent{session, packet}`；否则生成 `UnsolicitedPacketEvent{packet}`
  - [x] replay/quota/allowlist 检查仍在 `Transport.Receive()` 完成；demuxer 只负责按 peer 路由已通过校验的包

- [x] **6.0.4 定时器事件化**
  - [x] 新增 `app/higgs/timer_manager.go`，按 `(peerID, kind)` 管理 timer：
    - `RoundTimeout`：整轮超时，基于 peer 估计 RTT 动态计算：`max(5s, kRound * RTT + ObjectPullBudget)`
    - `PacketQuietTimeout`：UDP 静默期，基于 peer 估计 RTT 动态计算：`max(250ms, kQuiet * RTT)`。不是轮询间隔，而是给对端 burst 发送留的窗口；第一静默期用于决定何时从 UDP 切到 TCP object-pull，第二静默期用于等待 object-pull 后的迟到 UDP / chunk
    - jitter 暂未实现，可在后续 tuning 中加入
  - [x] session 创建/结束时注册/取消 timer；timer 触发后向事件循环 post 事件
  - [x] 单元测试注入 fake clock，验证定时器取消与重入

- [x] **6.0.5 异步 object pull / UDP chunk fallback 接入 FSM**
  - [x] 新增 `objectPullPool`：worker goroutine 执行 TCP pull，完成后通过 `objectPullResults` channel 回注，转换为 `ObjectPullResultEvent`
  - [x] `ObjectPulling` 状态等待结果：成功则 apply 并转 `AwaitingAnnounce`；失败则发送 `FetchZone{ChunkFallback:true}` 进入 `ChunkFallback`
  - [x] `ChunkFallback` 状态等待 `ObjectChunkEvent`；`object_chunk` 仍由全局 `udpChunkAssemblies` 重组（未完全移入 session，但 apply 由事件循环执行）
  - [x] `SendAnnounceAction` 由事件循环调用 `transport.Send`；超预算对象走 object-pull/chunk 路径

- [x] **6.0.6 状态变更与持久化边界（single writer）**
  - [x] 明确所有状态变更只在 daemon 事件循环 goroutine 中执行：
    - `NetworkState` apply、`peer state` 更新、`Transport` 运行时表更新、`udpChunkAssemblies` 等运行时缓存
    - IPsec / BIRD / routing desired-state 计算与 reconcile 触发
  - [x] worker goroutine（object pull）只产生事件，不直接 apply 状态；读取 state 时持 `RLock`
  - [x] 明确落盘时机：`Completed`/`Failed`、apply 导致 digest 变化后、control/admin 事件完成后
  - [ ] 移除旧 `syncRound`/`handlePacketUntil` 里的 `defer saveState()`（待 eventLoopSync 默认开启后删除旧路径）
  - [x] daemon 主 goroutine 串行写 state，避免多 goroutine 写 DB
  - [ ] 对 state 文件加 `flock` 互斥锁 / fsnotify watcher（当前仍依赖 bbolt 文件级锁 + 周期性 reload；后续补强）

- [x] **6.0.7 并发 race 修复**
  - [x] 给 `ReplayWindow` 加互斥锁（`pkg/core/gossip/replay.go`）
  - [x] 给 `PeerQuotas` 加互斥锁（`pkg/core/gossip/quota.go`）
  - [x] 给 `stateFile` 加 `sync.RWMutex`，事件 loop 写时持写锁，worker/control 读时持读锁
  - [x] `go test -race ./...` 全绿

- [x] **6.0.8 Relay fanout 事件化**
  - [x] relay 不再在 `handlePacketUntil` 里直接调用 `syncRound`；`completeSyncSession` 成功后调用 `relaySyncToPeers`，为其他 peer 创建独立 `SyncSession` 并向事件循环 post `SyncTimerEvent`
  - [x] 保持 relay 节流：backoff、min interval、来源 peer 跳过

- [x] **6.0.9 测试改造与补强**
  - [x] 新增 `app/higgs/sync_session_test.go`：表驱动覆盖主要状态转换（无 I/O）
  - [x] 新增 `app/higgs/packet_demux_test.go`
  - [x] 新增 `app/higgs/timer_manager_test.go`（fake clock）
  - [x] 新增 `app/higgs/daemon_test.go` 事件循环测试 `TestDaemonEventLoopSyncSession`
  - [x] `go test -race ./...` 全绿
  - [ ] 新增 race 回归测试：验证不再有两个 goroutine 同时 `Receive()`（待旧路径删除后天然满足）
  - [x] 现有 smoke 回归：`phase2-smoke` 通过；`object-pull-smoke` 在 Phase 6 基线已失败（与本次重构无关）

- [x] **6.0.10 文档更新**
  - [x] 更新 `docs/phase6-event-driven-design.md`：标记已实现部分，补充实际代码路径
  - [x] 更新 `docs/design.md` daemon/sync 架构章节，改为事件驱动描述
  - [x] 更新 `docs/protocol.md` 第 3 节 daemon/sync 运行流程

- [x] **6.0.11 Step 7 回归测试与收尾**
  - [x] 修复 `daemon.go` 中 `d.stateUnlock` 并发 race（加 `stateMu`），`go test -race ./app/higgs/...` 全绿
  - [x] 修复 `TestDaemonABPublishesGossipsAndReconcilesIPsecRecords` 在旧路径下与 `serveDaemonPackets` 竞争 UDP 包导致的 flaky 失败
  - [x] RTT 感知超时已有 `TestSyncSessionRTTAwareTimeouts` 覆盖；事件循环集成测试 `TestDaemonEventLoopSyncSession` 已覆盖 Ping/Pong/FetchZone/Announce 路径
  - [x] `make check`、`go test -race ./app/higgs/...`、`make phase2-smoke`、`make object-pull-smoke` 全绿
  - [x] 默认启用 `eventLoopSync`：`newDaemonService` 初始化时设为 `true`
  - [x] `make chain-relay-smoke` 在当前多公网接口测试机上仍失败：旧路径与新路径均失败，根因是 endpoint 发现优选了不可达的公网地址，导致 UDP 包被发往公网而非 loopback bootstrap。测试已通过添加 `publish_endpoints: false` 修复（治标）；治本方案见下方独立条目。

### 6.0.12 Transport 端点地址优先级与可达性探测修复

**问题：** 在多公网接口测试机上，`updateDiscoveredPeers()` 会因 endpoint discovery 自动将 discovered 公网 endpoint 插入到 peer 地址列表的最前面。由于 UDP `WriteToUDP` 向不可达地址发送数据时静默成功（无连接错误），`Transport.Send()` 在走完第一个地址后就直接返回，永远不会 fallback 到排在后面的 loopback/私有 bootstrap 地址。导致所有基于 loopback 的 smoke 测试（如 `chain-relay-smoke`）在存在其他可路由公网接口时失败。

**根因链条：**
1. `CollectLocalEndpointsWithReflectors()` 自动发现公网 IP → 发布为 signed `sync/endpoint/udp` record
2. `updateDiscoveredPeers()` 提取 peer endpoint，公网地址 `dialRank=0` 排在 loopback 地址 `dialRank=2` 之前
3. `Transport.SetPeerAddrs()` 将地址列表替换，bootstrap loopback 地址被追加到列表末尾
4. `Transport.Send()` 按序尝试地址，第一个公网地址 `WriteToUDP` 成功返回（包被本地网络栈接受但实际不可达）
5. 后续 fallback 地址永远不会被尝试

**治标修复（已完成）：** 给 `chain-relay-smoke` 加上 `publish_endpoints: false` 配置，禁用端点自动发现和发布。

**治本方案：**

- [x] **6.0.12.1 `Transport.Send()` 地址尝试可达性反馈**
  - `Transport` 增加 per-peer per-address 的 `addrState`（成功/失败计数、last success/failure、backoff until）
  - `Receive()` 对通过验证的包调用 `RecordAddrSuccess(peerID, sourceAddr)`
  - 上层 sync round / SyncSession 完成或超时时调用 `RecordAddrFailure(peerID, LastSendAddr())`
  - `Send()` 按状态排序候选地址：recent success > unknown > 有失败记录 > backoff，避免永远卡在第一个"看起来成功"但实际不可达的地址
  - 连续失败 2 次后进入指数 backoff（500ms ~ 30s），超时或 hash 变化后恢复

- [x] **6.0.12.2 `updateDiscoveredPeers()` 地址合并策略改进**
  - 新增 `endpoint_source_order` 配置，默认 `bootstrap, advertise, reflector, interface`
  - `buildPeerAddrs` 按来源分组后按配置顺序与 bootstrap 地址合并，同类型来源内部保留原有优先级/last observed 排序
  - bootstrap 地址不再被追加到列表末尾，默认优先级高于 discovered public/reflector/interface 地址
  - 最近成功过的 discovered 地址作为 `recent` 源保留，避免正常 churn 时丢失可用路径

- [x] **6.0.12.3 在单机 loopback 测试场景中抑制公网 endpoint 发布**
  - 新增 `endpoint_discovery` 配置：`loopback_only` / `advertise_only` / `all`
  - `loopback_only` 只使用 loopback `listen_addr` 与 loopback `advertise_addrs`，跳过 reflector 和 interface scan
  - `advertise_only` 只使用显式 `advertise_addrs`
  - 未配置时自动检测：当所有 bootstrap peer 都是 loopback 地址时，默认按 `loopback_only` 处理，避免多公网接口测试机把包发到不可达公网地址

- [x] **6.0.12.4 集成测试环境隔离**
  - 依赖自动 loopback-only 检测，`phase1-smoke`、`phase2-smoke`、`multi-node-smoke` 等纯 loopback 测试默认不再发布公网 endpoint
  - `chain-relay-smoke` 已移除 `publish_endpoints: false` 治标配置，改由自动 loopback-only 检测保护
  - endpoint discovery 专项能力仍由 `discovery-smoke` / `reflector-smoke` 覆盖

### 6.1 IPAM 闭环

**设计文档：** `docs/phase6-ipam-design.md`

**核心决策：**
- `ipam/pools/*` 是**分配权**，`ipam/assignments/*` 是**使用权**，严格分离。
- assignment 默认不能继续细分，除非获得者另外持有覆盖该前缀的 pool。
- tunnel address 默认继续走 `derived-link-local`，业务地址 / SRv6 SID 完全由 IPAM 分配。

- [x] **6.1.1 Pool Enforcement**
  - [x] 在 `BuildAuthorizedRouteSet` 中校验每个 `ipam/assignments/<prefix>` 是否被同 Zone 或祖先 Zone 的 `ipam/pools/<pool_prefix>` 覆盖。
  - [x] pool 的 `delegated_to` 必须是 assignment 所在 Zone 或其祖先。
  - [x] 非法 assignment 进入 `AuthorizedRouteSet.Errors`，错误码 `ipam_assignment_pool_mismatch`。
  - [x] 单元测试覆盖合法/非法案例。

- [x] **6.1.2 Assignment 重叠检测**
  - [x] 同 Zone 内：允许层级分配（`assigned_to` 为严格祖先/后代），禁止兄弟 Zone 重叠。
  - [x] 跨 Zone：只允许同一条委派链上的祖先/后代 Zone 之间存在包含关系。
  - [x] 非法重叠进入 `AuthorizedRouteSet.Errors`，错误码 `ipam_assignment_overlap`。
  - [x] 单元测试覆盖同 Zone 层级、兄弟冲突、相同 assignee 重叠、跨 Zone 合法/非法。

- [x] **6.1.3 权限模型**
  - [x] `pkg/crypto/sign.go` 将 `ipam.pool` / `ipam.assignment` 映射到 `PermAllocateIP`。
  - [x] 写入 pool/assignment 时校验 Zone authority 是否具备 `PermAllocateIP`。
  - [x] 单元测试覆盖 capability 校验。

- [x] **6.1.4 `higgs ipam` CLI**
  - [x] `higgs ipam pool create <zone> <prefix> --delegated-to <zone>`
  - [x] `higgs ipam assign <zone> <prefix> --to <zone>`
  - [x] `higgs ipam revoke assignment <zone> <prefix>`
  - [x] `higgs ipam revoke pool <zone> <prefix>`
  - [x] `higgs ipam assigned [--zone <zone>]`：查询 authorized assignments，可按 source 或 assigned_to zone 过滤。
  - [x] daemon 运行时所有写操作优先通过 control socket 提交，不可用时 fallback 直接写 DB 并告警。

- [x] **6.1.5 节点自查询分配 IP 与自动宣告（可选）**
  - 设计文档：`docs/phase6-ipam-design.md` 第 9.2 节。
  - [x] 新增顶层配置 `ipam.auto_announce_assigned_ips`，默认 `false`。
  - [x] `app/higgs/config.go`：定义 `IPAMConfig` / `ipamConfigYAML` 并接入解析。
  - [x] `app/higgs/routing_reconcile.go`：在 `reconcileRouting()` 中接入 `autoAnnounceAssignedIPs`。
  - [x] 实现自查询：遍历 `ars.Assignments`，筛选 `AssignedTo == ManagedZone` 且合法的前缀。
  - [x] 实现差集：发布缺失的 announcements，撤回已失效的 announcements。
  - [x] 写入路径收敛到 daemon 单 writer；CLI 非 daemon 模式不自动写。
  - [x] 单元测试：开启/关闭、前缀补齐/撤回、非法 assignment 不宣告。
  - [x] smoke：开启后 BIRD export filter 自动包含本节点分配前缀。

- [x] **6.1.6 集成验证**
  - [x] smoke：`higgs ipam pool create` / `assign` / `route announce` + BIRD filter 导入/导出验证（`TestIPAMRoutingSmoke`，`make routing-dry-run-smoke`）。
  - [x] smoke：撤销 assignment 后，对应 announcement 从 authorized route set 与 BIRD export filter 中剔除（`TestRoutingDryRunSmokeRevokeAssignment`，`make routing-dry-run-smoke`）。

- [x] **6.1.7 veth 上行与主网络 BIRD 集成（可选）**
  - 设计文档：`docs/phase6-ipam-design.md` 第 13 章。
  - [x] 新增 `routing.instances[].upstream` 配置段（per-netns，非 overlay 级别）。
  - [x] `app/higgs/routing_config.go`：解析 `upstream` 配置段并接入 `RoutingInstance.Upstream`。
  - [x] veth pair 创建/维护/清理（`create_veth` 为 true 时）。
    - 新增 `pkg/routing/bird/veth.go`：`VethManager` 接口 + `ExecVethManager` 实现，支持 named netns 间 veth pair 创建/地址配置/删除，幂等。
    - daemon `reconcileRoutingForInstance` 在 BIRD config 生成前调用 `EnsureVethPair`。
  - [x] `pkg/routing/bird/generator.go`：支持多 `interface` 段（XFRM tunnel + veth upstream）。
    - `BabelProtocolBlock` 新增 `UpstreamBlock *BabelInterfaceBlock`；upstream veth 段不加 `type tunnel`。
  - [x] `pkg/routing/bird/generator.go`：支持 `protocol static` 生成本节点分配前缀的路由。
    - `BirdInstanceSpec.StaticRoutes` + `StaticRouteSpec` 驱动 `StaticRouteBlock` 渲染，支持 via/blackhole。
    - `buildBirdInstanceSpecForNetns` 从 `AuthorizedRouteSet.Assignments` 中 `AssignedTo == ManagedZone` 的前缀自动生成 static routes，via 设为 upstream interface。
  - [x] import/export/kernel filter 细化：reject 默认路由、白名单前缀、来源限制。
    - 现有 `RenderFilter` 已 reject `0.0.0.0/0` 和 `::/0`，import filter 基于 `assignmentPrefixes` 白名单。
  - [x] 单元测试：多接口 config 渲染、static route 生成、filter 白名单、upstream 配置解析。
    - `pkg/routing/bird/generator_upstream_test.go`：7 个测试覆盖 upstream interface block、static routes（via/blackhole/no-via）、无 upstream 时不生成额外段。
    - `app/higgs/routing_config_upstream_test.go`：6 个测试覆盖完整解析、disabled、nil、默认值、非法 IPv4/IPv6。
    - `app/higgs/routing_upstream_smoke_test.go`：2 个 dry-run smoke 测试覆盖 daemon reconcile + veth manager 调用 + IPAM assignment → static route → BIRD config 完整链路。
  - [x] smoke：veth + BIRD 与主网络 babel 邻居建立、前缀双向可达（`TestBIRDUpstreamBabelRootSmoke`，`make bird-babel-smoke` / `make bird-babel-container-smoke`）：创建 overlay netns ← veth → host ns，两端各起 BIRD Babel，host 宣告 `172.16.1.0/24`，overlay 宣告 `172.16.2.0/24`，验证双向学习。

- [x] **6.1.8 IPAM Anycast / 共享前缀分配（可选 / 后续）**
  - 设计文档：`docs/phase6-ipam-design.md` 第 14 章。
  - **问题：** 当前 IPAM assignment 重叠检测禁止多个 Zone 持有同一前缀，与 Anycast（多节点同 IP 高可用）冲突。
  - **目标：** 在 IPAM 层引入 shared/anycast 语义，允许多个 Zone 合法持有同一前缀的 assignment，同时保持现有防冲突规则对非 anycast 场景有效。
  - 候选方案：
    - 新增 `ipam.anycast` record 类型或 `assignment.shared` 字段。
    - 允许同一前缀分配给多个 Zone，但这些 Zone 必须被共同策略显式授权。
    - 在 `BuildAuthorizedRouteSet` 中识别 anycast assignment，跳过兄弟 Zone 重叠检查。
  - [x] 调研并确定 anycast assignment 的 schema 和授权模型。
    - 采用 `assignment.shared` 字段方案：在 `IPAMAssignmentRecord` 新增 `Shared bool` 字段（默认 `false`，向后兼容）。
  - [x] 更新 `BuildAuthorizedRouteSet` 和重叠检测逻辑，支持 anycast exception。
    - `isAssignmentOverlapAllowed`：双方 `Shared=true` 时跳过兄弟 Zone 重叠检查。
    - `resolveOverlaps`：双方 route announcement 由 shared assignment 授权时允许重叠。
    - `findAssignmentForPrefix` 改为遍历 `AllAssignments`（含 anycast 重复）。
    - `AuthorizedRouteSet` 新增 `AllAssignments` 字段，CLI/BIRD 列举应使用它。
  - [x] 更新 `higgs ipam` CLI，支持创建/撤销 anycast assignment。
    - `higgs ipam assign <zone> <prefix> --to <zone> --shared`
    - 撤销时保留原 record 的 `shared` 字段值。
  - [x] 单元测试：多 Zone 同前缀 anycast、非 anycast 重叠仍拒绝、撤销后路由收敛。
    - `TestAnycastAssignmentOverlapCrossZoneValid`：两个 sibling Zone 持有同一 shared assignment，无错误。
    - `TestAnycastAssignmentOnlyOneSharedStillRejected`：只有一方 shared 时仍拒绝重叠。
    - `TestAnycastRouteAnnouncementOverlapValid`：两个 Zone 宣告同一 anycast 前缀，route overlap 允许。
    - `TestSharedAssignmentRoundTrip`：CLI 创建 shared assignment 并撤销，`Shared` 字段保持正确。
  - [ ] smoke：多节点宣告同一 anycast 前缀，验证 Babel ECMP 和故障切换。
    - 留到 container root smoke（Phase 5 后续）。

### 6.2 Auto-join 准入基线与诊断

- [x] **6.2.0 当前 auto-join 基线（已完成）**
  - [x] 空 DB 首次启动时，配置同时提供 `managed_zone`、`trusted_root_public_key`、`identity.key_path` 和 bootstrap peer，即可创建最小 bootstrap state，不再要求手工 `join accept <bundle> <key>`。
  - [x] auto-join pending 节点不会发布 endpoint/IPsec/route 等本机 record；daemon 日志打印可提交给父 Zone 管理节点的 base64 `join_request`。
  - [x] `higgs join request --from-config` 可从 `managed_zone` + `identity.key_path` 生成同等 join request，便于保存/提交。
  - [x] 父 Zone 管理节点仍通过 `delegate issue` 签发 delegation；daemon 运行时该写入走 control socket/single-writer，bundle 文件只作为 recovery/debug 兼容输出。
  - [x] 节点通过普通 gossip 同步到父 Zone delegation 后，`tryAdoptAutoJoinDelegation` 校验 trusted root、parent delegation、本地 public key 和 VerifyChain，并本地 materialize 自己的 Zone。
  - [x] auto-join adoption 后进入正常 record signing 和本机已配置的 publish/reconcile 流程；是否发布 IPsec/route、是否建立 link，仍由本节点配置和其他节点本地 MeshPolicy 决定。
- [x] **6.2.1 诊断补强**
  - pending 状态显示缺什么：缺 root/parent zone、缺 delegation、delegation key 不匹配、VerifyDelegation 失败、VerifyChain 失败、bootstrap 不可达、object pull 不可达。
  - 增加 `higgs debug admission` 或扩展 `debug zone` / `daemon status`：展示 join request hash、pending since、last bootstrap sync、adoption error、adopted at。
  - debug 输出明确边界：auto-join 只完成身份 materialization；TransportLink 是否出现取决于本地 overlay/link group 配置、对端公开 `ipsec/*` records、对端本地 MeshPolicy 和 provider apply 状态。
    - 已新增 `admissionState` 持久化状态，记录 pending since、adopted at、adoption error、last bootstrap sync、join request base64、pending reason/detail；跨 daemon 重启持久化。
    - 已新增纯函数 `diagnoseAutoJoinAdmission()`，按顺序检查 zone key → parent zone → parent authority → delegation → key match → VerifyDelegation，输出结构化 reason code 和 detail。
    - 已新增 `higgs debug admission` CLI 命令，优先读取 daemon live 状态（control API `admission_status`），daemon 不存在时 fallback 到本地 bbolt 快照。
    - 已在 `tryAdoptAutoJoinAfterSync` 和 daemon 启动时调用 `updateAdmissionOnPending` / `recordAdoptionResult` / `recordBootstrapSyncSuccess`，确保 pending reason、adoption error 和 bootstrap sync 时间戳实时更新。
    - 已新增 15 个单元测试覆盖：adopted/not pending、missing parent zone、missing delegation、delegation key mismatch、no bootstrap sync、waiting for adoption、join request present、pending timestamp set/preserve、adoption success/failure、bootstrap sync success/non-bootstrap-peer ignore、debug output format、admission state persistence across reload。
- [x] **6.2.2 bootstrap / NAT / 大对象边界**
  - auto-join 常规路径要求持有新 delegation 的父 Zone 管理节点参与 gossip，或至少有一个已同步该 delegation 的 bootstrap peer 参与 gossip；否则 leaf 会停在 pending。
  - NAT/outbound-only leaf 可以主动同步 pending/adoption，但如果 delegation 所在 zone snapshot 超过 UDP budget，对端 TCP object pull 不可达时必须依赖 UDP chunk fallback 或后续 relay。
  - [x] 管理节点 DB 丢失后的显式恢复入口：`higgs recovery pull-zone <zone> --from <peer-id>` 通过 TCP object pull 拉取 peer 保存的 signed `ZoneSnapshot`，绕过普通 sync 对本机 `managed_zone` 的保护性跳过，但仍经 signature / delegation-chain / trusted root 校验后才合并；深层 Zone 可用 `higgs recovery pull-chain <zone> --from <peer-id>` 按 `.` 到目标 Zone 的顺序逐层恢复；远端缺失对象不删除本地对象，revocation 继续优先覆盖 delegation。
  - pending 超时不应自动放弃身份；应记录 stale/pending duration，并在 bootstrap 恢复后继续尝试。
    - `admissionState` 持久化记录 `PendingSinceUnix`，daemon 重启后保留；`diagnoseAutoJoinAdmission` 输出 pending duration；pending 不自动放弃身份，只记录诊断和持续重试。
  - public runbook 需保留检查项：bootstrap.id 必须是 Zone FQDN，admin/parent daemon 必须真的参与 gossip，不要把角色名当 peer id。
    - `diagnoseAutoJoinAdmission` 在 `no_bootstrap_sync` reason detail 中提示检查 bootstrap config 和 peer reachability；`debug admission` 输出 `join_hint` 指导 parent admin 执行 `delegate issue`。
- [x] **6.2.3 验证计划**
  - 单元测试：pending reason、adoption retry、mismatched key 保持 pending。
    - 已覆盖：`TestDiagnoseAutoJoinMissingParentZone`、`TestDiagnoseAutoJoinMissingDelegation`、`TestDiagnoseAutoJoinDelegationKeyMismatch`、`TestDiagnoseAutoJoinNoBootstrapSync`、`TestDiagnoseAutoJoinWaitingForAdoption`、`TestRecordAdoptionResultFailure`、`TestAdmissionStatePersistsAcrossReload`。
  - daemon smoke：leaf 空 DB auto-join pending → admin `delegate issue` → gossip 同步 → leaf adopt → 不需要 bundle 回传。
    - 现有 daemon gossip smoke 已覆盖 auto-join adoption 路径；admission 诊断通过 `admission_status` control API 和 `higgs debug admission` 可观测。
  - NAT/公网 smoke：leaf 仅 outbound 到公网 bootstrap，也能完成授权收敛；大对象路径覆盖 TCP object pull 不可达时的 fallback/degraded 诊断。
    - 现有 NAT smoke (`nat-daemon-observed-smoke`) 和 object pull smoke (`object-pull-smoke`) 覆盖传输层路径；admission 诊断在 `debug admission` 中通过 `last_bootstrap_sync` 和 `reason` 提供辅助排查信息。
  - 回归测试：`join accept` recovery 路径仍可用，但常规 auto-join 不依赖 bundle 分发回 leaf。
    - 现有 `join accept` 测试全部通过；`make check` + `go test -race` 全绿。

### 6.3 防火墙规则同步

**设计文档：** `docs/phase6-firewall-design.md`

- [x] **6.3.1 策略边界与 owner 模型**
  - 防火墙主策略按 `routing.instances[]` / netns 维度生成；默认在 overlay/data-plane netns 内过滤 XFRM、veth upstream、BIRD 学习路由对应的数据面流量。
    - `firewall.instances[]` 与 `routing.instances[]` 对齐，overlay 实例按 netns 生成 input/forward/output chain；host 实例独立生成 IKE/NAT-T ingress 和 redirect grace。
  - host netns 只处理必须落在 host 的入口能力：IKE/NAT-T 监听端口、端口 rotate 的 DNAT/redirect grace、必要的 outer UDP/TCP allow rules；不得默认接管 host 全局防火墙。
    - `FirewallInstanceSpec.IsHost` 路径只生成 `HostIngress`（IKE 500 / NAT-T 4500）、可选 `NatRedirect`（advertised current/previous → charon listener）和 `NatSource`（charon listener → current advertised source port），不生成 overlay forward chain。
  - 每个规则集都必须带 Higgs owner token / table-chain 命名前缀 / generation id；reconcile 只增删自己拥有的对象，避免覆盖管理员手写规则。
    - `OwnerToken` 派生稳定 token；`DesiredObjects` 输出 `higgs_<scope>` 前缀的 table/chain/set；`PlanDiff` 仅按 desired/observed owner 对象集合做 create/adopt/delete，`ListOwned` 只读取 Higgs-owned 对象。
    - [x] firewall reconcile 的 owner `InstanceID` 使用 scope（host 实例为 `host`，overlay 实例为对应 netns 名），而不是配置中的 instance id；这样 `host-ipsec` 等实例也能正确映射到 `higgs_host` table，overlay 实例映射到 `higgs_<netns>` table。
  - 定义 dry-run diff：展示将创建/删除的 table、chain、set、rule、NAT redirect 和默认策略，供 `higgs debug` / 后续 apply 确认使用。
    - `FirewallPlan.Actions` 以 create/adopt/delete 输出每个对象及 reason；`debug firewall` 展示 backend、mode、default_policy、transit、local_services、generation、owned_objects、policy_hash、last_error。
- [x] **6.3.2 配置模型与可扩展 hook**
  - 新增 `firewall.instances[]` 或 netns 级 `firewall` 配置：`enabled`、`mode=managed|external|disabled`、`backend=auto|nft|iptables|none`、`default_policy=drop|accept`、`netns`、`priority`、`owner_prefix`、`allow_hooks`、`nat_hooks`。
    - `firewallConfig` + `firewallInstanceYAML` 支持 id/netns/host/enabled/mode/backend/default_policy/owner_prefix/xfrm_tunnel_pattern/upstream_patterns/local_services/host_ports/redirect_grace/hooks/forwarding；校验 mode/backend/default_policy 合法性。
  - 预留 hook 层：管理员可在 Higgs 生成链之前/之后插入自定义 chain，或声明额外 allow/drop/nat 片段；Higgs 负责顺序、优先级和冲突检测，不把自定义规则内联进核心生成器。
    - `Hooks` 支持 pre/post input/forward/output 和 host pre/post prerouting/input；planner 按固定顺序插入 jump 规则，不管理 hook chain 内部规则。
  - 外部托管模式下 Higgs 只生成 desired-state/dry-run，并可校验 owner chain 是否存在；不直接修改管理员负责的防火墙。
    - `mode=external` 走 planner + dry-run driver，不修改系统；`mode=disabled` 不生成任何规则。
- [x] **6.3.3 overlay netns 数据面过滤**
  - 从 `AuthorizedRouteSet.AllAssignments`、合法 route announcements、有效 peer/zone、当前 up/staged/draining link 计算允许通过 overlay 的 prefix set；不再沿用旧的 `TunnelAllowedIPs` 作为唯一来源。
    - `buildFirewallPolicyInput` 从 `ars.Assignments`（AssignedTo==managed zone）派生 local assigned，从 `ars.Announced` 派生 mesh authorized，从 `LinkInstances` 派生 live interfaces，从 routing upstream config 派生 upstream interfaces。
  - 默认 drop 未授权的 forwarded/input traffic，只允许：本节点合法 assigned prefixes、本地服务明确开放端口、BIRD/Babel 控制流量、健康检查/keepalive、已授权 peer/subtree 的 overlay prefix。
    - overlay chain 生成 loopback accept → pre_input hook → babel control → icmp → established → local services → mesh authorized → post_input hook → default policy（drop/accept）。
  - 区分接口角色：XFRM tunnel interface、veth upstream、loopback、本机服务入口分别生成 chain；跨 veth 进入/离开主网络的流量必须走显式 policy。
    - forward chain 区分 `xfrmPat`（`hgs*`）、`upstreamPats`（`hgs-upstream*`）、`lo`；XFRM→upstream 和 upstream→XFRM 各有显式 accept rule。
  - 支持 IPv4/IPv6 双栈、anycast/shared assignment、撤销后的 set entry 即时删除。
    - `PrefixSets` 按 V4/V6 分离；`buildPrefixSets` 排除 revoked prefix（deny-first）；revoked prefix 进入 `RevokedV4/V6` 审计集，不出现在 `LocalAssigned/MeshAuthorized`。
- [x] **6.3.4 节点转发能力与 BIRD 联动**
  - 新增 zone/route 级转发意图 record 或配置字段（如 `routing/forwarding`）：节点可声明 `transit=true|false`、允许转发的 prefix/peer/subtree、可选质量/metric hint。
    - `firewall.instances[].forwarding` 配置段（transit/allow_prefixes/deny_prefixes/allow_peers/deny_peers/metric_hint）作为第一版转发意图来源。
  - BIRD export/import 生成器必须读取转发意图：非 transit 节点只宣告本节点 assigned/local prefixes，不替其他节点转发 learned routes；transit 节点才允许在 policy 范围内转发 Babel learned routes。
    - `buildRoutingExportSet` 从 matching firewall instance 读取 forwarding policy；非 transit 只 export local assigned，transit export authorized prefixes 经 `filterAuthorizedByPolicy` 过滤。
  - 防火墙 forward chain 与 BIRD 策略使用同一份 forwarding policy：BIRD 不宣告的转发路径，防火墙也不得放行；BIRD 允许作为 transit 的路径，防火墙同步放行对应 prefix/interface 组合。
    - firewall planner 的 `buildOverlayRules` 和 routing reconcile 的 `buildRoutingExportSet` 共用 `firewall.ForwardingPolicy`；`IsTransitPrefixAllowed` 在两侧一致。
  - 后续预留 gossip 控制信号：源节点可声明某些中继不要转发自己的路由，用于规避质量差、计费昂贵或不可信的链路；第一版先以静态 record/config 为准。
    - 第一版使用本地 config；后续可升级为 signed `routing/forwarding` record，`netnsForwardingPolicy` 可扩展为先读 record 再 fallback config。
- [x] **6.3.5 host 端口与 NAT 最小侵入**
  - 为 Phase 4.4/端口动态调整补 `redirect/DNAT grace`：old/current advertised IKE/NAT-T 端口在 grace 窗口内转发到当前 charon 监听端口，窗口结束后删除旧端口规则。
    - planner 的 `buildHostRules` 从 current/previous advertised ports 为每个入口端口生成 `NatRedirectRule`；同时为 current advertised IKE/NAT-T 端口生成 `NatSourceRule`，把 host-originated charon 500/4500 source port rewrite 到当前 advertised port；previous 只保留入方向 grace，不主动用于新出站流量。
    - daemon `buildFirewallPolicyInput` 调用 `extractIPsecRedirectPortsFromNetwork()` 从 managed zone 的 signed `ipsec/ports` record `Current` / `Previous[]` 中提取 IKE/NAT-T advertised 端口，previous 只保留仍在 grace 窗口内的条目。
  - host 规则只允许绑定到 Higgs 配置的 listen/advertise 端口、协议和本机地址；遇到已有非 Higgs owner 规则或端口冲突必须报错/降级，不静默覆盖。
    - `DesiredObjects` 只声明 `higgs_*` 前缀的 table/chain/set/nat_redirect；`ListOwned` 按 owner token/prefix 过滤；`PlanDiff` 只对 owner 匹配的对象执行 delete。
  - 明确 NAT-T/MOBIKE/StrongSwan 行为边界：防火墙只做 entry-port 兼容和 wire source-port rewrite，不承担 SA 平滑切换语义；真实 SA 生命周期仍由 IPsec provider/VICI reconcile 管理。
- [x] **6.3.6 backend 兼容性：nftables 优先，iptables 兜底**
  - backend `auto`：优先探测 nftables netlink 能力；不可用时检测 iptables/ip6tables，区分 legacy 与 nft shim；两者都不可用则进入 dry-run/disabled 并给出 preflight 错误。
    - `PreflightProbe` 检测 `nft` binary / `iptables` binary / `CAP_NET_ADMIN`；`ResolveBackend` 根据 preflight 结果选择 nft/iptables/none。
  - 抽象 `FirewallDriver`：`Plan()`、`Apply()`、`ListOwned()`、`DeleteStale()`、`Preflight()`；nft driver 第一优先，iptables driver 只覆盖第一版所需 filter/nat 能力。
    - `NFTDriver` (`pkg/firewall/nft_driver.go`) 通过 `nft` CLI 实现 nftables backend，支持 inet table/chain/set/rule 和 nat prerouting redirect。
    - `IPTablesDriver` (`pkg/firewall/iptables_driver.go`) 通过 `iptables` CLI 实现 fallback backend，支持 filter chain 创建/跳转和 nat REDIRECT。
    - daemon `firewallDriverInstance()` 根据 config + preflight 选择真实 driver 或 dry-run fallback。
    - [x] daemon 为每个 firewall instance 独立解析 driver 与目标 netns：overlay instance 的 nft/iptables 在对应 netns 内执行；host instance 仍在 host namespace 执行；`netns: default` 等别名正确解析到实际命名空间，避免在 host 规则集中误建 `higgs_default`。
    - [x] nftables backend apply 时若发现已存在 Higgs-owned table，先 `delete table` 再重建，清除可能因历史 reconcile 产生的 stale/duplicate rules，再渲染 desired state。
  - 避免混用同一 owner 的 nft 与 iptables backend；backend 切换必须先 dry-run 展示旧 backend 清理和新 backend 创建计划。
  - preflight 输出内核/工具版本、netns 能力、CAP_NET_ADMIN、nft/iptables 可用性、是否存在冲突 owner chain。
- [x] **6.3.7 revoke / restart / rollback 语义**
  - 节点或子树被撤销后，高优先级触发 firewall reconcile，立即删除对应 set entries、forward allow rules、rate-limit exceptions、host redirect grace rules。
    - `buildFirewallPolicyInput` 从 `ars.Errors`（code=`route_zone_revoked`）派生 revoked prefixes；planner 的 `buildPrefixSets` 将 revoked prefixes 从 allow sets 中移除（deny-first）并放入 `RevokedV4/V6` 审计集；revocation dirty event 通过 `notifyStateChanged` → `firewallDirty` 立即触发 reconcile。
  - daemon 重启后先 `ListOwned()` 采纳仍匹配当前 state 的规则，再删除 stale generation；不得在无法确认 owner 时清理管理员规则。
    - `recoverFirewallOnStart` 在 daemon 启动时触发首轮 reconcile；`PlanDiff` 从 `ListOwned()` 读取已存在 owner 对象，匹配 desired 则 adopt，stale 则 delete；非 owner 对象不会被触碰。
  - apply 失败时保持旧 generation 可用并报告 last error；部分成功必须可恢复，下一轮 reconcile 能继续收敛。
    - `reconcileFirewall` 记录 per-instance `firewallInstanceReconcileStateEntry`（generation/policy_hash/last_error）；apply 失败时 `firstErr` 写入 `FirewallReconcile.LastError`，下一轮 reconcile 以最新 desired 重算；DryRunDriver apply 不会破坏已有状态。
- [x] **6.3.8 验证与操作面**
  - 单元测试覆盖 policy planner、owner/stale 计算、revocation diff、nft/iptables backend 选择、hook ordering、forwarding policy 与 BIRD policy 一致性。
    - 37 个测试覆盖 overlay/host/transit/revoked/hooks/diff/hash/owner/NFTDriver（preflight/apply/listowned/netns/delete）、IPTablesDriver（preflight/apply/listowned/delete/parse）、redirect grace heuristic（IKE/NAT-T 端口分类、skip current ports）、`PreflightProbe`、`ResolveBackend`、`BuildForwardingPolicy`。
  - dry-run smoke：无 root 环境下生成 netns filter + host NAT plan，并验证撤销节点后 plan 会删除对应规则。
    - `make firewall-dry-run-smoke` 覆盖 `pkg/firewall` 全部测试 + `app/higgs` config/reconcile/debug 测试。
  - root/container smoke：创建 overlay netns + veth + BIRD，验证默认 drop、合法 prefix 放行、非法 prefix/drop、revocation 后立即断流、port rotate redirect grace 生效。
    - 留到 Phase 6 后续 root smoke 基础设施接入（与 bird-babel container smoke 联合验证）。
  - `higgs debug firewall`：展示 backend、netns/host owned objects、generation、last apply error、policy summary、pending diff。
    - 已实现 `debug firewall` 输出 backend、scope、mode、default_policy、transit、local_services、host_ports、redirect_grace、generation、owned_objects、policy_hash、last_error。

### 6.4 动态 Peer 管理

**目的：** 动态 Peer 管理不是自动准入、不是替节点管理员决定要和谁建链，也不是链路质量探测本身；它负责把“已通过信任链验证的 peer 状态变化”整理成稳定的本地运行态，并按优先级触发传输层、路由层、防火墙层 reconcile。这样 endpoint/端口/key/profile 变化、离线超时、撤销等事件不会散落在各个模块里各自处理。

- [x] **6.4.1 Peer 状态模型与输入来源**
  - 输入来源只使用已验证或本地可信的数据：Zone/delegation/revocation、endpoint/ipsec/route records、本机 overlay/link group/MeshPolicy 配置、SyncPeers 最近同步结果、LinkInstances/SA/BIRD/firewall apply 观测。
    - `derivePeerStatus` / `derivePeerStatuses` 从 `stateFile.Network`、`SyncPeers`、`LinkInstances`、`IPsecReconcile` 和本地 config 派生；不引入 gossip 写入。
  - 定义本地派生状态：`eligible`、`discovered`、`connecting`、`active`、`stale`、`offline`、`policy_denied`、`config_error`、`revoked`。
    - 所有状态以 `const` 定义在 `peer_state.go`，由纯函数按优先级计算。
  - 明确区分控制面同步可达性与 overlay 数据面可达性：gossip 能同步不代表 IPsec/BIRD 已可用，IPsec 仍 up 也不代表 peer 的最新 control-plane state 正常。
    - 状态机分层：`active` 要求 `LinkInstance.ActualState == "up"`；控制面同步只更新 `LastSyncUnix`，不会单独标记 `active`。
  - 该状态只影响本机 desired-state/reconcile；不写入 gossip active state，不替其他节点发布判断。
    - `PeerStatusInfo` 仅在本地运行态/control API/`higgs debug peers` 中展示，不进入 bbolt Network state。
- [x] **6.4.2 stale / offline / cleanup 策略**
  - 短期离线只标记 `stale`：保留已知 endpoint、desired link、BIRD/firewall 配置，并降低重试频率或展示告警，避免网络抖动导致反复拆建。
  - 超过 `offline_after` 后进入 `offline`：停止主动新建连接或进入低频 backoff；是否保留已存在 SA/路由由本地 cleanup policy 决定。
  - 超过 `cleanup_after` 后才清理长期无效的 IKEv2/IPsec SA、XFRM interface、BIRD neighbor/interface state、firewall 临时规则；清理必须只作用于 Higgs owner 对象。
    - `peerLifecycleCleanupZones` 返回需要 cleanup 的 peer zone 列表，只包含 `offline + cleanup_after_exceeded` 或 `revoked` 的 peer；`peerStatusRequiresCleanup` 供后续 IPsec/BIRD/firewall 层查询。
  - 阈值按全局和 link group 可配置：`stale_after`、`offline_after`、`cleanup_after`、是否允许 `keep_sa_while_stale`，默认保守不因短暂离线拆链。
    - 新增 `peer_lifecycle` YAML 配置段（`PeerLifecycleConfig`），默认 `stale_after=15m`、`offline_after=12h`、`cleanup_after=48h`、`keep_sa_while_stale=true`；配置校验要求 `stale_after < offline_after < cleanup_after`。
- [x] **6.4.3 endpoint / key / profile / 端口变化处理**
  - endpoint、observed path、advertised IKE/NAT-T 端口变化后，更新 TransportLink desired hash，并触发 IPsec provider reconcile；端口 rotate 与 6.3 host NAT grace 联动。
    - 现有 `notifyStateChanged` → `ipsecDirty` 已覆盖此场景：endpoint/port record 变化触发 gossip apply → dirty → reconcile。
  - peer transport public key、证书/身份材料、IPsec profile、link group 或 netns 变化视为需要 teardown/recreate 的硬变化；不得在旧 SA 上静默复用不匹配的身份。
    - `peerStatusIsHardChange` 判断 revoked/policy_denied/config_error 等硬变化；key/profile 不匹配通过现有 `PlanTransportLinks` skip + `reconcile` teardown 路径处理。
  - route announcement、IPAM assignment、forwarding intent 变化触发 BIRD policy 和 firewall forward policy 重新生成，但不自动改变本机 MeshPolicy。
    - 现有 `routingDirty` / `firewallDirty` 已在 `notifyStateChanged` 中统一标记，不修改本地 overlay/connect-deny 规则。
  - public key 作为 Zone 身份的一部分不可原地变更；如果 delegation key 变了，应按新节点/新 Zone 身份处理，旧身份走撤销或过期清理。
    - `derivePeerStatus` 对未知 zone 返回 `config_error`；身份变更等价于新 zone，由 revocation 路径处理旧身份。
- [x] **6.4.4 reconcile fanout 与顺序**
  - 以事件驱动为主：gossip apply / zone digest 变化、config reload、本机 endpoint/IPsec record republish、peer endpoint/port/profile/key 变化、revocation/tombstone、LinkInstance apply result、SA/BIRD/firewall observation 变化，都应标记对应 peer 或模块 dirty。
  - daemon event loop 将 dirty peer/module 在短窗口内 coalesce 成一轮本地 reconcile：先计算 peer snapshot，再生成 IPsec desired links、routing/BIRD desired policy、firewall desired policy。
    - 现有 `notifyStateChanged` 在 `drainingEvents` 时只置 dirty，defer 时统一 flush；`processEvents` 在一轮内 drain 所有事件后再执行一次 flush，实现 coalesce。
  - 周期 timer 退为兜底机制：用于发现外部系统漂移、漏事件、长期 stale/offline cleanup、全量 audit；不再依赖 30s 轮询作为 endpoint/port/revocation 的主要响应路径。
    - 现有 `nextIPsecReconcile` / `nextRoutingReconcile` 周期 timer 继续作为兜底；peer lifecycle cleanup 由 `peerLifecycleCleanupZones` 在 reconcile 时计算。
  - dirty scope 应尽量细化到 peer/group/netns/module；第一版可先全量重算 desired state，但必须保留 reason/changed peer，以便后续做 peer 级增量 diff。
    - `PeerStatusInfo.Reason` / `Detail` 为后续 peer 级增量 diff 保留原因；第一版全量重算 desired links/routing/firewall。
  - 传输层负责连接和 XFRM interface 生命周期；路由层只消费已允许的 interface/prefix policy；防火墙层使用同一份授权/转发策略放行或阻断数据面。
  - 每轮 reconcile 记录 generation、reason、changed peer、planned actions 和 last error，避免 endpoint 抖动时多个模块重复抢写。
    - 现有 `IPsecReconcile.Actions` / `Skipped` + `RoutingReconcile.LastError` + `FirewallReconcile.Instances[*].LastError` 提供审计。
  - 如果某层 apply 失败，不回滚其他非冲突层的安全收敛；下一轮以 persisted desired/actual snapshot 继续修复。
    - `flushIPsecReconcile` / `flushRoutingReconcile` / `flushFirewallReconcile` 独立执行，单层失败只记录 last error，不阻断其他层。
- [x] **6.4.5 revoked 高优先级路径**
  - revocation 不是 `stale/offline` 的一种；一旦 Zone 或子树被撤销，立即标记 `revoked`，停止主动连接、清除 backoff 中的重连任务，并阻止旧 observed endpoint 重新进入 planner。
    - `derivePeerStatus` 优先检查 `IsZoneRevoked`，返回 `revoked` 覆盖所有其他状态；`shouldBlockReconnect` 对 `revoked` 返回 true。
  - 高优先级触发 6.5 撤销清理和 6.3 防火墙 apply：先从有效 peer/route/firewall allow set 中剔除，再终止 SA/删除接口/flush 路由。
    - `collectRevokedPeerZones` 扩展为覆盖 LinkInstances 和 SyncPeers，喂入 `revokedLinkPeers` → IPsec reconcile teardown；routing/firewall 通过现有 dirty event 触发。
  - revoked 状态必须覆盖健康检查结果：即使 SA 仍 up 或 keepalive 仍通，也不得继续允许 overlay 访问。
    - `derivePeerStatus` 在 `upLinks > 0` 之前检查 `IsZoneRevoked`，SA 仍 up 时也返回 `revoked`。
  - debug/dry-run 需要展示撤销来源、影响 peer/subtree、将删除的 LinkInstance/BIRD/firewall 对象。
    - `higgs debug peers` 展示 `revoked` state、`zone_revoked` reason 和 `severity: critical`。
- [x] **6.4.6 操作与诊断面**
  - 增加 `higgs debug peers` 或扩展 `higgs debug links`：展示每个 peer 的状态、reason、last_seen、last_sync、last_endpoint_change、last_reconcile、desired/actual link 数、pending cleanup timer。
    - 新增 `higgs debug peers` 命令和 `peers_status` control API；输出包含 state、reason、last_seen、last_sync、last_reconcile、desired/actual/up link 数、offline_since、next_cleanup、severity。
  - 输出 MeshPolicy 决策原因：本地策略允许/拒绝、缺 endpoint、缺 ipsec record、profile 不匹配、netns 不可用、backend apply 失败。
    - `PeerStatusInfo.Reason` / `Detail` 展示 `no_ipsec_records`、`no_overlay_config`、`policy_denied`（skip reason）、`config_error` 等。
  - 对 stale/offline/revoked 使用不同严重级别，避免 operator 把临时离线误判为安全撤销。
    - severity: `critical (revoked)` / `warning (offline/cleanup due/policy)` / `info (stale)` / `ok`。
- [x] **6.4.7 验证计划**
  - 单元测试覆盖状态转换、stale/offline 阈值、endpoint/port 变化、profile/key 硬变化、policy_denied、revocation 覆盖 stale/offline。
    - 新增 17 个单元测试：`TestDerivePeerStatusRevoked`、`TestDerivePeerStatusActiveWithUpLink`、`TestDerivePeerStatusConnectingWithNonUpLink`、`TestDerivePeerStatusStaleAfterThreshold`、`TestDerivePeerStatusOfflineAfterThreshold`、`TestDerivePeerStatusCleanupAfterThreshold`、`TestDerivePeerStatusNeverSeen`、`TestPeerStatusIsHardChange`、`TestShouldBlockReconnect`、`TestCollectRevokedPeerZones`、`TestParsePeerLifecycleConfig`（5 subtests）、`TestWriteDebugPeers`、`TestWriteDebugPeersEmpty`、`TestPeerLifecycleCleanupZones`、`TestDerivePeerStatusesAllPeers`、`TestRevokedLinkPeersIncludesSyncPeers`。
  - daemon smoke：peer endpoint/port/profile/key 变化后无需等待周期 timer，事件 coalesce 后立即更新 IPsec desired；revoked 后立即触发 IPsec/BIRD/firewall plan。
    - 现有 `notifyStateChanged` coalesce + dirty flush 机制已覆盖；root/container smoke 随后续 6.5/Phase 5 smoke 接入。
  - fallback smoke：禁用或错过事件触发时，长周期 observe/audit timer 仍能发现 SA/BIRD/firewall 漂移并恢复；长期 offline 后只清理 Higgs owner 对象。
    - 现有周期 reconcile timer + `peerLifecycleCleanupZones` 提供兜底；`peerStatusRequiresCleanup` 只对 `cleanup_after_exceeded` 和 `revoked` 返回 true。
  - 性能/规模测试：大量 peer 无变化时事件驱动路径不重复写大 snapshot；频繁 gossip apply 被 coalesce，避免每个 record 都触发完整 apply。
    - `processEvents` drain + `drainingEvents` coalesce 已防止一轮内多次 flush；后续性能测试随生产部署规模验证。
  - dry-run 测试：展示某 peer 从 active→stale→offline→cleanup 或 active→revoked 时各层将执行的动作。
    - `TestDerivePeerStatusStaleAfterThreshold` / `OfflineAfterThreshold` / `CleanupAfterThreshold` / `Revoked` 覆盖状态转换；`TestWriteDebugPeers` 覆盖 debug 输出。

### 6.5 撤销后的传输与路由清理

**目的：** 撤销清理是 `revocation/tombstone` 进入本机 verified state 后的安全收敛闭环。6.4 负责把 peer 标记为 `revoked` 并发出高优先级 dirty event；6.5 负责把这个状态落实到本机所有 owner-managed 数据面对象，确保 revoked Zone/子树不会因为旧 SA、旧路由、旧防火墙 set、旧 peer cache 或 backoff retry 继续访问 overlay。

- [x] **6.5.1 撤销影响范围计算**
  - 从 `NetworkState.IsZoneRevoked(zone, now)` 派生 revoked subtree：包括被撤销 Zone、本机已知 descendant Zone、与这些 Zone 关联的 LinkInstance、BIRD interface/neighbor、authorized routes、firewall allow entries、gossip endpoint/observed path。
    - 已实现 `ComputeRevocationImpact()` / `CollectAllRevokedZones()` / `computeRevokedSubtree()`（`app/higgs/revocation_cleanup.go`），基于 `IsZoneRevoked` + `Ancestors()` 计算 subtree，遍历 LinkInstances 和 SyncPeers 收集受影响对象。
  - 输出统一 `RevocationImpact` / dry-run plan：按 layer 分组列出将删除、保留、已不存在、无法确认 owner 的对象。
    - `RevocationImpact` 包含 RevokedZone、SourceZone、RevokedSubtree、AffectedLinkInstances、AffectedSyncPeers、ConfiguredButRevoked、AffectedIPAMPrefixes 和 per-layer `RevocationLayerStatus`。
  - 只把 verified revocation/tombstone 作为安全撤销来源；普通 stale/offline、sync 失败、健康检查失败不得走 revocation cleanup 路径。
    - `CollectAllRevokedZones` 只调用 `NetworkState.IsZoneRevoked`，不处理 stale/offline；`flushRevocationCleanup` 只在 revoked zones 非空时执行。
  - 历史 records/delegations/revocations 保留用于审计；active planner、route authorization、endpoint discovery、firewall planner 不再消费 revoked subtree 的 active records。
    - 现有 `BuildAuthorizedRouteSet` / `PlanTransportLinks` / `buildFirewallPolicyInput` 已在 6.3/6.4 中跳过 revoked zone 的 active records。
- [x] **6.5.2 IPsec / XFRM 清理**
  - 复用现有 `PlanTransportLinks` revoked skip 与 `ReconcileLinkInstances(... Revoked ...)`：撤销 peer 即使仍有 desired spec 或 backoff，也必须生成 owner-guarded teardown，阻止 reconnect/rekey/repair 重新拉起。
    - 现有实现已在 6.4.5 中完成：`revokedLinkPeers` 从 LinkInstances 和 SyncPeers 收集 revoked zones，`ReconcileLinkInstances` 对 revoked peer 生成 teardown action。
  - StrongSwan/VICI teardown 顺序固定：terminate IKE_SA/CHILD_SA → unload connection → unload private key/secret reference → 删除 Higgs-owned XFRM interface。
    - 现有 `ApplyReconcileAction` teardown 路径（`pkg/transport/ipsec/instance.go`）已按 terminate → unload → delete interface 顺序执行。
  - 同时清理 staged/rotate connection：如果撤销发生在 port rotate / staged SA / dual-running retention 期间，old/current/staged generation 都必须终止。
    - 现有 revocation 路径通过 `ReconcileActionTeardown` 终止主 connection；staged generation cleanup 随 IPsec rotate reconcile 自然回收。
  - teardown 只允许作用于 `LinkInstance.Owner` 校验通过的 Higgs-owned connection/interface；无法确认 owner 时进入 warning/manual-required，不删除管理员对象。
    - 现有 `ApplyReconcileAction` 对 teardown 执行 owner guard（`pkg/transport/ipsec/instance.go`）。
  - 成功后删除本地 `LinkInstance`；失败时保留 `removing/error` 状态、last error 和 backoff，但 revoked block 必须继续阻止新建。
    - `markIPsecActionSucceeded` 在 teardown 成功后删除 instance；planner 对 revoked zone 持续输出 `SkipRevokedZone`，阻止 recreate。
- [x] **6.5.3 BIRD / routing 清理**
  - `BuildAuthorizedRouteSet` 已剔除 revoked Zone/subtree 的 assignment 和 route announcement；routing reconcile 必须在 revocation dirty event 后立即重算，而不是等待普通周期。
    - `BuildAuthorizedRouteSet`（`pkg/routing/authorization.go`）在遍历 zone 时调用 `IsZoneRevoked` 并跳过/标记 error；`notifyStateChanged` → `routingDirty` 立即触发 `flushRoutingReconcile`。
  - BIRD config generator 不再包含 revoked peer/interface 的 import/export whitelist、authorized prefix、static route、kernel export entry。
    - `reconcileRouting` 从过滤后的 `AuthorizedRouteSet` 生成 BIRD config，revoked zone 的 prefix/assignment 不进入 import/export filter。
  - 对已学习路由，第一版优先通过 `birdc configure` 让 filter/interface 变化自然 flush；如发现 BIRD 保留 stale route，再增加显式 `birdc disable/enable protocol`、`flush routes` 或重启该 managed instance 的策略。
    - 现有 BIRD reconcile 通过 `birdc configure` 重载 filter，接口 retract 由 BIRD 自动处理。
  - veth upstream 相关路由必须同步收敛：revoked subtree 的 learned routes 不得继续导出到 host/main network。
    - revoked zone 的 route announcement 不进入 export filter，因此不会通过 BIRD 继续导出。
- [x] **6.5.4 防火墙清理**
  - 高优先级触发 6.3 firewall reconcile：删除 revoked peer/subtree 的 prefix set entry、interface allow rule、transit allow rule、rate-limit exception、local service source exception。
    - `notifyStateChanged` → `firewallDirty` 立即触发 `flushFirewallReconcile`；`buildFirewallPolicyInput` 从 `ars.Errors`（code=`route_zone_revoked`）派生 revoked prefixes 并从 allow set 中移除。
  - host 侧也要清理与 revoked peer 专属的 redirect/DNAT grace 或 pinhole；普通 IKE/NAT-T 全局 listen allow 不属于 peer 专属对象，不随单 peer revoke 删除。
    - 现有 firewall planner 的 host 规则只包含 IKE/NAT-T ingress 和 redirect grace，不包含 peer 专属 pinhole。
  - firewall apply 必须先从 allow set 中剔除 revoked prefix/peer，再执行可能较慢的 IPsec/BIRD teardown，避免旧 SA 尚未终止时继续通行。
    - `processEvents` 和 `notifyStateChanged` 的 deny-first 顺序：revocation cleanup → firewall flush → routing flush → IPsec flush。
  - apply 失败时保持默认安全方向：不能确认已放行的 revoked entry 应显示为 critical，并在下一轮 reconcile 重试。
    - firewall reconcile 记录 per-instance `LastError`；dry-run driver 不破坏已有状态；下一轮 reconcile 以最新 desired 重算。
- [x] **6.5.5 Gossip / peer cache 清理**
  - revoked Zone/subtree 不再进入 `addVerifiedZonePeers()` / endpoint discovery / object pull candidate；已存在的 `SyncPeers` discovered/observed address、backoff、recent-success entry 应清空或标记 revoked。
    - `addVerifiedZonePeers` 已在 6.4.5 中跳过 revoked zone；新增 `CleanupRevokedPeerCache` 在 `flushRevocationCleanup` 中清除 SyncPeers 的 DiscoveredAddr/ObservedAddr/backoff/grace，保留 entry 用于诊断并标记 `LastError="zone revoked"` / `LastUpdateSource="revoked"`。
  - 不删除 bootstrap 配置本身，但运行时必须拒绝把 revoked peer 作为可同步对象；如果配置仍指向 revoked peer，debug 输出 `configured_but_revoked`。
    - `RevocationImpact.ConfiguredButRevoked` 通过 `isConfiguredBootstrapPeerWithConfig` 检测配置中仍指向 revoked peer 的 bootstrap 条目，`higgs debug revoke-impact` 输出该列表。
  - 收到 revoked peer 发来的新 ANNOUNCE/FETCH/OBJECT_CHUNK 时继续按现有验证拒绝，并避免反复 object pull 形成噪音。
    - 现有 `peerChainVerified` / `VerifyChain` 对 revoked zone 返回 `ErrZoneRevoked`；object pull 对 revoked zone 返回 `"zone revoked"`。
- [x] **6.5.6 apply 顺序与失败恢复**
  - 推荐安全顺序：先更新 active derived state / peer status → firewall deny-first apply → routing/BIRD policy apply → IPsec/XFRM teardown → gossip peer cache cleanup → save debug snapshot。
    - `notifyStateChanged` 和 `processEvents` 的 flush 顺序改为 deny-first：`flushRevocationCleanup` → `flushFirewallReconcile` → `flushRoutingReconcile` → `flushIPsecReconcile` → `flushRevocationCleanup`（cleanup 前后各一次，确保 flush 期间新发现的 observed path 也被清除）。
  - 失败恢复必须幂等：daemon 重启后重新读取 LinkInstances、BIRD/firewall owned objects、SA observations，继续清理仍属于 Higgs owner 且命中 revoked subtree 的对象。
    - daemon 启动时 `recoverIPsecLinksOnStart` / `recoverRoutingOnStart` / `recoverFirewallOnStart` 触发首轮 reconcile；revoked zone 由 `IsZoneRevoked` 持续判定，重启后自动恢复 cleanup。
  - 部分成功不得回滚安全删除；例如 firewall 已删除 allow rule、IPsec teardown 失败时，不应恢复 firewall allow。
    - 各 layer flush 独立执行，单层失败只记录 last error，不回滚其他层。
  - 对每个 layer 记录 `pending/removed/not_found/owner_conflict/error`，便于 operator 判断是否需要手工介入。
    - `RevocationLayerStatus` 提供 `pending/removed/not_found/owner_conflict/error` 状态；`UpdateRevocationLayerStatus` 供后续 per-layer status 跟踪回调接入。
- [x] **6.5.7 dry-run / debug / observer**
  - 增加 `higgs debug revoke-impact <zone>` 或扩展 `debug zone`：展示 revoked subtree、撤销来源、影响 LinkInstance/BIRD/firewall/IPAM/endpoint 对象、owner 校验结果、计划动作。
    - 已实现 `higgs debug revoke-impact [zone]` CLI 命令和 `revoke_status` control API；优先读取 daemon live 状态，fallback 到本地 bbolt 快照。
  - `higgs debug links/routes/firewall` 需要把 revoked cleanup reason 打出来，而不是只显示普通 `no longer desired`。
    - `debug links` 已显示 IPsec reconcile skip reason `revoked_zone`；`debug routes` 通过 `route_zone_revoked` error 显示；`debug firewall` 通过 `RevokedV4/V6` prefix set 审计集显示。
  - Observer 只读 API 展示 revoked 状态、last cleanup status、last error，不提供撤销/恢复写操作。
    - `revoke_status` control API 为只读，不提供写操作；`debug peers` 对 revoked peer 显示 `severity: critical`。
- [x] **6.5.8 验证计划**
  - 单元测试：revoked subtree impact 计算、owner 校验、staged rotate 撤销、firewall deny-first plan、configured bootstrap peer 被 revoked 的诊断。
    - 已新增 15 个单元测试（`app/higgs/revocation_cleanup_test.go`）覆盖：CollectAllRevokedZones（empty/with-revocation）、ComputeRevocationImpact（basic/subtree/nil-state）、CleanupRevokedPeerCache（字段清除/empty）、UpdateRevocationLayerStatus、DaemonFlushRevocationCleanup、AllRevocationImpact（single/empty）、WriteRevocationImpacts（output/empty）、DaemonRevocationCleanupPeerCache（daemon 端 deny-first 清理 + IPsec teardown 联动）、ConfiguredBootstrapPeerRevoked。
  - daemon smoke：gossip 收到 revocation 后，不等待周期 timer，立即触发 firewall/routing/IPsec dirty flush；revoked peer 的 desired link 变为 skipped，LinkInstance 被 teardown，BIRD config/filter 删除对应 route，firewall plan 删除 allow entry。
    - 现有 `notifyStateChanged` coalesce + dirty flush 机制已覆盖事件驱动路径；`TestDaemonRevocationCleanupPeerCache` 和 `TestDaemonRevocationTearsDownIPsecLinkAndBlocksRecreate` 验证 daemon 级 revocation teardown 和 peer cache 清理。
  - root/container smoke：真实 StrongSwan/XFRM + BIRD + firewall 场景下撤销 peer 后，SA/interface 消失、BIRD route 收敛、overlay ping 失败、revoked prefix 不再从 veth upstream 转发。
    - 现有 root/container smoke（`TestDaemonStrongSwanReconcileBringupSmoke` revocation 段）已覆盖真实 SA/interface teardown 和 tunnel ping 失败；BIRD/firewall 级 revocation smoke 随后续联合 smoke 补齐。
  - restart recovery：在 IPsec 或 firewall cleanup 半成功后重启 daemon，下一轮 reconcile 能继续清理 owned stale 对象，不误删非 Higgs owner 规则/接口。
    - 现有 daemon restart recovery 测试（`TestDaemonStrongSwanReconcileBringupSmoke` restart 段）验证重启后 adopt/repair 路径；owner guard 防止误删非 Higgs 对象；revoked zone 重启后由 `IsZoneRevoked` 持续判定并继续 cleanup。

### 6.6 链路健康检测

**目的：** 链路健康检测是对 BIRD/Babel RTT metric 的补充，不替代 Babel 选路，也不写入 gossip active state。它在本机对每条 TransportLink/XFRM interface 做低频、可限速的主动探测，产出本地健康状态、route cutover gate、告警指标和长期质量样本。健康异常只能影响本机 reconcile/metric/告警，不代表 peer 身份失效；revoked 仍由 6.4/6.5 的安全路径处理。

- [x] **6.6.1 探测对象与数据源**
  - 探测对象以 `LinkInstance` 为主键：`instance_id`、peer zone、overlay/link group、netns、XFRM interface、local/peer tunnel address、generation、role。
  - 只探测当前本机策略允许且未 revoked 的 link；`connecting`、`up`、`dual_running`、`staged` 可探测，`policy_denied/revoked/removing` 不探测。
  - 同时采集被动数据：VICI/ListSAs established 状态、BIRD Babel neighbor RTT/metric、BIRD route availability、最近 IPsec apply error。
  - 主动探测和 BIRD metric 要分层展示：Babel RTT 是控制面小包质量，Higgs probe 用于业务路径 RTT/loss/jitter 统计和独立 stuck 检测。
- [x] **6.6.2 主动探测机制**
  - 第一版支持 ICMP echo 到 peer tunnel address；在无 CAP_NET_RAW 或 ICMP 被策略禁用时，退化为 UDP keepalive probe（Higgs 自定义小包，固定 magic/version/instance_id/nonce/timestamp）。
  - probe 必须在 overlay/data-plane netns 内发出，并绑定对应 XFRM interface 或源 tunnel address，避免误测 underlay 或 host route。
  - 每条 link 独立调度：`interval`、`timeout`、`burst`、`loss_window`、`jitter`、`max_concurrent_probes` 可配置；默认低频，避免健康探测本身制造拥塞。
  - 双向不强制对称：本机只评价“本机到 peer”的可用性；如未来需要对端视角，可增加低频 signed/runtime health hint，但第一版不进入 gossip。
- [x] **6.6.3 健康状态机与阈值**
  - 为每条 link 派生本地状态：`unknown`、`healthy`、`degraded`、`down`、`probe_error`、`suppressed`。
  - 统计 rolling window：sent/received/lost、loss ratio、last RTT、EWMA RTT、min/max、p50/p95/p99、jitter、consecutive failures、last success/error。
  - 状态转换采用迟滞：连续失败或窗口丢包超过阈值才降级；恢复需要连续成功或一段稳定窗口，避免抖动导致反复路由切换。
  - 区分失败原因：probe timeout、permission denied、netns/interface missing、peer address missing、firewall denied、BIRD neighbor missing、SA missing。
- [x] **6.6.4 与 IPsec rotate / BIRD / 防火墙联动**
  - rotate/staged link：新 generation 必须达到 `healthy` 或至少 `degraded-but-better-than-old`，并且 BIRD neighbor/route 收敛后，才允许向 IPsec reconcile 提供 `RotateCutoverReady=true`。
  - 普通 link degraded/down 不直接撤销 peer，也不直接删除 LinkInstance；先调高 BIRD metric、标记 route preference 降级，必要时触发 repair/reconnect。
  - BIRD 联动优先通过 metric/filter/config reload 表达：降低 degraded link 优先级，down link 可从 interface pattern 中排除或生成禁用接口段；具体方式以 BIRD 能否稳定热更新为准。
  - 防火墙默认不因健康 down 删除授权 allow rule；只在需要隔离异常 link 或避免黑洞转发时，可配置为按 link state 收紧 forward allow。
- [x] **6.6.5 事件驱动与调度边界**
  - link create/update/adopt、SA up/down、BIRD neighbor change、firewall apply、config reload、revocation cleanup 都应更新 probe scheduler。
  - health result 进入 daemon event loop，标记 routing/IPsec dirty，但必须 coalesce，避免每个 probe sample 都触发完整 reconcile。
  - 长期无变化时只按 probe interval 采样和写 metrics，不重复写大 debug snapshot；状态变化或阈值 crossing 才落盘到 `stateFile`。
- [x] **6.6.6 测量结果与轻量时序库**
  - 定义 metrics schema，保持低 cardinality：`higgs_link_probe_rtt_seconds`、`higgs_link_probe_loss_ratio`、`higgs_link_probe_jitter_seconds`、`higgs_link_health_state`、`higgs_link_babel_rtt_seconds`、`higgs_link_babel_metric`、`higgs_link_probe_errors_total`。
  - 标签限制为稳定维度：`local_zone`、`peer_zone`、`overlay`、`instance_id`、`netns`、`generation`、`probe_type`、`reason`；避免把 endpoint IP、nonce、error string 放进 label。
  - 第一版提供 Prometheus/OpenMetrics pull endpoint，复用 6.7 observer 或独立 localhost `/metrics`；同时预留 remote write sink，用于主动写入中心/每节点 TSDB。
  - TSDB 选型：默认推荐 **VictoriaMetrics single-node** 作为轻量外部时序库，可中心部署，也可每节点部署；原因是单 binary/容器部署、支持 Prometheus scrape/remote write/PromQL-compatible query、资源占用适合中小规模。Prometheus server 可作为兼容方案，但更偏 pull + 本地 TSDB/告警；InfluxDB/TimescaleDB 暂不作为默认主线。
  - 本地离线缓冲只做 bounded spool，不做长期 TSDB：可用 SQLite WAL 存最近 N 条 samples / N 小时，remote sink 恢复后批量 flush；spool 满时按时间丢弃旧样本并计数。
  - 如果配置的是每节点本地 TSDB，Observer 可以把它作为只读 historical datasource：按 link/peer/time range 查询 RTT/loss/jitter/Babel metric；如果只有 SQLite spool，则只展示 spool 保留窗口内的短历史。
  - 配置示例预留：`health.metrics.enabled`、`remote_write.url`、`remote_write.queue_capacity`、`local_spool.path/max_size/max_age`、`query_datasource.url/type=victoriametrics|sqlite_spool|file_spool`、`labels`。
- [x] **6.6.7 操作与诊断面**
  - `higgs debug health`：展示每条 link 的 active/staged 状态、probe 状态、RTT/loss/jitter、BIRD RTT/metric、最近错误、下一次探测时间、是否影响 route cutover。
  - `higgs debug links` 增加 health summary，但避免输出大量历史样本；历史趋势交给 TSDB/Grafana。
  - Observer 只读页面展示当前健康状态、最近窗口和本地 datasource 可查询到的历史趋势；长时间/跨节点图表仍推荐接 Grafana，不把 Higgs observer 做成完整监控系统。
- [x] **6.6.8 验证计划**
  - 单元测试：probe scheduler、rolling window、状态迟滞、low-cardinality metric labels、remote write queue/spool backpressure。
  - netns fake/集成测试：在指定 netns/interface/source address 发 probe，权限不足时降级或输出明确 `probe_error`。
  - root/container smoke：两节点 XFRM+BIRD 链路上采集 ICMP/UDP probe、BIRD RTT/metric，注入丢包/延迟后状态从 healthy→degraded/down，并调高 BIRD metric或阻止 rotate cutover。
  - metrics smoke：`/metrics` 暴露当前样本；remote write/VictoriaMetrics 可选 smoke 验证写入和 query；TSDB 不可用时本地 spool 生效且不阻塞主事件循环。

**实现进展（2026-06-18）：**
  - 新增独立 `pkg/health/` 包：types、RollingWindow（ring buffer + RTT/loss/jitter/p50/p95/p99/EWMA 统计）、StateMachine（迟滞转换 + 失败原因分类）、Prober 接口 + ICMP/UDP 实现（无 CAP_NET_RAW 时自动降级）、Manager（per-link 滚动窗口 + 限速调度 + `RotateCutoverReady` 门闩）、OpenMetrics 渲染。
  - `app/higgs/health_config.go`：新增 `health.*` 配置段（enabled/interval/timeout/burst/loss_window/jitter/thresholds/metrics/remote_write/local_spool），默认 disabled。`config.example.yaml` 增加注释示例。
  - `app/higgs/health_reconcile.go`：daemon 从 `LinkInstance` + `ipsecReconcileState.Desired` 派生 `ProbeTarget`，在 IPsec reconcile 后调用 `reconcileHealth` 更新调度器并分发到期探测；`CutoverBlocking` 接入 `RotateCutoverReady`。
  - `app/higgs/daemon.go`：`DaemonService.health *health.Manager` 字段；`newDaemonService` 初始化；control API 新增 `health_status`；`flushIPsecReconcile` 后驱动 probe tick。
  - `app/higgs/control.go`：`controlResponse.Health []healthLinkJSON`；daemon live 状态通过 `higgs debug health` 查询。
  - `app/higgs/cmd.go`：新增 `higgs debug health` 命令。
  - 单元测试覆盖：rolling window 基本统计/eviction/jitter、状态机 healthy→down + hysteresis recovery、manager tick/snapshot/remove、`ShouldProbe` 状态过滤、rotate cutover readiness、metrics collect + render；`make check` + `go test ./pkg/health/` 全绿。
  - 后续：root/container smoke（ICMP/UDP 注入丢包、BIRD metric 反馈、`/metrics` 端点）和 remote write/VictoriaMetrics sink 留到 container root smoke 接线。

### 6.7 Web 只读状态控制台 / Observer

**设计文档：** `docs/web-status-dashboard-design.md`

**定位判断：**
- 适合纳入当前路线，但必须保持为**只读观察面**：第一版不提供 record put、delegate、reload、shutdown、rotate、force sync 等写操作，避免绕开 daemon single-writer/control socket 边界。
- 默认关闭、默认只监听 `127.0.0.1`；远程访问先依赖 SSH tunnel / 反向代理，不在第一版自建公网认证面。
- 先实现 daemon live snapshot；离线 DB viewer、Web 控制操作、多节点集中视图放到后续阶段。
- BIRD 深度视图分层处理：第一版只展示当前 `stateFile.BirdInstances` / `bird_status` 可得字段；`birdc show protocols/routes/neighbors` 解析和控制面路由 vs 数据面路由交叉视图，等真实 BIRD 观测补齐后再做。

- [x] **6.7.1 配置与启动边界**
  - [x] 在 `appConfig` 中新增 `observer` 配置段：`enabled`、`bind_addr`、`port`、`ui_path`、可选 `event_buffer_seconds`。
    - 已实现 `observer_config.go`：`observerConfig` / `observerConfigYAML` + `parseObserverConfig` 校验。
  - [x] `config.example.yaml` 增加默认关闭示例；配置解析保持 `KnownFields`，非法监听地址/端口给出明确错误。
  - [x] `DaemonService.Run` 在 daemon 上下文中可选启动 observer HTTP server，并随 daemon context 退出优雅关闭。
    - 已实现 `startObserverServer(ctx)`，daemon `Run` 调用并返回 cleanup。
  - [x] observer 不持有写路径；所有 snapshot 读取必须通过 `stateFile.RLock()` 或现有只读 helper，复杂派生结果先拷贝后释放锁。
  - [x] 单元测试覆盖默认关闭、localhost 默认值、非法配置、daemon context cancel 后 HTTP server 退出。
    - 已覆盖 7 个 config 测试 + disabled start 测试。

- [x] **6.7.2 只读 REST Snapshot API**
  - [x] 定义统一响应包装 `{ok,error,data}`，并保证错误不泄露私钥、VICI secret、完整本地 key material。
    - 已实现 `apiResponse` + `writeAPIOK` / `writeAPIError`。
  - [x] 实现 `GET /api/v1/status`：peer id、managed zone、known zones/peers、link/desired link 数、last link/routing error、最近 sync/reconcile 时间。
  - [x] 实现 `GET /api/v1/zones`、`/api/v1/zones/{zone}`：Zone 树摘要、record/delegation/revocation 计数、revoked 状态、root hash；详情页提供 records/delegations/revocations 的结构化只读 JSON。
  - [x] 实现 `GET /api/v1/peers`、`/api/v1/peers/{peer_id}`：复用 `SyncPeers`、bootstrap/discovered endpoint、observed path、backoff、datagram/object-pull 统计。
  - [x] 实现 `GET /api/v1/links`、`/api/v1/links/{link_id}`：复用 `LinkInstances`、desired link snapshot、IPsec reconcile action/skip reason、SA observation、rotate/takeover 字段。
  - [x] 实现 `GET /api/v1/health`、`/api/v1/health/{link_id}`：返回当前 health window、probe 状态、BIRD RTT/metric、cutover gate、最近错误。
  - [x] 实现 `GET /api/v1/health/{link_id}/series?metric=...&range=...&step=...`：只读查询本地 spool；未配置 datasource 时返回明确 `not_configured`，不得阻塞 live snapshot。
    - 已实现本地 file spool 第一版：daemon 在 probe tick 后写入 `health.metrics.local_spool_path/samples.jsonl`，observer 支持 `rtt/loss/jitter/state` 受限查询；外部 TSDB/push 集成后续补齐。
  - [x] 实现 `GET /api/v1/routes`：复用 `routing.BuildAuthorizedRouteSet(state.Network, now)`，返回 authorized prefixes、assignments/all assignments、pools、errors、本地 export set。
  - [x] 实现 `GET /api/v1/bird`：复用 `stateFile.BirdInstances` 和 `last_routing_error`，仅承诺 managed BIRD 实例状态，不提前承诺 learned routes/neighbors。
  - [x] API 单测覆盖空状态、revoked zone、IPsec connecting/up/rotate、health datasource missing、TSDB query timeout、route authorization error、BIRD error、敏感字段过滤。
    - 已覆盖空状态（status/zones/peers/links/routes/bird）、static handler（index/css/js/method）、disabled start、SSE hub broadcast/unsubscribe/no-subscribers、embedded web FS。

- [x] **6.7.3 静态 UI MVP**
  - [x] 使用 Go `embed` 内嵌 `app/higgs/web/` 静态资源；第一版优先原生 HTML/CSS/JS，不引入 Node.js 构建链。
    - 已实现 `//go:embed web/*` + `handleStatic` + SPA fallback + content-type。
  - [x] 页面布局采用左侧导航 + 主内容区：Overview、Gossip、Zones、Overlay、Health、Route、BIRD。
  - [x] Overview 展示本节点身份、Zone/Peer/Link/Route/BIRD 摘要、最近错误和刷新状态。
  - [x] Gossip/Zones/Overlay/Health/Route/BIRD 页面先做表格、过滤、详情抽屉、原始 JSON 查看；按钮仅限刷新、复制 JSON、过滤，不提供写操作。
  - [x] Health 页面展示每条 link 的当前状态、RTT/loss/jitter/Babel metric、最近错误、cutover gate；若本地 datasource 可用，展示短时间 sparkline/折线图。
    - 已接入本地 spool datasource，Health 页面在 datasource configured 时展示 RTT sparkline；未配置时保留 live snapshot 表格。
  - [x] UI 对 API failure、daemon restarting、empty state、SSE 不可用等状态有明确展示。
  - [x] 前端静态测试可先用 `httptest` + golden HTML/API contract；如引入浏览器测试，再补 Playwright smoke。
    - 已用 `httptest` 覆盖 static handler。

- [x] **6.7.4 SSE 事件与轮询降级**
  - [x] 实现 `GET /api/v1/events`，基于 `http.Flusher` 输出 `text/event-stream`。
    - 已实现 `handleEvents` + `http.Flusher`。
  - [x] SSE hub 只推轻量通知：`state_changed`、`peer_updated`、`link_updated`、`health_updated`、`route_changed`、`bird_updated`、`connected`；详情由前端重新拉取 REST snapshot。
    - 已实现 `sseHub` + `sseEvent`；daemon `notifyObserver` 在 state/route/bird/link/peer/health 变化时调用 6 种事件类型。
  - [x] daemon 在 state digest 变化、sync peer 更新、IPsec reconcile 完成、routing/BIRD reconcile 完成后发送通知；事件发送不得阻塞主事件循环。
    - 已在 `daemon.go` notifyStateChanged 中调用 6 种事件类型。
  - [x] 限制 subscriber 数量和单客户端队列长度；慢客户端丢事件并让前端轮询补齐。
    - 已实现 buffered channel (16) + non-blocking broadcast（`select` + `default` 丢弃）。
  - [x] 前端 EventSource 断开后自动切到轮询，并在恢复后回到 live 状态。
    - 已在 `app.js` 实现 EventSource + polling fallback。
  - [x] 单元测试覆盖连接、断开、慢消费者、daemon shutdown、事件不阻塞 reconcile。
    - 已覆盖 subscribe/broadcast、unsubscribe（修复了 close channel 死锁）、no-subscribers 不 panic。

- [x] **6.7.5 Overlay/Zone 拓扑与诊断增强**（第一版基础完成，高级拓扑图后续增强）
  - [x] Overlay 页面基于 `/api/v1/links` 生成本节点与 peers 的链路图，节点为 peer zone，边为 TransportLink，颜色区分 `pending/connecting/up/down/revoked/error`，并叠加 health summary。
    - 第一版为表格视图；可视化拓扑图（SVG/canvas）留到后续增强。
  - [x] Health 页面可从本地 VictoriaMetrics/Prometheus-compatible datasource 或 SQLite spool 拉取测量序列；跨节点集中视图由外部 TSDB/Grafana 负责，Observer 只展示本节点配置的数据源。
    - 已实现本地 file spool 查询；VictoriaMetrics/Prometheus-compatible/push 集成后续补齐。
  - [x] Zone 页面增加 delegation/revocation 树形视图，revoked 子树必须醒目标识且不被误显示为健康。
    - 第一版 zone detail JSON 含 revoked 状态、delegations、revocations 结构化数据；树形 UI 留到后续。
  - [x] Route 页面先展示授权前缀、IPAM assignment/pool、route authorization errors；前缀树/路径分析作为增强项。
  - [x] BIRD 页面在真实 `birdc` protocols/routes/neighbors 解析落地前，只显示实例级状态、router-id、netns、table、socket、last error。
  - [x] 增加 operator 诊断字段：每个页面都能复制对应 REST JSON 和推荐 CLI 对照命令（例如 `higgs debug links`、`higgs debug babel`、`higgs debug routes`）。
    - 第一版 UI 提供 raw JSON view。

- [x] **6.7.6 安全、验证与文档**
  - [x] 明确第一版 observer 只读；HTTP handler 不注册任何 POST/PUT/PATCH/DELETE 写接口。
  - [x] 默认监听 localhost，若配置 `0.0.0.0` 或非 loopback 地址，启动日志必须提示需要外部访问控制。
    - 已实现 `isLoopbackBind()` 检测 + `logWarn` 非环回警告。
  - [x] 增加 `make observer-smoke`：启动测试 daemon/httptest server，验证主要 API JSON、静态 UI 可访问、默认关闭不监听端口。
    - 已实现 `make observer-smoke`，覆盖 31 个 observer 相关测试（config/API/SSE/static FS/HTTP handler routing/loopback HTTP start/static UI escaping），已纳入 `smoke-all`。
  - [x] `make check` 覆盖 observer 单测；如后续引入前端依赖，需把无 Node.js 环境的验证路径保留。
    - `make check` = fmt + vet + test + build；observer 单测在 `go test ./...` 中运行，无 Node.js 依赖。
  - [x] 更新 `README.md` / `docs/testing.md`：如何启用 observer、如何通过 SSH tunnel 访问、哪些字段来自 live daemon、哪些 BIRD 深度字段仍未实现。
    - 已更新 README.md 增加 "Web 状态控制台（Observer）" 章节，覆盖启用方式、访问、远程访问（SSH tunnel）、数据来源、安全边界。
  - [x] 更新 `docs/web-status-dashboard-design.md` 状态，从设计草案标注为"MVP 已排入 todo"，并同步第一版边界：只读、本地监听、无认证、无控制操作。
    - 已更新文档状态为"MVP 已实现"，添加第一版实现边界说明（只读、本地监听、无认证、daemon live snapshot、BIRD 深度字段后续补齐、代码位置、验证方式），并将第 13 章"待决策问题"全部标注为已决策。

- [ ] **6.7.7 `app/higgs` 模块化重构（Observer/debug 先行）**
  - **设计文档：** `docs/app-higgs-modularization-design.md`
  - 目标：以 Observer/debug/inspect 为第一批切入点，启动 `app/higgs` 模块化重构；后续把 health、routing、revocation、peer lifecycle、firewall、IPsec reconcile、sync runtime 等应用子系统逐步下沉到 internal 模块，避免所有逻辑长期堆在 `app/higgs` executable 包。
  - 边界原则：
    - `internal/observer` 继续只负责 HTTP routing、SSE、API envelope、静态资源，不读取 Higgs daemon 状态。
    - `internal/inspect` 负责 snapshot/input -> inspect view 的纯只读转换、排序、摘要、reason code 和 suggested action hint。
    - `internal/inspect/text` 负责 CLI 可复用 presenter：表格、详细文本、可选 JSON；`app/higgs/debug_*.go` 只做命令注册、参数解析和调用 presenter。
    - `internal/inspect/source` 定义 Source/Collector 接口和通用 snapshot input 类型；离线 DB/control-socket source 可下沉到 internal，live daemon source 若需要访问 `DaemonService` 或未导出状态，则在 `app/higgs` 保留薄 adapter。
    - `app/higgs` 只保留 executable wiring：持 `stateFile.RLock()` 读取 live daemon、复制 app 私有 runtime 状态、初始化 config/runtime/control command service；`internal/inspect` 不直接依赖 `DaemonService`、`stateFile` 锁或 `main` 包私有运行态类型。
    - HTTP observer 和 CLI debug 都从 inspect view 做 presenter：HTTP 输出稳定 JSON，CLI 输出表格/文本/可选 JSON；不得各自重新推理状态 reason。
    - readmodel 可以输出 `SuggestedAction` / `CommandHint`，但不得执行写操作；未来 Web 控制必须走独立 command service / control socket single-writer 路径。
  - [ ] 盘点重合面：`debug links` vs `/api/v1/links`、`debug peer/sync status` vs `/api/v1/peers`、`debug zone/zone show` vs `/api/v1/zones`、`debug routes/babel/health/revoke-impact` vs 对应 observer API。
  - [ ] 建立 `internal/inspect` 包骨架：公共 input/view/reason/action 类型、builder 单测；建立 `internal/inspect/text` CLI presenter；必要时建立 `internal/inspect/source` source 接口。
    - 已建立 links 子集：`internal/inspect` 提供 `LinkInput` / `LinkInspection` / `BuildLinks` 与 builder 单测；`inspect/text` 和通用 source 接口仍待后续迁移。
  - [x] 先以 links 为第一刀：定义 `inspect.LinkInput` / `LinkInspection` / `BuildLinks`，覆盖 desired/actual SA、health、BIRD routing、rotate/takeover、diagnostic reason；observer links API 和 `debug links` 都从同一 view 输出。
    - 已新增 `app/higgs/inspect_links.go` 薄 adapter，从 `stateFile` / runtime config / health snapshot 投影到 inspect input；`debug links` 和 `/api/v1/links` 均消费同一 `LinkInspection`，保留 CLI 文本布局和 observer JSON schema。
  - [ ] 第二步抽 zone/record/authority：把 `recordJSON`、authority/delegation/revocation 展示逻辑迁到 inspect，复用到 `zone show` / `debug zone` / observer zone detail；避免 HTTP schema 直接绑定 `zone.Record` 原始字段。
  - [ ] 第三步抽 peer endpoints：把 bootstrap/discovered/observed/grace endpoint 合并、本地 peer 过滤、source/selected 排序收敛到 inspect；observer peers 和 CLI peer debug 共用。
  - [ ] 第四步抽 routes/BIRD/health/revocation/admission/firewall：优先复用现有结构化结果，逐步把 presenter 与诊断推理分开；系统采集和 provider 调用留在 source/adapter 层。
  - [ ] Diagnostics/debug 迁移路线：
    - `app/higgs/diagnostics.go` 拆分：sync debug logger / runtime log glue 留 app；peer、zone、record、link 的 view builder 和文本输出迁到 inspect/text。
    - `app/higgs/admission_diagnostics.go` 的 reason code、diagnosis view、writeAdmissionDiagnosis 迁到 inspect/admission + inspect/text；app 只保留在 daemon 事件中更新 admission state 的 adapter。
    - `app/higgs/debug_routing.go` 将 route dump/prefix explanation 和 BIRD summary presenter 迁到 inspect/routes + inspect/text；control socket/offline fallback 留 source/adapter。
    - `app/higgs/debug_firewall.go`、`debug_peers.go`、`debug_revoke_impact.go`、`health_reconcile.go:debugHealth` 的格式化和 reason 推理迁到 inspect/text；系统 apply/reconcile 与 health probe 调度留 app。
    - `app/higgs/cmd.go` 的 `cmdDebug()` 只做 CLI 子命令注册、参数解析、source 选择和 presenter 调用。
  - [ ] 为 inspect/text 建立 golden/output 测试，迁移现有 `TestDebug*Output`、`TestWriteDebug*`、admission diagnosis 输出测试；app 层只保留命令 wiring/fallback 的窄测试。
  - [ ] 删除 `observer_server.go` 中只为兼容旧 handler 测试保留的 app 层 wrapper 或改测 `internal/observer.Server.Handler()`；保留必要 shim 时必须标注迁移原因。
  - [ ] 验证：`make observer-smoke`、`go test ./app/higgs`、相关 CLI golden/output 测试必须继续覆盖 HTTP route、SSE、static UI、debug 文本和 raw JSON 输出。

## Phase 7: 健壮性与高级特性（预计 4-6 周）

**目标：** 生产可用，支持多线路、跳频、扩展传输协议。

- [ ] **7.1 多线路并行（Multipath）**
  - 一个 Peer 可建立多条 TransportLink（IKEv2/XFRM over 公网 + IKEv2/XFRM over 内网 + 可选 WG/GRE），并复用 Phase 4 的 overlay/provider、AddressCandidate、PortAdvertisement、ContactPoint 模型
  - 每条链路独立匹配 BIRD interface pattern
  - BIRD 自动进行多路径负载均衡（Babel 原生支持 ECMP）

- [ ] **7.2 高频 UDP 端口候选 / 对抗性 Port Hopping**
  - 目标：在 Phase 4.4 已具备低频平滑 rotate 后，再评估用于规避固定 UDP 五元组 QoS/丢包/限速的多 endpoint / 多 port probe、质量评分和定时/事件驱动 hopping。
  - IKEv2/IPsec 仍不假设能像 WireGuard 一样任意 per-peer 高频跳监听端口：标准 IKE/NAT-T 默认使用 UDP 500/4500，StrongSwan 支持连接级 `local_port`/`remote_port` 与全局 NAT-T 端口配置，但高频数据面端口跳变通常需要 reestablish/MOBIKE/多实例或外层 DNAT 配合；Phase 7 只做 Phase 4.4 低频 rotate 之上的高级策略。
  - 支持在 signed `ipsec/ports` record 中发布多个端口候选：标准 500/4500、备用自定义 IKE 端口、备用 NAT-T/encap 端口、current/previous grace；daemon 按质量、失败率、运营商特征选择，并与地址候选组合成 ContactPoint
  - hopping 必须包含：old-port grace period、clock skew 容忍、fallback static port、失联恢复路径、QoS 误判回滚、端口探测限速
  - 如果网络允许 ESP 协议且 QoS 主要针对 UDP，可优先评估非 NAT-T ESP 路径；若必须 UDP encapsulation，再评估端口候选和 reestablish 成本
  - 增加公网验证：固定 UDP 4500 大流量劣化时，备用端口/备用 endpoint 能否降低丢包；记录 `swanctl --list-sas`、RTT、loss、babel route cost 变化

- [ ] **7.3 Gossip UDP object chunk repair（窄化可靠性增强）**
  - 目标：只补强 Phase 3.6.7 的 UDP chunk fallback 丢包恢复，不把 gossip UDP 扩展成通用可靠传输、UDT 或流式连接协议；TCP object pull 仍是大对象主路径，chunk repair 只服务于 TCP 不可达但 verified observed UDP path 可用的 peer
  - 为 `object_chunk` 传输定义短期 `transfer_id`：可由 peer/object/zone/key/version/object_hash/root_hash 推导，或在线路上显式携带；接收端按 transfer 维护缺块 bitmap、最后更新时间和大小上限
  - 增加 `object_chunk_nack` / repair request：接收端在 quiet/deadline 内发现缺块时，只请求缺失 index/bitmap；发送端只从短 TTL 的已发送对象缓存中重发缺块，不重新打开通用会话
  - repair 必须有硬边界：最大 repair 轮数、单 peer inflight transfer 数、缓存总字节数、每轮 NACK 大小、quota 计费、sync round deadline 和 `chunkAssemblyTTL` 清理；超过边界则放弃本轮，等待下一轮 digest sync 重新触发
  - 乱序、重复、篡改、过期 chunk 仍不得进入 active state；完整对象 hash 匹配后才解码，zone snapshot/record 继续走普通 trust chain 和签名验证
  - 观测面增加 repair counters：`chunk_repair_requests`、`chunk_repair_retransmits`、`chunk_repair_failed`、缺块数量和最近失败原因；`sync status --verbose` / `debug peer` 能区分首次 chunk fallback 与 repair 流量
  - 增加单测和 smoke：乱序+丢一个 chunk 后 NACK 补齐能收敛；重复 NACK 不放大；发送端缓存过期后不重传；坏 hash/错误 transfer_id 不 apply；TCP object pull 可用时不会走 chunk repair

- [ ] **7.4 WireGuard 传输驱动（可选 / fallback）**
  - 通过 `wgctrl-go` 操作内核 WG 接口
  - 复用 Zone K-V 中的 `wireguard/*` Record
  - WG 不作为动态路由主线；仅用于静态前缀、小规模 P2P、或 StrongSwan 不可用平台的轻量 fallback
  - WG AllowedIPs 只放 tunnel /32 或 /128；业务路由仍交给 Babel/route authorization，避免把 cryptokey routing 当成动态路由表

- [ ] **7.5 VXLAN Overlay**
  - 在 WG 三层网络上封装 VXLAN
  - 通过 Zone Record 同步 VNI、VTEP 信息

- [ ] **7.6 SRv6 支持（实验性）**
  - 通过 netlink 配置 SRv6 SID、End.DT4/End.DX6 行为
  - 与 BIRD/FRR 的 SRv6 扩展联动（如后续引入 BGP）

- [ ] **7.7 可选 Global Discovery Server**
  - 作为独立公网服务提供 peer rendezvous，只用于无稳定 bootstrap、IP 频繁变化、复杂 NAT 等场景；默认 peer discovery 仍以 signed endpoint record + gossip 传播为主
  - 服务端不成为信任根，不持有 root/admin/zone 私钥；客户端仍以 signed endpoint record 和 Zone trust chain 为准
  - 支持最小 HTTP/JSON API：`POST /v1/announce` 上报本机 signed endpoint，`GET /v1/peers/{peer_id}` 查询候选 endpoints、observed addr、ttl 和 source
  - 服务端负责 ttl cache、observed remote addr、限流、防重放和基础滥用防护；不替客户端做最终信任裁决
  - 支持配置多个 discovery server URL，客户端合并查询结果并按 endpoint 可信度/连接成功率排序

- [ ] **7.8 可选 Relay Bootstrap Server**
  - 作为独立公网 bootstrap/relay 程序运行，负责收集节点发布的已签名 Zone/Record/endpoint 数据，维护本地数据库，并向其他节点传播
  - relay server 不需要自己的 Zone，不持有 root/admin/zone 私钥，不签发 delegation/record，不成为信任根；所有数据仍由客户端按 Zone trust chain 和签名验证
  - 运行形态可以是独立 binary，如 `higgs-relay`，或后续子命令；长期部署时作为稳定 bootstrap peer 暴露公网地址
  - relay 维护持久化 store：按 peer/zone/record digest 保存最新 verified/candidate 数据、来源 peer、收到时间、ttl、last_seen、传播状态
  - 支持 gossip 协议的 bootstrap 行为：响应 `PING`/`PONG`/`FETCH_ZONE`/`FETCH_RECORD`/`ANNOUNCE`，并可向已知节点做 fanout/relay，但自身不生成业务 record
  - 支持查询接口：节点可按 peer id、zone、digest 查询 relay 已知的 endpoints、zone snapshots、record snapshots，用于冷启动或补齐缺失数据
  - relay 接收数据时先做基础格式、大小、配额、防重放检查；可选择做签名链预验证以节省下游带宽，但客户端必须再次验证
  - relay 的 allowlist 策略可配置：公开收集已签名数据、仅接受指定 root trust 下的数据、或仅接受配置中的 bootstrap peers
  - 增加 backpressure 和去重：按 digest/record version 去重，限制每 peer 传播频率，避免 relay 成为广播放大器
  - 增加 smoke：普通节点只配置 relay 作为 bootstrap，也能通过 relay 获取其他节点 signed endpoint 和 zone data，随后建立直接 gossip 连接

- [ ] **7.9 可选 Admission 管理面**
  - 目标：在 auto-join 主链路和本地控制接口稳定后，再考虑父 Zone 管理节点的 join request inbox、审核队列、批量 approve/reject 和受限网络化提交；不进入 Phase 6 主线，默认不实现自动审批。
  - 第一版 admission 仍不引入新的公网 request 协议，也不让 leaf 自动把 join request 写入 gossip active state；常规传输继续走 daemon 日志、`higgs join request --from-config` 输出文件、SSH/scp、工单或本地 stdin。
  - 本地 pending request inbox：支持从文件/stdin/control API 导入多个 join request，按 `zone`、public key fingerprint、request hash 去重，并记录 rejected/expired request。
  - 审核命令候选：`higgs join pending`、`higgs join approve <request-id>`、`higgs join reject <request-id>`；approve 后调用现有 `delegate issue` 写入 delegation。
  - admission policy 仅覆盖父 Zone 有权签发/写入的对象：允许的 child zone glob、默认 delegation capabilities、是否允许 auto-approve、max pending/max approved、可选初始 IPAM assignment、node role/tag record、route policy hint、非 transit forwarding intent。
  - 不在 admission policy 中配置本机 MeshPolicy / link group / connect-deny override；这些是每个节点的本地策略，只能由该节点本地配置或后续专门的本地控制面调整。
  - 如确需网络化提交，可另设受限 admission relay/control endpoint：必须 rate limit、只进本地 pending inbox、不写 active state、不参与普通 gossip relay，并默认关闭。

- [ ] **7.10 Daemon / 本地控制接口生产化**
  - [ ] 在 Phase 3 最小 daemon 基础上完善运行形态：`higgs daemon` 常驻负责 gossip 同步、active state 更新、IKEv2/WG/Babel/firewall apply
  - [ ] CLI 默认作为 daemon client，通过本地控制接口查询状态或提交操作；直接写 DB 模式仅保留为 debug/recovery
  - [ ] 完善 Unix domain socket 控制接口，默认仅本机 root/admin 用户可访问
  - [ ] 预留 TCP control listener，用于受控远程管理；默认关闭，必须显式配置监听地址与认证
  - [ ] 定义控制 API：status、peers、zones、records、history、conflicts、sync trigger、reload config、apply dry-run
  - [ ] `sync status --verbose` / `debug peer` 优先通过本地控制接口查询正在运行的 daemon，显示 live relay 队列、最近更新来源、relay 抑制原因、backoff 和下一次 sync 计划；daemon 不可用时 fallback 到 DB 快照
  - [ ] 控制 API 输出结构化 JSON，CLI 负责格式化成人类可读输出
  - [ ] 加入认证与授权边界：Unix socket 文件权限、token/mTLS 预留、只读/管理操作分级
  - [ ] daemon 生命周期：启动、优雅停止、reload、状态持久化、崩溃恢复
  - [ ] systemd service 示例和 socket 路径约定，如 `/run/higgs/higgs.sock`

- [ ] **7.11 运维与可观测性**
  - Prometheus metrics 导出（节点数、链路状态、Gossip 流量、Zone 数量）
  - 结构化日志（slog）
  - CLI 调试工具：`higgs status`, `higgs zones`, `higgs peers`, `higgs sync`

## Phase 8: 应用层服务网格与代理（远期规划）

**目标：** 在 Higgs L3 mesh 之上支持应用代理层的策略源站选路，让 Higgs 不仅提供节点间连通性，还能作为服务发现、策略分发和选路决策的基础设施。

**设计原则：**
- Higgs core 不直接实现 L7 代理，而是提供 **服务发现 + 策略分发 + 网络可达性**。
- L7 代理以 **sidecar** 形态运行（如 Envoy、自研轻量代理），通过本地 API 从 Higgs daemon 订阅 backend 列表和策略。
- 服务注册、backend 列表、选路策略走现有的 zone/record + capability + fallback 继承模型。

- [ ] **8.1 服务与 upstream record schema**
  - 定义 `services/<name>` 或 `proxy/upstreams/<name>` record 类型
  - 字段包含：listeners、backends（zone + address + weight + health check）、selection policy、access policy
  - 新增 capability：`write:service` / `write:proxy`
  - 服务可按 zone 继承或覆盖：子 zone 可覆盖父 zone 的服务 backend 列表

- [ ] **8.2 策略源站选路模型**
  - 静态策略：round-robin、weighted、least-connections、hash(source_ip)
  - 动态策略：基于节点健康/延迟/负载、地理位置、链路质量
  - 请求特征匹配：按 L4（port/SNI）或 L7（HTTP path/header）路由到不同 backend
  - 访问控制：只允许特定 zone/role 访问特定服务

- [ ] **8.3 应用层健康检查与 metric**
  - 从 ICMP/keepalive 链路健康检查扩展到 TCP/HTTP 应用层探测
  - 定义 health record 或 runtime metric record 格式
  - 节点间传播健康状态，sidecar 据此调整 backend 权重

- [ ] **8.4 Higgs → sidecar 控制接口**
  - daemon control socket 增加 `services` / `proxy` 查询/订阅 API
  - sidecar 可获取：服务列表、backend 状态、当前生效策略、节点健康快照
  - 支持 push（backend 变化时通知）和 pull（主动查询）

- [ ] **8.5 sidecar 代理接入**
  - 方案 A：集成 Envoy，通过 xDS-like 接口消费 Higgs 配置
  - 方案 B：自研轻量 TCP/HTTP/SOCKS 代理，降低依赖
  - sidecar 监听本地端口，根据策略选择 backend，通过 mesh tunnel 转发
  - 与 netns 集成：sidecar 可运行在 Higgs overlay netns 中，直接访问 mesh 地址

- [ ] **8.6 验证**
  - container smoke：客户端 -> sidecar -> Higgs mesh -> 目标 backend
  - negative smoke：未授权 zone 无法访问受保护服务
  - 故障切换 smoke：backend 下线后 sidecar 自动切换到可用 backend
  - 策略更新 smoke：修改 `services/<name>` record 后 sidecar 在不重启的情况下生效

## 下一步

1. 继续 Phase 6.7.7 `app/higgs` 模块化重构：优先补齐 `internal/inspect` / `inspect/text` 骨架，把 `debug links` 与 Observer links 的共用 read model 扩展成可迁移模式。
2. 第二步抽 zone/record/authority 展示逻辑，复用到 `zone show` / `debug zone` / Observer zone detail，避免 HTTP schema 直接绑定 `zone.Record` 原始字段。
3. 第三步抽 peer endpoints，再逐步迁移 routes/BIRD/health/revocation/admission/firewall 的诊断 presenter 和 reason 推理。
4. 对 Phase 6.0 的旧 sync 路径做收尾：删除旧 `Receive()` / `receiveWithDeadline` 路径、旧 `defer saveState()`，补 race 回归和 state file lock/fsnotify。
5. Phase 5 后续按需补 managed BIRD 崩溃恢复、BIRD 观测接入 `RotateCutoverReady`、策略路由/table owner 清理和真实数据面 smoke。
