# Higgs Todo

设计文档见 [docs/design.md](docs/design.md)。本文件只保留可执行任务。

## 已完成里程碑归档

完整历史清单已拆到 [docs/roadmap-archive.md](docs/roadmap-archive.md)，主 TODO 只保留当前执行队列和后续计划。

- [x] Phase 0-2：可信状态机、join/delegation、gossip 同步、discovery、bounded history 和操作文档。
- [x] Phase 3-3.6：daemon/single-writer 基座、NAT/observed path、MTU-safe gossip 和 object-pull/chunk fallback。
- [x] Phase 4：StrongSwan/XFRM 主线、daemon admin 写入、auto-join、planner/reconcile、host-born XFRM、低频 rotate、bidirectional takeover。
- [x] Phase 5：BIRD Babel、route authorization、per-netns BIRD 配置模型、routing debug 和 dry-run smoke 基座。
- [x] Phase 6.0-6.7.6：事件驱动控制面、IPAM、准入诊断、防火墙、动态 peer、撤销清理、链路健康和 Observer MVP 主线。

- [x] **6.7.7 `app/higgs` 模块化重构（Observer/debug 先行）**
  - **设计文档：** `docs/app-higgs-modularization-design.md`
  - 目标：以 Observer/debug/inspect 为第一批切入点，启动 `app/higgs` 模块化重构；后续把 health、routing、revocation、peer lifecycle、firewall、IPsec reconcile、sync runtime 等应用子系统逐步下沉到 internal 模块，避免所有逻辑长期堆在 `app/higgs` executable 包。
  - 边界原则：
    - `internal/observer` 继续只负责 HTTP routing、SSE、API envelope、静态资源，不读取 Higgs daemon 状态。
    - `internal/inspect` 负责 snapshot/input -> inspect view 的纯只读转换、排序、摘要、reason code 和 suggested action hint。
    - `internal/state` 承接可被 app runtime、inspect、observer/source 共同引用的持久化/运行时 snapshot 类型；`app/higgs` 负责写入和生命周期，`internal/inspect` 只解释这些只读结构。
    - `internal/inspect/text` 负责 CLI 可复用 presenter：表格、详细文本、可选 JSON；`app/higgs/debug_*.go` 只做命令注册、参数解析和调用 presenter。
    - `internal/inspect/source` 定义 Source/Collector 接口和通用 snapshot input 类型；离线 DB/control-socket source 可下沉到 internal，live daemon source 若需要访问 `DaemonService` 或未导出状态，则在 `app/higgs` 保留薄 adapter。
    - `app/higgs` 只保留 executable wiring：从 `DaemonStateStore.Snapshot()` / control socket / 离线 DB 构造 inspect input，复制 app 私有 runtime 状态，初始化 config/runtime/control command service；`internal/inspect` 不直接依赖 `DaemonService`、`stateFile` 锁或 `main` 包私有运行态类型。
    - HTTP observer 和 CLI debug 都从 inspect view 做 presenter：HTTP 输出稳定 JSON，CLI 输出表格/文本/可选 JSON；不得各自重新推理状态 reason。
    - readmodel 可以输出 `SuggestedAction` / `CommandHint`，但不得执行写操作；未来 Web 控制必须走独立 command service / control socket single-writer 路径。
  - [x] 盘点重合面：`debug links` vs `/api/v1/links`、`debug peer/sync status` vs `/api/v1/peers`、`debug zone/zone show` vs `/api/v1/zones`、`debug routes/babel/health/revoke-impact` vs 对应 observer API。
  - [x] 建立 `internal/inspect` 包骨架：公共 input/view/reason/action 类型、builder 单测；建立 `internal/inspect/text` CLI presenter；必要时建立 `internal/inspect/source` source 接口。
    - 已建立 links/zone/peers/routes/health/revocation/admission/firewall/routing/records 子集：`internal/inspect` 提供共享 view/builder/filter，`internal/inspect/http` 提供 observer DTO/builder，`internal/inspect/text` 提供 CLI presenter 与 focused output 单测；`internal/inspect/source` 仍留到 source/fallback 瘦身阶段。
  - [x] 先以 links 为第一刀：定义 `inspect.LinkInput` / `LinkInspection` / `BuildLinks`，覆盖 desired/actual SA、health、BIRD routing、rotate/takeover、diagnostic reason；observer links API 和 `debug links` 都从同一 view 输出。
    - 已新增 `app/higgs/inspect_links.go` 薄 adapter，从 committed state snapshot / runtime config / health snapshot 投影到 inspect input；`debug links` 和 `/api/v1/links` 均消费同一 `LinkInspection`；debug links CLI presenter 已迁到 `internal/inspect/text`，Observer status/links/bird HTTP DTO 与 status response builder 已迁到 `internal/inspect/http`。
  - [x] 第二步抽 zone/record/authority：把 `recordJSON`、authority/delegation/revocation 展示逻辑迁到 inspect，复用到 `zone show` / `debug zone` / observer zone detail；避免 HTTP schema 直接绑定 `zone.Record` 原始字段。
    - 已新增 `internal/inspect` zone/record/authority view 与 `internal/inspect/text` zone presenter：Observer zone detail、`zone show`、`debug zone`、`record get` 复用同一套 `BuildZoneDetail` / `BuildRecord`；Observer zones summary HTTP DTO 已迁到 `internal/inspect/http`。
    - 已新增 `inspect.RecordDetailView` / `BuildRecordDetail` 与 `inspect/text.WriteJSON`：`record get` / control `record_get` 不再在 app 层手工拼 `map[string]any` record JSON，`zone show` 也复用 shared JSON presenter。
  - [x] 第三步抽 peer endpoints：把 bootstrap/discovered/observed/grace endpoint 合并、本地 peer 过滤、source/selected 排序收敛到 inspect；observer peers 和 CLI peer debug 共用。
    - 已新增 `internal/inspect.BuildPeerIDs` / `PeerKnown` / `BuildPeerEndpoints` 与 `PeerStatusInfo` view：peer 候选集合、本地 peer 过滤、zone-path 排序、bootstrap/signed/selected/observed/grace endpoint 合并去重均已下沉；Observer peers API 与 `debug peer` endpoint resolution 已改用该 view；Observer peers HTTP DTO 已迁到 `internal/inspect/http`。
  - [x] 拆 peer runtime control vs observability readmodel：已通过 `internal/state.PeerRuntimeState` 将 peer runtime 状态从 `app/higgs` 私有类型提升为 `app/higgs`、`internal/inspect`、control/observer 共用的只读快照类型；`PeerDebugInput`、`inspecthttp.PeerJSON`、`inspect.SyncVerbosePeerView` 均直接嵌入/复用 `PeerRuntimeState`，删除了 `PeerSyncFlowInput`、`PeerDatagramStatsInput`、`PeerObjectPullStatsInput` 等重复中间类型，消除了 app/inspect/observer 之间大量字段复制。backoff、observed path、rejected digest/record cache、relay eligibility 等控制字段仍由 daemon runtime 写入。`DatagramStats`、`ObjectPullStats`、read-only responder、last catalog/page/reject、chunk fallback/too-large counters 等纯诊断字段当前仍随 `PeerRuntimeState` 持久化，尚未完全迁出到独立 metrics store；待后续建立 `internal/inspect/source` 或 metrics store 后再评估彻底拆出，避免统计计数频繁推动主 committed state revision。
  - [x] 抽 link runtime snapshot 到 `internal/state`：已将 `LinkInstanceState`、`DesiredLinkState`、`LinkSAState`、`LinkActionState`、`LinkSkipState`、`LinkOwnerState` 从 `app/higgs/state.go` 提升到 `internal/state`，`app/higgs` 通过类型别名复用；`internal/inspect` 中 `LinkOwner`/`LinkSA` 与共享状态别名等价，`LinkInstance`/`DesiredLink`/`LinkAction`/`LinkSkip` 通过 `Build*FromRuntime` builder 从共享状态构建，`app/higgs/inspect_links.go` 不再逐字段复制，统一走 inspect builder。`LinkHealth`/`LinkRouting`/`LinkRotation`/`LinkTakeover` 等纯 inspect view 类型保留在 `internal/inspect`，与持久化/runtime snapshot 解耦。
  - [x] 第四步抽 routes/BIRD/health/revocation/admission/firewall：优先复用现有结构化结果，逐步把 presenter 与诊断推理分开；系统采集和 provider 调用留在 source/adapter 层。
    - 已新增 `internal/inspect/http` health response / health series DTO 与 health context builder：Observer health list、health series envelope、health sample + link instance + desired context 合并/补 unknown/排序已从 `observer_server.go` 下沉，`debug health` target 排序已收敛到 `inspect.BuildHealthDebugView`，app 层仍负责 health spool 查询和私有 runtime state 投影。
    - 已新增 `internal/inspect/text` health presenter：`debug health` 的 target 排序、目标输出、live health sample 输出已从 `health_reconcile.go` 下沉，app 层仅保留 LoadState、control socket live snapshot 和私有 `healthLinkJSON` 投影。
    - 已新增 `internal/inspect/text` peer lifecycle presenter：`debug peers` 的 lifecycle config header、summary、peer detail、severity 文本输出已从 `debug_peers.go` 下沉，app 层仅保留 daemon status banner、state load、lifecycle derive 和 cleanup zone runtime 逻辑。
    - 已新增 `internal/inspect` peer lifecycle readmodel：`BuildPeerLifecycleStatus` / `PeerStatusRequiresCleanup` / `PeerStatusIsHardChange` / `ShouldBlockPeerReconnect` 承接 revoked、policy_denied、active/connecting/discovered、stale/offline/cleanup_after 等状态规则；app 层仅保留 `stateFile` / runtime config 到 `PeerLifecycleInput` 的薄投影，兼容用的 app 层 lifecycle 状态常量、config/status alias 和 helper wrapper 已移除，调用点直接引用 inspect。
    - 已新增 `inspect.BuildPeerLifecycleDebug` / `PeerLifecycleDebugInput`：`debug peers` 的 config normalization 与最终 debug view 组装下沉到 inspect；app 层仅保留 state/config 到 peer status 列表的投影。
    - 已新增 `internal/inspect/http` routes response / BIRD route view DTO 与 `internal/inspect/text` routes presenter：route export/authorized/assignment/error 生成、BIRD route authorized/import_allowed 标注和排序、`debug routes` / `debug route` 文本输出均已下沉并补 schema/output 单测；app 层暂留 control socket、BIRD client 采集和 offline fallback adapter。
    - 已新增 `internal/inspect` revocation/firewall debug view 与 `internal/inspect/text` presenter：`debug revoke-impact` 的影响详情输出、revocation layer view/status、`debug firewall` 实例摘要输出已从 app 层迁出；app 层保留 impact 计算、daemon control fallback、firewall config/snapshot 投影 adapter。
    - 已新增 `internal/inspect` admission diagnosis view/reason code 与 `internal/inspect/text` presenter：`debug admission` 文本输出和 output 测试已下沉；app 层保留 auto-join state/key/delegation 检查与 admission state 更新 adapter。
    - 已新增 `internal/inspect` routing/BIRD debug view 与 `internal/inspect/text` presenter：`debug bird-dump` raw command 输出、`debug babel` BIRD instance 摘要已从 `debug_routing.go` 下沉；app 层保留 BIRD client/control socket/offline fallback adapter；BIRD runtime snapshot 已迁到 `internal/state.BirdInstanceState`，`inspect.BabelDebugInput` 直接消费共享 state，去掉 `BabelRuntimeState` 字段搬运 DTO。
    - 已清理 app 层仅为迁移兼容保留的 inspect / inspect/http alias：routes/BIRD、admission、revocation、rotate、peer lifecycle 调用点直接引用 `internal/inspect` 或 `internal/inspect/http`；app 层只保留 runtime/control/state adapter。
    - 已将 `LinksDebugView` 从 `internal/inspect/text` 迁回 `internal/inspect`，CLI text presenter 只消费 inspect view；`PlannedSpecs` 仍暂存原始 `ipsec.TransportLinkSpec`，后续需继续拆成纯 inspect StrongSwan config view，消除 text/inspect 对 runtime spec 的直接耦合。
    - 已将 `ZoneDebugView`、`PeerLifecycleDebugView` / config、`HealthDebugView` / live/target view 从 `internal/inspect/text` 迁回 `internal/inspect`；`text` 包继续瘦身为 writer/formatter，不再定义跨包 debug view，也不再直接依赖 `pkg/health`。
  - [x] Diagnostics/debug 迁移路线：
    - `app/higgs/diagnostics.go` 拆分：sync debug logger / runtime log glue 留 app；peer、zone、record、link、endpoint 的 view builder 和文本输出迁到 inspect/text；`debug peer` / `debug links` / `debug endpoints` CLI presenter 与 `debug records` records view/presenter 已下沉。
      - 已新增 `inspect.BuildEndpointDebug`：`debug endpoints` 的 local candidate / discovered peer / signed endpoint 稳定排序、reflector error 展示规则和 endpoint debug view 构建下沉到 `internal/inspect`；app 层仅保留 local/discovered endpoint 采集与 gossip 类型适配。
    - `app/higgs/admission_diagnostics.go` 的 reason code、diagnosis view、writeAdmissionDiagnosis 已迁到 inspect + inspect/text；app 只保留在 daemon 事件中诊断/更新 admission state 的 adapter。
    - `app/higgs/debug_routing.go` route dump/prefix explanation、BIRD raw dump、Babel summary presenter 已迁到 inspect + inspect/text；control socket/offline fallback 留 source/adapter。
      - 已新增 `inspect.BuildBabelDebug` / `BabelDebugInput`：BIRD runtime state 合并、mode/default/disabled、shutdown policy 展示规则已从 `debug_routing.go` 下沉；app 层仅保留 config/state/control response 投影和 BIRD client fallback。
    - `app/higgs/debug_firewall.go`、`debug_revoke_impact.go` 已完成 presenter 迁移；后续只保留系统 apply/reconcile、control socket/offline fallback 和 app 私有 runtime adapter。
      - 已新增 `inspect.BuildFirewallDebug` / `FirewallDebugInput`：firewall config + reconcile snapshot 到 debug view 的转换下沉到 inspect；firewall reconcile snapshot 已迁到 `internal/state.FirewallReconcileState`，inspect 直接消费共享 state，app 层仅保留 control socket/offline fallback 与 config 投影。
    - `app/higgs/debug_rotate.go` 已新增 `inspect.RotateDebugView` + `inspect/text.WriteRotateDebug`：rotate 文本 presenter 已下沉，app 层保留 control socket、live SA 采集和 current/staged runtime adapter。
      - 已将 rotate/links 共享的 IPsec 端口 generation/port 摘要 helper 下沉到 `internal/inspect`，`debug links` presenter 和 `debug rotate` adapter 复用同一套只读 formatter；对应测试迁到 `internal/inspect`。
      - 已新增 `inspect.BuildRotateDebug` / `RotateDebugInput`：rotate current/staged runtime view、stored/live SA 匹配、path-family 过滤和最终 debug view 组装已从 `app/higgs/debug_rotate.go` 下沉；app 层仅保留 control socket/offline fallback、live StrongSwan SA 采集和 app 私有 SA 状态投影。
    - `app/higgs/debug_ping.go` 已新增 `internal/ping` + `inspect.PingDebugView` + `inspect/text.WritePingDebug`：一次性 ping 的 target 过滤、prober 执行、debug view 构建和文本 presenter 已下沉；ping target 排序/instance 分组已收敛到 `inspect.BuildPingDebugView`，app 层仅保留 state/config -> health targets 的 adapter 和 CLI wiring。
    - `sync status --verbose` 已新增 `inspect.SyncStatusView` + `inspect/text.WriteSyncStatus`：summary、bootstrap/discovered peer 明细、sync_flow、datagram/object_pull 诊断行和 zone 摘要输出已从 `sync.go` 下沉；app 层仅保留 state/config/gossip digest 到 view 的投影。
    - 已新增 `internal/state.PeerRuntimeState` + `inspect.BuildPeerDebugFromRuntime`：`debug peer` 与 `sync status --verbose` 可消费共享只读 peer runtime snapshot，共用 peer status、backoff、observed path、relay suppression、sync flow、datagram、object pull 诊断 view 构建；app 层保留 `syncPeerState` / stats / rejected digest alias 来表达 `stateFile` ownership，`debug_peer.go` 只做命令 wiring 与 endpoint 选择。
    - 已将 `cmdDebug()` 从 `app/higgs/cmd.go` 拆到 `app/higgs/debug_cmd.go`，root command 文件不再承载 debug 子命令注册细节；`cmdDebug()` 仍只做 CLI 子命令注册、参数解析、source 选择和 presenter 调用。
    - 已新增 `inspect.BuildZoneDebug` / `ZoneDebugInput`：`debug zone` 的 zone detail、root digest、verify result、active revocation view 构建下沉到 inspect；app 层只保留 state/configureValidation/missing-zone error adapter。
    - 已将 `app/higgs/diagnostics.go` 拆成 `debug_peer.go`、`debug_links.go`、`debug_zone_records.go`、`debug_endpoints.go`、`debug_format.go`，admission CLI glue 合入 `admission_diagnostics.go`；`diagnostics.go` 现在只保留 sync debug logger / log-level glue。
  - [x] 为 inspect/text 建立 golden/output 测试，迁移现有 `TestDebug*Output`、`TestWriteDebug*`、admission diagnosis 输出测试；app 层只保留命令 wiring/fallback 的窄测试。
    - 已新增 peer/endpoints/rotate/ping/sync status/links/routes/routing/health/zone/records/revocation/firewall/admission 等 inspect/text focused output 测试；`debug ping` 选择/执行/view 构建测试已迁到 `internal/ping`，文本断言已迁到 `internal/inspect/text`；app 层 legacy `TestDebug*Output` / `TestWriteDebug*` 已移除，保留的 app 窄测试只覆盖 app runtime/source 到 inspect view 的窄 wiring。
  - [x] 删除 `observer_server.go` 中只为兼容旧 handler 测试保留的 app 层 wrapper 或改测 `internal/observer.Server.Handler()`；保留必要 shim 时必须标注迁移原因。
    - 已删除 `observerServer.handleStatus/handleZones/handlePeers/handleLinks/handleHealth/handleRoutes/handleBird/handleEvents/handleStatic` 和 `apiResponse` 兼容 alias；observer API/static/events/firewall 相关测试已改走 `srv.handler().ServeHTTP` + `observer.APIResponse`。
  - [x] 验证：`make observer-smoke`、`go test ./app/higgs`、相关 CLI golden/output 测试覆盖 HTTP route、SSE、static UI、debug 文本和 raw JSON 输出。

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

- [ ] **7.12 可选策略路由与系统路由审计（远期）**
  - 当前主线保持一个 netns 一个 BIRD 实例，BIRD 直接写该 netns 的 main table；默认不启用额外 `ip rule` / per-overlay table 隔离。
  - 如后续需要 external BIRD、管理员自定义策略路由、或非默认共享 netns 拓扑，再补 `ip rule` / fwmark / iif-oif 策略路由和 `/run/higgs/rt_tables.d` 诊断输出。
  - route-table auditor 仅作为可选兜底，用于交叉检查 Higgs authorized route set、BIRD learned/installed routes 与内核 route table 是否一致。
  - 若未来开始 apply table routes/rules，必须同时实现 teardown/revocation 对 Higgs-owned routes/rules 的 owner-guarded 清理。

## Phase 7 之后的远期后续

- [ ] 跨数据面 rotate smoke：结合端口/IPsec rotate 与真实 BIRD route/metric 观测验证数据面切换窗口；不阻塞 Phase 5/6 收尾。
- [ ] state 文件外部协调补强：在现有 bbolt 文件锁基础上增加显式 `flock` / fsnotify watcher，避免多进程或外部修改时状态漂移。
- [ ] Observer 增强：拓扑图、zone tree、VictoriaMetrics/Prometheus-compatible datasource/push 集成、BIRD protocols/routes/neighbors 深度解析。

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

1. 进入 Phase 7：启动 7.1 多线路并行（Multipath）设计，明确单 Peer 多条 TransportLink 共存、per-link BIRD interface pattern 匹配和 Babel ECMP 行为。
2. 远期补强 `internal/inspect/source` 与 peer 可观测性 readmodel：在 metrics store 就绪后，将 `DatagramStats`/`ObjectPullStats` 等纯诊断计数从 `PeerRuntimeState` 完全拆出，避免统计写入推动主 committed state revision。
3. 继续按 `docs/app-higgs-modularization-design.md` 推进 `internal/*` 应用层拆分（peer lifecycle、revocation impact、admission、health/routing/firewall/ipsec app 层等），待接口稳定后再评估 `stateFile` 迁移。
