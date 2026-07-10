# Higgs Todo

设计文档见 [docs/design.md](docs/design.md)。本文件只保留可执行任务。

## 已完成里程碑归档

完整历史清单已拆到 [docs/roadmap-archive.md](docs/roadmap-archive.md)，主 TODO 只保留当前执行队列和后续计划。

- [x] Phase 0-2：可信状态机、join/delegation、gossip 同步、discovery、bounded history 和操作文档。
- [x] Phase 3-3.6：daemon/single-writer 基座、NAT/observed path、MTU-safe gossip 和 object-pull/chunk fallback。
- [x] Phase 4：StrongSwan/XFRM 主线、daemon admin 写入、auto-join、planner/reconcile、host-born XFRM、低频 rotate、bidirectional takeover。
- [x] Phase 5：BIRD Babel、route authorization、per-netns BIRD 配置模型、routing debug 和 dry-run smoke 基座。
- [x] Phase 6.0-6.7.6：事件驱动控制面、IPAM、准入诊断、防火墙、动态 peer、撤销清理、链路健康和 Observer MVP 主线。

- [x] Phase 6.7.7：`app/higgs` 模块化重构第一阶段（Observer/debug/inspect 先行）。`internal/observer`、`internal/inspect`、`internal/inspect/http`、`internal/inspect/text` 和 `internal/state` 已承接读侧 view、HTTP DTO、CLI presenter、通用 observer handler 和共享 snapshot 类型；`app/higgs` 保留 executable wiring、daemon provider、control/live/offline source adapter。详细归档见 [docs/roadmap-archive.md](docs/roadmap-archive.md)，后续约束见 [docs/app-higgs-modularization-design.md](docs/app-higgs-modularization-design.md)。

## Phase 7: 生产化收口与高级能力候选

**目标：** 先把 daemon/control/运维面补到可长期运行，再按真实需求推进 multipath、可靠性补强和可选传输能力。Phase 7 不要求按编号顺序执行。

**当前建议顺序：**
1. 先做 **7.10 剩余项**：本地控制接口生产化、CLI daemon-client 默认路径、权限边界、systemd/socket 运行约定。这块最贴近现有完成度，也能支撑后续所有高级能力的操作面。
2. 并行做 **7.1 设计冻结**：先明确单 peer 多 TransportLink 的数据模型、BIRD/Babel 行为和 smoke 验收，不急着实现。
3. 选择一个窄切口进入实现：若目标是稳定性，优先 7.3 chunk repair；若目标是公网部署体验，优先 7.7/7.8 discovery/relay；若目标是运维可见性，优先 7.11 metrics。
4. 7.2 高频 port hopping、7.4 WireGuard、7.5 VXLAN、7.6 SRv6 暂作为可选能力保留，等需求和实验环境明确后再开。

- [ ] **7.10 Daemon / 本地控制接口生产化（建议优先）**
  - 已完成基座：
    - [x] `higgs daemon` 常驻运行主线已负责 gossip 同步、committed state 更新、IPsec/XFRM、BIRD/Babel、firewall、health、observer 等 runtime apply。
    - [x] Unix control socket、control command dispatch、daemon event loop single-writer、committed snapshot 读写分离已落地。
    - [x] 多个 CLI 写命令已优先尝试 daemon control，daemon 不可用时 fallback 到直接 DB/debug/recovery 路径。
    - [x] status、admission、peers、revoke、health、observer/debug 相关 control/readmodel 已有结构化响应或共享 inspect view。
    - [x] `sync status --verbose`、`debug peer`、`debug links`、`debug health` 等已能优先使用 daemon/control/live source，并 fallback 到 DB/offline source。
  - 剩余可执行项：
    - [ ] 梳理 CLI daemon-client 默认策略：明确哪些命令必须走 daemon，哪些允许 direct DB fallback，哪些仅 debug/recovery 才可直接写 DB。
    - [ ] 固化 Unix socket 路径、目录权限、文件权限和 root/admin 用户边界；补 socket stale cleanup 与错误提示。
    - [ ] 补全 control API surface 清单：status、peers、zones、records/history/conflicts、sync trigger、reload config、apply dry-run、health/routes/links/admission/revoke。
    - [ ] 将 control DTO/client helper 逐步下沉到 `internal/controlapi`，避免 app 层和 CLI 调用点重复拼请求/响应。
    - [ ] 增加只读/管理操作分级；TCP control listener 仅预留设计，默认关闭，后续需要时再加 token/mTLS。
    - [ ] 补 daemon 生命周期文档：启动、优雅停止、reload、状态持久化、崩溃恢复、observer/control socket 交互。
    - [ ] 增加 systemd service/socket 示例和路径约定，如 `/run/higgs/higgs.sock`。

- [ ] **7.1 多线路并行（Multipath，先设计冻结）**
  - 待明确：一个 peer 下多条 TransportLink 的 identity、owner token、link group、path priority/weight、health gate 和 cleanup 语义。
  - 待明确：IKEv2/XFRM over 公网 + IKEv2/XFRM over 内网 + 可选 WG/GRE 共存时，哪些字段属于 signed record，哪些属于本地 policy。
  - 待明确：每条链路如何独立匹配 BIRD interface pattern，Babel ECMP/metric 如何与 health/quality 联动。
  - 待明确：debug/observer/readmodel 如何展示 per-peer 多 link 状态，避免只显示“peer online/offline”的单链路视角。
  - 设计冻结后再拆实现：先 planner/readmodel/smoke，再 runtime apply。

- [ ] **7.3 Gossip UDP object chunk repair（窄化可靠性增强）**
  - 目标：只补强 UDP chunk fallback 丢包恢复，不把 gossip UDP 扩展成通用可靠传输；TCP object pull 仍是大对象主路径。
  - 定义短期 `transfer_id`、接收端缺块 bitmap、quiet/deadline 和大小上限。
  - 增加 `object_chunk_nack` / repair request；发送端只从短 TTL 已发送对象缓存中重发缺块。
  - 设置硬边界：最大 repair 轮数、单 peer inflight transfer 数、缓存总字节数、每轮 NACK 大小、quota 计费、sync round deadline 和 TTL 清理。
  - 观测面增加 repair counters，并让 `sync status --verbose` / `debug peer` 区分首次 chunk fallback 与 repair 流量。
  - 增加单测和 smoke：乱序+丢 chunk 后 NACK 补齐、重复 NACK 不放大、缓存过期不重传、坏 hash/错误 transfer_id 不 apply。

- [ ] **7.7 可选 Global Discovery Server**
  - 作为独立公网 rendezvous 服务，只用于无稳定 bootstrap、IP 频繁变化、复杂 NAT 等场景；默认 discovery 仍以 signed endpoint record + gossip 为主。
  - 服务端不成为信任根，不持有 root/admin/zone 私钥；客户端仍以 signed endpoint record 和 Zone trust chain 为准。
  - 支持最小 HTTP/JSON API：`POST /v1/announce` 上报本机 signed endpoint，`GET /v1/peers/{peer_id}` 查询候选 endpoints、observed addr、ttl 和 source。
  - 服务端负责 ttl cache、observed remote addr、限流、防重放和基础滥用防护；不替客户端做最终信任裁决。

- [ ] **7.8 可选 Relay Bootstrap Server**
  - 作为独立公网 bootstrap/relay 程序运行，负责收集节点发布的已签名 Zone/Record/endpoint 数据，维护本地数据库，并向其他节点传播。
  - relay server 不需要自己的 Zone，不持有 root/admin/zone 私钥，不签发 delegation/record，不成为信任根。
  - 支持 gossip bootstrap 行为：响应 `PING`/`PONG`/`FETCH_ZONE`/`FETCH_RECORD`/`ANNOUNCE`，并可 fanout/relay verified data。
  - 支持查询接口：节点按 peer id、zone、digest 查询 relay 已知 endpoints、zone snapshots、record snapshots。
  - 增加 backpressure、去重、allowlist 策略和 relay-only smoke。

- [ ] **7.11 运维与可观测性**
  - Prometheus/OpenMetrics 导出：节点数、链路状态、gossip 流量、zone 数量、chunk repair、object pull、health probe。
  - 评估 peer observability readmodel / metrics store，将 `DatagramStats`、`ObjectPullStats` 等纯诊断计数从 `PeerRuntimeState` 拆出。
  - 梳理 `higgs status`、`higgs zones`、`higgs peers`、`higgs sync` 等面向日常运维的简洁 CLI。
  - Observer 后续增强另见 Phase 7 之后远期后续。

- [ ] **7.13 IPsec/XFRM maintenance 冗余命令优化（待实现）**
  - 问题：`maintainExistingXFRMInterfaces()` 在 `runtime_ensure` 阶段已通过 `InspectLink` 获得接口 flags/addresses，但随后仍无条件调用 `EnsureInterface` / `AssignAddress` / `AssignExtraAddress`。
  - 影响：每次 IPsec reconcile（含启动 recovery、sync timer、endpoint timer 触发）都会对所有已匹配 link 重复执行 `ip link set up/multicast/addrgenmode`、`ip addr replace`、sysctl 等命令；4 link 节点每次 reconcile 约几十次 netns exec 调用。
  - 优化方向：在 `maintainExistingXFRMInterfaces` 中利用 `xfrmLinkStateMatchReason` 的 observed 结果做短路；若 flags/address 已匹配则跳过对应 `EnsureInterface` / `AssignAddress` 调用，仅保留需要一次性确认的配置（如 addrgenmode、forwarding sysctl）。
  - 注意：需同步调整 `TestMaintainExistingXFRMInterfacesRefreshesNoopUpLink` / `RefreshesAdoptedLink` 的测试预期；评估 race condition 与周期性自愈语义之间的取舍。
  - 相关代码：`app/higgs/ipsec_reconcile.go:115-193`、`pkg/transport/ipsec/xfrm_exec.go:64-113`、`pkg/transport/ipsec/xfrm_exec.go:245-274`、`app/higgs/daemon_ipsec_reconcile_test.go:71-158`。

- [ ] **7.14 daemon 启动/endpoint timer 重复触发 reconcile 优化（待实现）**
  - 问题：启动后 `nextEndpointPublish = now` 导致 endpoint timer 立即触发；`handleEndpointTimerEvent` 写 state 后无条件调用 `notifyStateChanged()`，直接 flush IPsec/routing/firewall；同时 endpoint timer 返回 `triggerSync=true`，又把 `nextSync` 重置为 `now`，sync timer 立即再次 flush IPsec。
  - 影响：启动后短时间内（日志里约 300ms）出现两次完整 IPsec reconcile；即使 endpoint/ipsec/routing record 都 `updated=false` 也无法避免。
  - 优化方向：
    1. `runStateStoreWrite` / `notifyStateChanged` 区分“state 是否真正变更”，无变更时不触发 layer flush；
    2. 或 `handleEndpointTimerEvent` 仅在 record 有更新时才返回 `triggerSync=true`；
    3. 或 `notifyStateChanged` 不再直接调用 `flushIPsecReconcile` / `flushRoutingReconcile`，而是把 dirty 标记留给主循环统一 flush，避免一次事件两次 flush。
  - 注意：需保证启动 recovery 后第一次 publish 不会漏掉必要的 layer reconcile；同步更新相关测试，验证无更新时不产生多余 flush。
  - 相关代码：`app/higgs/daemon.go:314-342`（endpoint/sync timer 主循环）、`app/higgs/daemon.go:1053-1072`（`runStateStoreWrite`）、`app/higgs/daemon.go:1355-1386`（`notifyStateChanged`）、`app/higgs/daemon.go:1201-1221`（`handleEndpointTimerEvent`）。

- [ ] **7.15 gossip unsolicited ping summary 短路优化（待实现）**
  - 问题：收到 unsolicited `MessagePing` 且 `msg.Ping.Summary != nil` 时，当前实现直接调用 `handleAnnounceHint(peerID)` 创建 `SyncSession`；session 起来后又会发一次 ping、等一次 pong，才能完成 catalog 对账。但 unsolicited ping 里已经携带了对端的 catalog summary，若 root 和本端一致，这次 ping-pong 完全是冗余的。双方因此形成“对方 ping 触发我开 session → 我发 ping → 对方开 session → 对方又 ping …”的循环，日志里反复出现 `hinted_sync_started reason=announce_hint`。
  - 影响：稳态下每次 unsolicited ping 都走一遍完整 sync round（ping/pong/catalog diff/save state），浪费 CPU 和网络；state 保存还会级联触发 IPsec/routing/firewall dirty flush（见 7.14）。
  - 优化方向：在 `daemon_sync.go:162-171` 的 unsolicited `MessagePing` 处理路径中，先复用 `gossip.CatalogSummaryFor` 生成本端 summary，与 `msg.Ping.Summary.CatalogRoot` 比较；若一致，直接更新 sync peer 状态（`recordSyncHint` + `recordPeerSync`）并返回，**不创建 `SyncSession`**；若不一致，再走 `handleAnnounceHint` 拉差异。
  - 关键设计：
    - 仅对带 summary 的 `MessagePing` 做短路；`MessageAnnounce` 只带 digest hint，无法直接比较，仍走原逻辑；
    - 必须保持现有 `respondPing` 行为（回 pong），让对端能拿到本端 summary；
    - 短路路径要补上 session 完成时会做的状态更新（`LastSyncUnix`、清除 backoff 等），避免 debug/status 显示未同步；
    - 不改变 `SyncSession` 状态机，只改 ingress 处是否创建 session 的判断；
    - 可在此基础上看效果决定是否保留一个较短的 hint cooldown（5s）作为补充兜底，用于处理 root 不一致但仍频繁互相触发 session 的场景。
  - 注意：启动后或长时间未同步时，第一次 unsolicited ping 的 summary 通常会和本端不一致，正常开 session；比较逻辑要注意空 snapshot / nil summary 的边界。
  - 相关代码：`app/higgs/daemon_sync.go:162-171`（unsolicited ping handler）、`app/higgs/daemon_sync.go:226-246`（`handleAnnounceHint`）、`app/higgs/sync_session.go:309-319`（`handleCatalogSummary` 的 root 比较逻辑可复用）、`app/higgs/state.go:470-498`（`recordPeerSync` / `recordSyncActivePull`）、`app/higgs/daemon_sync_test.go`（补“summary 一致时不开 session”测试）。

- [ ] **7.9 可选 Admission 管理面**
  - 在 auto-join 主链路和本地控制接口稳定后，再考虑父 Zone 管理节点的 join request inbox、审核队列、批量 approve/reject 和受限网络化提交。
  - 第一版 admission 仍不引入新的公网 request 协议，也不让 leaf 自动把 join request 写入 gossip active state。
  - 候选命令：`higgs join pending`、`higgs join approve <request-id>`、`higgs join reject <request-id>`。
  - admission policy 仅覆盖父 Zone 有权签发/写入的对象，不配置本机 MeshPolicy / link group / connect-deny override。

- [ ] **7.2 高频 UDP 端口候选 / 对抗性 Port Hopping（可选实验）**
  - 在 Phase 4.4 低频平滑 rotate 之上评估，不默认承诺高频跳端口。
  - IKEv2/IPsec 不假设能像 WireGuard 一样任意 per-peer 高频跳监听端口；高频数据面端口跳变通常需要 reestablish/MOBIKE/多实例或外层 DNAT 配合。
  - 若推进，必须包含 old-port grace、clock skew 容忍、fallback static port、失联恢复路径、QoS 误判回滚和探测限速。

- [ ] **7.4 WireGuard 传输驱动（可选 / fallback）**
  - 通过 `wgctrl-go` 操作内核 WG 接口，复用 Zone K-V 中的 `wireguard/*` record。
  - WG 不作为动态路由主线；仅用于静态前缀、小规模 P2P、或 StrongSwan 不可用平台的轻量 fallback。
  - WG AllowedIPs 只放 tunnel /32 或 /128；业务路由仍交给 Babel/route authorization。

- [ ] **7.5 VXLAN Overlay（远期可选）**
  - 在 WG 或其他三层底座上封装 VXLAN。
  - 通过 Zone record 同步 VNI、VTEP 信息。

- [ ] **7.6 SRv6 支持（实验性）**
  - 通过 netlink 配置 SRv6 SID、End.DT4/End.DX6 行为。
  - 与 BIRD/FRR 的 SRv6 扩展联动，如后续引入 BGP。

- [ ] **7.12 可选策略路由与系统路由审计（远期）**
  - 当前主线保持一个 netns 一个 BIRD 实例，BIRD 直接写该 netns 的 main table；默认不启用额外 `ip rule` / per-overlay table 隔离。
  - 如后续需要 external BIRD、管理员自定义策略路由、或非默认共享 netns 拓扑，再补 `ip rule` / fwmark / iif-oif 策略路由和 `/run/higgs/rt_tables.d` 诊断输出。
  - route-table auditor 仅作为可选兜底，用于交叉检查 Higgs authorized route set、BIRD learned/installed routes 与内核 route table 是否一致。

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

1. 优先收敛 7.10 剩余项：CLI daemon-client 默认策略、Unix socket 权限/路径、control API surface、`internal/controlapi` 边界、systemd/socket 文档。
2. 并行写 7.1 multipath 设计冻结稿：先明确数据模型、BIRD/Babel 行为、health/quality 语义、debug/observer 展示和 smoke 验收，再决定实现切口。
3. 选择一个窄实现切口进入 Phase 7：稳定性优先选 7.3 chunk repair；公网部署体验优先选 7.7/7.8 discovery/relay；运维可见性优先选 7.11 metrics/readmodel。
4. 后续模块化不再单独扩大范围；新增 debug/observer/control 输出默认走 `internal/inspect` view + `inspect/text` 或 `inspect/http` presenter，写侧/daemon adapter 继续留在 app 层直到接口稳定。
