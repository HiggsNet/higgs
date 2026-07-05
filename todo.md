# Higgs Todo

设计文档见 [docs/design.md](docs/design.md)。本文件只保留可执行任务。

## 已完成里程碑归档

完整历史清单已拆到 [docs/roadmap-archive.md](docs/roadmap-archive.md)，主 TODO 只保留当前执行队列和后续计划。

- [x] Phase 0-2：可信状态机、join/delegation、gossip 同步、discovery、bounded history 和操作文档。
- [x] Phase 3-3.6：daemon/single-writer 基座、NAT/observed path、MTU-safe gossip 和 object-pull/chunk fallback。
- [x] Phase 4：StrongSwan/XFRM 主线、daemon admin 写入、auto-join、planner/reconcile、host-born XFRM、低频 rotate、bidirectional takeover。
- [x] Phase 5：BIRD Babel、route authorization、per-netns BIRD 配置模型、routing debug 和 dry-run smoke 基座。
- [x] Phase 6.0-6.7.6：事件驱动控制面、IPAM、准入诊断、防火墙、动态 peer、撤销清理、链路健康和 Observer MVP 主线。

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

## 当前 P0：Daemon state 读写分离 / committed snapshot 重构

**优先级判断：** 这是当前 daemon 稳定性的阻塞项，不应该按 Phase 7.10 的普通排期理解。`debug links`、observer、control socket、gossip fast path 被长 reconcile 写锁拖住时，运维面会在最需要诊断时失明；因此它优先于 multipath、port hopping、relay/admission 等高级功能。

**当前处理方式：** 先完成 `DaemonStateStore` / committed snapshot / revision / 短事务写回这条主线，再继续推进 Phase 6.7.7 模块化和 Phase 7 其他增强。详细设计和拆分清单见下方 `7.10.1`，暂时保留在 daemon/control 生产化章节下作为实现归属，但执行顺序按本 P0 小节优先。

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
  - [ ] **7.10.1 Daemon state 读写分离 / committed snapshot 重构（当前 P0）**
    - **背景问题：**
      - 当前 `stateFile` 已有 `sync.RWMutex`，但 daemon event handler 直接在 live `*stateFile` 上原地修改 map/slice/字段。
      - 为避免 reader 看到半写入状态，writer 拿 `Lock()` 后所有 observer/debug/control 的 `RLock()` 都会等待；当写事务内同步执行 IPsec/VICI、BIRD、firewall、health probe 等外部 I/O 时，只读查询也会被长时间阻塞。
      - IPsec/routing/firewall reconcile 的结果并非同质：有些是会影响下一轮决策的 runtime control state，有些只是诊断摘要。把它们放在同一个长写锁里，颗粒度过粗。
    - **当前过渡修复（保留）：**
      - daemon startup 先发布本机 endpoint/IPsec/routing capability records，再进入 startup recovery；避免数据面 recovery 卡住时阻塞 `ipsec/profile` 从旧 schema 迁移到 `role` 版。
      - `notifyStateChanged()` 在发现 event loop 已持有 state 写锁时，只设置 `ipsecDirty` / `routingDirty` / `firewallDirty`，不在锁内同步 flush reconcile；真实 event loop 在锁释放后统一 flush。
      - IPsec/routing/firewall flush 默认套 `defaultReconcileOperationTimeout`，防止无 deadline 的外部 I/O 无限阻塞主循环；已有更短/更明确 deadline 的调用方保持原 deadline。
      - control/observer 读路径使用 bounded read lock timeout，锁忙时返回明确错误而不是永久卡住。
    - **字段分层：**
      - Source-of-truth state：`Network`、`ManagedZone`、root/zone keys、本机发布的 signed records、config 派生的本地 capability records。
      - Runtime control state：`LinkInstances`、`BirdInstances`、`IPsecTransportKey`、`IPsecPortRecord`、`SyncPeers` 的 backoff/cache/observed path、admission state。这些字段会影响下一轮 plan/reconcile，需要强一致或按 key 条件提交。
      - Observability summary：`IPsecReconcile`、`RoutingReconcile`、`FirewallReconcile`、最近 actions/skips/actual SAs、last error、backend summary。这些字段主要供 CLI/observer/diagn断使用，可以接受读到最近一次 committed snapshot，写回策略也可以比 runtime control state 更宽松。
    - **目标设计：**
      - 引入 `StateStore` / `DaemonStateStore`，daemon 不再把 mutable `*stateFile` 指针裸露给 observer/control/debug。
      - Store 维护 committed snapshot 与 revision：
        - `Snapshot() (snapshot *stateFile, rev uint64)` 返回稳定只读快照；reader 读取最近一次 committed snapshot，不等待长写事务。
        - `BeginUpdate()` / `Update(fn)` 用于短事务修改 committed state；禁止在 update 闭包中做 VICI/BIRD/nft/DNS/ping/文件系统长 I/O。
        - `CommitIfRevision(rev, fn)` 或按对象 `CommitLinkInstancesIfMatch(...)`，用于 reconcile result 条件写回；revision 或 per-object token 不匹配时丢弃旧 result 并重新置 dirty。
      - 写事务采用 copy-on-write / writer workspace：
        - writer 从 committed snapshot clone 出 workspace，在 workspace 上计算和执行需要强顺序的 state transition。
        - 外部 I/O 尽量锁外执行；需要事务顺序的 layer 保留 daemon single-writer 调度，但不持 reader-visible state 写锁。
        - commit 时短锁/atomic swap committed snapshot；reader 可能读到稍旧 snapshot，但不会看到半写入状态，也不会被长事务阻塞。
    - **IPsec reconcile 拆分策略：**
      - 第一阶段只做 snapshot 输入：
        - 从 committed snapshot 复制 `Network`、`ManagedZone`、`LinkInstances`、`IPsecTransportKey`、`IPsecPortRecord`、revoked peers、health cutover readiness 和 link group config。
        - 锁外执行 `PlanTransportLinks`、`ListSAs`、XFRM inspect 和 `ReconcileLinkInstances`。
      - 写回分层：
        - `LinkInstances` 按 `InstanceID` 条件提交，检查当前 instance 的 `DesiredSpecHash` / generation / owner token / rotate phase 是否仍匹配 reconcile 起点；不匹配则跳过该 instance 并保持 `ipsecDirty=true`。
        - `IPsecReconcile` summary 可写入“最近一次 attempt”，但必须标注 `snapshot_revision` / `committed=false|stale` 或在 stale 时只记录 last_error，不覆盖当前 desired/action summary。
        - `ActualSAs` 属于 observation，可允许用较新 observe 覆盖摘要，但不得驱动旧 desired 覆盖 `LinkInstances`。
      - 失败处理：
        - apply 失败后的 backoff/failure count 写回也必须按 instance 条件提交；提交失败说明状态已被新事务接管，旧失败不应污染新 instance。
        - 外部 apply 已发生但 commit 失败时，下一轮 reconcile 通过 observe/live state 收敛，而不是强行写旧结果。
    - **Routing / BIRD reconcile 拆分策略：**
      - `BirdInstances` 是 runtime control state：config hash、pid/control socket、state、failure count、backoff 会影响下一轮 start/reload/adopt，需按 netns 条件提交。
      - BIRD config 生成可基于 snapshot 锁外完成；写 config 文件、start/reload/status 都必须在 reader-visible lock 外执行。
      - `RoutingReconcile` last run/error 是 summary，可独立宽松提交。
      - `autoAnnounceAssignedIPs` 会修改 source-of-truth records，不能混入普通 routing reconcile 的长事务；需要拆成独立 command/update 事务，再触发 routing dirty。
    - **Firewall reconcile 拆分策略：**
      - firewall desired 主要从 source snapshot + config 构建；`FirewallReconcile` 基本是 observation summary。
      - List/Plan/Apply 必须锁外执行；summary 写回短事务即可。
      - 因 firewall result 不应改变 source-of-truth，stale summary 可以被下一轮覆盖；需要避免 stale apply 后误报为最新 policy hash。
    - **Reader / control / observer 语义：**
      - `debug links`、observer API、`daemon status` 默认读 latest committed snapshot，不等待 active writer；输出 `state_revision`、`snapshot_time`、`reconcile_in_progress` / dirty flags，必要时标注结果可能是上一次 committed view。
      - 强一致命令（如 record put 后立即 get）可选择等待指定 revision committed；普通只读命令不等待。
      - gossip ping/pong 响应不读长写锁；需要更新 observed path 时投递 writer event，由 single-writer 后台提交。
    - **实施顺序：**
      - [x] 设计并引入 `DaemonStateStore` 骨架：committed pointer、revision、snapshot clone、short update、dirty flags；先不迁移所有调用，只提供并行 API。
        - 已新增 `DaemonStateStore` 并接到 `DaemonService`：旧事件循环仍操作 live `Sync.State`，`setState` / `notifyStateChanged` 发布 committed snapshot；后续 reader/reconcile 逐步迁到 store API。
      - [x] 补 `cloneStateFile` / snapshot clone 测试，确保 `Network`、records/history、maps/slices、runtime states 深拷贝，不共享可变 map。
      - [x] 迁移 observer/control/debug 只读路径到 `Snapshot()`，去掉对 live `stateFile.RLock()` 的依赖；输出 revision/dirty/reconcile status。
        - control `status` / `record_get` / `bird_status` / `routes_dump` / `admission_status` / `firewall_status` / `links_status` / `peers_status` / `revoke_status` 已读 committed snapshot，并返回 `state_revision` / `snapshot_time_unix` / dirty / reconcile flags；observer provider 已改用 snapshot，status API 输出 revision/dirty 信息；CLI debug 在线路径经 control 间接受益。
      - [x] 迁移 gossip packet 快路径：ping/pong 响应不等待 writer；observed path 作为 event 异步提交。
        - packet event 已从 `handleEvent` 全局 live state 写锁前分流，处理后发布 committed snapshot；object-pull TCP lookup 改为读取 snapshot getter，不再持 live `RLock()`；已补 live state 写锁被持有时 packet event 仍返回并提交 observed path 的回归测试。后续 sync FSM 更细粒度写回仍归入 reconcile/store 条件提交阶段。
      - [x] 先拆 IPsec reconcile：snapshot input、锁外 plan/apply、按 instance 条件提交 `LinkInstances`，summary 带 revision/stale 标记。
        - `reconcileIPsecLinks` 基于 committed snapshot 做 plan/list/XFRM inspect/reconcile/apply；写回先走 source revision 快路径，revision 变化时按变更 instance 的 owner token 合并 `LinkInstances`，只在同 id token 冲突时保留当前 snapshot、写 stale diagnostic 并重新置 `ipsecDirty`。`IPsecReconcile` summary 已包含 `source_revision`、`committed`、`stale`。
      - [ ] 再拆 routing：BIRD config/start/reload/status 锁外执行，按 netns 条件提交 `BirdInstances`；拆出 `autoAnnounceAssignedIPs` 为独立 state update。
        - 已完成 routing 第一刀：`reconcileRouting` 基于 committed snapshot workspace 生成 `BirdInstances` / `RoutingReconcile`，BIRD config/start/reload/status 和 health observation 不再读写 live state pointer；提交先走 source revision 快路径，revision 变化且无 auto-announce 网络改动时按 netns 的 BIRD owner token 合并 `BirdInstances`，冲突则保留当前 snapshot 并重新置 `routingDirty`。后续仍需把 `autoAnnounceAssignedIPs` 从 routing workspace 内拆成独立 StateStore update。
      - [ ] 再拆 firewall：锁外 apply，短事务写 `FirewallReconcile` summary。
      - [ ] 最后移除 `DaemonService.stateUnlock` / `lockState()` 这类 live pointer 锁追踪，daemon event loop 只通过 StateStore 操作。
      - [ ] 增加并发回归测试：长 IPsec/BIRD/firewall reconcile 阻塞时，`daemon status` / `debug links` / observer API 仍能返回 latest committed snapshot；旧 snapshot result 不覆盖新 revision；dirty coalescing 能在 stale commit 后触发下一轮 reconcile。
    - **验收标准：**
      - 长时间 IPsec/VICI/BIRD/firewall apply 不阻塞 observer/control 普通只读查询。
      - 单写事务顺序仍保留：record put / reload / reconcile result 不并发修改同一 runtime control state。
      - 旧 snapshot 的 runtime result 不覆盖新 committed state；stale result 会置 dirty 并由下一轮收敛。
      - `go test ./app/higgs`、observer/control/debug 相关测试、IPsec/routing/firewall reconcile 测试均覆盖 MVCC 语义。

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

1. 启动当前 P0 / Phase 7.10.1 Daemon state 读写分离 / committed snapshot 重构：先实现 `DaemonStateStore` 骨架、snapshot clone、revision/dirty 语义和 reader 快照路径，解决 observer/control/debug 被长写事务阻塞的问题。
2. 继续 Phase 6.7.7 `app/higgs` 模块化重构：优先补齐 `internal/inspect` / `inspect/text` 骨架，把 `debug links` 与 Observer links 的共用 read model 扩展成可迁移模式；该 read model 后续直接消费 StateStore snapshot。
3. 第二步抽 zone/record/authority 展示逻辑，复用到 `zone show` / `debug zone` / Observer zone detail，避免 HTTP schema 直接绑定 `zone.Record` 原始字段。
4. 第三步抽 peer endpoints，再逐步迁移 routes/BIRD/health/revocation/admission/firewall 的诊断 presenter 和 reason 推理。
