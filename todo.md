# Photon Todo

设计文档见 [docs/design.md](docs/design.md)。本文件只保留可执行任务。

## 已完成里程碑归档

完整历史清单已拆到 [docs/roadmap-archive.md](docs/roadmap-archive.md)，主 TODO 只保留当前执行队列和后续计划。

- [x] Phase 0-2：可信状态机、join/delegation、gossip 同步、discovery、bounded history 和操作文档。
- [x] Phase 3-3.6：daemon/single-writer 基座、NAT/observed path、MTU-safe gossip 和 object-pull/chunk fallback。
- [x] Phase 4：StrongSwan/XFRM 主线、daemon admin 写入、auto-join、planner/reconcile、host-born XFRM、低频 rotate、bidirectional takeover。
- [x] Phase 5：BIRD Babel、route authorization、per-netns BIRD 配置模型、routing debug 和 dry-run smoke 基座。
- [x] Phase 6.0-6.7.6：事件驱动控制面、IPAM、准入诊断、防火墙、动态 peer、撤销清理、链路健康和 Observer MVP 主线。
- [x] Phase 6.7.7：`app/photon` 模块化重构第一阶段（Observer/debug/inspect 先行）。`internal/observer`、`internal/inspect`、`internal/inspect/http`、`internal/inspect/text` 和 `internal/state` 已承接读侧 view、HTTP DTO、CLI presenter、通用 observer handler 和共享 snapshot 类型；`app/photon` 保留 executable wiring、daemon provider、control/live/offline source adapter。详细归档见 [docs/roadmap-archive.md](docs/roadmap-archive.md)，后续约束见 [docs/app-photon-modularization-design.md](docs/app-photon-modularization-design.md)。
- [x] Phase 7.1 异构 TransportLink 并行共存（模型、实验与公共边界已冻结）。
- [x] Phase 7.3 Gossip UDP object chunk repair。
- [x] Phase 7.10 Daemon / 本地控制接口生产化。
- [x] Phase 7.13-7.15 稳态冗余优化（XFRM maintenance、endpoint timer、unsolicited ping）。
- [x] Phase 7.16 Firewall backend-native inline hooks 及后续收口（external mode、ip6tables 双栈探测、`photon debug firewall` flag、nft priority 配置）。详细实现归档见 [docs/roadmap-archive.md](docs/roadmap-archive.md)。

## Phase 9: Observer Web UI 重构（已完成）

**目标：** 解决现有 observer 网页视觉陈旧、信息架构混乱的问题。设计定稿见 [docs/new/observer-ui-redesign.md](docs/new/observer-ui-redesign.md)；observer 只读定位、REST API 形状与安全模型不变。

**约束：** 零构建（原生 ES Modules + 多 CSS 文件，无 Node 工具链）、零运行时依赖、纯 embed；注意 `//go:embed web/*` pattern 需随新增子目录扩大。

- [x] **9.1 设计基座**
  - `web/style/tokens.css`：中性灰底 + 单一 accent + 语义状态色（ok/warn/err/unknown）、字号/间距阶梯、radius token。
  - 布局壳重写：侧栏分组导航（总览 / 网络 / 监控）、底部连接状态三态指示、统一页头（标题 + 说明 + 页面级操作区）。
  - 基础组件收敛到 `style/base.css`：card、stat-card、badge、dot、table、kv、details、empty/loading/error 三态。

- [x] **9.2 前端模块化与重绘策略**
  - `app.js`（1153 行单文件）拆分为 `web/src/` 原生 ES modules：`api.js` / `store.js` / `events.js` / `router.js` / `format.js` / `components/*` / `pages/*`，单文件 < ~200 行。
  - store 按 endpoint 缓存 + 事件类型到 endpoint 的失效映射，SSE 事件只重取受影响键，不再整页刷新。
  - 重绘保留 scrollTop / 输入 / `<details open>` 状态，删除 `foldState` 全局补丁。
  - Health 页 sparkline 懒加载，消除每次刷新每条 link 一个 series 请求的 N× 放大。

- [x] **9.3 页面信息架构重构**
  - Overview 仪表盘化：全局状态横幅 + 问题清单（带深链）优先，统计卡与 reconcile 摘要其次。
  - Overlay（控制面：planner/SA/reconcile/rotation）与 Health（数据面：探针/RTT/loss/曲线）职责分离，导航文案明确。
  - Zones 双栏布局；authority/proof/revocations/history/Raw JSON 全部收入 Inspect 折叠区；hash 截断 + 点击复制。
  - Routes 错误置顶 + zone 过滤；BIRD 错误醒目展示；Gossip diagnostics 格式化 kv。
  - 全局：相对时间、列表页文本过滤、选中态写入 hash 可深链。

- [x] **9.4 事件链路补完（可选，动后端）**
  - `daemon.go` 广播点携带轻量 payload（`link_id` / `peer_id`），前端条目级失效。
  - 落地 `event_buffer_seconds` 环形缓冲 + Events 时间线页（独立可裁）。

- [x] **9.5 测试与文档收口**
  - `webapp_test.go` token 断言改写为模块化后的关键导出；`static_test.go` 覆盖新增子目录；`internal/observer` 与 `app/photon` observer 族测试全绿。
  - `app/photon/observer_api_*_test.go` 不应需要修改（REST 响应不变，9.4 除外），若需修改则说明越界。
  - `docs/new/observer.md` 第 6/9 节同步为重构后行为。

## Phase 7: 生产化收口与高级能力候选

**目标：** 先把 daemon/control/运维面补到可长期运行，再按真实需求推进异构 TransportLink 并行、可靠性补强和可选传输能力。Phase 7 不要求按编号顺序执行。

**当前建议顺序：**
1. 7.7/7.8 discovery/relay 或 7.11 metrics/readmodel，按实际需求选择下一窄切口。
2. 7.2 高频 port hopping、7.4 WireGuard、7.5 GRE/VXLAN、7.6 SRv6 保持可选，等需求和实验环境明确后再开。

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
  - 先按 7.11.0 将 peer 纯诊断数据从 committed state 拆到独立 observability store；不能用 peer ID、endpoint 或原始错误串作为 metrics label。
  - 梳理 `photon status`、`photon zones`、`photon peers`、`photon sync` 等面向日常运维的简洁 CLI。
  - Observer 后续增强另见 Phase 7 之后远期后续。
  - Health probe 性能：已实现按 netns 常驻的 raw-ICMP worker，worker 固定 OS thread 后 `setns` 并按源/接口复用 ICMP socket；raw socket / `setns` 的 setup 失败自动回退 exec prober，消除正常路径的 `ip netns exec ping` fork/exec/mount 开销。待完成 root smoke：IPv4、IPv6 link-local scope、netns 删除/重建、`CAP_NET_RAW` / `CAP_SYS_ADMIN` / `NoNewPrivileges` 缺失时的降级；验收后再确认默认路径的长期运行行为。
  - **Daemon state-store 性能（perf 2026-07-24，2026-07-31 复核）**
    - daemon 生产写路径由主事件循环串行执行；packet receiver、object-pull、health 和 control 后台 goroutine 只投递事件或更新独立 observability，正常运行时不会并发执行两个 routing reconcile，也不会在 reconcile 中途插入另一个 committed writer。`DaemonStateStore` 的锁仍用于并发读和边界防护，全局 `revision` 用于排序及检测意外绕过 single-writer 的写入，而不是把多 writer 当作正常工作模式。
    - 当前 committed root 及其可达子结构必须永久不可变；写操作只修改 detached workspace 或 typed COW 拥有的字段，发布时在锁内替换一次 root。`Snapshot()` 在取得 root/revision 后释放锁再复制是安全的，前提正是旧 root 不再原地修改。
    - 当前主要成本不在 commit 语义，而在 `BeginUpdate`、`Commit` 和只读 snapshot 反复通过 JSON round-trip 复制完整 state，体积最大的 `Network` 因此反复分配、base64 编解码并增加 GC/缺页压力。
    - 实机 `photon db stats` 显示逻辑有效数据约 1,094,124 bytes：`_meta` 约 34,099 bytes（3.1%），所有 `zone:*` bucket 约 1,060,025 bytes（96.9%）。磁盘文件约 4 MB 是 bbolt 页、空闲页和索引等分配后的文件大小；此前提及的 48 MB 是 health spool，不是 Network/state DB。
    - [x] 将每个 `zone/key` 的 `RecordHistory` 上限从 128 收紧为最近 16 条；新写入持续按 16 条截断，加载旧数据库时也裁掉更早历史，下一次成功保存会重写逻辑值。bbolt 文件不会因此自动缩小，物理回收若有需要应另做离线 compact，不纳入当前 CPU 修复。
    - 保留通用 `StateStore.Update` 当前的完整隔离语义：不得直接转移 workspace 所有权，也不得单独删除 commit 的第二次 clone。`Workspace()` 仍会把裸指针交给调用者，且 callback 可以 retain 指针；在 typed mutation 收口前，第二次 clone 是 committed 私有性的保证。
    - 不把完整 clone 移入 store 锁内；仅把 clone 延后到第一次 revision 检查之后只能优化 stale transaction，当前 perf 未证明 stale 是热点，不作为独立优化。
    - 不引入 component/per-chunk revision。typed COW 继续使用单一全局 revision；按 single-writer 设计，stale 属于异常防护，必须丢弃结果并重新排队，不能通过字段级 merge 把基于旧输入计算的结果合入新 root。若未来明确把 routing/IPsec reconcile 改为后台并行计算，再单独设计 read-set/component revision。
    - 决定先实现完整手写深拷贝，作为保持现有事务边界不变的低风险降本层。2026-07-31 使用 1000 records、每条 128-byte value 的同一 Network fixture 复核：JSON clone 为 4.61-4.90 ms、1.47-1.56 MB、约 10,055 allocs；现有类型化手写 Network clone 为 0.212-0.226 ms、471 KB、4,013 allocs，约快 21-23 倍。该结果只代表 record-heavy Network，不把它直接外推为整机固定收益；手写 clone 之后仍需以同负载 perf 决定后续 COW 优先级。
    - `ZoneState.MerkleRoot` 当前没有完整的计算/失效维护，不能直接作为 digest cache。只有未来 perf 再次证明 zone digest 是热点，并覆盖 record/history、delegation、revocation、snapshot apply、recovery/import/purge、join/adoption 等所有 Network mutation 后，才考虑启用。
    - 不新增高基数内部 metrics；阶段验收继续由开发者手工运行 perf/strace，对比 idle CPU、clone/alloc、`LoadNetwork` 和 fork/exec。

  - [x] **7.11.0 先拆 committed control state 与纯 observability**
    - 这一步是 state-store 性能优化的前置阶段。Phase 6.7.7 已把 inspect/readmodel/presenter 从 `app/photon` 拆出，但数据所有权仍集中在 `stateFile`：代码模块化不等于存储模型已经模块化。先消除不该发生的 commit，再优化剩余 commit 的复制方式。
    - 先按语义把数据分为三层：必须强一致和持久化的权威状态；会影响调度、路径选择和重启收敛的控制器运行状态；只供 observer/debug/status 使用、允许丢失或短暂不一致的 observability。readmodel 在读取时合并 committed control snapshot、observability snapshot 和 health/BIRD actual snapshot，现有 CLI/HTTP DTO 尽量保持不变。
    - 第一窄切口只迁移已经确认纯诊断的 `DatagramStats` 和 `ObjectPullStats`，包括其中的 catalog/page/reject、too-large、repair/fallback 计数与最近一次详情。随后逐字段审计并考虑迁移 hint accepted/suppressed、read-only responder、active-pull 展示状态、relay suppression reason 和其他最近一次 action/error detail；不能因为字段显示在 debug 页面就认定它是纯诊断。
    - `BackoffUntilUnix`、`FailureCount`、`LastRelayUnix`、`DiscoveredAddr`、observed path/TTL/grace、`LastSyncUnix`、`RejectedDigests` 等仍影响同步、限流或实际路径，先留在 control state。`LastError` 当前也参与 observed/discovered path 判断，迁移前应先拆成稳定的控制错误码/状态和仅展示的错误文本。
    - 引入有界的 `PeerObservabilityStore`，优先放在窄职责的 `internal/observability`，由 `app/photon` 负责 wiring，由 `internal/inspect` 继续负责纯 view 构建；不要把 mutable store 放进 `internal/inspect`。store 自带独立锁或分片、按 peer snapshot 和删除/过期能力，不持有 `stateFile` 或 committed 子结构指针。
    - 第一版 diagnostics 不随主 state 持久化，daemon restart 后计数归零；旧 state 中遗留字段可兼容读取但不再回写。live observer/debug 合并新 store，offline DB 诊断允许显示 unavailable/reset。若以后确有历史需求，再低频批量写独立 spool/metrics store，不能重新推动主 revision。
    - 将 `recordDatagram*`、`recordCatalog*`、`recordObjectPull*` 等调用改写为 observability store 更新后，不得调用 `StateStore.Update`、install、publish 或 `SaveState`。补充并发 snapshot、peer 清理、restart reset、旧 state 兼容以及 CLI/HTTP schema 测试，再跑相同负载 perf 判断剩余 `recordSyncPeerState` 热点。

  - [x] **7.11.1 合并同一事件内的重复 peer mutation**
    - 在纯 diagnostics 迁出后，合并同一个 sync/packet 事件内剩余的 `sync_hint`、`peer_sync`、observed path、backoff/rejected digest 等控制状态写入，尽量一次提交；observability 更新独立聚合，不再参与 committed transaction。
    - 不改变状态机、control/observer DTO、落盘格式和 wire 格式；先做调用点收敛，不修改通用 `StateStore.Update`。
    - sync event 现在用事件内 mutation batch 按原顺序聚合 active-pull、backoff 和 completion，并在 `SaveState` 前 flush；hint shortcut 与 hinted-session 初始化也各自合并为一次提交。fetch responder packet 将 observed-path 与 read-only responder 合并，除仍会直接 apply Network 的 object-chunk 外，不再在 packet 末尾重复 publish 已安装的 committed snapshot。

  - [x] **7.11.2 实现 `UpdateSyncPeer` 局部 COW**
    - 保留全局 revision/CAS；新版本只构造新的 state root，复制 `SyncPeers` map，并深拷贝目标 peer 中会修改的 map、slice、pointer；`Network` 和其他未修改块只读共享。
    - mutation API 不向调用者暴露完整可变 `*stateFile`，也不得允许 callback retain 最终 committed root。`stateFile` 含 mutex，不能用普通结构体赋值直接复制锁；应显式构造不复制 mutex 的 root，或先拆出不含锁的 immutable root。
    - stale 时只允许有界重试。mutation 必须纯粹且可重放：不得在 callback 内执行 transport、网络、磁盘、`SaveState`、事件广播或外部计数；时间/随机输入在重试外捕获；依赖 Network 的判断每次基于最新 committed revision 重新计算。
    - 第一阶段继续保留 `Snapshot()` 和 `installCommittedSnapshot` 的完整 clone，让 `d.Sync.State` 仍是与 committed 隔离的可变副本；先消除 `recordSyncPeerState` 中 `BeginUpdate` + `Commit` 的全量 JSON clone，不同时改 live-state 一致性模型。
    - 只迁移剩余高频且确实影响控制行为的 `SyncPeers` 写路径，例如 backoff、observed/discovered path、relay throttle 和 rejected digest；peer repair、chunk fallback/NACK 等纯诊断应已在 7.11.0 迁出。`updateDiscoveredPeers` 必须拆成“从 immutable view 计算变化 → 提交 peer mutation → commit 成功后更新 transport”，避免 CAS retry 重复 transport 副作用。
    - `UpdateSyncPeer` 使用最多 4 次全局 revision/CAS 重试，只复制 state root、`SyncPeers` map 和目标 peer，并在 commit 前仅二次复制目标 peer 来隔离 retained callback；sync event/hint/backoff/relay/read-only responder/observed-path 已切换到局部 COW，`Snapshot()`/install 仍按计划保留完整 clone。
    - `updateDiscoveredPeers` 已拆成 replayable batch plan：基于每次最新 immutable view 一次计算 peer state replacements 与 transport plan，通过局部 COW 一次提交所有变化，commit 成功后才更新 known peer、discovered/observed transport cache；stale/no-op 都会复核 revision，无状态变化不升 revision但仍可修复 transport cache。daemon 调用点均切到新路径，独立非-daemon helper 保留原兼容行为。
    - 当前 1 MiB Network benchmark 的短基准为：通用 full update 约 15.99 ms / 6.53 MB / 137 alloc，local COW 约 633 ns / 1.26 KB / 6 alloc；该结果只确认复制路径量级，阶段后的实机 idle/perf 仍按上面的手工验收约定执行。

  - [x] **7.11.3 阻断 daemon 自写导致的 state reload**
    - 现有 `reloadStateIfChanged` 已用同一文件、mtime、size 的文件标记跳过无变化的 `BoltStore.LoadNetwork`；文件原子替换、读期间变化或 `stat` 失败时继续保守重读。
    - daemon 自己成功完成 Bolt save/commit/close 后，再读取并记录稳定的文件标记；reload 仅在标记明确等于当前进程刚完成的自写结果时跳过。保存期间文件再次变化、`stat` 失败或标记不确定时清空缓存并在下一轮正常 reload，不能屏蔽外部管理命令或其他进程写入。
    - 该项与 state COW 独立，可并行实现；perf 中剩余 `LoadNetwork` 约 1.49% 不保证全部来自自触发，改后需通过调用次数和新 perf 区分合法 reload。
    - 已完成：daemon 所有 SyncRuntime/StateStore 持久化路径统一在 Bolt transactions 与 `Close` 成功后记录文件 identity/size/mtime；close 前后标记不稳定、`stat` 失败或保存失败时保持空缓存。命中当前进程的稳定自写标记时只报告“无外部变化”，不返回任何内存 state；测试覆盖自写零 loader、外部写入仍 reload、读取期间文件变化不缓存以及保存失败清标记。

  - [x] **7.11.4 清零对 `d.Sync.State` 的直接写入**
    - 完整盘点 direct writer，至少覆盖 object chunk snapshot apply、rejected digest、discovery、admission，以及启动阶段 endpoint/IPsec/routing record publish；chunk fallback、NACK/peer repair 等纯诊断在 7.11.0 后不应再写 `d.Sync.State`。
    - 高频 `SyncPeers` writer 使用 `UpdateSyncPeer`；低频 admission、endpoint、IPsec、routing writer可先迁到现有通用 `StateStore.Update`，优先统一写入权威，不要求为每个字段预先建立专用 chunk API。
    - object chunk 对 `Network` 的修改是移除 live/store 双状态前的关键阻塞项：先提供保证 committed 隔离的 Network mutation；若完整 Network clone 仍成为热点，再进入 per-zone COW。
    - `recordBirdHealthObservationForState` 只从 state 读取并更新 health manager，不是 state writer；迁移时改用 immutable read/view，不为它新增 `BirdInstances` mutation。
    - 同时审计所有可能 retain/mutate committed 子结构的入口，不限于 `ReadCommitted`：包括返回 `*stateFile`/`*NetworkState` 的 API、validation 配置、map/slice/pointer 内部修改和 `d.Sync.State` 的全部调用点。结构共享后，任何旧 revision 被修改都会污染共享它的新 revision。
    - daemon UDP object chunk 已把 assembly/repair 与 committed mutation 分开：完整 zone snapshot 通过通用 StateStore workspace apply，损坏 chunk 的 rejected digest 通过 peer 局部 COW 提交；成功路径只升一个 apply revision，不再在 packet 尾部反向 publish。`sync serve` / `sync once` 也通过 DaemonStateStore 运行事件循环。
    - daemon 启动 admission diagnosis、endpoint、IPsec 和 routing record publish 已合并为一个隔离 workspace、一次 commit 和一次 save；无变化的第二次 prepare 不升 revision。外部 state reload 直接替换 committed authority。
    - reader/retain 审计已处理 transport observed grace slice 的原地 compact、verified-zone validation hook 对 Network root 的写入、health/BIRD 的状态读取，以及 `OnStateChanged` hook retain：transport/health 改读不可变 view，hook 接收 detached snapshot。`SyncRuntime.State` 字段已删除，编译器会阻止重新引入旧的双状态调用方式。

  - [x] **7.11.5 移除 live/store 双状态桥接**
    - 仅在 direct writer 清零、所有 reader 均遵守不可 retain/mutate 约定后，才把 runtime 读侧切换为 immutable committed view 或更小的 store projection；不要仅把一个仍可写的 `d.Sync.State` 指针指向 committed。
    - 随后删除 `installCommittedSnapshot` 的完整 clone 和 packet 后的 `publishCommittedStateSnapshot`；短、确定纯读的操作使用 committed view 或 `ZoneDigests()`、peer summary 等返回小结果的 projection，不为读操作复制完整 Network。
    - routing reconcile 的第二次 snapshot 保留其一致性语义：auto-announce 可能修改/撤回 record，BIRD 配置必须读取提交后的新状态。只有等价的数据依赖得到证明后才允许收敛，不能仅以减少 clone 为由删除。
    - 已删除 daemon 的 install/publish 桥接；peer、packet、object chunk、discovery、reconcile 和 control 写侧只提交 StateStore，持久化直接保存 committed snapshot。`SyncRuntime.State` 字段及无 StateStore fallback 已删除；transport 初始化和 legacy/standalone helper 必须显式接收 state，不能暗中持有第二份状态。
    - PING、catalog summary/page、hint session、timer、普通 `FETCH_ZONE`、relay、object-pull 与 observed-path seed 已改为 committed view 内生成 detached projection；回调外发送消息、更新 transport 或记录日志。完整 chunk fallback 与 reconcile 继续使用隔离 snapshot，避免在 committed 读锁中执行外部副作用。
    - routing reconcile 的 auto-announce 后第二次 snapshot 保留；空 firewall/routing flush、peer 局部写和 daemon 自写 reload 回归测试检查 revision 不被隐式 republish、committed state 不被旧快照替换。1 MiB Network 的服务级 `recordSyncPeerState` 隔离基准约 0.92–1.00 µs / 2.10 KB / 10 alloc，对照通用 full update 约 15.5–15.8 ms / 6.44–7.08 MB / 136–139 alloc。

  - [ ] **7.11.6 StateStore 正确性、手写 clone 与分层 COW**

    **目标与边界**
    - 在不改变 daemon single-writer、磁盘格式、wire 格式、sync 部分成功语义和现有 control/observer DTO 的前提下，先修复 snapshot apply 的失败原子性，再降低完整 clone 单价，最后逐步消除不必要的完整 clone。
    - 保留一个全局 `revision`。本阶段不增加 Network/Link/IPsec/Routing/Peer component revision，不支持两个 routing reconcile 并行合并，也不把 StateStore 扩展为通用多 writer MVCC。
    - committed root 及所有共享子结构一经发布不得原地修改；任何会写 map、slice、pointer 或 validation hook 的代码必须先取得该对象的独占副本。只读共享可以跨 revision 保留，Go GC 负责旧 root 生命周期。
    - 通用 `StateStore.Update` 在 typed mutation 完成前继续保留 detached workspace 和 commit 前第二次 clone，防止 callback retain `Workspace()` 后污染 committed。每个 typed COW API 只拥有明确字段，不向 callback 暴露完整可写 `*stateFile`。
    - 每个子阶段独立落地、独立 benchmark/测试；前一阶段的正确性和 perf 数据验收后再进入下一阶段。不得为了达到最终 COW 形态而在一个改动中同时重写 sync、routing、IPsec、firewall 和 persistence。

    - [x] **7.11.6.1 修复 `ApplySnapshot` 失败原子性**
      - 当前 `gossip.ApplySnapshot` 使用完整 candidate 验证 trust chain，但验证后转而修改传入 `NetworkState`；delegation/revocation 已写入或部分 record 已 `PutAt` 后发生错误时，调用者可能提交部分 snapshot。
      - 将 authority、parent proof、delegation、revocation、record/history 的全部变更先应用到 detached candidate；只有所有验证和 record apply 完成后才一次性安装结果。任何错误返回时，传入 Network 的字段、map、slice、record/history、root 和 validation hook 均保持不变。
      - 保持现有 stale record、record conflict、apply count、delegation count、auto-join 和 rejected digest 对外语义。snapshot apply 失败只记录 rejected digest；失败 snapshot 不得借由外层 `StateStore.Update` 提交 Network 的部分变化。
      - 测试至少覆盖：trust chain 失败、delegation/revocation 校验失败、前一条 record 成功而后一条失败、stale/conflict 被跳过、成功 apply；失败用序列化状态或逐字段断言验证前后 Network 等价，并运行 `pkg/core/gossip` race 测试。
      - 已完成：snapshot 的 trust、delegation、revocation 和有序 record 合并全部在完整 detached candidate 上执行，成功后才一次替换传入 Network；candidate clone 保留 nil/empty 形态、root、validation hook 和 nil zone entry。回归测试覆盖全部失败点、stale/conflict 跳过、成功 history 更新及 retained target/snapshot 隔离；`go test -race ./pkg/core/gossip ./pkg/core/zone`、全量测试、`make check`、chain relay/object pull/routing dry-run smoke 均通过。

    - [x] **7.11.6.2 删除 routing stale 字段级 merge**
      - 保留 `routingSnapshot()`：只深拷贝 routing-owned 的 `BirdInstances`、`RoutingReconcile`，`Network`、link/IPsec 和其他 committed 子结构继续只读共享。
      - `commitRoutingIfRevision` 正常成功时按现有方式替换 routing-owned 字段；全局 revision stale 时不再调用 `commitRoutingBirdInstancesByNetNS`，不比较 owner token，也不按 netns merge。直接保留最新 committed、设置 `routingDirty` 并等待下一次完整 reconcile。
      - auto-announce 在同一 reconcile 内主动更新 Network 后必须继续重新取得 routing snapshot/revision，并基于提交后的 Network 重建 authorized route set；不得因为 single-writer 假设删除这次 refresh。
      - 删除只服务于 stale merge 的 helper/测试，增加防护测试：reconcile 被测试桩阻塞时人工推进 revision，旧 routing 结果不得覆盖新 state，服务必须重新标 dirty。生产路径出现 stale 应记录足够诊断信息，因为它意味着 single-writer 假设被绕过。
      - 已完成：删除按 netns 重取 snapshot/比较 base/合并的 stale fallback；CAS stale 现在记录 source/current revision 与 changed netns，保留最新 committed 并发布 routing dirty。阻塞式 BIRD 测试覆盖 reconcile 中途推进全局 revision，确认旧 `BirdInstances`/`RoutingReconcile` 被整体丢弃且不会额外升 revision；auto-announce 后 refresh 保留。相关 app race、全量 `make check` 与 routing dry-run smoke 通过。

    - [x] **7.11.6.3 以完整手写 clone 替换 JSON round-trip**
      - `cloneStateFile` 保持现有输入输出、nil 处理、detached 语义和 validation 配置语义，但不再调用 `json.Marshal`/`json.Unmarshal`。不得在本步骤删除 `BeginUpdate` 或 commit 的任一次 clone。
      - clone 代码按类型所有权集中：`NetworkState`/`ZoneState`/authority/delegation/revocation/record/history 由 zone/core 层提供完整 clone；daemon-local state 为私钥 byte slice、SyncPeers、IPsec key/port、LinkInstances、IPsecReconcile slices、RoutingReconcile、FirewallReconcile、EndpointACL selectors、Bird overlays 和 Admission 分别提供显式 clone helper。
      - 明确保留 nil 与 empty map/slice 的区别；复制所有 `[]byte`、map、slice、pointer 和嵌套 pointer；函数 hook 不得通过 JSON 偶然丢失，app clone 完成后仍保证 `RecordVerifier`/`RecordHasher` 配置正确；不得复制 `stateFile.mu`。
      - 扩充 clone 完整性测试：修改 clone 的每个可变叶子均不得影响原值，反向修改原值也不得影响 clone；增加字段清单/schema guard，使 `stateFile` 或核心状态类型新增字段时测试强制提醒更新 clone。
      - 保留 record-heavy fixture benchmark，并增加包含 SyncPeers/IPsec/routing/firewall 的完整 `stateFile` benchmark；记录 JSON 基线与手写 clone 的 ns/op、B/op、allocs/op，随后重跑 2026-07-31 同负载 perf。
      - 已完成：`cloneStateFile` 和 core Network 已改为完整手写 clone，完整性、双向隔离、nil/empty、nil entry、validation hook 与 schema guard 测试通过。1000 records + 完整 peer/IPsec/routing/firewall fixture（最终 3 次）中，JSON 基线为 4.52-4.59 ms / 1.23-1.32 MB / 8,969-8,971 allocs，手写 clone 为 0.230-0.239 ms / 479 KB / 4,057 allocs，约快 19-20 倍。另以独立 data/control/UDP/observer 的 1000-record 常驻 daemon 执行并发 observer status 实测：`strace -f -c` 覆盖 630,976 个 HTTP 200 响应；无超时截断的 5 秒文件 trace 完成 216,853 个 HTTP 200（43,356 req/s，p50 0.154 ms、p99 0.908 ms），并确认状态 DB 仅在启动阶段打开，并发读取阶段没有状态文件 open/fsync/fdatasync。宿主机 `perf_event_paranoid=4` 且容器无 `CAP_PERFMON`，root `perf record` 亦被内核拒绝，已保留明确诊断而不修改宿主 sysctl。

    - [x] **7.11.6.4 用 detached 只读投影替换高频完整 Snapshot**
      - 盘点 `snapshotState()`/`Snapshot()` 调用，按调用频率和返回数据量排序；优先替换只需要 ManagedZone、zone digests、catalog page、peer endpoint、route/link summary 的路径。
      - projection 必须在锁内完成必要读取并返回独立标量、slice/map 或 DTO；不得让 `*stateFile`、`*NetworkState`、zone map、record pointer 从通用只读 API 逸出。`configureValidation` 只能作用于 detached Network root，不能在 read path 修改共享 committed。
      - persistence 单独提供受限的 committed immutable view/lease：取得某一 revision 的 root 后可在锁外编码，因为旧 root 永不修改；接口只供保存适配器使用，不升级为通用裸指针 API。保存完成时记录的文件 marker 必须对应实际编码的 revision。
      - 每替换一个 projection 都补充 detached/retain 测试，并确认调用方的日志、transport、磁盘和 hook 副作用发生在 store 锁外。
      - 已完成：删除生产通用 `ReadCommitted(func(*stateFile))` 与 `snapshotState()`，按 status/record/ACL/BIRD/routes/link/peer/health/revocation、sync timer/catalog/digest/fetch/object-pull/relay/discovery、GC/purge/auto-announce 等调用形状提供锁内构造的 detached DTO/scalar projection；传输、日志、BIRD 查询、observer 编码与磁盘保存均在解锁后执行。持久化仅保留私有 `committedStateLease{state, revision}`，直接编码不可变 committed root，并在成功关闭 DB 后记录与实际 root 对应的 revision marker；retain/嵌套可变叶子和 schema guard 回归通过。生产完整 Snapshot 仅保留 daemon 启动 transport 初始化、独立启动兼容读取和任意 `OnStateChanged` hook 的显式 detached clone。1000-record benchmark（最终 3 次）中完整 Snapshot 为 239-248 us / 473 KB / 4,026 allocs，status projection 为 29.1-29.4 ns / 0 B / 0 allocs，persistence lease 为 4.61-4.71 ns / 0 B / 0 allocs；app/gossip/zone race、全量 `make check`、chain relay、object pull 和 routing dry-run smoke 均通过。

    - [x] **7.11.6.5 收敛 typed COW mutation，仍使用全局 revision**
      - typed API 的目的只是表达字段所有权并减少复制，不提供并行 writer merge：Peer 路径复用现有 `UpdateSyncPeer`；Routing 只拥有 `BirdInstances`/`RoutingReconcile`；IPsec 只拥有 transport key/port、LinkInstances 和 IPsecReconcile；Firewall 只拥有 EndpointACLs/FirewallReconcile；Network mutation 使用独立入口。
      - 开始事务时只复制该事务会修改的字段；提交时在锁内确认全局 revision 未变化，从当前 committed root 显式构造新 root并替换 detached owned fields。stale 时丢弃结果、标记相应 dirty/重新排队，禁止字段级 merge。
      - mutation callback 必须无 transport、文件、网络、日志计数和其他外部副作用；需要执行的外部动作在 commit 成功后进行。routing/IPsec reconcile 中本来就先执行的幂等系统操作维持现有模型，但若最终 commit 意外 stale，必须 dirty 重跑，不能伪造已提交状态。
      - 为每类 typed mutation 增加 ownership 测试：未拥有的子结构应保持共享且不可修改，拥有的所有可变叶子必须 detached；保留 race、retained callback 和 stale 防护测试。
      - 已完成：Routing 延用 `routingSnapshot`/CAS；IPsec 新增完整 key/port/link/reconcile owned snapshot/commit；Firewall 新增 ACL/reconcile owned snapshot/commit；Network 新增独立 snapshot/commit 并迁移 daemon `record_put`。已删除 IPsec stale instance/owner-token merge、stale diagnostic 回写和 Firewall 在新 revision 上重提旧 summary；所有 stale 结果现在整体丢弃、记录 source/current revision 并 dirty 重跑。ownership、retained input、stale 与 race 测试、全量 `make check`、chain relay、routing/IPsec/firewall dry-run smoke 均通过；使用 Nix StrongSwan PATH 的完整 `make root-smoke` 也通过，覆盖 StrongSwan/XFRM lifecycle/IKE/takeover/rotate、BIRD/Babel exchange/filter/failover/adopt、nft firewall、health fault injection 和 revocation deny-first。

    - [x] **7.11.6.6 收敛 daemon authoritative mutation 与 fail-closed control 写入**
      - 事故背景：root 身份运行测试时，CLI 使用测试临时 DB 中的 synthetic root pool 完成 IPAM dry-run，却把 mutation 通过生产 `/run/photon/photon.sock` 作为通用 `record_put` 交给 daemon；daemon 未按自己的当前 Network 重新执行 pool ownership/assignment covering 校验，最终在生产 `catofes.` 写入测试 pool/assignments。测试/smoke 已先增加私有 `TMPDIR`、按 `data_dir` 派生 control socket、清空 `PHOTON_STATE` 覆盖和 root 回归测试作为止血，但这不能替代 authoritative mutation 修复。
      - 所有在线 mutation 必须只向 daemon 发送 typed intent；client 只负责 CLI 参数解析、类型编码和展示响应，不加载本地 StateStore、不执行任何依赖 Network/revision 的预校验，也不在 client/daemon 之间维护两套 semantic validation。daemon 在 single-writer 事件循环中基于当前 committed StateStore revision 完成输入规范化、权限、当前对象状态、跨 record 约束和撤销条件校验，再构造/签名 record、typed COW commit、持久化并触发对应 reconcile；预览如有需要也必须作为 daemon typed dry-run 请求执行。
      - 将每类操作收敛成接收 `(committed state, typed intent)`、返回 `(candidate/typed patch, effects, error)` 的纯领域 mutation，验证与构造不可拆开且成功前无外部副作用。在线 handler 在 daemon single-writer 内调用它；显式 `--direct` 的 recovery/offline 路径在取得独占状态后复用同一领域 mutation，再完成持久化，不能另留一套 client/direct 验证实现。
      - 新增 typed control methods 覆盖 `ipam_pool_create/revoke`、`ipam_assignment_create/revoke`、`route_announce/withdraw`、`service_publish/withdraw`；IPAM 必须在 daemon 当前 Network 上校验 `allocate-ip`、pool ownership/covering、overlap/shared/tag，route 必须校验 assignment 与当前 active record，service 必须校验 managed zone、endpoint schema 和当前 authorized assignment。
      - 通用 `record_put` 只保留非保留命名空间的普通应用/policy record；拒绝 `ipam/`、`routes/`、`services/`、`routing/`、`ipsec/`、endpoint/sync 等 daemon-owned key/type，防止调用者绕过 typed API 写入结构合法但语义无效、或覆盖 daemon 生命周期 record。保留命名空间和 key/type 配对必须集中定义并有表驱动测试。
      - mutation control socket 不可用时一律 fail closed；只有用户显式传入 `--direct` 的 recovery/offline 命令才可写本地 DB。逐项删除 record、IPAM、route、service、delegation issue/grant/revoke、join accept、recovery import/purge、state GC、IPsec cleanup 的隐式 direct fallback；只读 status/debug/list 仍可安全回退离线视图。Endpoint ACL 与 rotate-port 已有的 require-daemon 行为保持不变。
      - 审计现有 typed handlers：delegation、recovery、Endpoint ACL、GC、rotate/cleanup 继续由 daemon 当前状态重验；将 `join_accept` 从内部直接 `SaveState` 后 reload 收敛到 typed StateStore COW；Endpoint ACL 的 assignment 校验和 commit 应绑定同一 source revision，意外 stale 时丢弃并重试/报错，不跨 revision 接受旧判断。
      - 回归测试必须故意让 CLI 本地 DB 与 daemon committed state 不一致：本地有 pool/assignment 而 daemon 没有、本地旧 active record 而 daemon 已撤销/替换、本地 service endpoint 合法而 daemon assignment 已变化；在线 client 不应读取该本地 DB，daemon 应按自己的 revision 接受或拒绝，拒绝时 revision、record/history、磁盘和 reconcile 均不变。另覆盖 daemon typed dry-run 与真实 mutation 使用同一验证结果、online/direct 复用同一领域 mutation、raw `record_put` 保留命名空间拒绝、socket 缺失 mutation 不落盘、显式 `--direct` 才允许离线恢复，以及旧 client/new daemon 的 fail-closed 兼容行为。
      - 已完成：IPAM pool/assignment、route announce/withdraw 和 SOCKS5 service publish/withdraw 全部改为 typed intent；client 在线路径不再加载本地 StateStore，daemon 在 committed revision 的 detached Network workspace 上完成规范化、权限、pool/assignment/active-record/service endpoint 校验、签名和一次提交，direct 路径复用相同领域 mutation。通用 `record_put` 在 control 和 event 两层集中拒绝 IPAM/routes/services/routing/IPsec/sync endpoint 的保留 key/type；旧 client 的 raw 保留命名空间写会 fail closed。除 daemon 启动前的 `root init` bootstrap 外，所有管理 mutation 在 socket 缺失时返回错误，离线恢复/写入必须显式 `--direct`，Makefile smoke fixture 也已逐项显式声明；原 fallback smoke 改为验证先拒绝且不落盘、再显式 direct。daemon `runStateStoreWrite`、join accept、Endpoint ACL 和 IPsec cleanup 均改以 committed StateStore 为 authority，其中 join accept 不再内部 SaveState/reload，Endpoint ACL 校验与 firewall-owned CAS 绑定同一 revision。回归覆盖磁盘与 committed pool 状态双向不一致、拒绝不升 revision/不落盘、typed dry-run、direct/daemon 同源错误、typed control event、raw 保留命名空间拒绝和 socket 缺失不落盘；app/gossip race、全量 `make check`、admin daemon、phase3 fail-closed、chain relay、delegation revoke、routing/IPsec/firewall dry-run smoke 均通过。

    - [x] **7.11.6.7 实现 Network target-zone COW**
      - 在 7.11.6.1 的失败原子性稳定后，将 Network 写入从完整 Network clone 收敛为：浅复制 `NetworkState` root、复制 `Zones` map、完整复制目标 `ZoneState` 及实际会修改的 records/history/delegation/revocation；其他 zone 跨 revision 只读共享。
      - `ApplySnapshot`/Network mutation 应返回 detached 新 Network 或 typed patch，不直接修改传入 Network。validation 可在新 root 上读取共享祖先 zone，但只能修改 detached 目标 zone；成功后一次性挂到新 state root，失败直接丢弃 candidate。
      - 第一版不启用 `MerkleRoot`/digest cache；当前 root 缓存没有覆盖所有 mutation 的完整失效协议，不能与 target-zone COW 同时引入。
      - 测试覆盖：未修改 zone 确实共享、目标 zone 完全 detached、祖先 delegation/revocation 读取正确、目标 records/history 更新不泄漏、失败不变、连续更新同一 zone、不同 zone 顺序更新和 race。benchmark 分别使用单大 zone、多小 zone 和 history-heavy fixture。
      - 已完成：新增 `CloneNetworkStateForZone`，仅浅复制 Network root、复制 `Zones` map 并完整 detach 目标 `ZoneState`；`ApplySnapshot` 改为返回 detached candidate，不再修改输入，祖先 zone 保持只读共享。daemon 普通 record、IPAM、route、service typed mutation 也改用 target-zone workspace 和 ownership-transfer CAS commit，candidate validation 不再完整 clone Network；未引入 `MerkleRoot`/digest cache。回归覆盖结构共享、目标深层隔离、失败原子性、祖先 proof/revocation、同 zone 连续更新、不同 zone 正反顺序和 race；benchmark 覆盖单大 zone、多小 zone与 history-heavy fixture。

    - [x] **7.11.6.8 最后评估批量 `ApplySnapshot`**
      - 只有单 action 原子性、target-zone COW 和 typed Network commit 均验收后才开始；若新 perf 已不再显示 snapshot commit/persist 为热点，本项可以继续保留而不实现。
      - 必须保留当前“合法 action 成功、非法 action 被拒绝、后续 action 继续”的部分成功语义。每个 action 使用独立 savepoint：从批次工作 Network 创建 candidate，成功才推进批次工作副本，失败丢弃该 candidate 并记录 rejected digest。
      - 批次结束后最多一次 committed root 发布和一次持久化；日志、事件通知、transport send 等副作用只能基于成功提交的结果执行。虽然 single-writer 下正常不会 stale，意外 stale 时仍应丢弃整个批次结果并重新排队，不能直接重放带副作用的 callback。
      - 明确并测试可见性变化：读者从“可能看到逐 action 的中间 revision”变为“只看到最终批次 revision”。若该变化不可接受，则保持逐 action commit，只复用 target-zone COW，不实施批量发布。
      - 已完成：同一 sync event 的 snapshot actions 先收集为批次，每个 action 从当前批次工作 Network 创建独立 target-zone candidate；合法 action 推进 savepoint，非法 action 只记录 rejected digest，后续 action 继续。批次最终通过一次 CAS 发布一个 committed revision，成功后只持久化一次；stale 会丢弃并从新 committed root 重新计算整批，日志和 transport 等外部副作用均移到成功发布后。可见性明确为读者只观察到最终批次 revision；回归覆盖“成功—拒绝—后续成功”的部分成功、rejected digest、未修改 zone 共享、两个成功 target detach、单 revision 发布和持久化 reload。

    **阶段验收**
    - 必跑 `go test ./pkg/core/gossip ./pkg/core/zone ./app/photon`、相关 `-race` 测试、`make check` 以及 snapshot/routing/sync smoke；涉及真实 BIRD/IPsec 行为的步骤继续跑对应 root smoke。
    - 每一性能步骤使用相同 fixture 和相同实机负载记录 wall/CPU、clone 栈、alloc/GC、minor/major fault、bbolt 与 fork/exec；收益统计不得把 inclusive clone、GC 和缺页百分比直接相加。
    - 完成标志：snapshot apply 失败无任何 Network 变化；routing 不再进行 stale merge；JSON clone 不再出现在 daemon state clone 热路径；高频纯读不复制完整 Network；typed writer 只复制 owned fields；target-zone 写入成本随目标 zone 而非整个 Network 增长。

  - [ ] **7.11.7 `app/photon` 与 state ownership 后续模块化（性能收口后）**
    - `app/photon` 当前仍同时承载 daemon wiring、sync runtime、state adapter 和多个 reconcile 写侧，后续确有继续拆分价值；但本轮不机械搬迁整个 `stateFile`，也不在同一改动中同时重构 sync/IPsec/routing/firewall。
    - 先通过 7.11.0 验证一个完整的窄切口：独立数据所有者/store、app wiring、inspect view 合并、兼容测试。该边界稳定后，再按“权威 state / controller runtime state / observability”逐块迁移，而不是创建一批没有稳定 API 的空 package。
    - 后续候选包括：持久化 control-state store、peer sync controller state、reconcile observation store，以及 health/BIRD/actual source adapter。`Network`、密钥、owner token、rotate/adoption 等生命周期状态的归属必须由重启恢复语义决定，不能仅按文件大小或字段名字移动。
    - 每次只迁一个字段族并保持磁盘格式、wire 格式和 control/observer schema 的兼容；模块化不阻塞当前性能修复，是否继续拆由 7.11.0-7.11.5 完成后的新 perf 和调用关系决定。

- [ ] **7.9 可选 Admission 管理面**
  - 在 auto-join 主链路和本地控制接口稳定后，再考虑父 Zone 管理节点的 join request inbox、审核队列、批量 approve/reject 和受限网络化提交。
  - 第一版 admission 仍不引入新的公网 request 协议，也不让 leaf 自动把 join request 写入 gossip active state。
  - 候选命令：`photon join pending`、`photon join approve <request-id>`、`photon join reject <request-id>`。
  - admission policy 仅覆盖父 Zone 有权签发/写入的对象，不配置本机 MeshPolicy / link group / connect-deny override。

- [ ] **7.4 WireGuard 传输底座与上层 per-peer 接口（可选实验）**
  - 通过 `wgctrl-go` 操作内核 WG 接口，复用 Zone K-V 中的 `wireguard/*` record。
  - WG 与 IPsec/XFRM 可以作为同一 peer 的并行 active TransportLink；是否表现为等价路径、较高 cost 的 fallback 或按目的前缀分流，由本地 policy/Babel 决定，不固化在 provider 类型中。
  - 不把共享裸 WG mesh interface 直接交给 Babel：WG 需要依靠 AllowedIPs 选择加密 peer，若把业务前缀写入 AllowedIPs，会与 Babel 的动态多跳下一跳选择重复并冲突。
  - WG AllowedIPs 只放每个直连 peer 的 transit `/32` 或 `/128`；业务前缀仍交给 Babel/route authorization。WG 上层通过 GRE 或其他封装提供独立 per-peer 接口，使 Babel 选择接口/下一跳后，WG 只负责把外层包投递给对应 peer。
  - WG、上层封装与 Babel 接口原则上归属同一个目标 netns；若 WG 留在 host netns，必须显式设计跨 netns underlay、路由、转发、防火墙和 teardown，不作为默认拓扑。
  - 若进入正式实现，先一次性落地 provider-aware Link ID helper，并覆盖 StrongSwan legacy ID adopt/restart 迁移；随后实现 WG records/overlay intent、本地 policy、shared device/peer desired state、独立持久化 state、owner/live marker、inspect/reconcile/apply/teardown、private key 持久化、staged device rotate、listener/firewall grace 与零引用 cleanup。不得迁移或包装 StrongSwan 内部 lifecycle。

- [ ] **7.5 GRE / VXLAN 上层封装选择（远期可选）**
  - 先用真实 netns + WG + BIRD smoke 比较 GRE 与 VXLAN；仅需 point-to-point 三层 Babel 接口时优先评估 GRE，明确需要二层承载时再选 GRETAP/VXLAN。
  - VXLAN 方案必须明确 VNI、VTEP、静态/动态 FDB、广播/多播复制和额外 MTU 开销；共享 VNI 不能假设 WG 自动向所有 peer 复制广播/多播。
  - GRE/VXLAN endpoint 使用 WG transit address，业务前缀不进入 WG AllowedIPs；封装设备在目标 netns 内创建并通过 WG underlay 可达。
  - 选定上层封装后再实现 per-peer interface lifecycle 与 `LinkOutput` 投影，并收口 BIRD per-interface policy、LinkGroup base cost、按 peer/group/provider 展示、双 provider dry-run，以及 IPsec/XFRM + WG + GRE/VXLAN 联合 root/container smoke。

- [ ] **7.6 SRv6 支持（实验性）**
  - 通过 netlink 配置 SRv6 SID、End.DT4/End.DX6 行为。
  - 与 BIRD/FRR 的 SRv6 扩展联动，如后续引入 BGP。

- [ ] **7.12 可选策略路由与系统路由审计（远期）**
  - 当前主线保持一个 netns 一个 BIRD 实例，BIRD 直接写该 netns 的 main table；默认不启用额外 `ip rule` / per-overlay table 隔离。
  - 如后续需要 external BIRD、管理员自定义策略路由、或非默认共享 netns 拓扑，再补 `ip rule` / fwmark / iif-oif 策略路由和 `/run/photon/rt_tables.d` 诊断输出。
  - route-table auditor 仅作为可选兜底，用于交叉检查 Photon authorized route set、BIRD learned/installed routes 与内核 route table 是否一致。

## Phase 7 之后的远期后续

- [ ] 跨数据面 rotate smoke：结合端口/IPsec rotate 与真实 BIRD route/metric 观测验证数据面切换窗口；不阻塞 Phase 5/6 收尾。
- [ ] state 文件外部协调补强：在现有 bbolt 文件锁基础上增加显式 `flock` / fsnotify watcher，避免多进程或外部修改时状态漂移。
- [ ] Observer 增强：拓扑图、zone tree、VictoriaMetrics/Prometheus-compatible datasource/push 集成、BIRD protocols/routes/neighbors 深度解析。

## Phase 8: 应用层服务与代理（已验收）

**目标：** 在 Photon L3 mesh 上提供可发现、可授权的内网 SOCKS5 服务，同时支持本地唯一 endpoint 和 shared Anycast endpoint；应用层源路由 relay 保持独立演进。

**设计边界：**
- Photon 只负责服务地址归属、签名 record 发布/撤销和动态防火墙授权；独立 `photon-services` 读取 `/etc/photon/service.yaml` 并生成 Docker Compose/代理配置。两者都不通过 Docker API 管理容器生命周期，Compose 由管理员检查后手工启停。
- 本地网络通过 `auto` 选择当前节点唯一的非 shared assignment；Anycast 网络通过 shared assignment 的稳定 tag（如 `socks5.cn`）选择，`region` 仍只是公开 endpoint 的服务选择属性。
- Docker bridge 位于 host netns，容器地址属于 Photon 管理的服务前缀；host 侧通过指向 Photon netns 的聚合路由和 Docker connected route 最长前缀匹配，overlay 侧复用显式 `routing.instances[].upstream` 返回 host。
- SOCKS5 第一版可使用 `NO AUTH`，由 Photon overlay 身份/前缀和本机 firewall 提供 zone/node 级授权；这不承诺同一节点内的用户级身份区分。

- [x] **8.4 本地与 Anycast 数据面验证**
  - 已实现 `services-smoke`：真实 Docker bridge 上运行 SOCKS5 和目标 TCP 容器；client netns 经 BIRD/Babel、host route 和 static upstream 回程完成代理请求。
  - root smoke 断言 Docker connected route 优先于更宽的 host -> overlay 聚合路由；另一 Photon 前缀仍命中该聚合路由。
  - non-owner service publish、shared tag 冲突、空 ACL selector fail-closed、未监听 endpoint 不发布分别由 `pkg/service`、routing、firewall 与 `photon-services` 单元测试覆盖；shared prefix 成员故障收敛复用 BIRD Anycast root smoke。
  - 已于 2026-07-21 在允许 netns、具备目标 host firewall 配置的 root 环境执行 `sudo make services-smoke` 并通过。

- **8.5 不纳入 Phase 8**：客户端 service selection/health policy 不是 SOCKS5 发布数据面；Anycast 的 L3 选路和故障收敛交给 BIRD/Babel。出现明确客户端需求后再独立设计。

- **8.7 不纳入 Phase 8**：应用层源路由 relay 是独立协议/项目，不与 SOCKS5 发布、IPAM 或 BIRD 数据面耦合。

## 下一步

1. 7.11.6 StateStore 正确性、手写 clone、分层/target-zone COW 与批量 snapshot apply 已完成；后续先保持相同 fixture 观察实机 perf，不继续引入 `MerkleRoot`/digest cache，除非 profile 再次证明 digest 计算为热点。
2. StateStore 性能主线已收口；下一步按需求选择 7.7/7.8 discovery/relay 或 7.11 metrics/readmodel，WG 底座与 GRE/VXLAN 正式实现继续作为可选 7.4/7.5。
3. 后续模块化不再单独扩大范围；新增 debug/observer/control 输出默认走 `internal/inspect` view + `inspect/text` 或 `inspect/http` presenter，写侧/daemon adapter 继续留在 app 层直到接口稳定；公共 control DTO/typed client 等出现实际复用需求再迁移。
4. Phase 8、Phase 9 已完成验收；客户端服务选择和应用层 relay 按需作为独立项目评估。
