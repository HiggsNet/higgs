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

## Phase 10: Photon Windows（当前新主线）

**目标：** 在 `app/photon-windows` 新建独立子程序，产物名为
`photon-windows.exe`，先实现一个可在 Windows 上长期运行的 Photon 叶子客户端。
它使用 Wintun 承接 L3 流量，在用户态完成 IKEv2 initiator、ESP、Babel leaf 和
source-specific route lookup，并继续以 Photon 已验证 Zone state、IPAM、route
authorization 和 transport records 作为可信事实来源。

**项目命名与边界：**

- 对外项目只叫 **Photon Windows** 和未来的 **Photon Android**，分别对应两个明确的
  平台项目；Windows service、可执行文件、安装包、配置目录和
  IPC 名称都使用 Windows 专属名称。
- 当前只创建 `app/photon-windows`。Photon Android 暂不创建空工程、不引入
  Gradle/Kotlin/gomobile 构建，也不让 Android 的功耗与生命周期约束阻塞 Windows
  vertical slice。
- 允许两个产品未来复用不拥有平台资源的 portable Go core；共享库只是内部实现，不是
  第三个产品。Wintun、Windows Service、IP Helper、named pipe、Event Log 等代码必须留在
  Windows adapter，不能泄漏进 portable core。
- v1 是 **outbound-only leaf/stub**：不做 transit、不做 IKE responder、不做
  lite-to-lite、不转发从一个 gateway 学到的路由到另一个 gateway。先支持一个 active
  gateway；standby 第一版只保留配置与低频候选状态，不同时维持第二套活跃 Babel/ESP。
- Windows 第一条可验收路径是 split tunnel；full tunnel、DNS/NRPT、kill switch、GUI、
  auto-update 和多 active gateway 都在基础安全闭环之后实施。
- 不复用 Windows native VPN profile/WFP IPsec 作为主数据面。其单 gateway、认证与算法
  profile 无法表达 Photon raw Ed25519、多 peer、用户态 Babel/SADR 和自定义端口语义；
  Photon Windows 使用 Wintun + 用户态 IKEv2/ESP。

**已核对参考：**

- 前置调研见 [docs/photon-lite-research.md](docs/photon-lite-research.md)。实现参考固定在
  `NickCao/ranet-lite@24a24a2ff380c9f8ceb0092d640daa32e86b5eb5`，不要随 upstream
  master 漂移。该快照约 11.3k 行 Go，已具备 IKE initiator、ESP、共享 UDP/SPI mux、
  Babel leaf、SADR 和有序 TUN pipeline。
- `ranet-lite` 是设计与互操作参考，不直接 fork：其静态 registry、Linux/Unix signal、
  TUN 资源所有权和随机 Babel Router ID 不符合 Photon/Windows 边界；其 module 还要求
  Go 1.26.3，而 Photon 当前是 Go 1.25.0。
- `ranet-lite` 为 MIT。任何复制或实质派生的源文件必须保留来源、commit、原版权和 MIT
  notice，并在 `THIRD_PARTY_NOTICES` 中列出；只参考 RFC 后独立实现的文件也要在设计记录
  中说明来源边界。
- 当前仓库与既有调研中没有名为 `RightLight` / `NetLight` 的源码或链接。如果它们是
  `ranet-lite` 之外的项目，取得准确仓库 URL/版本后先做 license、代码结构、协议范围和
  Windows 资源所有权审计，再决定是否纳入；该缺失不阻塞下面的 Windows 骨架和 portable
  contract。

**实现进度（2026-08-25）：**

**架构纠偏（2026-08-29）：** `pkg/core/host.Runtime` 已经是唯一 common runtime。Windows composition
应与 Linux daemon 一样直接创建一个 HostRuntime、一个公共 Store/BoltStore 和一个平台 runtime；不得再增加持有
HostRuntime/Store 的 `photonclient.Runtime`。`internal/photonclient` 只在 IKE/ESP/Babel/SADR/TUN packet pipeline
出现真实复用点后承载用户态客户端数据面，不拥有 gossip、公共状态或产品生命周期。当前工作区中的 client runtime、
通用 `Resources.Validate` 和 gossip controller glue 已在 F0b 撤回，不作为 F 阶段产品边界。

- [x] 新建 `app/photon-windows`，提供独立 `photon-windows.exe`、`version`/`help` 和
  Windows amd64 交叉编译；Wintun/service 尚未接入前不暴露假的 `run`/connected 状态。
- [x] 新建 `docs/photon-windows/design.md`，冻结 leaf-only、单 active gateway、split
  tunnel、用户态 IKEv2/ESP/Babel/SADR 和平台资源注入边界，并记录 route-origin 剩余风险。
- [x] 撤回提前建立的 `photonclient.Runtime`、通用 `Resources` capability bag、资源完整性探测和 client gossip
  controller glue。保留可复用的 memory adapter/fixture 时必须把它们改为直接测试公共 HostRuntime、Store 或未来真实
  packet consumer，不能为了保住测试而维持第二个 runtime；对应 runtime/contracts/testkit 生产骨架与 Makefile 点名入口已删除。
- [ ] 用户态 IKE/ESP/Babel/SADR/TUN packet pipeline 出现首个真实调用点后，再从 consumer 侧提取最小接口和生命周期；
  Windows composition root 直接构造实际启用的组件，初始化失败当场返回具体错误，不先注入 nil 再探测平台能力。
- [x] Makefile 增加 `photon-windows-build`、`photon-windows-cross-build`、
  `photon-windows-test`，并把 Windows amd64 compile guard 纳入 `make check`；当前复用候选
  `pkg/core/zone`、`pkg/core/gossip`、`pkg/crypto`、`pkg/routing`、`pkg/transport/ipsec` 已通过
  Windows amd64 编译。
- [x] 新建 Photon Windows schema v1 和 `config validate`：root trust、managed zone、
  bbolt state、overlay/split aggregates、gateway selector/bootstrap
  hints、Wintun、log、reconnect 均严格解析；未知字段、多 YAML 文档、full-tunnel default
  route 和不完整配置 fail closed。
- [x] 保留 F0a 已验证的公共 Store 恢复语义并修正 owner：`internal/photonwindows.StateStore` 由 Windows
  composition 使用唯一 `state.BoltStore`、`LoadCommon/RestoreStore` 和真实 revision，执行 managed zone/root pin
  校验及 legacy-only/第二 handle fail closed；`photonclient` 不再持有公共 Store。
- [x] 将原先位于 Linux `app/photon/sync_session.go` 的无 I/O per-peer gossip FSM 与完整单测
  原样抽到现有 `pkg/core/gossip` 公共包；Linux 与 Windows 直接引用同一状态机，Windows
  compile guard 覆盖同一包。Linux event loop、bbolt commit、日志仍留在 composition layer，
  未把 Linux 专属副作用错误抽进公共协议包。
- [x] 先将 Linux `gossip_recv.go` 的有界 receive loop 移出 daemon，随后在 E2a 进一步归入
  `pkg/core/host.Runtime`：公共实现只依赖 `DatagramReceiver.Receive/Close`，固定 bounded
  backpressure、timeout/close 静默、普通错误回调后继续和唯一 stop/资源 ownership；Linux
  composition root 直接注入 transport 并就地映射日志，Windows 后续可注入自己的 receiver。
- [x] 将 `packet_demux.go` 的 active-session/unsolicited classifier 与事件类型抽到现有
  `pkg/core/gossip`；Linux 直接调用公共 classifier，不保留类型别名或转发函数。公共测试覆盖
  active hit、miss、nil packet/message 和 nil session entry，classifier 不解释 message type，
  也不持有 daemon、存储或平台日志依赖。
- [x] 将 chunk assembly、quiet-period NACK、sent-chunk repair cache 与全部 quota/TTL/hash
  policy 抽到现有 `pkg/core/gossip`；Linux 直接创建公共 store/cache，只保留发送/apply 副作用。
  原 repair 测试迁入公共包，并补齐 metadata tamper、object hash mismatch、per-peer inflight
  和 cache 输入/输出深拷贝负向测试；Windows 后续不得另写一套 chunk repair。
- [x] 将 datagram announce planning、wire-size 计算和 zone snapshot chunk packing 抽到现有
  `pkg/core/gossip`；排序、MTU budget、oversized 分类、object/root hash 和 chunk metadata
  由 Linux/Windows 共用同一实现。Linux executor 只生成随机 transfer ID、写 repair cache、
  调用 UDP send 和记录观测事件，所有调用点直接使用公共类型和函数。
- [x] 删除抽取后遗留在 `app/photon` 的 session alias、packet demux、receive、chunk constructor
  和 datagram forwarding 五组兼容壳；共享行为测试迁到 `pkg/core/gossip`，daemon timer 测试归位
  到 timer manager。同步事件名和 peer ID 提取也进入同一公共包，Linux/Windows executor 不再
  重复维护 event type switch。
- [x] 将 inbound verified packet 的 message policy 抽到 `pkg/core/gossip`：公共 planner 统一
  active/unsolicited 下 Ping/Pong、catalog、fetch、announce、object chunk/NACK 的允许范围、
  payload fail-closed 和 session event 转换，并保留 active Ping“先投递 summary event、再响应”
  的动作顺序。Linux daemon 只执行 planner action，继续拥有状态投影、发送、apply、日志和持久化。
- [x] 将 read-only request 分类、catalog-root equality 和 Ping response planning 抽到
  `pkg/core/gossip`：`fetch_zone`、`chunk_fallback`、`catalog_page` 标签及 nil payload 策略只有
  一个来源；Pong 必须先发，remote root 不同时再发 `FETCH_CATALOG_PAGE`。Linux 只读取 committed
  catalog、记录观测并按顺序发送 planner 生成的 message。
- [x] 曾将 per-peer protocol timer manager 从 `app/photon` 迁入 `pkg/core/gossip` 作为去重过渡；10.3A
  首个切口已继续删除该 `TimerManager/TimerClock`，通用调度资源与完整测试现位于 `pkg/core/host`，
  gossip 只保留 round/catalog-page kind、deadline policy 和 start/cancel action。
- [x] `gossip.Engine` 已从过渡期的 single-writer orchestration 收敛为同步协议对象：只拥有 session
  registry、pending announce hint、inbound planning 和 FSM advance，不再拥有 event channel、clock、timer、
  goroutine、stop/reset 或 resource API。Linux 已改从同一个 `host.Runtime` queue 消费 gossip 事件。
- [x] object-pull 请求/响应 exchange 已归入公共 gossip，bounded worker、背压和 completion delivery 已归入
  公共 HostRuntime；Linux daemon 私有 pool、result channel 和三处额外 event-loop 分支已删除。Linux 只提供
  TCP dial/listen/deadline 与观测 adapter，Linux/Windows 不再各写一份 object-pull host loop。
- [x] 单个 gossip event 的 `Engine.HandleEvent -> ordered action executor -> NetworkChanged accumulation` 已收进
  公共 `HostRuntime.HandleGossipEvent`。Pong/catalog enrichment 与 round-timeout chunk cleanup 的类型解释也只有
  公共 host 一份；chunk assembly 已从 Linux 包级全局变量变为每个 Runtime 独占的可丢失内存。Linux 只提供
  当前 state 的 catalog filter、传输/观测 capability，以及日志和 session 完成后的平台收尾。
- [x] chunk quiet-repair 已删除 `ChunkAssemblyStore` 内部 `time.AfterFunc`：gossip 只计算 repair deadline 和
  缺失索引，HostRuntime Scheduler 以 peer/transfer generation 统一 replace/cancel/stale-fire，并把到期事件经
  同一个 host queue 发送 NACK；`pkg/core/gossip` 已不再创建任何 timer/ticker/goroutine。
- [x] peer discovery 的 verified-zone admission、endpoint/source 排序、recent/observed path、checkpoint
  patch、persist-before-publish 和 UDP address book 更新已整体进入公共 HostRuntime；Linux 原 planner/apply
  及重复地址合并实现已删除。在线 daemon 直接从 common Store 与 Linux cleanup owner 组装输入，不新增
  `DaemonStateStore` discovery view。
- [x] `daemon_sync.go` 已不再读取完整 `stateFile`：catalog summary、action state view、managed-zone snapshot
  apply guard 和 observed checkpoint 规划均直接使用 common Store/HostRuntime；删除 catalog summary、sync state
  两个 daemon projection，observed 地址迁移与 grace patch 也由公共 discovery policy 生成。
- [x] fetch-zone datagram/chunk 响应已直接从 common Store detached view 生成，删除对应两个 projection 与
  Linux 私有 not-found wrapper；catalog-page 的 managed-zone/rejected-root 过滤进入公共 host policy，并删除
  无生产调用的 catalog-page projection 和 Linux filtered-catalog projection。
- [x] object-pull 响应改为由公共 gossip 直接读取 detached verified Network；在线 worker 的 TCP 目标选择改为
  公共 host discovery policy，统一使用 verified observed path、bootstrap 和签名 endpoint，删除 daemon 中对应的
  response/address projection。recovery pull 也已改为使用同一 discovery input，并通过唯一 BoltStore 恢复 common
  Store、逐个调用 typed recovery import；删除旧 `stateFile` 地址选择和 pull 参数，不再反向写旧 Network。
- [x] 周期同步和 relay 不再读取 daemon 聚合 projection：公共 host policy 直接从 verified Network、gossip
  checkpoint 与 bootstrap 输入生成 outbound peers，并统一 backoff、source-loop、catalog-root no-op 和 relay
  throttle 判断；删除 timer/relay projection 及 Linux 重复 policy。
- [x] recovery export、direct import 和 object-pull 已切到唯一 BoltStore/common Store：export 读取 common view，
  import/pull 调用 typed recovery API，删除 Linux 私有 snapshot apply/root-pin 复刻。启动恢复先读取新 schema，
  仅在 common state 确实不存在时进入一次旧 bootstrap/migration，common 独立写入后不再依赖旧 Network reader。
- [x] `purge-revoked --direct` 删除旧 `LoadState/SaveState`：公共 purge policy 与 Linux runtime 组合 typed plan，
  先执行 IPsec teardown 并以当前 VerifiedRevision 持久化 runtime cleanup，再由 common Store 删除 revoked zone
  与 checkpoint；dry-run 只读取两个 owner，不触发平台动作或写入。
- [x] IPsec cleanup 的资源 owner 校验、指定 link teardown、缺失资源幂等处理和 StrongSwan orphan cleanup 已迁入
  `internal/photonlinux/ipsec_cleanup.go`；`cleanup-ipsec --direct` 也已改为唯一 BoltStore/Linux runtime candidate + revision
  commit。新增 `internal/photonlinux.Runtime` 作为 Linux 平台组合根，daemon 启动时安装唯一实例，实际持有
  IPsec/XFRM driver 与关闭生命周期，配置 reload 先构造候选再替换并关闭旧实例，daemon 退出统一关闭；cleanup、
  IPsec reconcile、lifecycle watcher、在线 revoked purge 均复用该实例，direct purge/cleanup 才按离线命令生命周期
  临时创建。`DaemonService` 原有 IPsec/XFRM/close 三份字段已删除。当前不预建 `PlatformCapabilities` 或多个公共
  Controller；完整 IPsec reconcile 与 netns/network/firewall/routing 的共享执行上下文随真实调用点继续迁入。
  app 只负责 control/CLI、Linux runtime 构造、runtime DTO 转换和公共/平台提交顺序，不再执行平台 action 或写旧 stateFile。
- [ ] 配置重载保持管理员显式触发，不监听或轮询 `config.yaml`。后续补齐 `photon daemon reload`，通过 control API
  串行执行 parse/validate/runtime replacement；Linux systemd unit 可选增加 `ExecReload` 映射该 CLI，但配置文件
  变化本身不得自动重启或 reload。Windows 复用同一 CLI/control 语义，不依赖 Unix signal。
- [x] LinuxRuntime 已接管 IPsec SA live observation、reconcile action apply 和 StrongSwan lifecycle subscription；
  daemon reconcile/watcher/debug 不再取得 IPsec driver。XFRM batch observe、missing-link filter、diagnostic address 与
  drift repair 已整组下沉到 `internal/photonlinux/xfrm.go`；这些是真正实现逻辑的 `photonlinux.Runtime` 方法，不是
  对子 runtime 或同名函数的转发。IPsec/XFRM driver 在配置构造时明确选择并由唯一 Runtime 持有，不在运行中隐式
  补 DryRun；Runtime 只接收一个 logger，并在内部选择 debug/warn 级别，不保存两套日志回调；迁移期
  `XFRMDriver()` 访问口和嵌套 IPsec Runtime 均已删除。
- [ ] 按 10.3A 将 Linux `stateFile` 中的 verified Network/sync metadata 与
  firewall/IPsec/routing/BIRD/admission runtime state 解耦；先形成 Linux/Windows 共用的
  `pkg/core/state`，再让 Photon Windows 接入网络同步。不得在 Windows composition root 中复制
  Linux snapshot apply、auto-join、record mutation 或 bbolt schema。
  - discovery 不得通过 `DaemonStateStore` 新增专用组合 view：peer/endpoint 规划和可重建 UDP address
    book 已归公共 HostRuntime/transport runtime，平台 adapter 只负责 socket I/O；待公共 Runtime 直接持有
    common/Linux owner 后删除 `daemon_discovery.go` 中剩余的输入组装与触发。
  - `daemon_state_projection.go` 不是目标架构层；每个调用方改用其 owner 的 typed input 后立即删除对应
    projection，最终删除整个文件。observer 的 zone/peer 读取已完成首个切口：zone 直接使用 common verified
    Network，peer 直接组合 common verified Network、gossip checkpoint 与独立 observability snapshot，control
    `record_get` 也直接查询 common verified Network；已删除 `zonesProjection`/`peersProjection`/
    `recordDetailProjection`。observer 事件中的 link ID 直接读取 Linux runtime，peer ID 直接读取 common gossip
    checkpoint；reload 的 identity key path 与 IPsec interval 的 link 存在性也直接读取 Linux runtime。对应删除
    `linkIDsProjection`/`peerIDsProjection`/`identityKeyPathProjection`/`hasLinkInstancesProjection`，不再为这些只读
    视图构造聚合 `stateFile`。`endpoint_acl_list` 直接从 Linux runtime 复制并排序 ACL，删除
    `endpointACLProjection`；BIRD HTTP/control status 也直接复制 Linux runtime 的 instance/reconcile 数据，删除
    `birdStatusProjection`；firewall control status 直接复制 Linux runtime reconcile，删除
    `firewallStatusProjection`。HTTP status 在单写边界内分别读取 common verified/checkpoint 与 Linux runtime，control
    status 只读取 Linux runtime/store metadata，删除 `statusProjection` 及其聚合 DTO。HTTP routes 只读取 common
    verified Network，control routes 再独立复制 Linux BIRD runtime，删除 `routesProjection`。启动 auto-join 提示
    直接读取 common verified state，删除 `autoJoinLogProjection`。health context 直接组合 Linux runtime 的
    link/reconcile 与 health manager 快照，删除 `healthContextProjection`。admission status 显式组合 common
    verified identity/network 与 Linux runtime admission history，删除 `admissionProjection`。state GC 只根据 Linux
    runtime BIRD instances 与 routing 配置规划，并按 runtime revision 提交，删除完整 Snapshot 与
    `stateGCPlanProjection`。health target 显式组合 common managed zone 与 Linux runtime link/IPsec desired，离线
    state wrapper 反向复用同一纯函数，删除 `healthTargetsProjection`。
    links HTTP/control status 直接组合 Linux runtime 的 link/IPsec/BIRD 与 health snapshot，reconcile inspection builder
    改为显式平台输入并删除 `linksStatusProjection`；原 projection 专用测试文件随最后一个测试删除。
    auto-announce planner 只接收 common verified Network/managed zone、授权路由集合与 IPAM 配置，发布逻辑直接读取
    common Store，删除 `autoAnnouncePlanProjection`。
    peer status 显式组合 common verified Network/managed zone、gossip checkpoint 与 Linux cleanup/link/IPsec runtime，
    control 不再构造聚合 stateFile，删除 `peerStatusProjection`。
    peer lifecycle cleanup 直接从 common Network/gossip checkpoint 与 cloned Linux cleanup markers 生成 plan；先按
    source revision 提交 runtime marker，再删除 common checkpoint，删除预判 projection 与完整 Snapshot。
    revoked gossip cleanup 直接读取 common verified Network/checkpoint 并提交 checkpoint patch，删除
    `revocationCleanupProjection`。
    revocation impact 显式组合 common Network/gossip peers、Linux link instances 与 bootstrap 配置，删除永远返回
    false 的 state bootstrap 占位推断和最后一个 `revocationImpactProjection`；`metaLocked` 归回 StateStore 后删除整个
    `daemon_state_projection.go`。
    随后回收迁移残留：revocation impact 的显式 owner 输入成为唯一 API，删除 stateFile wrapper 与 `FromOwners`
    双层命名；删除已经零调用的 `buildLinkInspectionFromReconcile`。health target 与 state GC 也删除
    `FromState/FromRuntime/FromBirdInstances` 双入口，调用方直接提取 owner 字段后调用唯一业务 API。
    peer lifecycle input/status/cleanup 同样删除 stateFile wrapper 与 `FromOwners` 命名，在线、direct CLI 和测试均显式
    传入 Network、checkpoint peer、cleanup/link/IPsec runtime。
    admission diagnosis 以 common VerifiedState + Linux admission history 作为唯一生产 API，删除 stateFile wrapper
    与 `FromOwners` 命名；重复 fixture 转换仅保留在测试 helper。
    第二遍调用图审计继续删除只为旧名字或测试默认参数存在的转发：CLI `syncRun`、transport peer seed、packet/timer
    handler 双入口、object chunk/fetch-zone/chunk-send 的 nil-address 便捷层及 link netns 别名均已移除；测试直接调用
    实际入口。跨 common/Linux owner 的 discovery input、revocation purge plan、stored link inspection、link output 和
    transport key 转换保留其真实组合逻辑，但统一改成 `build/merge/stored` 业务命名，不再用 `FromOwners/FromRuntime`
    暗示迁移层。接口实现、平台 Runtime 对 driver 的封装、以及真正被多个调用方使用的默认参数/序列化边界不按
    “一行函数”机械删除。
    `DaemonStateStore` 已进一步删除长期缓存的完整 `committed *stateFile`：common Store 与 Linux runtime 是仅有的
    常驻 owner，旧 planner 需要聚合形状时才在单写边界内按需生成一次 detached snapshot。routing/IPsec/firewall
    专用 snapshot 包装和 root-sharing clone 随之删除；公共 Store 提供不克隆 payload 的 `VerifiedRevision()` 标量
    读取，common/runtime commit 只更新 revision/timestamp 元数据，不再为每次写入重建完整 Network 聚合副本。
    root smoke 中遗留的 daemon BIRD/IPsec 断言也已停止调用旧 `Runtime.LoadState()`：BIRD control socket、managed
    process adopt、XFRM/StrongSwan reconcile 与 daemon-run 等待条件直接读取活动 `DaemonStateStore`。底层数据面原本
    正常，旧测试因读取迁移前 legacy owner 得到空 `BirdInstances/IPsecReconcile` 而误报；修正后完整 `root-smoke`
    已覆盖 IPsec/XFRM、BIRD/Babel、firewall、health fault 与 revocation deny-first 并通过。

### 10.0 冻结 v1 契约与威胁模型

- [x] 新建 `docs/photon-windows/design.md`，把本节产品边界转为版本化设计；至少画清
  `Windows stack -> Wintun -> packet engine -> SADR -> per-peer ESP -> shared UDP ->
  Photon gateway` 的数据流，以及 Babel control packet 不经过 Wintun、直接在 ESP 内层
  per-peer 收发的旁路。
- [ ] 冻结首个支持矩阵：开发/CI 先保证 Windows 11 amd64，随后覆盖仍在微软支持期内的
  Windows 10/11 amd64；arm64 只在 amd64 vertical slice 通过后开启。明确不承诺 32-bit、
  Windows 7/8、Windows Server Core GUI 或未经测试的 Wine 行为。
- [ ] 冻结首版算法集：Ed25519 raw public-key auth、X25519、AES-GCM-16、
  ChaCha20-Poly1305、SHA-256 PRF、UDP encapsulation；每个算法必须与 Photon StrongSwan
  responder 的实际 proposal 一致，不能只凭 ranet-lite 默认值假设互操作。
- [ ] 冻结路由模式：v1 只向 Wintun 安装稳定 Photon/IPAM aggregate split routes；Babel
  learned route 只写用户态 SADR table，不随每次 update 反复改 Windows route table。
  full tunnel 后续必须同时解决 DNS、underlay endpoint bypass 和断线泄漏，不能只添加
  `0.0.0.0/0` / `::/0`。
- [ ] 冻结身份与 bootstrap：本机使用 Photon Zone identity 和 transport key；gateway
  只能来自已验证的 `ipsec/profile`、addresses、ports、transport-key 与兼容 overlay
  intent。静态 endpoint 只能作为 bootstrap hint，不能替代签名记录或放宽 peer auth。
- [ ] 写明 v1 route-origin 威胁边界：Babel route 在安装前必须通过
  `AuthorizedRouteSet`；还需决定 Babel 64-bit Router ID 如何稳定绑定到 verified Zone。
  在端到端 origin binding 完成前，只允许显式信任的单 gateway，并记录“已认证 gateway
  可冒充另一个已授权 origin”的剩余风险；不得把这一状态标为 production secure。
- [ ] 定义恢复与撤销 SLO：revocation/authorization withdrawal 收到后立即停止新流量并
  删除相关 SADR route/SA；service crash/restart 后不遗留 Photon-Windows-owned route；网络切换
  v1 允许 teardown/reconnect，不要求 MOBIKE，但必须有明确恢复时限和状态展示。

### 10.1 仓库骨架、构建边界与命名

- [ ] 新建 `app/photon-windows`，第一版只做 composition root 和命令入口；业务协议不得
  继续堆进 `main.go`。建议目录边界：
  - `internal/photonclient`：未来 Windows/Android 可复用的用户态 packet pipeline、IKE/ESP/Babel/SADR；
  - `internal/photonclient/ike`、`esp`、`babel`、`sadr`、`transport`：协议窄包；
  - `internal/photonclient/trust`：Photon verified state 到 client desired state 的 adapter；
  - `internal/photonwindows`：service、Wintun、IP Helper、named pipe、Event Log；
  - `app/photon-windows`：CLI 参数、Windows/service wiring、version。
- [ ] 提供非 Windows 可构建的 portable packages 和 `windows` build-tag adapter。Linux 上的
  `go test ./...` 不应因为导入 `x/sys/windows` 或 Wintun 失败；`app/photon-windows`
  在非 Windows 要么用清晰 stub 返回 unsupported，要么仅由 Windows build target 编译。
- [ ] 增加 Makefile 目标：`photon-windows-build`、`photon-windows-cross-build`、
  `photon-windows-test`、`photon-windows-package`；`make check` 至少覆盖 portable
  单测和 `GOOS=windows GOARCH=amd64` 编译，不在普通 Linux CI 尝试运行 Windows 二进制。
- [ ] 固定命名：可执行文件 `photon-windows.exe`，SCM service name
  `PhotonWindows`，display name `Photon Windows`，adapter base name
  `Photon Windows`，control pipe `\\.\pipe\photon-windows-control`。不要沿用
  `photon-lite` / `ranet-lite` 作为运行时资源名。
- [ ] 固定默认目录并允许显式覆盖：配置与持久状态放在
  `%ProgramData%\HiggsNet\Photon Windows\`，日志优先 Windows Event Log；开发态
  `run --console --config <path>` 可使用用户指定目录，不默默读取 Photon Linux 路径。
- [ ] 增加 Windows-aware version 输出与 build metadata；版本、commit、Go version、
  Wintun DLL/driver version、schema version 可从 CLI/IPC 查询，日志不得输出私钥、完整 key
  material、IKE AUTH payload 或未截断的敏感配置。
- [ ] 建立 `THIRD_PARTY_NOTICES` 和 dependency/license 检查。Wintun DLL 必须从明确版本和
  hash 获取，不能下载 “latest” 后直接随包发布；明确 DLL/driver 的签名校验、升级与卸载
  所有权。

### 10.2 Portable 用户态数据面按调用点提取

- [ ] 不在写 Wintun/IKE/ESP 前冻结一整套平台 capability。每个真实 consumer 出现时才提取最小接口，并同时定义
  资源所有者、并发模型、关闭顺序、backpressure 和 error semantics；接口由 consumer 定义，不建立包含未来所有
  能力的 `Resources` struct，也不做平台能力 nil 扫描。
- [ ] portable packet core 不得自行创建 Wintun、修改 OS route/DNS、安装 service、读取 Windows registry 或监听
  Unix signal。socket/TUN 的创建和 Windows handle ownership 留在 `internal/photonwindows`；用户态协议只消费首个
  真实数据路径所需的窄 read/write/rebind 调用面。
- [ ] 现有 memory TUN/datagram/network/clock 只证明各 adapter 的复制、阻塞、rebind 和 close 行为；仓库尚无
  `inner packet -> route lookup -> ESP -> datagram` pipeline，不得将其标成端到端完成。真正 packet pipeline 落地时再
  建立正反向、丢包、背压和关闭测试。
- [ ] 生命周期由 Windows service/composition root 统一管理。公共 HostRuntime、Store、Windows 平台 runtime 和未来
  packet engine 各自暴露真实 Start/Close/Wait 语义；不再创建一个通用 portable supervisor 包住所有组件。
- [ ] 定义 packet ownership：buffer pool 借用/归还规则、最大 inner/outer packet、batch
  上限、有界 channel 和过载策略。不得 per-packet goroutine；加密并行可以乱序执行但同一
  flow/读批次的发射顺序必须按已定义语义保持。
- [ ] 定义 MTU 计算：从 underlay MTU 扣除 IPv4/IPv6 + UDP + non-ESP/ESP + AEAD/padding
  开销，Wintun MTU 至少满足 IPv6 1280；先禁用依赖未验证 GSO/offload 的路径，并对超长
  inner packet 给出可观测丢弃/ICMP 策略。

### 10.3 Photon verified state 与配置

- [x] 盘点 `pkg/core/zone`、`pkg/core/gossip`、`pkg/crypto`、`pkg/routing` 和
  `pkg/transport/ipsec` 的 Windows buildability，形成复用矩阵：纯协议/验证代码直接复用；
  app state、VICI、XFRM、BIRD、netns、firewall、health 等 Linux runtime 绝不进入
  Photon Windows dependency graph。
- [x] 新建 Photon Windows 独立配置 schema。最小字段包括 trusted root、managed
  zone、state path、overlay id、gateway selector/bootstrap hints、Wintun adapter、
  split aggregates、MTU、log level 和 reconnect policy；默认 fail closed，未知字段报错，
  提供 `config validate`。
- [x] 第一窄切口支持加载已签名的预置 Photon state/snapshot，验证 delegation、record、
  revocation、有效期和 root trust 后才生成 client desired state；不能引入 ranet-lite
  `registry.json` 作为生产旁路。
- [x] Windows 与 Linux 必须直接复用同一套 `pkg/core/gossip` message、catalog、object-pull、
  quota 和 `ApplySnapshot`/verify 语义；不 fork 协议、不新增 Windows 专属 snapshot，也不另写
  一套“精简 gossip”。平台差异只允许存在于 UDP/network observer 等资源 adapter。leaf 可只
  请求运行所需的 Zone/record，但网络对象仍走现有共享 verify/apply 边界，再触发
  transport/routing reconcile；replay、chunk、bounded history 等行为随共享实现一起演进。

#### 10.3A 公共 verified state / gossip / zone 重构（Windows 网络同步前置）

**最终模块边界与单向依赖：**

```text
app/photon                         app/photon-windows
  one Linux composition root      one Windows composition root
       │          │                    │          │
       │          └─ photonlinux       │          └─ photonwindows
       │                               │             + future photonclient data plane
       ├───────────────┬───────────────┤
       ▼               ▼               ▼
 pkg/core/host.Runtime   pkg/core/state.Store/BoltStore
 queue/scheduler/gossip  verified/checkpoint + one DB handle
            │                         │
            ▼                         ▼
   pkg/core/gossip              pkg/core/zone
   Engine/FSM only              domain primitive

package dependency: app -> host -> gossip -> state -> zone
                    app ───────> platform controller implementations
```

- 依赖方向固定为 `gossip -> state -> zone`。`zone` 不得 import `state`/`gossip`，`state` 不得
  import `gossip`，平台 app/internal package 不得被三个公共包 import。
- 为避免 Go import cycle，将当前位于 `pkg/core/gossip`、实质描述可信状态的
  `ZoneSnapshot`/record snapshot、digest/catalog projection、snapshot verify/apply/result/limits
  迁到 `pkg/core/state`；gossip wire message 直接引用公共 state DTO。迁移完成后删除旧定义、别名
  和转发函数，不长期保留两套 API。
- `pkg/core/zone` 只保存最低层 `NetworkState`、`ZoneState`、authority/delegation/revocation/record
  模型、COW clone 与现有 bbolt bucket primitive；它不知道 managed zone、peer、sync round、
  auto-join、平台 controller 或 ChangeSet。
- `pkg/core/host` 提供 Linux/Windows 共用的唯一 HostRuntime 实现：拥有 bounded event queue、scheduler、
  gossip Engine/action ordering、receive/object-pull/chunk runtime。产品 composition 创建唯一 Store/BoltStore 并把
  common state/persistence 调用面交给 HostRuntime；HostRuntime 不自行按路径打开第二个 DB，也不把公共 gossip 执行
  回调给另一个所谓 client runtime。
- `pkg/core/state` 提供唯一一套 verified aggregate 与事务语义。公共 HostRuntime 同步调用
  `state.Store`，后者拥有 managed zone、root trust/pin、已验证 Network、本机 raw Ed25519
  private key material，并在独立逻辑分区中原子组合 loss-tolerant `GossipCheckpoint`；它不是第二个后台 runtime，
  不创建 goroutine/写入线程/独立 DB handle，也不拥有 socket、session、timer、object-pull worker、SA、
  route、firewall rule、BIRD process、Wintun/WFP handle 或任何 observed platform object。
- `pkg/core/gossip` 只拥有 wire codec、packet classifier、session FSM、Engine、timer action/event types、
  chunk/cache 和 object-pull protocol；timer deadline policy 留在 FSM，但不再
  持有 scheduler。HostRuntime 把平台 UDP 收到的相同 packet/event 注入 Engine，
  Engine 只返回平台无关的有序 Action；所有 read/apply/send/pull/persist/log effect 都交还同一个
  HostRuntime 执行。gossip 不直接调用 Store、打开 DB、保存私钥、修改 Network 指针或调用
  StrongSwan/firewall/WFP。

**公共 HostRuntime 与平台 composition：**

- [ ] `pkg/core/host.Runtime` 已存在；继续把 Linux daemon 中与平台无关的 event drain、Engine 驱动、common state
  transaction/persistence ordering、object-pull completion、timer dispatch 和 shutdown drain 收入同一个实例。
  `app/photon` 与 `app/photon-windows` 各自只创建一个 HostRuntime，不复制 host event/action switch。公共 host 不
  bind 平台 socket、不读取 registry、不调用 systemd/SCM，也不 import 具体 Linux/Windows 包。
- [ ] 只为 HostRuntime 的真实依赖保留窄 capability，例如已经存在的 `DatagramIO`、Clock 和 detached common Store
  调用面；不要预建统一 `PlatformController`。Linux/Windows 的 IPsec、route、firewall、Wintun 等差异保留在各自
  platform runtime，出现共同 consumer 后再抽取接口。
- [ ] 平台 reconcile 只接收 detached state view/ChangeSet 和自己的 observed input，返回 typed
  plan/completion；不得直接访问 Engine、event channel、bbolt handle 或 committed root。耗时 Observe/Apply
  可在 HostRuntime 管理的 bounded worker 中运行，completion 必须回到公共 event queue，由唯一 writer
  做 source-revision CAS 和 checkpoint commit。
- [ ] HostRuntime action executor 对 Linux/Windows 只有一份 type switch/order 测试。平台 adapter 只执行
  真实平台 I/O；测试用 memory UDP、公共 memory Store/Bolt fixture 和 manual clock 驱动完整
  `packet -> Engine -> state commit -> completion -> send`，不为测试引入第二个 runtime 或通用平台 controller。

**计时器 ownership：**

- [x] gossip timer 已分为“deadline policy”和“调度资源”：session 决定 timer key、deadline、replace/cancel
  和 timeout 状态转移；公共 HostRuntime 的 Scheduler 拥有 deadline heap、唯一 wakeup loop、event delivery、
  stop/drain 和 manual-clock test hook。Engine 已无 `time.Timer`、ticker、timer goroutine 或 event channel。
- [ ] controller timer 随 controller/runtime 迁移接入同一个 Scheduler；迁移后 controller 同样不得持有
  ticker、timer goroutine 或直接向私有 channel 投递 timeout。
- [ ] `gossip.Engine.Handle` 保持同步确定性：输入 `Packet/Event/TimerFired/ObjectPullCompleted`，输出有序
  `ScheduleTimer`、`CancelTimer`、read/apply/send/pull 等 Action。Engine 不拥有 event channel 和
  TimerManager；HostRuntime 执行 timer action，到期后把 `TimerFired{Owner, Key, Generation, Deadline}`
  投回公共 queue。generation/token 与当前 session round 双重校验，cancel/replace 后的 stale fire 无副作用。
- [ ] Scheduler 使用 namespaced owner/key 支持 gossip round/catalog、peer backoff、metadata checkpoint、
  controller debounce/maintenance，以及后续 IKE retransmit/DPD、Babel hello/expiry；协议/controller 只看到
  自己 namespace 的 fire event。安全撤销/deny 不经过 debounce，立即进入 event queue 高优先级路径。
- [x] 从 `pkg/core/gossip.TimerManager` 迁移通用 heap/wakeup 实现和 manual-clock tests 到公共 host，保留
  gossip timer kind/action/FSM tests 在 gossip。迁移完成删除 Engine 的 `events chan`、`timers` 字段及
  `StartTimer/CancelTimer/ResetTimers/Events/Post` 资源方法；所有生产事件统一由 HostRuntime queue 背压。
- [ ] 验证 timer 公平性和关闭语义：同 deadline 稳定排序、单次 wakeup 批量 drain 有上限、controller timer
  storm 不饿死 gossip/security event、queue full 不静默丢 timeout、Stop 后不再投递、fake clock 前进可
  确定性触发。运行 race，并覆盖 replace/cancel/stale generation、shutdown pending timer 和 resume catch-up。

**公共 state 数据与 API：**

- [ ] 定义不可混入平台字段的 `state.VerifiedState`：只包含 `ManagedZone`、`Network`、
  trusted-root identity/hash 和 root/identity raw Ed25519 private key；schema guard 明确禁止 peer、
  IPsec/link/firewall/routing/BIRD/admission observed state。peer retry/discovery 提示进入独立、可丢失并可从空状态
  恢复的 `GossipCheckpoint`，不得影响验签、授权或最终收敛。
- [ ] 定义 `state.VerifiedStore` 的单 owner/revision 模型和四组窄 API，由 HostRuntime 的唯一 event
  loop 同步调用，而不是暴露通用
  `func(*NetworkState)` callback：
  - `ReadView/ZoneDigests/Catalog/Snapshot`：锁内生成 detached 或 bounded DTO；
  - `ApplyLocalIntent(intent, now)`：从 Store 当前 revision 的本机私钥直接完成 authority-owned mutation；
  - `ApplyRemoteBatch(peer, snapshots, limits, now)`：远端 verified snapshot transaction；
  - `UpdatePeerCheckpoint(peer, typed patch)`：不改变 Network 的 loss-tolerant gossip checkpoint transaction。
- [ ] `ApplyLocalIntent` 统一承接 config/DNS/admin/endpoint publisher 产生的 typed intent，包括 signed
  record put/revoke、delegation/revocation 和需要的 recovery mutation。输入 adapter 只做语法解析和
  来源采集；基于当前 revision 的权限、版本、history、跨 record 约束、签名 payload 和最终验证必须
  只有 state 一份实现。Linux/Windows 使用相同的 raw Ed25519 key 字段和签名路径，不要求额外的平台
  密钥 capability、系统加密封装或不可导出密钥适配层。
- [ ] `ApplyRemoteBatch` 具体拥有 target-zone COW、逐 snapshot savepoint、部分成功、rejected digest、
  root pin/chain/record/revocation 验证、auto-join 和 managed-zone authority refresh；不提供 generic
  platform finalizer。中间失败保留此前成功并继续后续项，最终至多发布一个 verified revision；所有
  mutation 在唯一 event loop 中基于当前 root 串行重算，日志、send 和 controller callback 不得进入事务体。
- [ ] auto-join/authority refresh 从 `app/photon/identity_bootstrap.go` 迁入公共 transaction：父 snapshot
  可以更新本地 managed-zone 的 authority envelope，但不能覆盖本地 authority-owned records、child
  delegations、revocations/history；identity key 不匹配、旧 epoch、同 epoch 冲突和无效 parent proof
  均 fail closed。相关 mutable zones 必须由 state transaction 自己正确 COW，不由平台声明。
- [ ] 将 Linux `internal/state.PeerRuntimeState` 逐字段拆分：公共 `GossipCheckpoint` 只覆盖 retry/backoff、
  discovered/observed endpoint grace、rejected object digest 和 relay suppression 等重启提示；session phase、timer、
  cursor、chunk assembly、worker/inflight pull 只在 Engine/HostRuntime 内存；hint/responder/last-error 与 datagram/
  object-pull 计数进入有界 observability/metrics，不持久化。迁移后删除 Linux 大杂烩类型。
- [ ] `CommitResult` 返回唯一的 `VerifiedRevision`、changed zones/record families、
  `NetworkChanged`/`GossipCheckpointChanged` 和安全优先级；checkpoint 不拥有 revision，纯 checkpoint commit 不推进 verified revision、
  不唤醒数据面。ChangeSet 只描述已成功提交的事实，不携带平台函数或可变 state 指针。

**五条管理调用链必须按以下顺序实现：**

1. **本地配置/DNS/admin 写入**

   ```text
   config watcher / DNS resolver / daemon control request
       -> platform adapter 生成 typed LocalIntent
       -> state.ApplyLocalIntent(intent, now)，使用同一 committed candidate 中的本机私钥
       -> 基于 committed revision 验证、签名、构造 COW candidate
       -> BoltStore.CommitCommon(candidate) 成功
       -> 发布内存 revision，返回 CommitResult/ChangeSet
       -> 当前 HostRuntime 标记 Linux/Windows controller dirty
       -> 必要的安全 barrier 完成后再向管理请求确认
   ```

   - signer 调用和磁盘 I/O 不允许持有面向 reader 的长时间 callback；若采用乐观两阶段签名，签名前后
     必须比较 revision，并在 stale 时重新构造/重新签名，不能把旧 version/signature 强塞入新 root。
   - 在线管理 client 只能发送 intent；显式 offline recovery 必须独占打开同一个 BoltStore 并
     调用相同 mutation，不能继续维护 `app/photon` direct 写入的第二套校验。

2. **UDP gossip / object-pull 远端写入**

   ```text
   injected UDP receiver
       -> gossip verified packet + Engine session FSM
       -> Engine 产出 ApplyRemoteBatch action
       -> Action 返回当前 HostRuntime
       -> HostRuntime 调用 state.ApplyRemoteBatch
       -> state 原子验证/提交 Network + rejected/success metadata
       -> CommitResult 回到 HostRuntime
       -> HostRuntime 把 completion event 再喂给 Engine，并执行 send/timer Action
       -> HostRuntime 按 ChangeSet 调度平台 controller

   object-pull worker completion
       -> 同一个 Engine event/action
       -> 同一个 state.ApplyRemoteBatch
   ```

   - object-pull、UDP complete snapshot 和 repaired chunk 不得各自拥有 apply/commit 路径；差别只在对象
     如何到达 Engine。worker 不能直接拿 Store/Network 指针。
   - Engine 的 Action 可以引用 state DTO，但 Engine 不持有 Store/StatePort。state transaction 不知道 UDP、
     peer socket address、session phase 或 send action；协议失败映射由 HostRuntime 处理，验证拒绝原因由
     state 返回稳定枚举。Linux/Windows 必须执行同一 Action contract，不得各自解释一套 message 语义。

3. **gossip 只读响应**

   ```text
   Ping/fetch/catalog request
       -> Engine/planner
       -> read Action 返回 HostRuntime
       -> HostRuntime 调用 state bounded read projection
       -> gossip codec/datagram planner
       -> send Action 返回 HostRuntime
       -> HostRuntime 使用平台 UDP send
   ```

   - Store 只返回 digest/catalog page/snapshot 等 detached DTO；不得让 committed `NetworkState`、Zone map、
     record pointer 逸出。读取期间不 send、不记日志、不打开 DB。

4. **平台 controller 派生与 reconcile**

   ```text
   committed ChangeSet
       -> 当前 HostRuntime（state 锁外）
       -> state.ReadView(revision)
       -> Linux: StrongSwan/XFRM, firewall, BIRD/routing planner
          Windows: user-space IKE/ESP, WFP, Wintun/SADR planner
       -> Observe -> Plan -> Apply -> platform checkpoint
   ```

   - 平台 controller state 单独拥有并带 `SourceVerifiedRevision`；它是可从 verified state 重建的派生状态，
     不与 verified commit 组成跨平台大事务。reconcile 失败不得把 SA/rule/process 状态写回 verified store，
     也不得回滚已经接受的可信事实；应 fail closed、记录 controller error 并重试。
   - revocation/ACL/authorization withdrawal 等安全 ChangeSet 需要 composition 层的 deny-first acknowledgement
     barrier：state commit 和持久化仍先完成，平台 apply 在 state 锁外执行，但管理请求不得在必需的 deny
     生效前返回成功。普通 endpoint/metric 变化可 dirty/coalesce。

5. **启动、持久化与恢复**

   ```text
   HostRuntime 打开唯一 state.BoltStore/bbolt handle
       -> load verified buckets + platform runtime bucket
       -> state.VerifiedStore 校验 root pin/schema/invariants
       -> HostRuntime 发布 initial revision
       -> HostRuntime 创建 gossip Engine 并启动平台 UDP receive
       -> platform controllers 从 initial ChangeSet 全量 reconcile
   ```

   - [ ] 每个平台进程只打开一个公共 `state.BoltStore`、一个 bbolt handle 和一个 event-loop writer；逻辑上把
     root 拆为公共 verified/sync bucket 与平台 runtime bucket，但不引入第二个后台 Store/DB writer。
     Linux/Windows 的 gossip packet、control intent、timer、object-pull completion 和 controller result
     全部回到各自唯一 HostRuntime 串行提交，保持现有 transaction/CAS/persistence ordering。
   - [ ] 在 `pkg/core/state` 定义公共 `BoltStore` 与 verified bucket codec/transaction contract，供平台
     在同一个 Store 的单笔 bbolt `Update` 中组合；公共代码固定 verified/sync bucket/schema，
     平台代码只扩展 Linux/Windows runtime bucket。Store 只在持久化成功后发布内存 root 和 ChangeSet，
     失败时 revision/state/events 全不变化。不得由 state、IPsec、firewall、routing 各自打开同一路径。
   - [ ] 平台 runtime family 使用 typed transaction 和独立 source revision；IPsec、firewall、routing 等
     可以锁外并发 Observe/Plan/Apply，但 completion 必须回到 HostRuntime，经同一个 BoltStore
     检查 source revision 后提交。bbolt 的单 writer 只负责磁盘序列化，不能替代 stale-result/CAS 检查。
     相同 substantive state 是 no-op，高频 summary/timestamp checkpoint 继续 coalesce，安全 deny 不延迟。
   - [ ] 设计 schema migration：兼容读取当前 `_meta/cli_state`，一次性拆成公共 verified/sync metadata 与
     Linux controller metadata；migration 必须同一 bbolt transaction、可重复、断电安全，并保留旧 DB
     fixture。迁移在唯一 BoltStore 的同一 bbolt transaction 内把旧大 JSON 拆为 verified/sync 与
     platform runtime bucket；失败整体 rollback，下次启动幂等重试。Windows 新库直接写新 schema，
     root/identity/transport 私钥作为普通 raw key material 进入同一个 BoltStore transaction。

**Linux 逻辑拆分、单 Runtime/单写迁移：**

- [ ] 保留 `DaemonStateStore` 作为 Linux 内存态唯一 writer，并由公共 BoltStore 统一持久化；把根对象逻辑拆为公共
  `state.VerifiedState` 与 `LinuxRuntimeState`。后者只包含 peer cleanup policy（若确认非 sync metadata）、
  IPsec key/port/link/reconcile、routing/BIRD、firewall/ACL reconcile、admission diagnostics 等平台/运维
  状态；逐字段按“是否属于可信事实、能否重建、是否跨平台”审计，不能只按当前文件位置移动。
- [ ] verified commit 后在锁外派发 ChangeSet；平台 apply completion 回到同一个 daemon event loop，再由
  同一个 DaemonStateStore 写入带 `SourceVerifiedRevision` 的 runtime checkpoint。crash 若发生在 verified
  commit 后、checkpoint 前，重启从 verified revision 全量 reconcile；若 OS apply 已成功但 checkpoint
  未写，Observe/adopt + 幂等 Apply 收敛。stale completion 一律忽略并重算。
- [ ] daemon 运行期间在线 CLI 只能经 control IPC 把 intent 投递到同一 event loop，不得另开同一 DB direct
  write。显式 offline recovery 要求 daemon 已停止并取得独占文件锁，随后复用同一个 BoltStore
  和公共 state transaction。
- [ ] 迁移期不得长期保留 `stateFile.Network/SyncPeers` 与公共 Store 双份真相源。允许一个短期 read-only
  compatibility loader 把旧 schema 转成新 aggregate，但所有在线 writer 切换必须在同一里程碑完成；
  加测试故意让旧字段与新 store 不一致并保证启动 fail closed，而不是静默选一份。
- [ ] Linux gossip executor 删除重复的 snapshot verify/apply、catalog 算法、object-pull completion mapping
  和 peer metadata mutation 语义；保留唯一 HostRuntime action executor，把 packet/event 注入公共 Engine、
  执行其公共 Action，并通过 DaemonStateStore 调用公共 state transaction。随后将该 executor/event loop
  迁入公共 `host.Runtime`；Windows 只注入 Windows UDP/controller adapter，两端不得维护不同的 action
  switch 语义。
- [x] 删除 `internal/photonclient/trust.StaticSource/LoadBoltSnapshot`，恢复入口已迁到
  `internal/photonwindows.StateStore`，由 Windows composition/state wiring 持有；复用公共 Store/BoltStore、真实
  revision 和 root/managed-zone 校验，不在平台 adapter 中重新逐 zone 实现验证循环。

**验收与迁移顺序：**

- [x] A：先移动 state-domain DTO/纯函数并消除 import cycle；所有现有 Linux 调用直接改用新包，删除旧
  alias/wrapper。跑 state/gossip/zone unit、fuzz/codec compatibility 和 Windows compile guard。
  - [x] A1：`ZoneSnapshot`/`RecordSnapshot`、`SyncLimits`、`ApplyResult` 和 snapshot create/record projection/
    verify/apply/target-zone COW 已整体迁入 `pkg/core/state`；gossip wire/object-pull/action 直接引用 state DTO，
    Linux daemon/recovery/join/trust adapter 直接调用 state API。已删除 `pkg/core/gossip/sync.go` 和全部旧定义，
    未保留 alias/forwarder；snapshot 原子性、chain、revocation、limit 测试同步迁入 state。
  - [x] A2：`ZoneDigest`、`CatalogSummary`、`CatalogPage`、`ZoneDigests/ZoneRoot`、catalog root/summary/diff
    已迁入 `pkg/core/state`，Linux daemon/inspect 与 gossip FSM/wire 直接引用 state DTO/API；删除 gossip
    `digest.go` 及旧定义/summary wrapper。`pkg/core/gossip/catalog.go` 只保留 cursor 校验和依赖实际 MessagePack
    Message wire-size 的分页装箱，未增加 forwarding API；纯 projection/root/diff 测试归入 state，wire budget/
    codec/session 测试留在 gossip。公共 state/gossip/host/trust race 与全量 `make check`（含 Windows amd64）通过。
- [x] B：Engine 输出平台无关的 timer/apply/send/pull/persist Action，HostRuntime 通过只读 state capability
  取得执行阶段所需投影；event queue/TimerManager 已迁出协议 Engine。公共 HostRuntime + Scheduler memory
  vertical slice 已证明 Linux/Windows adapter 使用同一 action executor。
  - [x] B1：完成 timer memory vertical slice：新增 `pkg/core/host.Runtime` bounded queue 和单 heap/wakeup
    Scheduler；Linux daemon、sync serve/once、object-pull result 和测试均切换到该 queue。Timer fire 携带
    namespace/owner/key/generation/deadline，消费时校验 generation；同 deadline 稳定排序、replace/cancel、
    namespace cancel、queue-full 不丢 timeout、stop/idempotence/manual clock 已覆盖，公共包 race 与全量
    `make check`（含 Windows amd64 build）通过。
  - [x] B2：state DTO 迁移后，把 read/apply/send/pull/persist action executor 和 object-pull completion
    收入公共 HostRuntime，并用 memory Linux/Windows adapter 证明只有一个 action ordering switch。
    - [x] B2a：删除未进入 wire 的 `LocalDigests/SendPingAction.Digests`、无生产者的
      `SendCatalogPageAction` 和 Linux `objectPullResultToEvent` 包装；将 chunk fallback 改为语义明确的
      `SendChunkFallbackAction`。gossip 统一把 send action 映射为 `OutboundMessage`，host 统一把 action
      分类为 apply/outbound/pull/timer/backoff/persistence phase 并合并 persistence scope；Linux executor
      已改为消费公共 plan，不再维护 send/apply/pull/timer/terminal action type switch。
    - [x] B2b：公共 `host.GossipActionController` 注入 verified-state、transport、object-pull、backoff 与
      metadata/persistence capabilities；`HostRuntime.ExecuteGossipActions` 唯一拥有 state read、snapshot
      apply、apply 后重新投影/reconcile、send、pull、timer、backoff、persistence 的执行顺序和失败短路。
      公共 inbound executor 同时接管 PING/PONG、bounded catalog responder、session event enqueue、announce/
      object-chunk 分发，Linux 已删除 `InboundActionKind` switch、`respondPing*`、catalog responder 和 summary
      shortcut 协议包装。object-pull completion 由公共 DTO 映射为 FSM event 并进入同一 bounded queue；Linux
      只保留 transport diagnostics。显式 memory Linux/Windows capability adapter 已逐项断言相同 ordering、
      apply failure short-circuit 和 persistence intent；公共 host/Linux daemon race、全量 `make check`（含
      Windows amd64 build）通过。
- [x] C：实现内存 VerifiedStore、单一 verified revision、local/remote transaction、ChangeSet 和 fake commit callback；覆盖
  retain、失败不变、success-reject-success、auto-join/refresh COW、concurrent read 与单 writer/race。
  - [x] C1：新增公共 `state.Store`/`VerifiedState`、detached `ReadView`/`ZoneDigests`、唯一
    `VerifiedRevision`、`ChangeSet` 和 commit-before-publish `CommitFunc` contract；`ApplyRemoteBatch` 以逐对象
    savepoint 保留 success-reject-success，统一 expected-root/验证拒绝元数据并单批发布。memory commit sink
    已覆盖持久化失败不发布、输入/读视图不 retain、并发 reader 与单 writer race。
  - [x] C2：补齐 typed `ApplyLocalIntent`、通用 `UpdatePeerCheckpoint`、auto-join/managed authority refresh COW；
    Linux 在线 adapter 的整体切换归入 E，不再让平台接线阻塞公共内存状态机里程碑。
    - [x] C2a：公共 Store 新增 typed peer checkpoint patch；parent snapshot apply 后在同一 savepoint 调用公共
      `ReconcileManagedAuthority`，匹配
      identity 才 adoption，refresh 保留本地 records/delegations/revocations/history，旧 epoch、同 epoch conflict、
      refresh identity mismatch 和无效 chain 均 fail closed；远端 managed-zone snapshot 不再覆盖本地内容。
    - [x] C2b：实现 typed `ApplyLocalIntent` 与 raw-key 串行重算；Linux snapshot apply、auto-join 和
      peer metadata adapter 的切换及 app 内重复 mutation 删除归入 E。
      - [x] C2b1：公共 Store 新增 sealed local intent：`PutRecordIntent`、`PutDelegationIntent`、
        `RevokeDelegationIntent`；Store 直接持有并持久化 root/identity raw Ed25519 private key，按当前 authority
        选择授权 key 后调用公共 crypto sign/verify。revocation 在同一
        commit 清理目标及后代 peer checkpoint，仅推进 verified revision 并返回 security-priority
        ChangeSet。persistence failure、missing/unauthorized key、record history、delegate/revoke ordering 与
        retained pointer 已覆盖。
    - [x] C2c：完成 Linux 整体切换所需的状态分区与一次性数据库迁移投影；投影只在旧 schema → 新 bucket
      的迁移事务内部使用，不暴露 DaemonStateStore 兼容 API，也不提供新状态 → 旧 `stateFile` 的反向映射。
      DaemonStateStore 嵌入公共 Store、在线 mutation 切换和旧逻辑删除统一归入 E。
      - [x] C2c1：按字段语义纠正 Store 分根：`VerifiedState` 不再包含 peer；新增独立
        无独立 revision 的 `GossipCheckpoint`，同一 CommitFunc 在 candidate 中原子组合 verified + checkpoint。
        checkpoint 只允许丢失后增加重试/重新发现的行为提示，纯诊断计数继续留在 observability。
      - [x] C2c2：新增旧 Linux `SyncPeers` 到公共 `GossipCheckpoint` 的单向白名单迁移与报告；
        session/active-pull/hint/responder/datagram/object-pull 诊断不进入 checkpoint，无效 peer、
        非 Zone rejected object 和 malformed hash 作为可丢失条目丢弃；不保留 daemon projection 方法。
      - [x] C2c3：新增旧 `stateFile -> CommitCandidate{Verified,Gossip}` detached 启动投影；公共
        `ValidateStateRoot` 统一校验 managed zone、Network、Ed25519 私钥长度和完整
        `trusted_root_public_key` pin。纠正原 `TrustedRootHash` 命名，Linux/Windows 不再各自解释 root pin。
- [x] D：实现公共 verified codec/transaction 与唯一 `state.BoltStore` 的 bbolt composition、旧 schema
  migration；覆盖事务失败、close failure、no-op、metadata-only、crash fixture/reload、外部锁冲突及
  Linux/Windows path adapter。
  - [x] D1：`pkg/core/state` 新增平台事务内公共 bbolt codec，固定 common/meta/verified/gossip bucket 与
    schema version；`LoadBoltState` 区分新根不存在、可信根损坏和可丢弃 checkpoint，`CommitBoltState` 在
    调用方 `*bolt.Tx` 内检查 verified payload/revision 一致性、校验 state root、稳定编码并返回 byte-level no-op。
    已覆盖 round-trip/detach、revision invariant、无变化 rollback、平台 bucket 同事务失败回滚、未来 schema
    fail closed 及 malformed checkpoint discard。codec 不持有 DB handle，不创建第二个 writer。
  - [x] D2：新增尚未接入在线 loader/writer 的 Linux 事务迁移函数：在调用方同一 `*bolt.Tx` 中读取旧
    `_meta/cli_state` 与 `zone:*`，投影公共 verified/gossip bucket 和只含 Linux controller/configuration 字段的
    `photon:linux-runtime` bucket，成功后删除旧 Network/metadata 表示。公共 `zone` 包提供 caller-owned
    `LoadNetworkTx`/`SaveNetworkTx`/`DeleteNetworkTx` primitive，不持有第二个 handle。迁移对新格式幂等，
    新旧表示并存时 fail closed，malformed metadata/任一步失败整体 rollback；fixture 覆盖字段 ownership、
    checkpoint 白名单、旧字段删除和重复执行。E 阶段整体切换前不调用该迁移，避免半切 writer。
  - [x] D3：新增尚未接入在线路径的公共 `state.BoltStore` owner：进程级只持有一个 bbolt handle、事务顺序与
    close lifecycle。Linux 不再定义自己的持久化 Store，只提供 bucket codec 与事务组合函数；首次聚合加载
    可在同一 Store 的事务内执行 D2 迁移。byte-identical aggregate 通过事务 rollback 成为真正 no-op；公共写入
    失败时同事务内先写的平台 payload 也整体 rollback。测试覆盖迁移后关闭/重开、事务 txid no-op、context
    cancellation、外部第二 handle 锁超时、close error 传播和重复 Close。BoltStore 仍不接当前 daemon loader/writer，
    留待 E 阶段一次性切换，避免 legacy/common 双写。
  - [x] D4：明确 metadata-only 持久化语义：公共 Gossip checkpoint 通过同一 BoltStore 保存但不推进
    `VerifiedRevision`；Linux runtime completion 只更新平台 bucket，并用其计算来源的唯一 verified revision
    对照当前磁盘 revision，拒绝旧 completion。该检查不创建 checkpoint/platform revision，也不允许 controller
    反向修改 verified payload。测试覆盖 checkpoint-only、runtime-only、verified 字节不变和 stale completion rollback。
- [ ] E：Linux 在保留单 DaemonStateStore/单 event-loop writer 的前提下先切换 verified bucket，再把
  platform-neutral host loop 替换为公共 Runtime；删除 `stateFile.Network/SyncPeers` 双份在线所有权，跑
  全量 `make check`、
  `-race`、chain relay、object-pull、bootstrap join、delegation revoke、firewall deny-first、IPsec/routing smoke。
  - [x] E0：公共 `RestoreStore` 可从 BoltStore 加载的 detached candidate 和既有 `VerifiedRevision` 恢复
    内存 Store，校验状态根并再次 detach 输入；后续 Network commit 从磁盘 revision 继续递增，而不是重置为 0。
    BoltStore 同时提供窄 `LoadCommon` 启动读取方法。
- [x] E1：DaemonStateStore 嵌入恢复后的公共 Store，并将在线 record/delegation/revocation、snapshot apply、
    auto-join 和 peer checkpoint 一次性切到公共事务；同时把 record/IPAM/service/route publisher、discovery、
    revocation cleanup 和 metadata checkpoint 纳入同一切换闭环。公共 Store 独占 `Network`/checkpoint，Linux
    runtime 独占 controller 数据；`stateFile.Network/SyncPeers` 只保留为 detached 聚合读形状，禁止新旧 writer 并存。
    - [x] E1a：完成新状态存储的启动恢复流程。启动时只打开一次数据库；遇到旧数据库就先升级，然后分别
      读出公共状态和 Linux 运行状态。公共状态恢复后可以继续写回同一个数据库，重启后 revision 和 gossip
      checkpoint 都能正确接续，且更新 checkpoint 不会误改 Linux 运行状态。这个入口暂不接入在线 daemon，
      E1b 已将该入口接入在线 daemon，并同步删除旧保存路径，避免新旧写入方式混用。
    - [x] E1b：整体切换所有在线 writer 并删除旧状态所有权与保存路径。
      - [x] E1b1：从旧 `PeerRuntimeState/SyncPeers` 类型中删除 `DatagramStats/ObjectPullStats`；在线统计只由
        有界 `PeerObservabilityStore` 持有，inspect/HTTP 构建器显式接收独立 diagnostics，不再把统计临时塞回
        legacy peer 对象。旧数据库 JSON 中这两个可丢失字段直接忽略且永不回写。
      - [x] E1b2：将 active-pull 展示状态、hint 计数/最近原因和 read-only responder 统计从 `SyncPeers` 删除，
        直接写入 `PeerObservabilityStore`；这些更新不再推进 daemon state revision 或触发 metadata checkpoint。
        Store 中的单 peer 值明确命名为 `PeerDiagnostics`，避免与协议状态/checkpoint 混淆；在线 inspect/HTTP
        只负责合并展示，离线数据库诊断按重启后已丢失处理。
      - [x] E1b3：最近一次 peer 错误归入可丢失但可持久化的 gossip checkpoint，使用实现 `error` 的具体
        `PeerFailure{Code, Message, AtUnix}`，不在数据库保存 Go `error` 接口，也禁止用 Message 文字控制行为。
        旧 Linux `LastError` 仅在一次性数据库迁移时转换为 `legacy` code；调度继续使用 FailureCount/backoff。
      - [x] E1b4：将 `LastUpdateSource`、`LastRelaySuppression/At` 和 `ObservedSource` 从旧 `SyncPeers` 与公共
        checkpoint 删除并迁入 `PeerDiagnostics`。这些字段只解释最近一次更新/抑制/观察的来源，不参与 relay
        节流或 observed path 有效性判断；在线 inspect/HTTP 继续展示，重启后丢失。relay 抑制诊断不再提交
        metadata，观察来源只在 endpoint 事务提交成功后记录。
      - [x] E1b5：补齐并整体切换公共 verified writer。`PutDelegationIntent` 已改为在同一事务同时更新父区
        delegation 与子区 authority，authority epoch 刷新保留子区 records/history，并把父区和子区都放入
        `ChangeSet.ChangedZones`。root authority grant 已有专用 `UpdateRootAuthorityIntent`，强制 epoch 单调、
        本地 root key 与 trusted root pin 不变且保留根区内容。join accept 的公共 `InstallIdentity` 已区分首次
        安装与同 managed zone refresh，校验 identity key/完整 chain/固定 root pin，拒绝身份切换、epoch 降级和
        同 epoch 冲突，且持久化成功后才发布。显式 recovery import 也已有公共事务入口，允许恢复 managed zone、
        保持 trusted root 不变、按字节 no-op 且持久化成功后才发布。revoked purge 的公共层也已收口：只负责
        verified zone 与 gossip checkpoint，保留父区 tombstone 和本机 identity chain；Linux IPsec/link 清理由
        平台层按公共 zone plan 执行。IPAM pool/assignment create/revoke、route announce/withdraw 和 SOCKS5
        publish/withdraw 已分别提供公共 typed intent，并在当前 Network 上复用 pool ownership/overlap、assignment、
        route 与 service endpoint 授权；通用 `PutRecordIntent` 在公共层拒绝对应保留 namespace/type。公共 preview
        复用完全相同的 normalization/validation/signing 路径但不落盘、不发布。daemon control request 到公共 intent
        的 adapter 只保留纯 DTO 转换，不读取本地 state、不重复 semantic validation；未接在线的独立 apply wrapper
        已删除，control handler 直接调用 DaemonStateStore 中的公共 Store。公共 `Store.ReadView()` 与 Linux runtime
        snapshot 生成 detached 的聚合 `stateFile`，仅供现有 projection/controller planner 读取，不提供保存或反向
        写回入口；checkpoint 到旧 peer 形状的映射也只发生在该读视图中。
        公共 remote batch 与 peer checkpoint 已使用相同的 commit-before-refresh 委托；checkpoint-only commit
        不推进 verified revision。Linux routing/IPsec/firewall completion 也已有按唯一 verified revision 检查的
        typed runtime commit，持久化失败、stale 和 no-op 都不发布，真实 BoltStore 关闭重开已证明 runtime 更新不会
        改动公共 revision。daemon 的 routing/IPsec/firewall reconcile、IPsec cleanup 与 Endpoint ACL 调用点已统一
        进入 runtime typed commit。生产启动现只打开一个 BoltStore，并已删除通用 `Update`、旧 peer/Network/snapshot
        writer、`saveCommittedMeta/saveCommittedState`、在线数据库重载与 self-write marker；不存在新旧在线双写模式。
        `stateFile` 目前只是 daemon planner/inspect 的 detached 聚合读形状，不再是持久化根，后续替换公共 host runtime
        时再按 consumer 逐项缩小，而不是为切换继续增加 adapter。
        常驻 BoltStore 切换后，离线 CLI 读取已优先组合 common + Linux runtime 分区；只有尚无 common schema 的旧库
        才进入保留的一次迁移/bootstrap 路径。`record put --direct` 也已改为在 daemon 停止后打开唯一 BoltStore 并提交
        公共 `PutRecordIntent`，不再把新 common 状态反向写回旧 Network/meta。daemon 与长期 `advanced sync serve` 均
        提供 control IPC；在线 records、sync、peer、zone 和 chain verify 读取 typed view，不与服务进程争抢 bbolt 文件锁。
        纯 gossip service 未配置 Linux runtime 时只提交/清理 common gossip 状态，不标记或执行 platform reconcile。
        相关切换已由完整 `make smoke` 验证，覆盖 phase1/2/3、admin、多节点、relay/discovery、bootstrap/NAT、revoke、
        object-pull/chunk fallback 及各 dry-run/observer smoke。
        公共 Store 已补充批量本机 intent 原语：多条 publisher mutation 在同一 detached candidate 中按顺序校验、
        签名，任一失败整批回滚，只执行一次持久化且 VerifiedRevision 最多推进一次；原单条 API 反向复用该实现，
        避免形成两套 mutation 语义。startup/endpoint、admin、remote snapshot、discovery、cleanup 与全部 controller
        completion 均已切换；全量 `make check`（含 Windows amd64 编译）通过。
  - [x] E2a：将有界 gossip packet receive loop 从 `pkg/core/gossip` 迁入公共 `host.Runtime`。公共 runtime
    现在独占唯一阻塞 Receive goroutine，packet 直接进入已有的 64 项 event queue，与 timer/completion 共用
    backpressure 和顺序边界，不再创建第二条 packet channel；`Runtime.Stop` 会 cancel、关闭注入的
    `DatagramReceiver` 并等待 goroutine 收口。Linux daemon、长期
    `advanced sync serve` 与一次性 `sync once` 已改用该入口，后者不再用 100ms deadline 轮询；gossip
    中原 `StartPacketReceiver`、资源接口和重复测试已删除，旧轮询 helper 也已移出生产代码。
    本切口完成时 `gossip.Transport` 仍暂时负责 Linux UDP bind；E2b 已继续拆除该所有权。
  - [x] E2b：为 `gossip.Transport` 注入窄 `DatagramIO` capability，并删除其 `UDPConn`、`ListenAddr`、
    `gossip.Listen` 与 Linux socket option 实现。Transport 只保留 wire codec、allowlist、replay/quota、地址选择
    和发送规划；Linux bind、`SO_REUSEPORT`、read/write/deadline/close 由 `internal/photonlinux` adapter 实现，
    composition 创建后交给唯一 HostRuntime 生命周期。端口默认值仍由 app/config 决定，不下沉到协议或 adapter。
    协议测试使用测试注入 adapter，Linux adapter 单独验证 UDP round-trip 与端口复用。当前 TCP object-pull
    listener 仍由 `app/photon` 创建，daemon 中 controller/control/health 的剩余调度也尚未收口，不能把 E2b
    误记为全部 runtime I/O 已完成。
  - [x] E2c：将 TCP object-pull server 生命周期收归唯一 HostRuntime。Linux composition 只负责按实际 UDP
    endpoint 创建 `net.Listener` 并注入；Runtime 独占 accept loop、默认 16 连接上限、单连接 deadline、过载拒绝、
    context cancel、listener close 与 handler drain。daemon、`advanced sync serve`、`sync once` 和测试均已切换，
    `objectPullTCPServe`、app 私有 accept goroutine、全局 server limiter 与重复 listen-address helper 已删除。
    gossip 继续独占 length-prefixed msgpack request/response codec 与 `ServeObjectPull` 语义；outbound TCP dial、
    client quota/diagnostics 目前仍由 Linux worker 执行，后续切 capability 时不得再创建第二套 worker/event queue。
    daemon 中 controller/control/health 的剩余调度尚未收口，不能把 E2c 误记为整个 daemon runtime 已完成。
  - [x] E2d：删除 `app/photon/objectpull.go` 与 Linux 私有 outbound worker。公共 host executor 统一处理
    discovery/address policy、每 peer 并发、字节/对象 quota、请求构造、响应/目标 zone 校验、completion 和
    diagnostics 分类，并同时供在线 Runtime worker 与离线 recovery 复用；Linux adapter 只负责 context-aware TCP
    dial、连接 deadline 和一次 gossip stream exchange。daemon 只在 `daemon_sync.go` 注入 listener/client、从
    committed verified view 构造响应，在 `diagnostics.go` 消费可丢失观测结果。旧全局 client limiter、peer limiter、
    quota wrapper、timeout helper、worker adapter 和两套 offline/online pull 路径均已删除；HostRuntime 的 4 个有界
    worker 是唯一全局并发边界。
  - [x] E2e：daemon 的 sync 周期、endpoint 发布、IPsec reconcile、routing reconcile 和 firewall reconcile
    不再维护私有 deadline 集合或每轮创建 `time.Timer`；五类 deadline 使用独立 key 进入 HostRuntime 的同一 namespaced Scheduler，fire
    通过公共 event queue 回到 daemon single-writer 后才校验 generation 并执行。配置变化、dirty flush 和显式 sync
    trigger 都以 replace/cancel 方式更新同一 timer identity，禁用 controller 时取消对应 timer。VICI 订阅重试和
    health probe 自身的异步生命周期尚未迁入公共调度，不能据此把全部 controller runtime 标为完成。
  - [x] E2f：进入 F 前完成 `app/photon` 在线边界收口审计，不带着旧组合视图入口继续扩平台。当前已删除旧 catalog
    filter、单 snapshot commit wrapper、legacy rejected/observed 写 helper、aggregate Linux commit 和重复 snapshot
    codec/hash helper，并将测试改到公共 Store 与正式 gossip controller。transport 启动已不再接收 `stateFile`，
    daemon、`sync serve` 与 `sync once` 均在启动 receiver 前通过同一 HostRuntime discovery 从公共
    verified/checkpoint 恢复 known peer、endpoint 和 observed path，旧 SyncRuntime 恢复/校验/排序 helper 已删除。
    firewall 也已补齐 30 秒周期 safety reconcile：启用实例时调度，显式 reconcile 后替换同一 timer，禁用全部实例时取消。
    admission、旧 auto-join、revocation purge 与 metadata-only state helper 已删除，测试分别改走公共 authority、
    `Store.PurgeRevoked` 和正式 Linux runtime merge；production staticcheck 已无告警。旧 `_meta/cli_state` 到公共/Linux
    bucket 的迁移仍由 `loadAndMigrateLinuxState -> migrateLegacyRuntimeStateTx` 在启动事务内单向执行，属于必须保留的数据库迁移，
    不再把它误删成在线兼容层。最终复核覆盖全部 74 个非测试 Go 文件，production staticcheck 清零；迁移报告已
    区分永久 composition、待下沉 Linux controller/driver 和必须保留的数据库迁移，未发现测试保活或在线双路径 wrapper。
  - [x] E2g：继续把 Linux controller 的实际 observe/apply 边界从 daemon 下沉到唯一 `photonlinux.Runtime`，
    但不预建统一 `PlatformCapabilities`/Controller 接口；公共侧保留 desired policy、调度、事件顺序与 completion commit。
    - [x] firewall backend preflight/选择、netns alias 解析、nftables/iptables driver 构造及 owned observe/plan/apply
      已整组迁入 Linux runtime。daemon 只构造 verified-derived desired state 与 owner，消费 apply result 后提交
      Linux runtime summary；app 私有 driver 接口、重复 backend probe、netns helper 和 test override 均已删除。
    - [x] routing upstream 的 veth/netns 与 `ip addr/route replace` 执行已迁入 Linux runtime；daemon 只根据
      authorized route set 构造 veth 与 upstream route spec，不再持有 veth/route manager 或 Linux 命令实现。
    - [x] BIRD 配置文件写入、per-netns process manager、start/stop/status/exit observation 和 birdc
      configure/status/raw 已迁入 Linux runtime。daemon 保留 managed/external 决策、restart backoff 和 runtime
      summary 更新；原 BIRD manager map、client factory 与 app 私有接口均已删除，测试通过同一 runtime 注入。
    - [x] health 的 raw ICMP socket、per-netns setns worker 与 `ip netns exec ping` fallback 已从公共
      `pkg/health` 迁入 `internal/photonlinux/healthprobe`，由唯一 Linux runtime 初始化、注入并关闭；daemon
      只把平台 prober 交给公共 manager。旧公共构造入口和未实际接线、语义不可靠的 UDP write prober 已删除，
      实现级测试随 owner 迁移。target 组合、manager policy 和 completion 仍非平台执行，不能借 E2g 一并下沉。
  - [x] E2h：收口 health 剩余 runtime 边界：将一秒 probe tick/completion 唤醒接入公共 HostRuntime scheduler/queue，
    Linux link/IPsec runtime 到 ProbeTarget 的组合随 link output DTO 下沉；spool、observer/control 展示分别归各自 owner。
    不把 `health.Manager` 状态机塞入 Linux runtime，也不为过渡新增 daemon wrapper。
    - [x] daemon 私有 `time.Ticker` 与 `healthUpdates` select 已删除；一秒 probe tick 使用 HostRuntime namespaced timer，
      async worker completion 通过同一个 bounded HostRuntime queue 回到 single-writer loop。`health.Manager` 仍独占
      target/window/hysteresis 状态，Linux runtime 仍只注入实际 prober。
    - [x] `LinkOutput -> ProbeTarget` 的 staged/old role、probe ID、underlay family 与有效 tunnel address 规则已迁入
      `internal/photonlinux/linkstate`；daemon 只把现有 provider-neutral link outputs 交给该 owner，不再重复理解 rotate 细节。
    - [x] JSONL spool 的配置、并发写入、保留期裁剪和 series query 已整体迁入
      `internal/observability/healthspool`；Observer 直接查询该 owner，daemon 只把 health snapshot 转为 Sample。
      app 私有 `health_spool.go` 已删除，纯 spool 测试随实现迁移。
  - [x] E2i：完成推荐顺序中的旧 direct writer 收口。
    - [x] record、IPAM、route、service 与 delegation issue/grant/revoke 的 explicit `--direct` 路径均直接使用
      唯一 BoltStore 恢复出的 common Store typed intent；删除旧 `stateFile` 手工 record/delegation 签名、候选授权校验、
      peer cleanup 和测试保活入口。只读 show/list 的 `LoadState` 不在本项冒充 writer。
    - [x] fresh join accept 直接初始化 common/Linux bucket，不先写 legacy `stateFile` 再依赖下次启动迁移；首次 identity 先由公共 Store 完整验证，再在同一 Bolt 事务原子写入两个 bucket，避免崩溃留下半初始化数据库。
    - [x] `state_gc --direct` 只读/提交 Linux runtime owner，不再 `LoadState -> SaveState` 聚合状态；提交绑定当前 common verified revision，但不会推进该 revision。
  - [x] E2j：删除在线 daemon 对聚合 `stateFile` Snapshot 的依赖，再处理离线只读 CLI。
    - [x] 增加同一写入边界内直接克隆 common view 与 Linux runtime 的内部读取，返回两个真实 owner 而不构造第三套状态；
      IPsec cleanup、revoked purge、Endpoint ACL、state GC、IPsec error completion 与 Firewall completion 已改用该边界。
      同时删除仅服务聚合状态的 IPsec cleanup wrappers，join key 恢复与 recovery revocation 统计直接读取 common verified state。
    - [x] 将 IPsec、routing、firewall 主 reconcile planner 输入和 `publishLocalProtocols` 从聚合 Snapshot 改为明确的
      common verified/checkpoint 与 Linux runtime 输入；随后删除 daemon `currentState()` 以及仅剩 hook/composition 所需的完整 Snapshot。
      IPsec 主 reconcile 已完成：desired link、contact-point quality、peer cleanup/revocation、transport key、link instance、
      diagnostic prefix 与 completion commit 均直接读取各自 owner，主执行路径及其 planner helper 不再接收 `stateFile`。
      Routing 主 reconcile 也已完成：authorized routes/auto-announce 刷新只读取 common verified，BIRD instance、IPsec link output、
      rotation metric 与 completion 只读取和提交 Linux runtime；剩余聚合读取限于 control/debug 与 hook/composition。
      Firewall 主 reconcile 已完成：planner 直接接收 `VerifiedState` 与 `linuxRuntimeState`，删除不读取参数的
      `firewallCharonPorts` wrapper，并把端口 record 的时间显式作为输入，不再依赖可变全局测试时钟。
      `publishLocalProtocols` 也已完成：endpoint、IPsec key/port、routing/netns 与 admission 规划分别读取 verified
      和 Linux runtime owner，启动发布不再构造聚合 Snapshot；相关 helper 与测试同步改为 owner 参数。
      随后 sync/peer/zone/BIRD control read model、配置 reload、手动 IPsec port rotate 与 state-changed hook 也已切走，
      production `currentState()` 已删除；线上 daemon/controller/composition 不再调用聚合 `Snapshot()`，完整组合读取仅剩
      `state.go` 的离线 CLI/旧数据库读取入口，测试断言 helper 只存在于 `_test.go`。
    - [x] 只读 CLI 已改为 online-first：daemon 在线时由 zone/service/route/IPAM/peer/endpoint/health 等面向命令的 control read model
      读取 daemon 内存 owner 与实时观测，不打开 bbolt；socket 不可用时才由 `loadOfflineOwnerViews` 复用启动迁移并返回 detached
      common/Linux owner，不创建第三套 Store。links/firewall/BIRD/status/admission/revocation 等同样只在离线分支读盘；`debug rotate --direct` 改用与 daemon
      相同的 common typed intent + Linux runtime 提交。production `Runtime.LoadState` 目前只服务旧 schema 首次迁移引导，
      以及尚待改造的测试 fixture，不再是 CLI read path。
  - [x] E2k：收敛 inspect/query/transport/presenter，删除 online-first 切换中新增和既有的多层 View/DTO 换壳。
    - 目标调用链固定为 `common/Linux owners -> 唯一查询投影 -> canonical inspect DTO -> control/CLI/HTTP presenter`。
      control 只传输 canonical DTO，不拥有第二套业务 View；CLI text writer 与 HTTP encoder 只做协议包装、过滤、排序和格式化，
      不重新推导 peer lifecycle、health、route authorization 等语义。
    - [x] E2k1：引入按 control method 类型化的 canonical view envelope；zone/service/route/IPAM/endpoint 直接传输最终 inspect DTO，
      ping 传输 CLI 执行探测所需的 typed target plan；上述字段以及 records/sync/peer/zone debug DTO 已从巨型 `controlResponse` 删除。
      online/offline 复用同一查询函数，route/IPAM read model 已归入 `internal/inspect`，control 不再按资源重复定义响应结构。
    - [x] E2k2：收敛 status/peers/health/links/firewall/BIRD；daemon 一次读取 owner/observability 后生成最终 inspect DTO，
      CLI 不再把 `PeerStatusInfo`、health targets/live、link control wrapper 二次 Build 成另一层 View。
      - 查询源必须按语义区分：verified/common 权威状态允许 offline bbolt fallback；gossip checkpoint 只能明确标为
        `checkpoint/last-known`；本机 endpoint 候选、health live、BIRD live dump、Firewall/Link driver observation 等
        platform runtime 状态必须由在线 daemon 返回，daemon 离线时报告 unavailable，禁止把落盘 reconcile snapshot
        冒充当前运行时状态，也禁止 CLI 绕过 daemon 直接调用 platform driver/control socket。
      - endpoint 第一切口已完成：查询不再扫描接口或访问 reflector，也不新增重复 runtime snapshot；`endpoints_view`
        直接从 verified `sync/endpoint/*` record 投影实际对外发布的 endpoint，reflector 即时失败继续由发布日志诊断。
      - 已删除 links control/build 换壳和只供旧 debug 测试调用的 live-replan builder；Firewall/Babel 由 daemon 直接返回
        canonical inspect DTO；health/links/firewall/BIRD/ping/peer lifecycle 均要求在线 daemon，CLI 不再从 bbolt 冒充 live。
        gossip peer 离线 fallback 明确标为 checkpoint；status 分别报告 gossip/platform source，离线不展示 platform runtime。
        ping target 复用 `HealthProbeTargetView`，删除 app 私有 JSON DTO；BIRD raw query 和 rotate SA live query 均由 daemon 执行。
    - [x] E2k3：将 routes 的 canonical DTO 从 `internal/inspect/http` 移到 `internal/inspect`，CLI 不再依赖 HTTP 包；Observer HTTP
      仅保留稳定 JSON envelope。同步盘点 zones/peers/links/status 的 HTTP 专用重复结构，只保留确有 API 契约差异的投影。
      - [x] routes 类型/builder 已整体迁到 `internal/inspect`；CLI/control 直接使用 canonical DTO，HTTP 包只留保持既有 JSON
        schema 的类型别名。zones/peers/status 的排序、来源和聚合投影也已下沉到 `internal/inspect`，HTTP 包只保留稳定
        schema alias；links 因 REST 契约明确同时暴露扁平兼容字段与 `raw` canonical view，保留薄的 HTTP adapter，不重复规划状态。
    - [x] E2k4：逐项拆除巨型 `controlRequest/controlResponse` 的只读分支，删除单次 wrapper、重复排序/过滤、旧 builder 和失去调用者的 DTO；
      mutation/event 回包另行按命令类型收敛，不与只读迁移混做一次大提交。
      - 已删除 `links_status`、`firewall_status`、`bird_status`、`peers_status`、`routes_dump`、`revoke_status` 及其
        resource-specific response 字段/helper；BIRD dump 和 revocation impact 也已直接使用 canonical envelope。
      - `record_get`、`admission_status` 与 `endpoint_acl_list` 已改为直接传输 typed view，删除巨型
        `controlResponse` 中的 Record/Admission/EndpointACLs 字段以及只为这些字段附加 metadata 的重复回包逻辑。
      - 已删除混合在线探测、root key 与 link summary 的旧 `status` 回包：Observer 与 control 的 operational status
        复用唯一 `DaemonStatusView` 投影，root key 使用独立 `root_public_key` typed view；旧 status metadata/resource 字段和
        `applyStateStoreMeta` 随之删除。
      - `verify_chain` 成功结果也改用 typed bool view；至此只读 control 分支全部退出 mutation `controlResponse`，后者只剩
        admin mutation/action 的 ack 与结果，后续按命令类型拆分时不再与 query DTO 迁移混做。
    - [x] 每个子阶段独立提交并运行 `make check`；回归测试确认 daemon 独占 Bolt handle、第二个 handle 超时时，CLI control 查询仍成功；
      daemon 关闭后 offline fallback 生成逐字段相同的 Zone canonical DTO；control、CLI presenter 与 Observer HTTP 对同一 owner fixture
      保持 Zone path、record/delegation/revocation count 和 revoked 语义一致。
- [ ] F：Photon Windows composition root 直接创建唯一 HostRuntime、公共 Store/BoltStore 和 Windows platform
  runtime；memory transport 双节点直接验证 common runtime 后再连接真实 Windows UDP；
  断言 Linux/Windows 对相同 snapshot、reject reason、revision、catalog 和 bbolt reload 得到逐字节等价结果。
  - [x] F0a：保留已经验证的状态恢复行为并调整 owner/包位置：`internal/photonwindows.StateStore` 不再调用
    `zone.OpenBoltStore/LoadNetwork`、逐 Zone 重放或把 revision 固定为 1；改为独占打开公共
    `state.BoltStore`、`LoadCommon`、`RestoreStore`，并校验配置中的 managed zone/root pin 与磁盘 root 一致。
  - [x] F0b：撤回 `photonclient.Runtime -> host.Runtime` 套层、通用 `Resources.Validate` 和 client gossip controller。
    `internal/photonclient` 不拥有 common runtime、公共 Store 或产品 lifecycle；未来只承载真实用户态 packet data plane。
  - [x] F0c：memory 双节点实验已改为直接围绕两个 HostRuntime、两个独立公共 BoltStore 和真实 gossip Transport，
    通过 Ping/Pong、catalog diff 与公共 object-pull executor 收敛，不借助第二个 client runtime 或
    `RequestZoneSnapshot` 测试入口；覆盖 snapshot/reject reason、catalog、revision、关闭重开和 common bucket 字节
    等价，错误 root 不推进 verified revision。
  - [x] F0d：`app/photon` 的 CLI/config/root smoke 留在 Linux composition；只有出现 Linux/Windows 真实共同调用点时
    才迁移 typed command/client helper。测试随被测 owner 迁移，不以减少 `app/photon` 文件数作为 F 的前置工作。
  - [ ] F0e：在连接 Windows UDP 前完成唯一 HostRuntime 的公共 gossip 执行闭环；保持平台 composition 创建 UDP
    `DatagramIO`、TCP listener/dialer，HostRuntime 独占 receive/accept/worker/event queue 生命周期，gossip 独占 wire
    codec、验证和 FSM。不得把平台 bind 下沉进 HostRuntime，也不得在 Windows 复制 Linux daemon executor。
    - [x] F0e1：把 common Store 作为 HostRuntime 的显式真实依赖；先收回 verified/checkpoint read projection 与 remote
      snapshot transaction，逐项缩小 `daemonGossipActionController`，不新增 `photonclient.Runtime`、capability bag 或第二条
      event queue。
      - [x] F0e1a：HostRuntime 构造时显式接收唯一 `GossipStateStore` 和固定的 peer/limits 配置，直接从 Store 生成
        verified catalog view，并在公共 executor 内完成 managed-zone guard、remote batch、apply 后重读和
        `SnapshotAppliedEvent` 回投。Linux 删除 `syncSnapshotApply/applySyncSnapshotBatch` 与 controller 的 state/apply
        capability；Windows memory 双节点也删除等价 state/apply glue，二者都直接使用同一个 Store transaction。
      - [x] F0e1b：discovery/address book 规划、catalog filter、UDP fetch-zone/chunk fallback 与 TCP object-pull responder
        已统一从 HostRuntime 绑定的同一 Store 读取；删除 daemon 的 `currentGossipDiscoveryInput/buildGossipDiscoveryInput`
        公共状态投影和 controller catalog-filter 回调。固定 bootstrap/endpoint policy 在 HostRuntime 构造时注入，Linux
        只叠加正在 cleanup 的 peer suppression，并继续负责创建 socket、选择 reply address 与记录平台观测；checkpoint
        先提交后发布 address book 的顺序不变。
    - [x] F0e2：HostRuntime 已直接执行 backoff、session completion、summary-match、认证 observed path、chunk reject 与 relay
      checkpoint mutation；同一个 FSM event 按 backoff 后 completion 的顺序生成最小字段 patch，并只提交一次 checkpoint
      transaction，不覆盖 discovery/reject 等无关字段且不推进 `VerifiedRevision`。object-pull worker completion 继续回投唯一
      HostRuntime queue，并由同一事件路径完成 checkpoint；删除 Linux `syncPeerStateMutationBatch`、controller persistence/backoff
      capability，以及已经失去语义的 `SaveStateAction/SyncPersistenceScope`。
    - [ ] F0e3：由 HostRuntime 统一消费 packet、gossip timer 和 object-pull completion，删除 Linux daemon 的公共 event/action
      dispatch；平台仅保留 socket 构造、日志/metrics hook 和 verified ChangeSet 触发的平台 reconcile。
      - [x] F0e3a：新增唯一 `HandleGossipHostEvent` 消费入口，packet 直接进入 inbound planner，gossip timer 与
        object-pull completion 统一进入 session FSM。daemon、`sync serve`、`sync once` 和 Windows memory 双节点均已删除
        自己的 packet/event type switch；旧 `daemonEventPacket` 及其单次转发也已删除。平台只读取 detached result 做日志、
        observability 和后续 reconcile，不再决定公共事件走哪条协议路径。
      - [x] F0e3b：把 announce hint、fetch-zone/chunk responder 和 chunk/NACK 的剩余公共执行从
        `daemonGossipIO` 收进 HostRuntime；reply address 作为本次 ingress 的临时发送上下文，不持久化也不交给
        平台重新解释协议 action。object chunk assembly、repair schedule、snapshot decode/root check、reject checkpoint 与 completion
        回投已经整体迁入 HostRuntime，`daemon_object_chunk.go` 已删除。sent-chunk cache、fetch-zone announce/chunk responder 与
        NACK repair 也已迁入每个 HostRuntime 实例：删除进程级 `udpSentChunkCache`、daemon fetch responder 及
        `SyncRuntime.handleObjectChunkNACKFrom`，平台只执行本次 ingress reply route 下的实际发送；公共 diagnostics 由 HostRuntime 直接记录。
        announce hint 的 active-session 判重、defer、session 创建、初始事件排队及 follow-up 启动也已迁入 HostRuntime；删除
        daemon `handleAnnounceHint/startHintedSyncSession`。common `PeerObservabilityStore` 从 `internal/observability` 移到
        `pkg/core/observability` 并由每个 HostRuntime 唯一持有，catalog/fetch/chunk/NACK/session/object-pull 统计在事件发生处
        直接更新；删除 `ObserveGossipCatalog*`、`ObserveGossipFetchZone`、`ObserveGossipChunkNACK`、
        `ObserveGossipObjectChunk`、`ObserveGossipSnapshot`、object-pull `ObserveAttempt/ObserveResult` 等只为绕回 daemon
        记账或日志存在的 effect/callback、DTO 和 `app/photon/diagnostics.go`。`SyncRuntime.Observability` 与
        `DaemonService.PeerObservability` 两个重复 owner 字段也已删除。
        gossip effect failure、event drop、session protocol error 与状态转换日志已先收回 HostRuntime；composition 仅在构造时
        注入统一 logger，不再通过 `ReportGossipIssue` 逐事件接收并重新解释日志。下一步同时把当前公开的
        `ExecuteGossipInbound`/`HandleGossipEvent` 两段改成 HostRuntime 内部 packet dispatch/session FSM dispatch，删除容易误解为
        两套 event loop 的 `InboundController/EventController` 边界。
        该 API 收口已开始：`ExecuteGossipInbound` 已变为私有 `executeGossipPacketActions`，`HandleGossipEvent` 已变为私有
        `handleGossipSessionEvent`，平台生产代码与 app 测试均只进入 `HandleGossipHostEvent`；旧的 packet/session controller
        已删除；packet failure 也已由 HostRuntime 记录，`GossipHostEventResult` 不再暴露原始 packet 或原始
        session event 给 daemon/`sync serve` 二次解释和输出日志。
      - [x] F0e3c：session 完成后的 timer cancel、累计 NetworkChanged、remove、pending-hint follow-up、relay fanout/
        checkpoint/observability 已收回 HostRuntime；删除 daemon `completeSyncSessionAfterPeerState`、`relaySyncToPeers` 及其观测
        helper，relay 测试迁到公共 host。daemon 现在只根据 detached terminal result 触发 Linux reconcile 和记录地址失败，
        不再读回或修改公共 session。入站 source 的 verified guard、checkpoint commit、观测来源和 commit 后 observed path 发布
        也已收回 HostRuntime；公共 Transport 自己保留一分钟的 recent-inbound live path，供 NAT 后续会话包优先原路发送，且不落盘。
        原 daemon checkpoint/seed/reply-route wrapper 已删除。
    - [x] F0e4：删除 `daemonGossipIO`、独立 address-book interface、daemon ingress-route map/send/budget 转发和 Windows memory
      test 等价 I/O glue。Linux/Windows composition 现在用 `StartGossipTransport` 把同一个公共 `gossip.Transport` 直接交给
      HostRuntime；Runtime 直接使用其 Send/SendTo、datagram budget 和可重建 address book，平台只创建底层 DatagramIO。
      通用 receiver capability 已改为 HostRuntime 私有实现细节，不再形成第二条公开 transport 边界。
    - [ ] F0e5：做一次“迁移只做加法”反向审计：生产代码中每个 `stateFile`/`DaemonStateStore.Snapshot`、单次 wrapper 和
      legacy alias 都必须列出真实调用方。只被测试构造器使用的兼容入口直接删除；仍串联 common commit 与 Linux runtime
      持久化顺序的方法保留到调用方改用 typed owner，期间不得新增 aggregate view。
      - [x] F0e5a：HostRuntime 直接持有 `*corestate.Store`，删除 `DaemonStateStore` 的 remote-batch/checkpoint/ReadView/
        ZoneDigests 转发和仅供旧 projection 构造的公开 constructor。platform-first protocol publish 改用 common Store 的
        expected-revision intent commit；gossip 若在两步之间推进 verified revision，旧平台计划 fail closed 并交给下一轮 reconcile。
      - [ ] F0e5b：迁走剩余 production `stateFile` 输入并批量改写依赖 `DaemonStateStore.Snapshot()` 的测试 fixture，随后删除
        aggregate Snapshot/clone、legacy alias 和没有多调用方价值的 runtime commit wrapper；同步更新 runtime migration report。
        - [x] 49 处测试读取已改为 test-only `snapshotTestDaemonState`，生产 `DaemonStateStore.Snapshot()` 已删除；测试需要的
          aggregate shape 不再迫使生产类型暴露 Snapshot API。
        - [x] aggregate `cloneStateFile` 已移入 test-only helper；生产 `state_clone.go` 只保留各 typed Linux runtime 字段的 clone。
          无调用方的 `stateFile` RLock/WithLock convenience API 已删除；最后只用于证明 constructor input 已 detached 的
          `Lock/Unlock` 与 mutex 也已移入 `_test.go`，生产 migration DTO 不再为了测试并发断言携带锁。
        - [x] 删除只做 nil guard 和单次转发的 `daemon_runtime_commit.go`；routing/IPsec/firewall/cleanup 调用方直接进入
          `DaemonStateStore` 当前的 typed runtime commit，后续随 Linux runtime owner 一起下沉。
        - [x] 删除 production 中只被测试调用的 aggregate helper：`autoJoinPending(stateFile)`、旧 `CleanupRevokedPeerCache`、
          `CollectAllRevokedZones(stateFile)` 和 record signing helper；测试直接使用 verified/network typed helper，签名 fixture 移入
          test-only helper。实际 revoked checkpoint 清理由在线 typed owner 路径及其测试覆盖。
        - [x] `loadState()`、`Runtime.SyncConfig(stateFile)` 已移到 test-only helper，零调用的
          `Runtime.ConfigureNetworkValidation` 删除；随后确认旧数据库已由首次 `loadAndRestoreLinuxState` 直接迁移，生产
          `Runtime.LoadState/loadPartitionedState/applyConfiguredIdentityOverlay` 也已整体移到 `_test.go`，启动不再重建 aggregate view。
        - [x] `init root` 直接原子初始化 common/Linux buckets，不再先写 legacy aggregate schema 等待下次 daemon 启动迁移；
          `Runtime.SaveState(stateFile)` 因此移到 test-only helper。旧 schema 读取/迁移仍保留。
        - [ ] 配置驱动的 pending auto-join 仍是唯一 production legacy writer：此时 managed zone authority 尚未同步，不能通过
          正式 common `ValidateStateRoot`。当前已缩成直接写 root-only Network 与 identity meta 的最小 writer，不再先构造或返回
          `stateFile`；待 state/admission 定义独立的 pending identity root 后改为新 schema，不能通过放宽 verified 校验来删除。
          通用 `saveStateAt/stateMetaFromState` 已移到测试。
        - [ ] 继续按 planner/inspect/offline migration 三组迁走 production `stateFile` 参数；全部调用方消失后删除 aggregate clone。
          production `cloneLinuxRuntimeState` 已改为直接复制 typed runtime，不再绕行
          `runtime -> stateFile -> runtime`；`composeLinuxStateView/applyLinuxRuntimeReadView` 已降为纯测试 fixture。
        - [ ] 清理测试侧 aggregate 债务：`daemon_test_helpers_test.go` 已膨胀到 1500 行，且普通 daemon 测试仍通过
          `stateFile` 构造 common/Linux owners。先增加直接接收 `VerifiedState + GossipCheckpoint + linuxRuntimeState` 的
          typed-owner fixture，并迁移 daemon lifecycle 基础测试；随后按 gossip、reconcile、root-smoke 拆分 helper 与调用方，
          最终只允许 legacy migration 测试使用 `LoadState/SaveState/cloneStateFile/stateMetaFromState`。
          - 第一批已建立 owner-first `buildTestDaemonOwners`，旧 `buildTestNetworkState` 只作为待迁调用方的反向组合 wrapper；
            daemon lifecycle、control common view、links/status、packet checkpoint 与 Observer snapshot 测试已直接准备 typed owners。
            原先通过锁住 constructor `stateFile` 验证 detached 的两组 read 测试，改为直接修改构造输入并断言 Store 的 owner clone
            不受影响；packet 测试直接断言 GossipCheckpoint，不再拼回 aggregate snapshot。
          - 第二批开始清理 `daemon_events_test.go`：删除重复的 constructor-lock record 测试，record/event-loop/endpoint 发布直接
            断言 common owner，IPsec port rotate 直接断言 Linux runtime owner；delegation issue 改用真实 persisted owner Store，
            关闭重开后验证 delegation，而不是把内存 aggregate snapshot 误称为“已持久化”。该文件已不再调用 `stateFile.Lock`。
          - gossip/sync 测试按被测 owner 重新归档：catalog summary 的 session/observability 覆盖已从 app daemon 迁到
            `pkg/core/host/gossip_event_test.go`；app 中 catalog/fetch responder、chunk fallback 和 invalid chunk reject 的重复测试删除，
            由 `pkg/core/host/gossip_inbound_test.go`、`gossip_chunk_test.go` 负责。app 只保留 HostRuntime 结果触发 Linux reconcile/
            state-changed hook 的薄集成覆盖。`sync_actions_test.go` 与 test-only `executeSyncActions`/sender wrapper 已删除：remote batch
            的 success/reject/no-op/checkpoint-only/managed-authority 原子语义归入 `pkg/core/state`，未验证 peer 的入站地址回复归入
            `pkg/core/host`；启动 authority 恢复与 chunk commit 后的平台通知分别保留为窄 app 集成测试。下一批继续审计
            `sync_transport_discovery_test.go`：verified/delegated peer admission、远端 endpoint 排序/替换/过期、checkpoint patch 与
            address-book publication 已迁入 `pkg/core/host/gossip_discovery_test.go`，旧 app 混合测试文件已删除。app 仅保留 transport
            replay/quota/logger 构造注入，以及仍直接读取 `syncConfigFile` 的本机 endpoint publish policy；后者在公共 config 边界确定前
            不额外创建 adapter。`sync_path_test.go` 的 observed path input-detach、outbound/expiry 与 preference 覆盖也已迁入 HostRuntime。
            `daemon_sync_test.go` 已从 10 个测试收敛为两个 app 组合验收：Linux daemon 双节点 UDP/TCP object-pull/event-pump 闭环，
            以及 daemon 周期 bootstrap 在公共事件队列已满时的 fallback。read-only responder、announce hint/defer、ping summary
            shortcut/mismatch、checkpoint/backoff 与 observability 均由 `pkg/core/host` 直接绑定 Store/Transport 验证。下一批审计
            `sync_mtu_test.go` 和剩余 `sync_endpoint_publish_test.go`：前者确认与 `pkg/core/gossip/datagram_test.go`、`catalog_test.go`
            完全重复后已删除；endpoint publish 已按真实边界拆开：app `SyncRuntime` 只从配置选择/采集本机候选地址并记录 reflector
            错误，`pkg/core/host.PlanGossipEndpointIntent` 统一负责 identity admission、record grace/refresh/clear/no-op 和 typed protocol
            intent，公共语义测试已下沉，app 仅保留采集结果接线测试。sync debug/status 中重复验证 inspect DTO 字段映射的测试也已删除，
            offline checkpoint 不冒充 ephemeral diagnostics、unknown peer 和 zone 排序的 app 边界测试保留。
- [x] 按 2026-08-29 架构审计更新 `docs/photon-windows/design.md`：明确 HostRuntime 是唯一 common runtime、
  composition root 持有 Store/平台 runtime、photonclient 只负责未来用户态数据面；撤回迁移报告中提前宣称进入 F、
  client runtime 已定型及下一步直接接 Windows UDP 的文字。代码纠偏和双节点验收完成前不得开始 Windows 专属分支。

- [ ] 从 verified records 生成 gateway candidate：同时满足 identity/key、address/port、
  overlay/path/tunnel address compatibility 和本地 selector；撤销或任一 record 不完整时
  立即失效，不沿用陈旧 endpoint/key 无限重试。
- [ ] 复用 `BuildAuthorizedRouteSet` 并包成窄 `RouteAuthorizer`。Babel install/replace 前
  检查 source/destination、origin/zone binding、assignment 与 announcement；authorization
  变化必须反向清扫已经安装的 SADR entry，不能只影响新 update。
- [ ] 私钥沿用 Photon 的管理员责任模型：root/Zone identity/transport raw key material 可直接存入 Windows
  公共 bbolt BoltStore，不强制 DPAPI/CNG/non-exportable key。安装器可设置合理 ACL，但本项目不宣称抵御
  已取得 Administrators/SYSTEM 权限的本机攻击者；仍禁止通过日志、IPC、Observer 或 gossip 输出私钥。
- [ ] 持久化只保存重启恢复所需状态：verified Zone store、identity private key、Babel
  originate seqno、schema/version 和必要 endpoint hints；SA traffic keys、临时 DH secret、
  UDP session 和 raw decrypted packet 不落盘。

### 10.4 用户态 IKEv2 initiator

- [ ] 先写 `docs/photon-windows/ranet-lite-port-map.md`，逐文件标明 ranet-lite IKE
  parser/crypto/state machine 是“独立重写、带 MIT notice 移植、暂不采用”中的哪一种；
  不直接 import upstream `internal/ike`，也不为此强行把主 module 升到 Go 1.26。
- [ ] 将 codec/parser 与会话状态机拆开：header/payload/SA proposal/SK/AUTH/NAT-T 可做
  deterministic unit/fuzz；随机数、时钟、UDP 和 peer identity 可注入，私钥从 Store 的 detached transaction
  candidate 读取并使用公共 Ed25519 实现。
- [ ] 实现 initiator-only `IKE_SA_INIT -> IKE_AUTH -> CHILD_SA`，强制验证 responder
  identity 与 verified `ipsec/transport-key`；拒绝 unknown critical payload、downgrade、
  proposal mismatch、错误 SPI/message ID、重复/越序 response 和未验证 AUTH。
- [ ] 与 Photon StrongSwan responder 对齐 ID encoding、raw Ed25519 RFC 7427/8420、
  traffic selector、NAT-T non-ESP marker、custom remote port、encap、DPD 和 delete 行为；
  建立固定 StrongSwan config/pcap/日志脱敏互操作 fixture。
- [ ] 实现 CHILD_SA rekey、IKE SA rekey、新旧 inbound SA overlap、simultaneous rekey
  collision 和 delete；失败指数退避带 jitter，sequence 即将耗尽时必须提前 rekey，不能
  允许 32-bit ESP sequence wrap。
- [ ] v1 网络变化时取消旧会话、rebind 共享 UDP、重新选择 verified endpoint 并全量重连；
  暂不实现 MOBIKE，但必须避免旧 receive loop/SA 在新网络继续接收或写 Wintun。
- [ ] parser/状态机测试覆盖 RFC vectors、malformed length、duplicate payload、unknown
  critical、AUTH failure、replay、timeout、loss/dup/reorder、rekey collision 和 context
  cancellation；fuzz corpus 不含真实 key/packet capture。

### 10.5 用户态 ESP 与共享 UDP Hub

- [ ] ESP 同样先完成 port map/license 决策；AES-GCM/ChaCha20-Poly1305 使用 Go 标准库或
  `x/crypto`，不自写 primitive。SA API 必须区分 inbound/outbound ownership，并支持 rekey
  overlap 后确定性回收旧 SA。
- [ ] 实现 tunnel-mode IPv4/IPv6 encap/decap，严格验证 SPI、sequence、AEAD tag、padding、
  Next Header、IPv4 header/total length 和 IPv6 payload length；任何失败只增加有界分类
  计数，不把原始密文/明文写日志。
- [ ] anti-replay window 默认与 StrongSwan peer profile 对齐，使用并发安全 bitmap/sliding
  window；测试 window 边界、duplicate、too-old、large jump、并发 receive 和 disabled
  配置。生产配置不得无提示关闭 replay protection。
- [ ] 一个共享 UDP socket 承载所有候选 peer；IKE 按 initiator SPI、ESP 按 inbound SPI
  demux。注册/替换/注销必须原子，未知 SPI、零 SPI、短包和 channel 满不得阻塞全 hub。
- [ ] Windows UDP adapter 使用阻塞或 IOCP/event-driven receive，不做 100ms polling；
  支持 IPv4/IPv6 endpoint、socket buffer、context cancellation 和网络变化 rebind。v1 不为
  每 peer 创建独立 socket/ticker。
- [ ] 明确 UDP send batch 在 Windows 不可用时的退化路径；先保证正确性与有界队列，再
  优化 `WSASendMsg`/RIO/IOCP。增加 loss/dup/reorder/delay/MTU black-hole network simulator。
- [ ] metrics 至少包含包/字节、auth/replay/padding/length drop、unknown SPI、queue drop、
  rekey、reconnect 和当前 endpoint；label 不使用 raw IP、Zone、SPI 或错误字符串造成高基数。

### 10.6 Babel leaf、SADR 与 route authorization

- [ ] 移植/重写标准 Babel wire codec：Hello、IHU、Update、AckReq/Ack、Route Request、
  Seqno Request、RTT extension 和 source-specific update；codec 与 speaker 分离并加入 RFC
  vector、unknown TLV、sub-TLV、truncation 和 fuzz 测试。
- [ ] speaker 只 originate 本节点被 Photon 授权的 prefix；永不把 learned route
  re-advertise 给另一 peer，永不声称 transit。控制包构造成内层 IPv6 link-local UDP/6696
  后直接走指定 ESP peer，不依赖 Windows multicast、scope route 或外部 babeld/BIRD。
- [ ] Router ID 从 root trust hash + managed Zone + overlay/path label 稳定派生，并持久化
  originate seqno。先完成与 Photon/BIRD 所用 Babel Router ID 表示的映射设计，再启用多
  origin route authorization；随机 Router ID 只允许测试 fixture。
- [ ] 实现 per-peer neighbor state、Hello/IHU expiry、RTT cost、triggered update、route
  selection 和 peer-down 立即撤回；desktop 初始 interval 与 Photon BIRD peer profile 显式
  对齐，不直接继承 ranet-lite 或现有 BIRD 的默认值。
- [ ] SADR lookup 规则固定为 destination longest match 优先、相同 destination specificity
  下 source longest match；equal metric/seqno/Router ID tie-break 必须 deterministic。
  route table update 与 packet lookup 并发安全，snapshot 不泄漏可变内部指针。
- [ ] route install 的唯一入口顺序为 decode/neighbor validation -> Babel selection ->
  Photon authorization -> SADR commit；authorization 拒绝、撤销、neighbor down、peer SA down
  都要删除已选 route，不能依赖下一次 periodic expiry。
- [ ] memory pipeline 端到端覆盖：两个 gateway 候选、route metric 切换、source-specific
  prefix、unauthorized update、revocation、route expiry、peer loss 和并发 TUN traffic；确认
  leaf 不会反射或重宣告 learned route。

### 10.7 Windows 平台层

- [ ] Wintun adapter 直接使用固定版本官方 API/binding：load signed DLL、create/open
  adapter、start session、receive/release packet、allocate/send packet、end session、close
  adapter。区分“本次创建”和“既有 adopt”，只删除本 service 明确拥有且 generation 匹配的
  adapter。
- [ ] 设计 Wintun ring capacity、read cancellation 和 shutdown；receive packet 必须及时
  release，send allocation 失败要形成 backpressure/drop counter，service stop 不得卡死在
  blocking receive。真实 Windows 测试覆盖 adapter 已存在、残留 session、DLL 缺失/签名
  错误和驱动升级。
- [ ] 用 IP Helper API 管理 address/route/interface metric，不 shell out 到 `netsh`、
  PowerShell 或 `route.exe`。通过 adapter LUID/index 精确定位，记录 owned address/route 的
  key 与 generation，adopt 前做 substantive equality，cleanup 不删除管理员或其他 VPN 的
  资源。
- [ ] route apply 使用 `Observe -> Plan -> Apply -> Re-observe`；启动中途失败要回滚本次
  owned 资源，service crash 后下次启动可 adopt/repair，外部删除后 periodic safety
  reconcile 可恢复。split aggregate 变更和撤销必须按 deny-first 顺序先收紧 route/packet
  admission，再建立新 SA/放宽。
- [ ] 使用 `x/sys/windows/svc` 接入 SCM，正确处理 Start/Stop/Shutdown/Preshutdown 和
  interrogate；启动 pending/checkpoint/wait hint 合法，只有 Wintun、route、UDP 和 core
  ready 后报告 Running。stop 有硬 deadline，超时记录未完成层但不能无限阻塞系统关机。
- [ ] 提供 `run --console` 复用同一 runtime，Ctrl-C/console close 只由 Windows build file
  处理。service 与 console 不能同时拥有同一个 state/adapter；用命名 mutex/文件锁明确
  单实例。
- [ ] 网络变化通过 Windows Network List/IP Helper notification 进入 `NetworkObserver`，
  事件去抖后触发 endpoint 重选、UDP rebind、IKE reconnect 和 MTU 重算；不能靠固定短
  interval polling default route。
- [ ] Windows Event Log 采用结构化 event ID/severity，敏感字段统一脱敏；debug 文件日志
  必须显式 opt-in、ACL 收紧并有大小/保留上限。崩溃报告不得包含 key、packet plaintext
  或完整配置。

### 10.8 本地控制面与可观测性

- [ ] service 暴露 versioned named-pipe IPC，不开放默认 TCP listener。pipe ACL 默认仅
  SYSTEM/Administrators 可写；普通交互用户是否可只读查询需单独授权设计，不能使用
  Everyone/Authenticated Users 全写权限。
- [ ] 首版 IPC/CLI 方法：`status`、`peers`、`routes`、`diagnostics`、`reload`、
  `service install/start/stop/uninstall`。所有 mutation 必须由 service single writer 执行；
  CLI socket/pipe 不可用时 fail closed，不直接编辑 live state。
- [ ] status 至少展示 service/core/Wintun/UDP/IKE/CHILD_SA/Babel/trust state 的分层状态、
  verified state revision、adapter LUID/name、MTU、active gateway、最近重连原因和 route
  数量；不得只给一个含义模糊的 connected 布尔值。
- [ ] `config validate` 和只读 offline diagnostics 可以不启动 service；涉及 identity/key 的
  输出只显示算法、fingerprint 和 storage backend，不显示私钥或完整 AUTH material。
- [ ] reload 先 parse/verify/plan，验证失败保持旧 runtime；需要替换 Wintun address/route/
  gateway 的变更使用 generation 和可回滚 cutover，不先拆掉可用路径再发现新配置非法。
- [ ] metrics/diagnostics 使用有界、低基数字段；named pipe request 有大小、并发、deadline
  和 method allowlist，畸形请求不能拖住 packet/SCM loop。

### 10.9 Windows vertical slice 与互操作验收

- [ ] 建立一台 Windows VM + 一台 Linux Photon gateway 的可重复 test rig。Linux 端运行
  Photon StrongSwan/BIRD，Windows 端安装固定 Wintun；fixture 使用临时 root/Zone/key，绝不
  接触生产 mesh。
- [ ] 第一里程碑：service 启动 -> Wintun ready -> split aggregate/address 可见 -> shared
  UDP bind -> verified gateway selected；此阶段允许 IKE/ESP fake，但 restart/adopt/cleanup
  必须真实验证。
- [ ] 第二里程碑：真实 IKE_AUTH/CHILD_SA 与 StrongSwan 建立，双向用户态 ESP 承载 IPv4
  和 IPv6 tunnel ping；断言 AUTH、proposal、SPI、selector、NAT-T/custom port 和 MTU。
- [ ] 第三里程碑：Windows 内嵌 Babel 与 gateway BIRD 建邻，授权 IPv4/IPv6/SADR route
  能选路；伪造未授权 prefix、错误 Router ID/origin、撤销 record 后不得继续转发。
- [ ] 第四里程碑：CHILD/IKE rekey、packet loss/dup/reorder、sequence/replay、gateway
  restart、Windows service restart、Wi-Fi/Ethernet 切换、sleep/resume、adapter/route 外部
  删除和 abrupt process kill 后均能有界恢复。
- [ ] teardown 验收：normal stop/uninstall 删除本产品 owned route/address/session/adapter；
  保留管理员预建或其他产品资源。kill/crash 后下次启动可识别残留并 adopt/repair；无法
  判断 ownership 时保守保留并给出诊断，不能误删。
- [ ] 建立 throughput/CPU/memory 基线：小包 PPS、单流/多流吞吐、加密 worker、Wintun
  ring、UDP queue、idle CPU、working set；先记录真实基线再定门槛，不用 ranet-lite Linux
  数字替代 Windows 测量。

### 10.10 安全、测试、CI 与发布门槛

- [ ] portable 单测在 Linux/Windows 都运行；每次提交至少执行 `go test ./...`、关键包
  `-race`（Windows runner）、`go vet`、`GOOS=windows GOARCH=amd64` 完整编译和依赖图
  Linux-only import guard。
- [ ] IKE/ESP/Babel/IP parser 持续 fuzz；corpus 覆盖 malformed/truncated/oversized packet、
  unknown critical payload、SPI spoof、replay、padding、inner IP、route TLV 和 decoder
  allocation bomb。每个入口先做长度/数量上限再分配。
- [ ] crypto/state tests 覆盖 RFC/IANA vectors、nonce/IV uniqueness、sequence exhaustion、
  anti-replay、AUTH mismatch、rekey overlap/collision 和 zeroization best effort；进入生产前做
  独立协议/密码学安全审计。
- [ ] Windows integration CI 使用隔离 runner/VM；需要管理员/driver 的测试显式分层，普通
  PR 不静默跳过后报告成功。保存脱敏日志、state transition 和 pcap metadata，失败 artifact
  不含 key/plaintext。
- [ ] 发布先做开发 ZIP/manifest，再做签名 installer。installer 必须校验管理员权限、
  Windows/arch、Wintun version/hash、配置迁移和正在运行的 service；升级可回滚，卸载需
  询问是否保留 identity/config，不能默认删除不可恢复身份。
- [ ] EXE、DLL、driver/installer 全部 Authenticode 签名并生成 SHA-256 checksum/SBOM；构建
  锁定 Go/module/Wintun 版本，可从 clean checkout 重现。auto-update 在签名、回滚与 service
  事务升级设计完成前保持关闭。
- [ ] production gate：真实 StrongSwan/BIRD 互操作矩阵、72h soak、sleep/resume 与网络切换、
  crash/restart、route/DNS leak 检查、revocation fail-closed、外部安全审计全部通过；否则
  明确标记 prototype/experimental。

### Photon Android（后续独立项目，当前不实施）

- [ ] Windows vertical slice 稳定后，另开 `app/photon-android` 与 Android 专属设计，不把
  Windows service/Wintun/IP Helper adapter 复制进 Android。
- [ ] Android 必须由 Kotlin `VpnService` 拥有授权、TUN FD、protected UDP socket、
  foreground/always-on、underlying network 和 lifecycle，再向 portable core 注入资源。
- [ ] Android 开工即建立 no-VPN/native IKE/current core 的功耗基线，测 CPU/timer wakeup、
  WLAN/cellular active time、Doze、Wi-Fi/cellular handoff、app kill/reboot/upgrade/revoke；
  Windows desktop interval 不得直接作为 Android 默认值。
- [ ] Android 低功耗必须采用 event-driven receive、统一 deadline heap、一个 active gateway、
  timer coalescing、1-2 个 crypto worker 和 gateway-side mobile Babel/DPD profile；具体门槛由
  真机 prototype 数据决定。

## Phase 7: 生产化收口与高级能力候选

**目标：** 先把 daemon/control/运维面补到可长期运行，再按真实需求推进异构 TransportLink 并行、可靠性补强和可选传输能力。Phase 7 不要求按编号顺序执行。

**当前建议顺序：**
1. Phase 7 的 7.11.8/7.11.9 已完成主要实现与真实节点复测；保留尚未实施的常驻 DB handle、rtnetlink 等长期候选，不阻塞新主线。
2. 当前工程优先级转到 Phase 10 Photon Windows；7.7/7.8 discovery/relay 或 7.11 metrics/readmodel 等待明确需求后再开。
3. 7.2 高频 port hopping、7.4 WireGuard、7.5 GRE/VXLAN、7.6 SRv6 继续保持可选，不与 Photon Windows 的用户态 IKEv2/ESP vertical slice 混做。

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
  - [x] **Health burst 按包统计与链路状态精度**：`ProbeResult`、rolling window、状态机、CLI/Observer、spool 与 OpenMetrics 已改为累计真实 sent/received/lost；RTT 明确定义为每个 burst 最后一个成功回复的 RTT，部分回复保留 RTT，jitter 按时间序相邻 replied burst 计算。`loss_window`、连续失败、冷启动 down 门槛与恢复迟滞仍按 burst 计数，仅 loss threshold 改用包级比例，以保持生产告警灵敏度。单测覆盖 `3/3`、`2/3`、`1/3`、`0/3`、跨 burst window、raw/exec 一致性、执行错误；root smoke 在真实 netns 以确定性 10%/30%/70% 丢包验证包计数及 healthy/degraded/down 状态，并保留 100% loss/cutover/recovery 验收。Observer 在 metrics 启用时新增 `/metrics`。
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
    - 第一窄切口迁移 `DatagramStats` 和 `ObjectPullStats`，随后已将 hint accepted/suppressed、read-only responder
      与 active-pull 展示状态一并迁出。继续逐字段审计 relay suppression reason 和其他最近一次 action/error
      detail；不能因为字段显示在 debug 页面就认定它是纯诊断。
    - `BackoffUntilUnix`、`FailureCount`、`LastRelayUnix`、`DiscoveredAddr`、observed path/TTL/grace、`LastSyncUnix`、`RejectedDigests` 等仍影响同步、限流或实际路径，先留在 control state。`LastError` 当前也参与 observed/discovered path 判断，迁移前应先拆成稳定的控制错误码/状态和仅展示的错误文本。
    - 引入有界的 `PeerObservabilityStore`，优先放在窄职责的 `internal/observability`，由 `app/photon` 负责 wiring，由 `internal/inspect` 继续负责纯 view 构建；不要把 mutable store 放进 `internal/inspect`。store 自带独立锁或分片、按 peer snapshot 和删除/过期能力，不持有 `stateFile` 或 committed 子结构指针。
    - 第一版 diagnostics 不随主 state 持久化，daemon restart 后计数归零；旧 state 中遗留字段由 JSON 解码直接
      忽略，不再保留临时字段兼容。live observer/debug 合并新 store，offline DB 诊断显示 unavailable/reset。
      若以后确有历史需求，再低频批量写独立 spool/metrics store，不能重新推动主 revision。
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
      - `state.ApplySnapshot` 已改为 detached target-zone COW candidate，调用者只在完整成功后发布；该历史风险
        已由 state snapshot atomicity tests 固定，后续 `ApplyRemoteBatch` 必须保持同一语义。
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

  - [ ] **7.11.8 收敛稳态 bbolt 写放大（实机问题，2026-08-22）**

    **实现进度（2026-08-22）**
    - [x] P0-A 第一窄切口：`SaveStateAction` 已携带显式 persistence scope；pong、matching/empty catalog、timeout/backoff 等 peer-only 路径改为 metadata-only，同批 snapshot 实际改变 Network 时由执行器自动升级为完整保存。未声明 scope 的未来调用默认 fail-safe 为完整保存。
    - [x] P0-B：IPsec/Firewall 已增加 substantive equality；时间戳、IPsec SA age/traffic counter 与 SA 返回顺序等纯采样变化不推进 revision，link lifecycle/owner/backoff、稳定 SA 状态、desired/action/skip、Firewall policy/backend/generation/error 等变化仍提交。重复相同 IPsec error 已去重，首次/变化/恢复仍保存；两类 reconcile 的实质 metadata 变化均改为 metadata-only。
    - [x] P1 存储窄切口：完整 state 的 `_meta` 与 Network 已合并为单一 bbolt transaction；JSON value 先稳定序列化并与现值比较，相同值不 `Put`，整笔无变化时 rollback 为 no-op。新增/删除 zone、失败回滚和 metadata-only 兼容路径保留。
    - [x] P2 checkpoint 第一窄切口：只延迟 sync FSM 明确标记为 peer metadata-only 的 `SyncPeers` 更新；第一次 dirty 后在 `min(sync interval, 1m)` 到期，后续 peer completion 不滑动 deadline。正常 shutdown 强制 flush，失败保持 dirty 并按 1s 起步指数退避；任何成功且 revision 足够新的即时 full/meta 保存会原子吸收待写 checkpoint。Network/admin/security mutation 仍同步持久化。
    - [x] 延迟期间的外部 Network reload 已按字段所有权 rebase：磁盘侧 Network 保留，内存侧 pending `SyncPeers` 覆盖到新 committed state，再推进 checkpoint revision；不会用磁盘旧 metadata 覆盖本地 peer runtime，也不会用本地旧 Network 覆盖外部权威变更。`kill -9` 最坏只丢最后一个 sync interval 内的 peer runtime；其影响是重启后一次额外重试或 recent endpoint grace 缩短，不影响 zone、ACL、密钥或 link ownership。
    - [ ] 常驻 DB handle 与 typed changed-zone set 尚未实施。当前写量已收口，常驻 handle 仍涉及在线 CLI/file-lock/external reload 协调，不和本轮低风险 checkpoint 合并。
    - [x] 验证进度：新增 transaction ID、原子失败、reconcile equality/error 去重、checkpoint 合并/固定 deadline/失败重试/shutdown/reload rebase/即时保存吸收测试；`make check`、完整 `make smoke-all`、Nix StrongSwan PATH 下的 `make root-smoke` 以及 `go test -race ./app/photon ./pkg/core/gossip ./pkg/core/zone ./pkg/routing/bird` 均通过。`less` 新候选版无调试器 65 秒 `write_bytes=258,048` bytes、`syscw=282`、CPU 1.076 秒（约单核 1.66%）；相对原始 39,849,984 bytes 写入下降 99.35%，相对上一正式版 1,548,288 bytes 再下降 83.3%。该窗口无真实 `zone_applied`，代表稳态 checkpoint 收益。

    **现场基线与根因**
    - `less`（17 peers、约 23 条 XFRM link）运行 19 小时后，`photon` 主进程 `/proc/<pid>/io` 的 `write_bytes` 约 47.8 GB；BIRD 只写 4 KB，journal 总占用约 495 MB，写盘主体可确定为 Photon 自身。`systemctl status` 的约 88.1 GB 同时累计了 device-mapper `254:0` 和底层块设备 `8:0` 的同一批 I/O，不能当作真实物理写入量，但去重后的约 47.8 GB 仍异常。
    - 无 strace 的 65 秒稳态采样写入 39,849,984 bytes、发生 3,459 次 write syscall，按当前负载约为 53 GB/天；4 MB 的 `/etc/photon/photon.db` 没有持续同比增长，问题是反复覆盖 bbolt 页并同步落盘。
    - 75 秒 syscall 采样捕获 1,320 次 `pwrite64` 和 88 次 `fdatasync`。一轮 60 秒同步中，17 个 peer 的 `LAST_SYNC` 几乎集中在同一秒；`SyncSession` 在 pong/catalog 无差异时仍生成 `SaveStateAction`，每个 peer 随后分别调用完整 `saveCommittedState()`。
    - `saveStateAtWithFileInfo` 每次先用一个 bbolt transaction 写 `_meta`，再用第二个 transaction 调用 `SaveNetwork`；一次完整 save 至少包含两次 commit/fsync，而且崩溃可能停在“新 meta + 旧 Network”的中间状态。`SaveNetwork` 又会遍历所有 zone 并重新 Put authority/proof/delegation/revocation/records/history/root；bbolt 不会因为调用方 Put 的字节相同就自动替 Photon 省掉所有 dirty page 写入。
    - 每次保存还会重新 `bolt.Open -> mmap/freelist -> transaction -> Close/munmap`。这是额外 CPU/锁开销，但在当前架构中也让外部 CLI 有机会取得 bbolt 文件锁；它不是可以脱离多进程协调语义“顺手复用句柄”的独立低风险改动。
    - IPsec 成功 summary 每轮都会更新 `LastRunUnix`/`SourceRevision` 并完整保存；`recordIPsecReconcileError` 的持续同错误路径也会每轮完整保存。Firewall 每次实际 flush 都会更新 summary/每实例 `LastRunUnix`，没有 substantive equality 检查并直接完整保存。需要注意：当前 no-diff sync timer 不直接周期 flush Firewall，Firewall 主要由启动和真实 state-change 通知触发；但它一旦运行就必定 commit/save，仍是明确的次级写放大源。

    **优化顺序与兼容边界**

    **P0-A：先停止无差异同步重写 Network**
    - 引入明确的持久化意图/dirty family，至少区分 `Network` 权威数据和 daemon-local metadata。所有调用点必须显式声明写入范围；发生 zone/delegation/revocation/record/history 变化时仍同步执行完整持久化并在成功后才对管理请求确认，不能降低权威 mutation 的 durability。
    - 第一窄切口只把 pong/catalog 无差异完成、round timeout/backoff 等只修改 `SyncPeers` 的路径改为 `saveCommittedMeta()`；snapshot/object chunk/typed Network mutation 仍走完整保存。保持现有 `_meta` JSON 和 zone bucket 格式，不做数据库迁移，旧二进制与离线 debug/db 命令应继续可读。
    - 不把 `LastSyncUnix`、backoff、failure 或 discovered/observed endpoint 笼统归类为纯 observability：`LastSyncUnix` 参与 recent discovered address 的 grace 判断，backoff/failure 参与下一轮调度，observed/discovered 状态影响连通路径。第一步仍保持这些字段每次同步完成后立即 metadata-only 落盘，只消除 Network rewrite，以最小化语义变化。
    - `SaveStateAction` 应携带或由 action result 推导 `networkChanged/metaChanged`，不能只靠 reason 字符串判断。成功 snapshot 与 peer completion 同属一个 action batch 时只做一次完整保存；失败/rejected digest 若只改 peer metadata，则只做 metadata 保存。

    **P0-B：IPsec/Firewall substantive equality 与错误去重**
    - 仿照 `routingReconcileResultEqual` 为 IPsec 和 Firewall 定义字段所有权清晰的 substantive comparator。比较时忽略经审计确认纯运行观测的 `LastRunUnix`；IPsec 的 `SourceRevision`、`Committed`、`Stale` 是否影响 restart/debug 必须逐字段证明后才能排除，不能简单把整个 summary 清零比较。
    - IPsec 必须同时比较 transport key/port、LinkInstances、desired/actual SA、actions/skips、rotate/takeover/draining、owner token 和稳定错误状态；Firewall 必须比较 EndpointACL、backend、policy hash、generation、owned object 数与稳定错误状态。实质结果相同则不升 committed revision、不持久化、不触发下游通知。
    - 有实质变化但 Network 未变时统一走 `saveCommittedMeta()`。`recordIPsecReconcileError` 对连续相同错误做去重：首次出现、错误类别/内容变化和恢复清零需要提交；相同错误仅刷新纯 live observation，不得每分钟 full save。错误去重不能压掉 failure count、backoff、stale/dirty 或 owner lifecycle 的真实变化。
    - Firewall 的优化不能改变 deny-first 顺序。ACL、revocation、authorized route 或 backend-owned object 变化仍必须在 control 请求返回前 apply 并持久化；这里只跳过“输入、observed、plan、result 均等价”的重复 summary。

    **P1：存储层原子事务与相同值兜底**
    - 将完整 state save 的 `_meta` 与 Network 写入合并到同一个 bbolt `Update`，把一次完整保存从两个事务降为一个，并消除 crash 时 meta/network 跨事务不一致窗口。先把现有 store helper 重构为接收同一 `*bolt.Tx` 的内部函数；metadata-only 路径仍保持单独一个 transaction。
    - 为 JSON value 写入提供 `putJSONIfChanged`：先稳定序列化，再与当前 bucket value 做 `bytes.Equal`，相同则不调用 `Put`；追踪本事务是否发生 Put/Delete，没有任何逻辑变化时通过受控 no-op/rollback 路径退出并用 syscall 测试确认不产生 fsync。必须保持 nil/empty、bucket create/delete 和 stale zone 删除语义。
    - 不用当前 `ZoneState.MerkleRoot` 判断 zone 是否变化：现有 TODO 已记录其计算/失效维护不完整。若相同值 guard 后仍需 zone delta，优先从 typed Network mutation 显式传递 changed/deleted zone set，并在保存失败时把 dirty set 与后续 mutation 做并集；不能用可能过期的 root 跳过权威写入。
    - 第一阶段继续保持每次保存独立打开/关闭 bbolt。常驻 DB handle 只能在 daemon 成为唯一在线 writer、所有管理写走 control socket、direct 模式要求 daemon 停止，并明确外部变更/reload/file-lock 行为之后单独评估；写量收口后先复测 Open/Close 是否仍是可见热点。

    **P2：有界 metadata checkpoint（仅在 P0/P1 验收后）**
    - 先逐字段形成 restart 语义表：权威/安全字段必须同步落盘；backoff/failure 丢失会导致重启后额外重试；`LastSyncUnix` 丢失可能让 recent discovered endpoint 失效；纯展示时间/计数可以丢失。只有明确最坏影响和恢复路径后，才允许把相应字段从 per-peer fsync 改为 checkpoint。
    - 启用延迟 checkpoint 前必须修正 `handleSyncTimerEvent` 的无条件 `LoadState -> ReplaceCommitted`：当前立即保存语义下它不会覆盖未落盘内存 mutation，但延迟后会直接丢失 metadata dirty。sync timer 应只在文件 marker 证明存在真实外部修改时 reload；若本地仍 dirty，必须先按 typed ownership 定义 flush/rebase/conflict 顺序，不能把磁盘旧 metadata 或本地旧 Network 任一方盲目覆盖到另一方。
    - `daemon.go` 的 sync timer 只负责启动一批异步 session，不代表该轮 peer 已全部完成，不能在那里直接“每轮保存一次”。最终采用 metadata dirty revision + 固定最大 deadline：第一次 dirty 从当前时刻计算 `min(sync interval, 1m)`，后续交错完成不滑动 deadline；相比依赖“本轮全部 terminal”，它也覆盖跨轮 timeout/持续流量，且不会被活跃 peer 无限推迟。管理/权威 mutation 成功时按 revision 吸收，shutdown 强制 flush。
    - 初始最大丢失窗口不超过一个 sync interval；如需扩到 5–10 分钟，必须先证明 endpoint grace、peer lifecycle/cleanup、backoff storm 和 bootstrap-only 节点重启行为可接受。SIGTERM/正常 shutdown 必须有界 flush；save 失败保持 dirty、指数退避重试，后续成功保存覆盖失败期间全部 metadata 变化。`kill -9` 明确允许只丢失最后一次成功 checkpoint 之后的非权威 metadata。
    - Network/admin/security mutation 不进入延迟队列。执行同步权威保存时可以顺带吸收当前 metadata dirty，但只有该事务成功后才能清 dirty；失败不得因稍后的 metadata-only save 而把未持久化 Network revision 标记为已保存。

    **共同限制与观测**
    - 不以 bbolt `NoSync`/`NoFreelistSync`、tmpfs 或关闭持久化作为修复；这些措施会改变断电/崩溃恢复保证。单纯增大 daemon interval 只允许作为临时运维缓解，不能作为验收结果。
    - 增加低基数持久化观测：按 `network/meta` 与固定 reason family 统计 requested、executed、no-op、coalesced、failed、duration；不得使用 peer ID、zone 或原始错误作为 metrics label。测试可注入 saver，精确断言每个事件的完整保存/metadata 保存次数。

    **回归与验收**
    - 单测覆盖：无差异 pong、matching/empty catalog、round timeout/backoff、含 snapshot 的部分成功批次、object chunk、endpoint publish、IPsec rotate/takeover、重复/变化/恢复的 reconcile error、Firewall ACL、routing auto-announce，以及连续 save failure 后恢复。逐项断言内存 revision、磁盘 reload 结果、dirty/retry 和通知顺序不变。
    - 增加 bbolt transaction/bucket 级回归：完整 save 只 commit 一次且 meta/network 要么同时可见要么都不可见；metadata-only save 不改写任何 `zone:*` value；相同值 guard 不 Put；Network save 仍完整保存新增/删除 zone、record/history 和 revocation。保存失败不能更新 reload marker，也不能向调用方报告成功。
    - checkpoint 测试使用可控 clock/saver 覆盖 peer 合并、交错完成不滑动 deadline、保存期间 revision 覆盖、失败保持 dirty/退避、shutdown 强制 flush、即时 full save 吸收，以及外部 Network reload 与 pending `SyncPeers` rebase。后续若把窗口扩到 5–10 分钟，再补 active session、discovered grace、backoff storm、peer lifecycle 与 `kill -9` 恢复的长窗口测试。
    - 保留外部 state 写入检测、daemon 自写 marker、显式 direct 模式和多进程 bbolt file lock 的既有测试；任何常驻句柄实验必须额外证明在线 CLI 不死锁、不永久阻塞且外部写入不会被 reload marker 屏蔽。
    - 必跑 `go test -race ./app/photon ./pkg/core/gossip ./pkg/core/zone`、`make check`、chain relay、object pull、delegation revoke、IPsec/firewall/routing smoke。分阶段实机验收：P0-A 后无差异 sync 不再调用 `SaveNetwork`，物理写入至少下降 80%；P0-B/P2 后 75 秒稳态 `fdatasync` 从 88 降到个位数、65 秒 `write_bytes` 以约 1 MiB 为目标且不得超过 2 MiB。peer 状态、重启恢复和同步收敛时间不得退化。

  - [ ] **7.11.9 消除 IPsec/XFRM 稳态 reconcile 子进程风暴（实机问题，2026-08-22）**

    **实现进度（2026-08-22）**
    - [x] P0 命令后端第一窄切口：`SystemXFRMDriver` 新增按 netns 批量观测；同一 namespace 使用一次 `ip -j -d link show`、一次 `ip -j addr show` 和一次批量 forwarding sysctl 读取形成 immutable snapshot，pre-filter 与 maintenance 复用同一份结果。批量 JSON/字段读取失败会记录 fallback 并回到原逐接口 inspection，不把 unknown 当 healthy。
    - [x] P0 drift-only apply：批量 snapshot 同时覆盖 UP/MULTICAST、IPv6 addrgen、namespace/interface forwarding、主地址和 diagnostic `/128`；健康接口零 mutation，单项漂移只修对应 flag/sysctl/address。namespace forwarding 每 namespace 至多修一次，既有 create/move/action 顺序未改变。
    - [x] P0 PATH 探测：driver 构造时解析 `ip`/`sysctl`/`true` 绝对路径，并把绝对内层命令交给 `ip netns exec`，减少每轮 execvp PATH 失败探测；保留零值 driver 的旧命令名以兼容 fake runner。
    - [x] P1 第一窄切口：sync timer 只启动异步 session，不再无条件 dirty/立即 flush IPsec 与 Routing。真实 snapshot apply 仍由 `notifyStateChanged` deny-first 唤醒三层，VICI/control/health 等原事件路径不变，独立 IPsec/Routing periodic timer 继续兜底。
    - [x] P2 routing/veth 后续窄切口：真实 profile 确认健康 `EnsureVethPair` 每轮仍无条件执行 addrgen/link-up/四个 forwarding sysctl，并按地址族重复查询。现改为每端一次 `ip -j addr show` + 一次多 key `sysctl -n`，内存比较 UP/addrgen/IPv4+IPv6 forwarding/地址，只修单项 drift；接口缺失、JSON 或 sysctl 不兼容时完整回退旧创建/修复流程。
    - [x] P3 有界函数级诊断入口：`photon daemon` 新增显式 opt-in 的 `--cpu-profile <absolute-path>` 与 `--cpu-profile-duration <duration>`；默认关闭，最长 30 分钟，只允许新建本地绝对路径、文件权限 `0600`、拒绝覆盖既有文件，也不开放 HTTP/远程 profile 端口。profile 到期只停止采样、不停止 daemon；daemon 提前退出时同步封口。进程入口现用 `signal.NotifyContext` 接管 SIGINT/SIGTERM，使正常 systemd stop 能真正经过 daemon shutdown defer 并强制 flush 待写 metadata checkpoint。
    - [x] P3 profile 第一处热点：`less` 5 分钟函数级采样共 8.95 秒 Photon CPU（约单核 2.98%，窗口内 35+ 次真实 `zone_applied`）；`flushRevocationCleanup` 累计 3.37 秒，其中 `DaemonStateStore.Update -> cloneStateFile/CloneNetworkState` 占约 3.3 秒。根因是数据库中存在长期有效 revocation 时，每个 packet/sync event 都进入全量 COW，即使对应 peer cache 已在第一次清理后达到目标状态。现增加与 `CleanupRevokedPeerCache` 字段一一对应的显式 typed predicate；仍先执行 deny-first flush hook并清理独立 `PeerObservability`，但只有 committed peer 字段确有 drift 才创建/提交 workspace。健康 revocation 快路径 benchmark 约 0.55 微秒、376 B、7 alloc/op，不使用 reflection。
    - [x] P3 digest 收口：撤销空转修复后的 5 分钟 profile 仅采到 1.48 秒 Photon CPU（约单核 0.49%，窗口内 6 次真实 `zone_applied`），全量 clone 热点消失；剩余 `ZoneDigests/ZoneRoot/RecordHash` 累计约 0.38/0.30 秒。event loop 现由 sync action 的 typed `networkChanged` 返回值决定是否刷新 reload 基线，timer、普通 packet 和 metadata-only completion 不再反复遍历 Network；summary+digests 组合投影及无会话 ping 的 pong/shortcut 在同一调用链内只计算一次 digest。没有加入跨事件缓存，避免改变按 `RevokedAt` 生效的时间语义或引入失效协议。最终 3 分钟 profile 遇到 10 次真实 `zone_applied`，Photon 样本 0.96 秒（约单核 0.53%）；Photon+BIRD cgroup 含启动为 2.03 秒/197 秒（约 1.03%），随后无 `zone_applied` 的 35 秒稳态为 0.212 秒（约 0.61%）、Photon `write_bytes` 90,112 bytes。25 条 XFRM link、BIRD 与同步均正常。
    - [x] 验证进度：新增批量解析、健康零 mutation、单项漂移、同轮 snapshot 复用和批量失败回退测试；目标节点已确认 XFRM 与 veth 所需 JSON/多 key sysctl 格式兼容。`make check`、完整 `make smoke-all`、Nix StrongSwan PATH 下的 `make root-smoke` 和相关 race 均通过，覆盖 restart/adopt、IKE/takeover/rotate、BIRD/Babel/veth upstream、nft、health fault 和 revocation deny-first。`less` 40 秒时间戳 profile 捕获一轮 XFRM + 两轮 routing，共 21 个成功 `execve`：XFRM 健康轮 7 个批量 observe，每个 routing veth 健康轮由约 17 个命令降为 6 个 observe，另保留 1 个 upstream source `addr replace`。65 秒逐进程 CPU 为 Photon 0.95 秒、BIRD 0.09 秒、cgroup 1.053 秒（约单核 1.62%）；目标机无 perf/bpftrace，35 秒 syscall profile 已确认仅 7 次 exec，函数级 pprof 结果与后续收口见 P3。upstream replace 若改成独立 `ip show` 只会一换一、不减少 fork，暂不扩大 manager 接口；后续若继续优化应共享 veth observed snapshot。

    **现场基线与根因**
    - cgroup 生命周期 CPU 约为单核 6%；无调试器的 65 秒窗口消耗 3.00 秒 CPU（约单核 4.6%），主要呈每分钟 reconcile 突发，而不是 BIRD 常驻计算。
    - 20 秒 process trace 捕获 552 次 `execve` 尝试，其中 229 次执行 iproute2 `ip`；其余包含 `true`、`sysctl` 及 `execvp` 沿 PATH 的失败探测。典型序列为每条 link 重复执行 `ip netns exec photon ip link show`、IPv4/IPv6 addr show/replace、namespace `true` 和 forwarding sysctl。
    - daemon 每轮 sync 启动后都无条件把 IPsec/Routing 标记为 dirty 并立即 flush；同时 IPsec 默认 1 分钟、Routing 默认 30 秒仍有 periodic safety reconcile。即时 flush 会重置下一次 deadline，因此不是简单把两个计时器次数相加，但它把“本轮只是发送 ping、尚无新输入”也当成 reconcile 输入，造成不必要的突发。
    - `SystemXFRMDriver.EnsureInterface` 对已存在接口仍逐条确保 namespace、addrgen、multicast、link up 和 forwarding，`InspectLink` 也按 link 独立查询。接口数增长时 fork/exec、`ip netns exec` namespace 切换和文本解析成本近似按 link 数线性放大。

    **优化顺序与兼容边界**

    **P0：先把单轮 XFRM reconcile 变成 no-op cheap path**
    - 先给 command runner 增加仅测试/诊断使用的固定 operation family 计数，建立一轮 reconcile 的 observe/mutate 命令清单；不能为了降低计数而取消周期性 drift 检查。缓存只能作为加速提示，内核实际状态仍是 reconcile authority。
    - 将 reconcile 明确拆成 `Observe -> Plan -> Apply -> Re-observe/Commit`：先按 netns 批量取得 link/address/namespace/forwarding 状态，构造不可变 observed snapshot，再只对缺失或不一致项执行 add/move/addr replace/flag/sysctl。健康接口的第二轮 no-op reconcile 不得执行 mutation 命令。
    - 第一阶段可继续使用现有命令 backend，但每个 netns 的 namespace existence 与 forwarding 只检查/设置一次，link/address 尽量用 `ip -j` 批量读取；解析失败或字段未知时 fail closed 到现有逐项检查，不得把 unknown 当作 already-correct。
    - 消除嵌套命令的 PATH 扫描：启动时解析受支持的 `ip`/`sysctl` 绝对路径并传给 netns wrapper，同时保留 NixOS 与普通发行版 PATH/安装探测测试。该项只减少 exec 探测，不能替代 observe/plan 去重。
    - 命令版 no-op 路径稳定后，再评估 rtnetlink + 每 netns 常驻 `setns` worker。若采用，worker 必须 `runtime.LockOSThread`、进入和恢复 namespace、支持 namespace 删除/重建、context cancel 与有界退出；不得让 Go runtime 的其他 goroutine 意外留在目标 netns。
    - 不在本阶段并行执行同一 netns 的 mutation，也不打乱 create/move/configure/up/route/BIRD 的既有顺序。StrongSwan SA、XFRM if_id、owner token、staged/draining/takeover、地址替换、IPv6 link-local 和 BIRD interface 可见性的现有语义必须保持。
    - 不以单纯增大 reconcile interval 作为修复；那会线性增加接口/namespace 漂移后的修复延迟。只有在 no-op 成本收口后，才根据明确的恢复 SLO 调整 periodic safety interval。

    **P1：按真实输入标 dirty，消除 sync timer 假唤醒**
    - 删除 `daemon.go` 中 sync timer 后的无条件 `ipsecDirty/routingDirty` 之前，先定义 typed dirty reasons/input generations，不能只比较 zone digest。Routing 的输入至少包括授权 route/announcement、link output、配置、BIRD lifecycle/force reload；IPsec 的输入还包括 transport contact-point quality、DNS/port generation、VICI lifecycle、rotate/takeover/draining/backoff deadline 和配置。
    - sync timer 仅启动 session，不应立刻触发 reconcile。成功 snapshot/record mutation、peer endpoint/path quality 的实质变化、link lifecycle event、配置 reload 或时间 deadline 到达时，分别标记对应 layer dirty；同一 event drain 内多个原因合并为一次 reconcile。纯 `LastAttemptUnix`/相同 catalog completion 不应唤醒数据面。
    - 保留现有 periodic safety reconcile，用于修复进程外 drift、namespace/interface 被管理员删除、BIRD/StrongSwan 状态变化但事件丢失等情况。event-driven dirty 负责低延迟，periodic timer 负责最终自愈；两者命中同一时刻必须合并，不能连续跑两遍。
    - deny-first/security 事件不得等待普通 debounce：revocation、ACL 收紧和授权 route 撤销仍按 Firewall -> Routing -> IPsec 的现有顺序立即 flush。新增/放宽策略可以合并，但必须保持 control 请求目前要求的同步 apply/错误返回语义。
    - 为每类 dirty reason 增加表驱动测试，证明“输入变化一定唤醒、纯观测变化不唤醒、丢失事件仍由 periodic 修复”。不得用 committed 全局 revision 是否变化作为唯一条件，因为 peer metadata revision 可能变化而数据面输入不变，transport runtime 也可能变化而 Network digest 不变。

    **回归与验收**
    - fake runner 测试精确覆盖首次创建、第二轮完全 no-op、单接口 down、multicast/addrgen 漂移、IPv4/IPv6 地址缺失或多余、forwarding 被关闭、接口被移回 host、namespace 删除重建，以及 observe/parse/apply 中途失败。no-op 必须零 mutation，任一漂移必须在下一轮修复。
    - root smoke 覆盖 daemon restart/adopt、23-link 规模、StrongSwan SA 与 XFRM link 映射、rotate/takeover/draining、BIRD 邻居/路由不中断、namespace 删除重建及 revocation deny-first；优化前后比较最终 `ip -j link/addr`、sysctl、SAs、routes 和 persisted owner state，而不只比较命令数。
    - 保留每个外部命令的 context timeout、错误输出截断、partial apply 后 dirty 重跑和 shutdown cancel 行为。批量 observe 失败时不得提交虚假的 healthy 状态，也不得清除原有可恢复的 LinkInstances。
    - 调度测试额外覆盖：no-diff sync 不触发数据面、snapshot/endpoint/quality/VICI/config/deadline 分别触发正确 layer、同 tick timer+event 只 reconcile 一次、事件漏失后 periodic 自愈，以及 revocation/ACL deny-first 不被 debounce。
    - 必跑 IPsec/XFRM 单测与 race、完整 `make root-smoke`、BIRD/Babel、health fault、firewall 和 revocation smoke。真实节点以相同 20/65 秒窗口复测；目标是健康稳态每轮外部命令数量从 O(links) mutation 降为 O(netns) observe、20 秒 `execve` 从 552 降到 50 以下（成功执行数量至少下降 90%），cgroup 单核占用从约 5–6% 降到 1% 左右且至少下降 60%，同时漂移修复时间和数据面连通性不退化。

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

1. F0a/F0b/F0c 已完成纠偏：没有第二个 client runtime，Windows Store 恢复归 Windows composition/state wiring，memory 双节点直接驱动 HostRuntime/Store/Transport。
2. 下一步继续收口唯一 HostRuntime：把 Linux daemon 中仍属公共 gossip 的 event drain、state apply/persistence、backoff/checkpoint 和 object-pull completion 执行移入公共边界；Windows 不复制 `daemonGossipActionController`。
3. 上述收口通过 Linux race/root smoke 与 Windows compile guard 后，才实现 Windows composition root 和真实 UDP adapter；不继续按文件数量搬迁 Linux CLI/config/test。
4. Windows 数据面按共享 UDP/ESP 基础 -> IKEv2 initiator/StrongSwan interop -> Babel/SADR/route authorization -> Wintun pipeline 推进；每个真实 consumer 出现时再提取窄接口。
5. 随后接 IP Helper address/route ownership、SCM service、named-pipe IPC 和 network-change/rebind；每层验证 restart/adopt/cleanup。
6. Photon Android 保持独立后续项目；只复用已经由 Windows 真实使用并稳定的用户态协议/packet core，不预建 Android 工程或抽象。
