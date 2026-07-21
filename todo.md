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
- [x] Phase 7.1 异构 TransportLink 并行共存（模型、实验与公共边界已冻结）。
- [x] Phase 7.3 Gossip UDP object chunk repair。
- [x] Phase 7.10 Daemon / 本地控制接口生产化。
- [x] Phase 7.13-7.15 稳态冗余优化（XFRM maintenance、endpoint timer、unsolicited ping）。
- [x] Phase 7.16 Firewall backend-native inline hooks 及后续收口（external mode、ip6tables 双栈探测、`higgs debug firewall` flag、nft priority 配置）。详细实现归档见 [docs/roadmap-archive.md](docs/roadmap-archive.md)。

## Phase 9: Observer Web UI 重构（当前执行队列）

**目标：** 解决现有 observer 网页视觉陈旧、信息架构混乱的问题。设计定稿见 [docs/new/observer-ui-redesign.md](docs/new/observer-ui-redesign.md)；observer 只读定位、REST API 形状与安全模型不变。

**约束：** 零构建（原生 ES Modules + 多 CSS 文件，无 Node 工具链）、零运行时依赖、纯 embed；注意 `//go:embed web/*` pattern 需随新增子目录扩大。

- [ ] **9.1 设计基座**
  - `web/style/tokens.css`：中性灰底 + 单一 accent + 语义状态色（ok/warn/err/unknown）、字号/间距阶梯、radius token。
  - 布局壳重写：侧栏分组导航（总览 / 网络 / 监控）、底部连接状态三态指示、统一页头（标题 + 说明 + 页面级操作区）。
  - 基础组件收敛到 `style/base.css`：card、stat-card、badge、dot、table、kv、details、empty/loading/error 三态。

- [ ] **9.2 前端模块化与重绘策略**
  - `app.js`（1153 行单文件）拆分为 `web/src/` 原生 ES modules：`api.js` / `store.js` / `events.js` / `router.js` / `format.js` / `components/*` / `pages/*`，单文件 < ~200 行。
  - store 按 endpoint 缓存 + 事件类型到 endpoint 的失效映射，SSE 事件只重取受影响键，不再整页刷新。
  - 重绘保留 scrollTop / 输入 / `<details open>` 状态，删除 `foldState` 全局补丁。
  - Health 页 sparkline 懒加载，消除每次刷新每条 link 一个 series 请求的 N× 放大。

- [ ] **9.3 页面信息架构重构**
  - Overview 仪表盘化：全局状态横幅 + 问题清单（带深链）优先，统计卡与 reconcile 摘要其次。
  - Overlay（控制面：planner/SA/reconcile/rotation）与 Health（数据面：探针/RTT/loss/曲线）职责分离，导航文案明确。
  - Zones 双栏布局；authority/proof/revocations/history/Raw JSON 全部收入 Inspect 折叠区；hash 截断 + 点击复制。
  - Routes 错误置顶 + zone 过滤；BIRD 错误醒目展示；Gossip diagnostics 格式化 kv。
  - 全局：相对时间、列表页文本过滤、选中态写入 hash 可深链。

- [ ] **9.4 事件链路补完（可选，动后端）**
  - `daemon.go` 广播点携带轻量 payload（`link_id` / `peer_id`），前端条目级失效。
  - 落地 `event_buffer_seconds` 环形缓冲 + Events 时间线页（独立可裁）。

- [ ] **9.5 测试与文档收口**
  - `webapp_test.go` token 断言改写为模块化后的关键导出；`static_test.go` 覆盖新增子目录；`internal/observer` 与 `app/higgs` observer 族测试全绿。
  - `app/higgs/observer_api_*_test.go` 不应需要修改（REST 响应不变，9.4 除外），若需修改则说明越界。
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
  - 评估 peer observability readmodel / metrics store，将 `DatagramStats`、`ObjectPullStats` 等纯诊断计数从 `PeerRuntimeState` 拆出。
  - 梳理 `higgs status`、`higgs zones`、`higgs peers`、`higgs sync` 等面向日常运维的简洁 CLI。
  - Observer 后续增强另见 Phase 7 之后远期后续。

- [ ] **7.9 可选 Admission 管理面**
  - 在 auto-join 主链路和本地控制接口稳定后，再考虑父 Zone 管理节点的 join request inbox、审核队列、批量 approve/reject 和受限网络化提交。
  - 第一版 admission 仍不引入新的公网 request 协议，也不让 leaf 自动把 join request 写入 gossip active state。
  - 候选命令：`higgs join pending`、`higgs join approve <request-id>`、`higgs join reject <request-id>`。
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
  - 如后续需要 external BIRD、管理员自定义策略路由、或非默认共享 netns 拓扑，再补 `ip rule` / fwmark / iif-oif 策略路由和 `/run/higgs/rt_tables.d` 诊断输出。
  - route-table auditor 仅作为可选兜底，用于交叉检查 Higgs authorized route set、BIRD learned/installed routes 与内核 route table 是否一致。

## Phase 7 之后的远期后续

- [ ] 跨数据面 rotate smoke：结合端口/IPsec rotate 与真实 BIRD route/metric 观测验证数据面切换窗口；不阻塞 Phase 5/6 收尾。
- [ ] state 文件外部协调补强：在现有 bbolt 文件锁基础上增加显式 `flock` / fsnotify watcher，避免多进程或外部修改时状态漂移。
- [ ] Observer 增强：拓扑图、zone tree、VictoriaMetrics/Prometheus-compatible datasource/push 集成、BIRD protocols/routes/neighbors 深度解析。

## Phase 8: 应用层服务与代理（已验收）

**目标：** 在 Higgs L3 mesh 上提供可发现、可授权的内网 SOCKS5 服务，同时支持本地唯一 endpoint 和 shared Anycast endpoint；应用层源路由 relay 保持独立演进。

**设计边界：**
- Higgs 只负责服务地址归属、签名 record 发布/撤销和动态防火墙授权；独立 `higgs-services` 读取 `/etc/higgs/service.yaml` 并生成 Docker Compose/代理配置。两者都不通过 Docker API 管理容器生命周期，Compose 由管理员检查后手工启停。
- 本地网络通过 `auto` 选择当前节点唯一的非 shared assignment；Anycast 网络通过 shared assignment 的稳定 tag（如 `socks5.cn`）选择，`region` 仍只是公开 endpoint 的服务选择属性。
- Docker bridge 位于 host netns，容器地址属于 Higgs 管理的服务前缀；host 侧通过指向 Higgs netns 的聚合路由和 Docker connected route 最长前缀匹配，overlay 侧复用显式 `routing.instances[].upstream` 返回 host。
- SOCKS5 第一版可使用 `NO AUTH`，由 Higgs overlay 身份/前缀和本机 firewall 提供 zone/node 级授权；这不承诺同一节点内的用户级身份区分。

- [x] **8.4 本地与 Anycast 数据面验证**
  - 已实现 `services-smoke`：真实 Docker bridge 上运行 SOCKS5 和目标 TCP 容器；client netns 经 BIRD/Babel、host route 和 static upstream 回程完成代理请求。
  - root smoke 断言 Docker connected route 优先于更宽的 host -> overlay 聚合路由；另一 Higgs 前缀仍命中该聚合路由。
  - non-owner service publish、shared tag 冲突、空 ACL selector fail-closed、未监听 endpoint 不发布分别由 `pkg/service`、routing、firewall 与 `higgs-services` 单元测试覆盖；shared prefix 成员故障收敛复用 BIRD Anycast root smoke。
  - 已于 2026-07-21 在允许 netns、具备目标 host firewall 配置的 root 环境执行 `sudo make services-smoke` 并通过。

- **8.5 不纳入 Phase 8**：客户端 service selection/health policy 不是 SOCKS5 发布数据面；Anycast 的 L3 选路和故障收敛交给 BIRD/Babel。出现明确客户端需求后再独立设计。

- **8.7 不纳入 Phase 8**：应用层源路由 relay 是独立协议/项目，不与 SOCKS5 发布、IPAM 或 BIRD 数据面耦合。

## 下一步

1. 当前执行队列为 Phase 9 Observer Web UI 重构（9.1 → 9.3 顺序实施，9.4 可选，9.5 收口），设计见 [docs/new/observer-ui-redesign.md](docs/new/observer-ui-redesign.md)。
2. 其后窄实现切口按需求选择 7.7/7.8 discovery/relay 或 7.11 metrics/readmodel；WG 底座与 GRE/VXLAN 正式实现继续作为可选 7.4/7.5。
3. 后续模块化不再单独扩大范围；新增 debug/observer/control 输出默认走 `internal/inspect` view + `inspect/text` 或 `inspect/http` presenter，写侧/daemon adapter 继续留在 app 层直到接口稳定；公共 control DTO/typed client 等出现实际复用需求再迁移。
4. Phase 8 已完成 root 数据面验收；客户端服务选择和应用层 relay 按需作为独立项目评估。
