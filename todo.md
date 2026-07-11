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
- [x] Phase 7 部分完成项：7.3 UDP chunk repair、7.10 daemon/control 生产化收口，以及 7.13-7.15 稳态 reconcile、endpoint timer 和 gossip ping 冗余优化。详细归档见 [docs/roadmap-archive.md](docs/roadmap-archive.md)。

## Phase 7: 生产化收口与高级能力候选

**目标：** 先把 daemon/control/运维面补到可长期运行，再按真实需求推进异构 TransportLink 并行、可靠性补强和可选传输能力。Phase 7 不要求按编号顺序执行。

**当前建议顺序：**
1. **7.1 异构链路模型与公共边界已完成**：BIRD 双接口、WG/GRE 基础数据路径与 staged rotate 均已在真实 root/netns lane 通过，公共 Babel-facing `LinkOutput` 已落地；WG 底座和 GRE/VXLAN 正式实现分别留在可选 7.4/7.5。
2. **7.3 chunk repair 已完成**；下一窄切口按需求选择 7.7/7.8 discovery/relay 或 7.11 metrics/readmodel。
3. 7.2 高频 port hopping、7.4 WireGuard、7.5 GRE/VXLAN、7.6 SRv6 暂作为可选能力保留，等需求和实验环境明确后再开。

- [x] **7.1 异构 TransportLink 并行共存（模型、实验与公共边界已完成）**
  - 设计文档：[`docs/phase7-1-heterogeneous-transport-design.md`](docs/phase7-1-heterogeneous-transport-design.md)。D1-D8 已冻结：一个 LinkGroup 一个 provider；静态 Babel base cost 属于 LinkGroup；Link ID 包含 provider 但无 ID version；WG device 按 LinkGroup + underlay family 共享；health 第一版不接管 BIRD；非秘密链路参数从 Link ID 派生；IPsec/WG 使用独立 ports record 与 overlay intent；rotate generation 语义可复用，但 lifecycle/resource graph 归各 provider；daemon 只统一调度和 Babel-facing link 输出，不统一 desired/runtime/action。
  - [x] **7.1.a BIRD 双接口验证性实验**：已由 `TestBabelDualInterfaceCostFailoverRootSmoke` 在真实 root/netns BIRD 2.19.1 lane 验证。两节点每端两条接口、同一 per-netns BIRD 建立两个 Babel neighbor；`rxcost` 是本机向对端公告的接收 cost：B 选择 A 设为低 cost 的左链，A 选择 B 设为低 cost 的右链。B 的优选链路 down 后切至另一条，恢复后回切；未接入 health 动态 metric。
  - [x] **7.1.b WG/GRE 基础验证性实验**：`TestWireGuardGREThreeNodeRootSmoke` 已在真实三节点 root/netns lane 验证。中心节点一个共享 WG device 同时持有两个 peer，AllowedIPs 仅含 transit `/32`；每个 peer 使用独立 GRE/Babel interface，B/C 业务前缀可经 A 学习并双向转发；GRE MTU 固定为 1360，BIRD/WG/GRE/netns cleanup 无残留。显式入口为 `sudo make phase7-1-wg-gre-experiment`，不进入默认 smoke。
  - [x] **7.1.c WG staged rotate 验证性实验**：`TestWireGuardGREStagedRotateRootSmoke` 已在真实三节点 root/netns lane 验证 old/staged WG devices 可复用逻辑 device key 与相同 peer public keys；generation-specific transit address 和 staged GRE interface 可与 old generation 并行，Babel 在 old GRE withdraw 后经 staged interface cutover；old/current UDP listener 与 nftables grace rule 同时存在，old shared device 在最后一个 peer 引用释放后才清理。与 7.1.b 共用 `sudo make phase7-1-wg-gre-experiment` 显式入口。
  - [x] **7.1.d 双 provider 抽象边界收口**：确认长期只维护 StrongSwan/XFRM 与 WG/GRE 两套 lifecycle。撤回未接生产路径的通用 `ProviderPlan`/`ProviderAction`/resource graph、通用持久化 instance、StrongSwan 双向 adapter，以及只覆盖部分 constructor 的 Link ID 提前迁移。StrongSwan 继续使用现有 planner/reconcile/apply/state；WG/GRE 自己管理 shared device/peer/GRE resource graph、引用和 rotate。
  - [x] **7.1.e 公共 LinkOutput 与消费者收口**：已在 `internal/state.LinkOutput` 落地 provider-neutral、只读的 Babel-facing 契约；StrongSwan current/staged runtime 投影为独立 active/staged 输出，health、firewall、BIRD health observation 和在线 `links_status.outputs` 统一消费/发布该聚合结果。公共结构不包含 owner、SA 名、rotate phase 或 action，不能反推 apply/teardown；routing/health readiness 保留后续 observation enrichment。

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

- [ ] **7.2 高频 UDP 端口候选 / 对抗性 Port Hopping（可选实验）**
  - 在 Phase 4.4 低频平滑 rotate 之上评估，不默认承诺高频跳端口。
  - IKEv2/IPsec 不假设能像 WireGuard 一样任意 per-peer 高频跳监听端口；高频数据面端口跳变通常需要 reestablish/MOBIKE/多实例或外层 DNAT 配合。
  - 若推进，必须包含 old-port grace、clock skew 容忍、fallback static port、失联恢复路径、QoS 误判回滚和探测限速。

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

1. 7.1 已完成并保持 StrongSwan 主链路现状；WG 底座与 GRE/VXLAN 正式实现分别留在可选 7.4/7.5，不作为当前主线的隐含下一步。
2. 7.3 chunk repair 已完成；下一窄实现切口按需求选择 7.7/7.8 discovery/relay 或 7.11 metrics/readmodel。
3. 后续模块化不再单独扩大范围；新增 debug/observer/control 输出默认走 `internal/inspect` view + `inspect/text` 或 `inspect/http` presenter，写侧/daemon adapter 继续留在 app 层直到接口稳定；公共 control DTO/typed client 等出现实际复用需求再迁移。
