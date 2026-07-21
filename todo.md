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

- [x] **Zone 写权限语义收口**
  - 普通网络节点默认持有通用 `write`，可维护本 Zone 的 control-plane records；relay 不持有 Zone authority / 私钥，只转发 verified gossip，不需要任何写权限。
  - 已移除 `write:route`、`write:service`、`write:wireguard` capability 及其 record type 映射；普通 Zone record 统一使用通用 `write`，并由 route / crypto 回归测试覆盖。

- [x] **7.16 Firewall backend-native inline hooks**（实现、YAML/driver/reconcile 测试和 nft root smoke 已完成；真实 iptables root smoke 仍需在具备 `iptables`/`ip6tables` 的环境复验）
  - **目标与边界**：允许管理员直接在 `config.yaml` 中为固定 hook point 写 nftables 或 iptables 的原生规则表达式，由 Higgs 将其编入自己管理的 generation/table；这不是跨后端规则 DSL，两种后端的等价语义由管理员分别维护。表达式只描述单条 rule body，不能创建、删除或 flush table/chain，也不能执行 shell。
  - **配置草案**：同一实例可以同时携带两套等价配置，运行时只使用最终选中 backend 对应的一套；`iptables_hooks` 先按 `ipv4` / `ipv6` 分组，分别对应 `iptables` / `ip6tables`，不在每条规则上重复声明地址族，也不从规则文本猜测地址族。

    ```yaml
    firewall:
      instances:
        - id: h2
          backend: auto
          nft_hooks:
            pre_input:
              - 'ip saddr 10.20.0.0/16 tcp dport 22 accept'
            post_forward:
              - 'counter log prefix "higgs-forward "'
          iptables_hooks:
            ipv4:
              pre_input:
                - '-s 10.20.0.0/16 -p tcp --dport 22 -j ACCEPT'
                - '-s 10.30.0.0/16 -p tcp --dport 443 -j ACCEPT'
              post_forward:
                - '-m comment --comment "higgs-forward-v4" -j LOG'
            ipv6:
              pre_input:
                - '-s 2001:db8:20::/48 -p tcp --dport 22 -j ACCEPT'
              post_forward:
                - '-m comment --comment "higgs-forward-v6" -j LOG'
    ```

  - **Hook point 集合**：第一版覆盖现有契约 `pre_input`、`post_input`、`pre_forward`、`post_forward`、`pre_output`、`post_output`、`host_pre_prerouting`、`host_post_prerouting`、`host_pre_input`、`host_post_input`；每个 point 是有序规则列表，按 YAML 顺序渲染。补齐当前未落地的 `pre_output` 和 host hook，不另造 backend 专属 point。
  - **顺序语义**：以 planner 中固定的安全/基础规则为锚点冻结每个 point 的准确位置；`post_*` 必须位于 Higgs 生成规则之后、terminal default verdict 之前。`ct invalid drop` 等不可绕过的安全规则是否先于 `pre_*`，需要在实现前写入设计说明并用逐条顺序测试锁定，禁止由 driver 各自决定。
  - **Backend 选择**：`backend: auto` 只有一套 inline hooks 时必须选择支持该配置的 backend；两套都存在时沿用正常探测优先级；显式 backend 若只有另一 backend 的配置则启动报错，不能静默忽略。选中 backend 后未使用的另一套配置保留用于异构主机，但 debug 输出必须明确显示 `inactive`。
  - **iptables 表达式**：只支持 `ipv4` 和 `ipv6` 两个 family block，分别编入 `iptables` 和 `ip6tables`；不提供 `both`、默认 family 或跨 family 自动复制。某一 family 未配置即表示该 family 没有管理员 inline rule。每个 hook point 是字符串列表，可连续写任意多条规则并保持配置顺序。使用 shellwords-compatible lexer 仅做参数分词，再以 argv 调用命令；禁止 shell expansion、换行、NUL、重定向/管道/命令连接符，以及 `-A/-I/-D/-R/-N/-X/-F/-P/-t/--table` 等越过当前 managed chain 的操作参数。
  - **nft 表达式**：只接受可追加到当前 managed chain 的单条 rule expression，不接受 `add/delete/replace/insert/flush table|chain|ruleset`、`include`、分号或换行等可逃逸单条规则上下文的语法。表达式与 Higgs 规则进入同一个 `nft -f` batch；任一表达式语法错误时整批失败，旧 table 继续生效。
  - **iptables 切换安全性**：inline rule 必须写入 inactive generation chain；所有 IPv4/IPv6 规则均成功后才切换内置链 jump。准备阶段任一规则失败时删除未激活 generation 并保留当前 active generation；切换某一地址族失败时必须补偿回切已切换的地址族，不能先清空线上链，也不能累积重复 jump。
  - **旧 chain hooks 已删除**：原先跳到管理员外部 chain 的 `hooks:` 配置和运行时支持已移除；只支持 backend-native inline hooks。
  - **模型与 reconcile**：为 backend-native rule 定义独立 typed config/desired model，不把原始文本伪装成现有通用 `Rule`；hook point、backend、family、规则顺序和原始表达式必须进入 desired-state hash。沿用当前低频 reconcile 行为：nft apply 整表原子替换，iptables apply 生成并切换 generation；inline hooks 不额外引入独立刷新周期。
  - **校验与诊断**：限制单 point 规则数、单条长度和总配置大小；错误需包含 instance、backend、hook point 和规则序号。`higgs debug firewall` 同时展示原始表达式、最终 backend、family、渲染位置和 active/inactive 状态，并在 dry-run 中显示将要发生的 generation/table 替换。
  - **测试与验收**：已覆盖 YAML parse/strict-field、hash 稳定性、同一 point 多条规则的精确顺序、backend auto/显式选择、IPv4/IPv6 独立渲染、缺省 family 不复制、拒绝 `both`、危险 token 拒绝、无 shell 执行、表达式变更切换、staging/activation 失败回滚、无重复 jump 和无半套双栈规则；root/netns smoke 已真实通过 nft overlay/host input/prerouting，iptables 路径已写入同一 smoke，但当前机器缺少 `iptables`/`ip6tables`，仍待具备命令的 root 环境验收。
  - **文档交付**：同步更新 `docs/new/firewall.md`、配置参考和示例，明确两套表达式不具备可移植性、Higgs 不验证其业务语义、`DROP/ACCEPT/RETURN` 会改变后续规则可达性，以及错误规则会让本次 reconcile 失败但不应破坏上一 generation。

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

## Phase 8: 应用层服务与代理（待 root 数据面验收）

**目标：** 在 Higgs L3 mesh 上提供可发现、可授权的内网 SOCKS5 服务，同时支持本地唯一 endpoint 和 shared Anycast endpoint；应用层源路由 relay 保持独立演进。

**设计边界：**
- Higgs 只负责服务地址归属、签名 record 发布/撤销和动态防火墙授权；独立 `higgs-services` 读取 `/etc/higgs/service.yaml` 并生成 Docker Compose/代理配置。两者都不通过 Docker API 管理容器生命周期，Compose 由管理员检查后手工启停。
- 本地网络通过 `auto` 选择当前节点唯一的非 shared assignment；Anycast 网络通过 shared assignment 的稳定 tag（如 `socks5.cn`）选择，`region` 仍只是公开 endpoint 的服务选择属性。
- Docker bridge 位于 host netns，容器地址属于 Higgs 管理的服务前缀；host 侧通过指向 Higgs netns 的聚合路由和 Docker connected route 最长前缀匹配，overlay 侧复用显式 `routing.instances[].upstream` 返回 host。
- SOCKS5 第一版可使用 `NO AUTH`，由 Higgs overlay 身份/前缀和本机 firewall 提供 zone/node 级授权；这不承诺同一节点内的用户级身份区分。

- [x] **8.1 最小 service record 与显式发布**
  - 定义固定的 `services/socks5` / `service.socks5.v1` record；新记录用 endpoints 数组同时发布多个 `region/address/port`，并兼容旧单 endpoint 字段和可选 `active`。
  - 增加 `higgs service publish/withdraw`；每个发布地址必须落在当前节点 active assignment 内（普通或 shared），撤销写入 `active:false` 新版本。
  - service record 使用通用 `write`、严格 schema 和 route-authorization 归属验证；从 Higgs 主配置删除 Docker/Compose/service instance 模型。

- [x] **8.2 独立 Compose 生成与 host/overlay 网络接入**
  - [x] 新增独立 `higgs-services`：读取 `/etc/higgs/service.yaml`，通过 `higgs ipam mine` 获取运行态，把全部双栈 external network 写入同一份 network Compose。
  - [x] 固定 SOCKS5 服务生成 `socks`、`dns`、`h2` 三容器 Compose，支持多个 network、`auto`/`tag:` assignment 来源、相对 base address、固定镜像默认值和 resolved lock。
  - [x] 生成命令只原子写 artifact，不执行 `docker compose up/down/pull`。
  - 校验 Docker service subnet、host connected route、host -> Higgs netns 聚合路由和 overlay -> host static upstream 不冲突；启用 service 不隐式改变现有 upstream 边界。
  - 明确区分 host 数据面聚合路由与 Babel export：前者可指向 root 拥有的大前缀，后者仍只宣告本节点实际拥有/获授权的服务前缀。

- [x] **8.3 发布、防火墙与运行状态**
  - [x] 将 `allow_zones` 通过通用 endpoint ACL `{destination, protocol, port, selectors}` 持久化，并动态解析为已授权 overlay 来源前缀；host FORWARD 对 endpoint 先 allow 后精确 drop，空匹配保持 fail-closed。
  - [x] `higgs-services publish` 核对 resolved lock 和当前 assignment，对所有 endpoint 执行 TCP 健康检查和 ACL，只为 shared endpoint 宣告整个 assignment prefix，再发布多 endpoint record；withdraw 先撤销 record，再清理 shared route 和全部 ACL。
  - 增加 `services` / `proxy` 本机查询与诊断输出，展示地址归属、路由、firewall、readiness 和当前 record。

- [ ] **8.4 本地与 Anycast 数据面验证**
  - 已实现 `services-smoke`：真实 Docker bridge 上运行 SOCKS5 和目标 TCP 容器；client netns 经 BIRD/Babel、host route 和 static upstream 回程完成代理请求。
  - root smoke 断言 Docker connected route 优先于更宽的 host -> overlay 聚合路由；另一 Higgs 前缀仍命中该聚合路由。
  - non-owner service publish、shared tag 冲突、空 ACL selector fail-closed、未监听 endpoint 不发布分别由 `pkg/service`、routing、firewall 与 `higgs-services` 单元测试覆盖；shared prefix 成员故障收敛复用 BIRD Anycast root smoke。
  - 待在允许 netns 且具备目标 host firewall 配置的 root 环境执行 `sudo make services-smoke`；通过后即可归档 Phase 8。

- **8.5 不纳入 Phase 8**：客户端 service selection/health policy 不是 SOCKS5 发布数据面；Anycast 的 L3 选路和故障收敛交给 BIRD/Babel。出现明确客户端需求后再独立设计。

- [x] **8.6 IPAM shared Anycast 与多网络发布**
  - shared assignment 支持可选稳定 tag；tag 仅用于 shared，同 tag/同地址族强制对应同一 prefix，本地唯一 assignment 保持无 tag 的 `auto` 语义。
  - 同一 owner 的 shared assignment 按成员分别存储，`ipam revoke assignment --to` 可精确撤销成员。
  - `ipam.announce` 用 `non-shared`、`tag:<tag>` 等 selector 固化长期 announcement；服务 Anycast 不加入该列表，由服务生命周期控制。旧 `auto_announce_assigned_ips` 保持兼容。
  - `publish` 用 `network: region` 映射同时发布本地和任意数量 Anycast endpoint，并为 shared endpoint 显式宣告整个 assignment（IPv6 最具体 `/96`、IPv4 最具体 `/28`），不发布 `/128`/`/32` host route。
  - 多节点 route/成员故障收敛由 `services-smoke` 与 BIRD Anycast root smoke 验证。

- **8.7 不纳入 Phase 8**：应用层源路由 relay 是独立协议/项目，不与 SOCKS5 发布、IPAM 或 BIRD 数据面耦合。

## 下一步

1. 7.1 已完成并保持 StrongSwan 主链路现状；WG 底座与 GRE/VXLAN 正式实现分别留在可选 7.4/7.5，不作为当前主线的隐含下一步。
2. 7.3 chunk repair 已完成；下一窄实现切口按需求选择 7.7/7.8 discovery/relay 或 7.11 metrics/readmodel。
3. 后续模块化不再单独扩大范围；新增 debug/observer/control 输出默认走 `internal/inspect` view + `inspect/text` 或 `inspect/http` presenter，写侧/daemon adapter 继续留在 app 层直到接口稳定；公共 control DTO/typed client 等出现实际复用需求再迁移。
4. Phase 8 的实现、单元测试与 `services-smoke` 已就绪；待 root 数据面验收通过后归档。客户端服务选择和应用层 relay 按需作为独立项目评估。
5. Firewall 管理员扩展采用 7.16 的 backend-native inline hooks：先冻结 hook 顺序、失败原子性和配置校验，再实现 nft/iptables 两条渲染路径。
