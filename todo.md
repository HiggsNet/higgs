# Higgs Todo

设计文档见 [docs/design.md](docs/design.md)。本文件只保留可执行任务。

## Phase 0: 单机可信状态机（预计 1-2 周）

**目标：** 在单机完成可验证的配置状态机，不依赖网络。

- [x] **0.1 项目结构**
  - 入口目录：沿用当前 `app/higgs/`；后续如需要标准 Go 布局，再迁移到 `cmd/higgs/`
  - [x] 已创建：`pkg/core/zone/`, `pkg/crypto/`
  - [x] 待创建：`pkg/core/{identity,merkle,gossip}`, `pkg/transport/wireguard/`, `pkg/routing/babeld/`
  - Go 版本已按当前依赖更新为 `go 1.25.0`
  - [x] 引入 Phase 0 依赖：`go.etcd.io/bbolt`, `golang.org/x/crypto`
  - `golang.zx2c4.com/wireguard/wgctrl`, `github.com/vishvananda/netlink` 延后到 WireGuard/路由阶段引入，避免 Phase 0 携带未使用依赖

- [x] **0.2 身份与密钥系统**
  - [x] ED25519 主密钥生成与本地存储
  - [x] 提供 passphrase + bcrypt 加密私钥工具；Phase 0 CLI 默认不强制使用，bbolt 状态库保持本地明文调试语义
  - [x] NodeID = blake2b(pubkey)

- [x] **0.3 Zone / Authority / Delegation / Record 基础模型**
  - [x] 定义设计文档中的核心数据结构
  - [x] 实现 `Get(fqkey)`：解析 Zone + Key → 本 Zone 查找 → 向上 fallback 直到根
  - [x] 实现基础 `Put(record)` 写入 active state
  - [x] 在 `Put(record)` 中接入本地 authority 验证、版本链和 pending record 处理

- [x] **0.4 签名与验证**
  - [x] 实现 Record / Delegation 的 Sign 和 Verify
  - [x] 实现 ZoneAuthority canonical hash
  - [x] 实现 VerifyChain
  - [x] 定义并使用 domain separator
  - [x] Phase 0 只接受 `threshold=1`，遇到 `threshold>1` 返回 `unsupported threshold`
  - [x] 预留 `Delegation.Scope`；Phase 0 只接受 `direct-child`，遇到 `subtree` 返回 `unsupported delegation scope`

- [x] **0.5 bbolt 持久化**
  - [x] 按 Zone 分 bucket 存储
  - [x] 加载/恢复/版本链审计
  - [x] 保留 `PendingRecords`，补齐版本链后再提升为 active

- [x] **0.6 CLI 调试**
  - [x] `higgs init`
  - [x] `higgs zone show <zone>`
  - [x] `higgs record put <zone> <key> <value>`
  - [x] `higgs verify <zone>`
  - [x] `higgs db dump [zone]`：以只读模式打开 bbolt，按 bucket 打印 key-value（JSON 美化）
  - [x] `higgs db stats`：统计各 bucket 的 key 数和数据大小

## Phase 1: 两节点 Zone 同步（预计 1-2 周）

**目标：** 跑通安全边界明确的同步流程。

- [x] **1.1 Gossip 传输层**
  - [x] UDP socket 监听（固定端口，如 33434）
  - [x] Protobuf 消息定义：`Ping`, `Pong`, `FetchZone`, `FetchRecord`, `Announce`
    - 已补 `gossip.proto`；Go 代码先使用稳定 message/codec，后续接入 pb 生成代码
  - [x] Anti-replay：64-bit nonce + 时间戳窗口（±5分钟）
  - [x] 限流与配额：每 peer 限制速率/字节/对象数

- [x] **1.2 节点发现**
  - [x] 通过配置文件中的 bootstrap 列表启动
  - [x] 仅接受已知 peer 的连接

- [x] **1.3 Whole-Zone 同步**
  - [x] Phase 1A 先不做 Merkle diff，hash 不同直接拉完整 Zone
  - [x] 数据进入候选状态（quarantine 语义），验签通过后才提升到 active store
  - [x] 逐条验证签名链（VerifyDelegation → VerifyRecord → VerifyChain）
  - [x] 缺失前驱的 Record 进入 `pending store`
  - [x] 验证通过后提升到 `active store`

- [x] **1.4 闭环验证**
  - [x] 节点 A 修改本地 Zone Record
  - [x] Gossip 到节点 B（`higgs sync serve` + `higgs sync once <peer>`）
  - [x] B 验证通过后 active store 可见
  - [x] CLI: `higgs sync status`

## Phase 1.5: 配置与节点准入工具（已完成）

**目标：** 把 Phase 1 的手工状态准备收敛成固定配置文件和可重复的 join/delegation 流程。

- [x] **1.5.1 固定配置文件**
  - [x] 默认读取 `config.yaml`，可用 `HIGGS_CONFIG=/path/to/config.yaml` 覆盖
  - [x] 配置数据库目录：`data_dir` / `database_dir`，默认状态库为 `<data_dir>/higgs.db`
  - [x] 配置监听地址：`listen_addr`，或用 `listen_port` 生成 `:<port>`
  - [x] 配置 bootstrap allowlist：`bootstrap: [{id, addr}]`
  - [x] 配置根信任公钥：`trusted_root_public_key`（默认 base64，兼容 hex 的 ED25519 public key）
  - [x] 提供 `config.example.yaml`

- [x] **1.5.2 根 Zone 与准入 CLI**
  - [x] `higgs root init`：只创建根域 `.` 的 root authority
  - [x] `higgs root pubkey`：输出根公钥，供其他节点配置 `trusted_root_public_key`
  - [x] root/admin 状态库与业务节点状态库分离；`node-admin` 只持有 `.` 的 root 私钥
  - [x] 一级管理 Zone（如 `catofes.`）也通过 join request / root delegation 独立加入，并由自己的管理私钥继续委派子 Zone
  - [x] `higgs keygen <key.json>`：生成新节点 ED25519 keypair
  - [x] `higgs join request <zone> <key.json> <request.json>`：新节点生成加入申请
  - [x] `higgs delegate issue <request.json> <bundle.json>`：父 Zone 持有者签发 delegation bundle
  - [x] `higgs join accept <bundle.json> <key.json>`：新节点导入信任链和本 Zone authority
  - [x] 新节点不会接触 root/admin 私钥，只持有自己的 Zone 私钥

- [x] **1.5.3 验证目标**
  - [x] `make check`：格式化、vet、单元测试、构建
  - [x] `make join-smoke`：本地验证 root/delegation/join/record/verify 流程
  - [x] `make phase1-smoke`：本地两 peer UDP gossip smoke；需要运行环境允许 UDP socket

## Phase 2: 双节点/多节点配置同步收敛（预计 1-2 周）

**目标：** 在不引入 WireGuard 的前提下，把配置状态同步做扎实：两节点可重复验证，三节点可传播，节点重启后可恢复，冲突/缺前驱/pending 状态可观测。

- [x] **2.1 双节点端到端同步验证**
  - [x] `node-admin` 创建 root `.`，不持有 `catofes.` 私钥
  - [x] `zone-catofes-admin` 通过 root delegation 加入并管理 `catofes.`
  - [x] `node-a`、`node-b` 都通过 `catofes.` delegation bundle 加入
  - [x] `node-a` / `node-b` 分别写入本 Zone record
  - [x] A/B 通过 gossip 双向同步
  - [x] 两端 `sync status`、`zone show`、`verify` 结果一致
  - [x] 将流程固化为不依赖手工复制 DB 的 `make phase2-smoke`

- [x] **2.2 多节点传播**
  - [x] 支持 B-A-C bootstrap 拓扑下的 transitive zone propagation
  - [x] 新 Zone/Record 从 B 写入，经 A 传播到 C
  - [x] 节点离线后重启，能通过摘要比较补齐缺失 Zone
  - [x] 增加 `make multi-node-smoke`，覆盖 3 节点本机流程

- [x] **2.3 同步状态可观测性**
  - [x] `higgs sync status` 输出每个 peer 的最近同步时间、已知 Zone 数、pending record 数
  - [x] 显示 local root hash / per-zone root hash / last error
  - [x] 扩展 `sync status` 用于排查 bootstrap 与 allowlist

- [ ] **2.4 Debug / Diagnostics 增强**
  - [x] 为 `sync serve` / `sync once` 增加结构化 debug log；`sync run` 接入留到 2.5 创建该命令时完成
  - [x] 输出消息方向、peer id、message type、zone 数、record 数、字节数、耗时
  - [x] 记录 reject 原因：unknown peer、addr mismatch、message too large、replay、quota、verify failed、unsupported wire version
  - [x] `sync status --verbose` 显示 bootstrap peers、discovered peers、allowlist 来源、resolved addr、last_success、last_error
  - [x] 增加 `higgs debug peer <peer-id>`：查看某个 peer 的最近同步、错误、backoff、known endpoint、发现来源
  - [x] 增加 `higgs debug zone <zone>`：查看 zone root、record/history/pending 数量、delegation、parent proof、验证结果
  - [x] 增加 `higgs debug pending`：列出 pending record、缺失 predecessor、预计 FETCH_RECORD selector
  - [x] 支持 `HIGGS_LOG_LEVEL=debug` 或配置项开启详细日志，默认保持简洁输出

- [ ] **2.5 自动重连与周期同步**
  - [ ] 增加长期运行模式：`higgs sync run`
  - [ ] `sync run` 同时执行 UDP serve 与周期性 outbound sync
  - [ ] 对 bootstrap peers 定时执行摘要比较和缺失 Zone/Record 补齐
  - [ ] peer 失败后记录 `last_error`，并使用 backoff 避免紧密重试
  - [ ] 网络恢复后自动重试并收敛，不需要手动 `sync once`
  - [ ] `sync status` 显示 peer online/stale/backoff/next_retry
  - [ ] 增加 smoke：断开/停止 peer 后恢复，验证自动补齐

- [ ] **2.6 Peer discovery / 动态 allowlist**
  - [ ] 明确默认身份模型：普通节点的 `peer_id` 默认等于本节点授权 Zone（如 `node-a.catofes.`），bootstrap/discovery 均以 Zone FQDN 作为 peer id
  - [ ] 明确 endpoint 模型：一个 `peer_id` 可对应多个 endpoint；多网卡、双栈、迁移地址不应引入多个 peer id
  - [ ] 定义高级例外：只有同一授权 Zone 下存在多个独立 gossip 实例/角色时，才引入 peer alias 或 instance id，并必须由该 Zone 显式授权
  - [ ] 定义绑定约束：endpoint record 必须由对应授权 Zone 签名，声明的 `peer_id` 默认应等于该 Zone，声明的 endpoints 才能进入 discovered peer table
  - [ ] 定义同步 endpoint record 格式，如 `sync/endpoints/udp` 或 `sync/peers/default`，支持一个 peer 下多个 endpoint
  - [ ] 新节点加入时写入自己的 gossip endpoint record
  - [ ] 从 verified active state 解析已授权 peer 的 endpoints
  - [ ] 将 discovered peers 合并到运行时 known peer table，bootstrap 作为种子节点保留
  - [ ] 接收包时仍按 peer id + endpoint allowlist 校验，避免 unknown peer 直接注入状态
  - [ ] endpoint 变更后更新 known peer table，过期/撤销后标记 stale 或移除
  - [ ] 增加 smoke：新 peer 不手写到所有节点 bootstrap，也能经已知节点发现并同步

- [ ] **2.7 Pending / FetchRecord 闭环**
  - [x] 构造高版本 record 先到达的测试场景
  - [x] 验证 pending store 中的缺前驱 record 会触发 `FETCH_RECORD`
  - [x] 前驱补齐后自动提升 active
  - [ ] 为 stale/conflict/pending 增加明确 CLI 输出

- [ ] **2.8 测试补强**
  - [ ] 为 `sync status --verbose`、`debug peer`、`debug zone`、`debug pending` 增加 CLI golden/output 测试
  - [ ] 增加 gossip 故障注入测试：unknown peer、addr mismatch、message too large、replay、quota、unsupported wire version
  - [ ] 增加 verify failure 测试：错误 root key、篡改 delegation、篡改 record signature、过期 authority key
  - [ ] 增加 pending 边界测试：重复 pending、冲突版本、stale record、缺多级 predecessor、pending 持久化后重启恢复
  - [ ] 增加 snapshot limit 测试：zone count、record count、message bytes 达到边界时的 accept/reject 行为
  - [ ] 增加 sync run 自动重连集成测试：peer 停止、恢复、backoff、最终收敛
  - [ ] 增加 peer discovery 集成测试：endpoint record 发布、更新、撤销后 known peer table 收敛
  - [ ] 将需要 UDP 的测试与纯逻辑测试分层，确保受限环境仍能跑完非网络测试
  - [ ] 为 smoke 目标输出失败时的关键日志，减少 CI/本机排障成本

- [x] **2.9 同步协议收敛**
  - [x] 明确 JSON wire format 的兼容边界和版本字段
  - [x] 为 message size、zone count、record count 增加可配置限制
  - [x] 梳理是否需要在 Phase 2 末尾切 protobuf；默认仍不引入 `protoc`

- [ ] **2.10 文档与操作手册**
  - README 增加双节点完整同步脚本
  - README 增加三节点传播示例
  - 记录常见错误：root public key 不匹配、unknown peer、UDP socket 不允许、pending 未补齐

## Phase 3: WireGuard 建链（预计 2-3 周）

**目标：** 两个节点能根据同步后的 Zone 配置自动建立 WG 隧道。

- [ ] **3.1 WireGuard 控制模块**
  - 通过 `wgctrl-go` 操作内核 WG 接口
  - 监听 `*.<parent_zone>./wireguard/*` Record 变更
  - 从 Zone 推导 PeerView：`PublicKey`、`Endpoints`、`TunnelAllowedIPs`、`AnnouncedRoutes`
  - 应用 WG 配置（add/remove/update peer）
  - WG AllowedIPs 只放 tunnel /32 或 /128，业务路由交给 Babeld

- [ ] **3.2 链路实例管理**
  - 当 WG peer 建立后，生成 LinkInstance
  - 跟踪链路状态：up/down/stale

- [ ] **3.3 最小闭环验证**
  - 节点 A 和 B 同步配置
  - 自动为对方添加 WG Peer
  - `wg show` 看到握手成功
  - 互相 ping 通 tunnel IP

## Phase 4: Babeld 路由 + Route Authorization Filter（预计 2-3 周）

**目标：** babeld 在 WG 接口上发现邻居、学习路由，且只接受被授权的前缀。

- [ ] **4.1 Babeld 路由适配器**
  - 启动 babeld 并通过控制 socket（`-G` Unix/TCP socket）发送命令
  - 命令封装：`add interface wg0`、`flush interface wg0`
  - 当 WG 接口建立/拆除时，动态通知 babeld 添加/移除接口

- [ ] **4.2 Route Authorization Filter**
  - 根据 active state 中的 `routes/announcements/*` 和 `ipam/assignments/*` 生成 prefix whitelist
  - 为每个 peer/interface 生成 babeld `import filter`
  - 拒绝 `0.0.0.0/0`、未授权前缀、他人网段

- [ ] **4.3 本地路由注入**
  - 通过 babeld 控制 socket 的 `install` / `uninstall` 注入本节点 AnnouncedRoutes
  - 或通过 `redistribute` 配置让 babeld 自动学习

- [ ] **4.4 闭环验证**
  - 3+ 节点组网
  - Babeld 在 wg0 上发现邻居，交换路由
  - 节点 A 尝试宣告未授权前缀时被其他节点过滤掉

## Phase 5: IPAM/准入扩展/防火墙（预计 3-4 周）

**目标：** 支持动态准入、IP 分配、链路健康、防火墙规则。

- [ ] **5.1 准入流程**
  - 新节点生成密钥对 → 向管理员申请 delegation
  - 管理员在父 Zone 创建 `nodeX.parent.` delegation
  - Gossip 全网传播后，新节点自动被所有节点识别并建立 WG Peer

- [ ] **5.2 IP 分配管理（IPAM）**
  - 拆分语义：`ipam/pools/*`、`ipam/assignments/*`、`routes/announcements/*`
  - 节点查询自己的 Zone fallback 路径，汇总所有分配到的 IPs
  - 冲突检测：按 ownership + version-chain 裁决，禁止仅按时间戳

- [ ] **5.3 链路健康检测**
  - 在 WG 隧道上周期性发送 ICMP/自定义 keepalive
  - 检测 RTT、丢包率
  - 链路异常时标记 down，从 babeld 接口中移除或降低优先级

- [ ] **5.4 动态 Peer 管理**
  - 节点离线超时后，保留配置但标记 stale
  - 长期离线后自动清理 WG Peer 和路由
  - 节点信息变更（endpoint、pubkey rotate）自动更新 WG 配置

- [ ] **5.5 防火墙规则同步**
  - 基于已同步的 Zone 中所有合法节点的 TunnelAllowedIPs
  - 通过 `nftables` netlink 接口生成 accept 规则，默认 drop

## Phase 6: 健壮性与高级特性（预计 4-6 周）

**目标：** 生产可用，支持多线路、跳频、扩展传输协议。

- [ ] **6.1 多线路并行（Multipath）**
  - 一个 Peer 可建立多条 TransportLink（WG over 公网 + WG over 内网 + GRE）
  - 每条链路独立运行 babeld 接口
  - babeld 自动进行多路径负载均衡（Babel 原生支持 ECMP）

- [ ] **6.2 UDP 端口跳频（Port Hopping）**
  - 先实现多 endpoint / 多 port probe 与质量选择
  - 如需 rotate，必须包含：old-port grace period、clock skew 容忍、fallback static port、失联恢复路径

- [ ] **6.3 IKEv2 (StrongSwan) 传输驱动**
  - 通过 vici 协议控制 StrongSwan
  - 复用 Zone K-V 中的 `ipsec/*` Record

- [ ] **6.4 VXLAN Overlay**
  - 在 WG 三层网络上封装 VXLAN
  - 通过 Zone Record 同步 VNI、VTEP 信息

- [ ] **6.5 SRv6 支持（实验性）**
  - 通过 netlink 配置 SRv6 SID、End.DT4/End.DX6 行为
  - 与 BIRD/FRR 的 SRv6 扩展联动（如后续引入 BGP）

- [ ] **6.6 Daemon / 本地控制接口**
  - [ ] 明确运行形态：`higgs daemon` 常驻运行，负责 gossip 同步、active state 更新、WG/IKEv2/Babel/firewall apply
  - [ ] CLI 默认作为 daemon client，通过本地控制接口查询状态或提交操作
  - [ ] 提供 Unix domain socket 控制接口，默认仅本机 root/admin 用户可访问
  - [ ] 预留 TCP control listener，用于受控远程管理；默认关闭，必须显式配置监听地址与认证
  - [ ] 定义控制 API：status、peers、zones、records、pending、sync trigger、reload config、apply dry-run
  - [ ] 控制 API 输出结构化 JSON，CLI 负责格式化成人类可读输出
  - [ ] 加入认证与授权边界：Unix socket 文件权限、token/mTLS 预留、只读/管理操作分级
  - [ ] daemon 生命周期：启动、优雅停止、reload、状态持久化、崩溃恢复
  - [ ] systemd service 示例和 socket 路径约定，如 `/run/higgs/higgs.sock`

- [ ] **6.7 运维与可观测性**
  - Prometheus metrics 导出（节点数、链路状态、Gossip 流量、Zone 数量）
  - 结构化日志（slog）
  - CLI 调试工具：`higgs status`, `higgs zones`, `higgs peers`, `higgs sync`

## 下一步

1. 开始 Phase 2 双节点端到端同步验证：node-admin root init → catofes. join → node-a/node-b join → record put → gossip sync → verify
2. 增加三节点传播 smoke：A-B-C 拓扑中 B 写入的 Zone/Record 能传播到 C
3. 强化 `sync status`：输出 per-peer / per-zone / pending / last error，方便排查同步状态
3. Phase 0 闭环验证：单机完成 `init` → `record put` → `verify chain` 的 CLI 流程
