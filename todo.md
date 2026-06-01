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
  - [x] 在 `Put(record)` 中接入本地 authority 验证、版本比较和冲突处理

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
  - [x] 保留 bounded `RecordHistory` 用于版本审计；普通同步不再维护 pending 补前驱状态

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
  - [x] 高版本 Record 验签通过后可作为 latest active state；历史补齐不阻塞普通同步
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

**目标：** 在不引入 WireGuard 的前提下，把配置状态同步做扎实：两节点可重复验证，三节点可传播，节点重启后可恢复，latest record / bounded history / conflict 状态可观测。

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
  - [x] `higgs sync status` 输出每个 peer 的最近同步时间、已知 Zone 数和本地 root hash
  - [x] 显示 local root hash / per-zone root hash / last error
  - [x] 扩展 `sync status` 用于排查 bootstrap 与 allowlist

- [ ] **2.4 Debug / Diagnostics 增强**
  - [x] 为 `sync serve` / `sync once` 增加结构化 debug log；`sync run` 接入留到 2.5 创建该命令时完成
  - [x] 输出消息方向、peer id、message type、zone 数、record 数、字节数、耗时
  - [x] 记录 reject 原因：unknown peer、addr mismatch、message too large、replay、quota、verify failed、unsupported wire version
  - [x] `sync status --verbose` 显示 bootstrap peers、discovered peers、allowlist 来源、resolved addr、last_success、last_error
  - [x] 增加 `higgs debug peer <peer-id>`：查看某个 peer 的最近同步、错误、backoff、known endpoint、发现来源
  - [x] 增加 `higgs debug zone <zone>`：查看 zone root、record/history 数量、delegation、parent proof、验证结果
  - [x] 支持 `HIGGS_LOG_LEVEL=debug` 或配置项开启详细日志，默认保持简洁输出

- [x] **2.5 自动重连与周期同步**
  - [x] 增加长期运行模式：`higgs sync run`
  - [x] `sync run` 同时执行 UDP serve 与周期性 outbound sync
  - [x] 对 bootstrap peers 定时执行摘要比较和缺失 Zone/Record 补齐
  - [x] peer 失败后记录 `last_error`，并使用 backoff 避免紧密重试
  - [x] 网络恢复后自动重试并收敛，不需要手动 `sync once`
  - [x] `sync status` 显示 peer online/stale/backoff/next_retry
  - [x] 增加 smoke：断开/停止 peer 后恢复，验证自动补齐

- [x] **2.6 链式拓扑主动传播 / relay fanout**
  - [x] 明确当前语义：在 A-B-C-D 链式 bootstrap 中，A 更新 record 后会优先同步/announce 给直接 peer B；C/D 默认依赖各自周期性摘要比较或 B 后续 outbound sync 才能得到更新
  - [x] 决定 Phase 2 目标语义：B/C 在成功 apply A 的新 Zone/Record 后，立即向除来源 peer 外的已知 peers 触发 lightweight sync round
  - [x] 增加基础变更来源 tracking：只在 zone digest 发生变化时 relay，并跳过来源 peer，避免 A-B-A、B-C-B 直接回环
  - [x] 为 relay 增加节流和批处理，避免一个 record 更新在稠密拓扑中产生广播风暴
  - [x] `sync run` 在本地 record put 或远端 apply 成功后，支持唤醒 outbound sync，而不是完全等待下一次 interval
  - [x] 增加 smoke：A-B-C-D 链式拓扑中 A 写入 record，验证 D 在无需等待完整轮询周期的情况下收敛
  - [x] `sync status --verbose` 显示已落盘的 peer 最近一次更新来源与 relay 抑制原因，方便离线排查“为什么只到 B 没到 C/D”

- [x] **2.7 Peer discovery / 动态 allowlist**
  - [x] 明确默认身份模型：普通节点的 `peer_id` 默认等于本节点授权 Zone（如 `node-a.catofes.`），bootstrap/discovery 均以 Zone FQDN 作为 peer id
  - [x] 明确 endpoint 模型：一个 `peer_id` 可对应多个 endpoint；多网卡、双栈、迁移地址不应引入多个 peer id
  - [ ] 定义高级例外：只有同一授权 Zone 下存在多个独立 gossip 实例/角色时，才引入 peer alias 或 instance id，并必须由该 Zone 显式授权
  - [x] 定义绑定约束：endpoint record 必须由对应授权 Zone 签名，声明的 `peer_id` 默认应等于该 Zone，声明的 endpoints 才能进入 discovered peer table
  - [x] 定义同步 endpoint record 格式，如 `sync/endpoints/udp` 或 `sync/peers/default`，支持一个 peer 下多个 endpoint
  - [x] 明确主路径：节点自动或手工获得自己的公网 endpoint 后，写入本 Zone 下的 signed endpoint record，再通过现有 bootstrap gossip 传播给其他节点
  - [x] 明确本机 endpoint 采集来源：手工配置的 `listen_addr` / `advertise_addr`、本机网卡地址扫描、public IP reflector 返回的公网地址；公网部署不考虑局域网 multicast/broadcast discovery
  - [x] 增加本机网卡地址扫描器：枚举可用 interface addresses，过滤 loopback、down interface、link-local、docker/容器/临时地址等不可发布地址，按 IPv4/IPv6、private/public、interface priority 生成候选 endpoint
  - [x] 增加显式 `advertise_addr` / `advertise_addrs` 配置，用于覆盖自动探测结果；自动发现只能补充，不应覆盖管理员显式声明
  - [x] 增加 public IP reflector 支持框架：可配置多个 reflector 服务（当前 stub，返回错误信号）
  - [x] 明确 reflector 结果只是本节点自发现输入：节点必须用自己的 Zone 私钥签名后写入 endpoint record，其他节点只信任 verified active state 中的 signed endpoint，不直接信任第三方 reflector
  - [x] 增加 reflector endpoint 定时刷新：配置 `reflector_interval` / `endpoint_ttl`，周期发布 endpoint record；IP 或端口变化时生成新的 signed endpoint record 版本并触发 outbound sync
  - [ ] 处理 endpoint 变更窗口：新 endpoint 发布后保留旧 endpoint grace period，远端根据 ttl/last_observed/连接成功情况逐步淘汰旧地址，避免公网 IP 切换时短暂失联
  - [x] 定义 endpoint 可信度与来源优先级：static advertise addr > signed active-state endpoint record > reflector-derived signed endpoint > interface scan；连接成功后提升可用性分数，失败/backoff 后降级
  - [x] endpoint record 中保留来源、scope、ttl、priority、last_observed 等元数据，避免把临时公网/NAT 反射地址永久固化为稳定配置
  - [x] 新节点加入时写入自己的 gossip endpoint record；如果启用自动探测，则先写入可验证的稳定候选，临时 observed endpoint 走 discovered peer table 而不是长期 record
  - [x] 从 verified active state 解析已授权 peer 的 endpoints
  - [x] 将 discovered peers 合并到运行时 known peer table，bootstrap 作为种子节点保留
  - [x] 接收包时仍按 peer id + endpoint allowlist 校验，避免 unknown peer 直接注入状态
  - [x] endpoint 变更后更新 known peer table，过期/撤销后标记 stale 或移除
  - [x] 增加 CLI 诊断：`higgs debug endpoints` 显示本机候选 endpoints、discovered peers；`sync status --verbose` 显示 discovered peers；`debug peer` 显示 discovered_addr
  - [x] 增加 smoke：`make discovery-smoke` 验证新 peer 发布 signed endpoint record 并经 gossip 传播后其他节点可动态发现
  - [ ] 增加 smoke：公网 endpoint 由 reflector 自动发现并签名发布；IP 变化后自动发布新版本，其他节点验证 record 后更新 known peer table，并在失败时回退 bootstrap/static endpoint

- [x] **2.8 Latest signed record / bounded history**
  - [x] 明确普通同步语义：更高版本且签名有效的 record 可直接成为 active，不要求从 `@1` 顺序重放
  - [x] `PrevHash` 降级为审计/调试约束：只有本地正好持有直接前驱时才检查，不阻塞跳版本 fast-forward
  - [x] Whole-zone snapshot 只同步 active records，不再把远端完整 `RecordHistory` 作为冷启动依赖
  - [x] 每个 `zone/key` 默认只保留最近 128 条历史版本，避免 DB 随版本无限膨胀
  - [x] 从普通同步主路径移除 pending 补前驱机制；最终一致性依赖 digest + snapshot + 更高版本 signed record
  - [x] 保留 `FETCH_RECORD` wire message 作为兼容和手工按需取单条历史 record 的能力

- [ ] **2.9 测试补强**
  - [ ] 为 `sync status --verbose`、`debug peer`、`debug zone` 增加 CLI golden/output 测试
  - [ ] 增加 gossip 故障注入测试：unknown peer、addr mismatch、message too large、replay、quota、unsupported wire version
  - [ ] 增加 verify failure 测试：错误 root key、篡改 delegation、篡改 record signature、过期 authority key
  - [ ] 增加 latest-record 边界测试：跳版本 fast-forward、同版本冲突、直接前驱 PrevHash mismatch、历史窗口裁剪、重启恢复
  - [ ] 增加 snapshot limit 测试：zone count、record count、message bytes 达到边界时的 accept/reject 行为
  - [ ] 增加 sync run 自动重连集成测试：peer 停止、恢复、backoff、最终收敛
  - [ ] 增加 relay fanout 集成测试：链式拓扑、去重、节流、最终收敛时间边界
  - [ ] 增加 peer discovery 集成测试：endpoint record 发布、更新、撤销后 known peer table 收敛
  - [ ] 将需要 UDP 的测试与纯逻辑测试分层，确保受限环境仍能跑完非网络测试
  - [ ] 为 smoke 目标输出失败时的关键日志，减少 CI/本机排障成本

- [x] **2.10 同步协议收敛**
  - [x] 明确 JSON wire format 的兼容边界和版本字段
  - [x] 为 message size、zone count、record count 增加可配置限制
  - [x] 梳理是否需要在 Phase 2 末尾切 protobuf；默认仍不引入 `protoc`

- [ ] **2.11 文档与操作手册**
  - README 增加双节点完整同步脚本
  - README 增加三节点传播示例
  - README 记录链式拓扑传播语义：周期收敛 vs 主动 relay fanout 的差异
  - 记录常见错误：root public key 不匹配、unknown peer、UDP socket 不允许、record conflict

- [ ] **2.12 应用运行时与依赖边界整理**
  - [ ] 盘点并收敛 CLI 层隐式依赖：config/state/store、sync transport、known peer table、logger、clock、stdout/stderr、validation hooks
  - [ ] 引入轻量 `Runtime` / `App` struct，负责一次性加载 `appConfig`、解析 state path、打开/保存 `stateFile`，并缓存由 config 派生出的 sync config
  - [ ] 将 `loadState()` / `saveState()` 拆出显式依赖版本，如 `loadStateAt(path, trustRoot)`、`saveStateAt(path, state)`；保留薄 wrapper 兼容简单 CLI 命令
  - [ ] 避免热路径重复读配置：`handleSyncPacket`、`relaySync`、`syncRoundWithTransport` 使用运行时持有的 sync config、limits、debug logger
  - [ ] 引入 `SyncRuntime` / `SyncService`，聚合 `state`、`syncConfig`、`transport`、`limits`、`logger`、`clock`，把 packet handling、round、relay fanout 收为方法
  - [ ] 将 `openSyncTransport` 的 replay window、peer quotas、known peers、debug logger 从局部构造改为运行时可配置依赖，为动态 discovery 和测试注入留接口
  - [ ] 把 `configureValidation(state.Network)` 这类散落调用收敛到 state/network 加载边界，或明确为 `Runtime.ConfigureNetworkValidation()`，避免忘记调用导致行为差异
  - [ ] 将 `time.Now()` 的同步/backoff/record timestamp 使用收敛到运行时 clock；生产默认真实时间，测试可注入固定时间
  - [ ] 将 CLI 输出从业务函数中逐步隔离：命令层负责 `fmt.Printf`，核心函数返回结构化结果；优先处理 sync status/debug/db dump 等未来要做 golden test 的命令
  - [ ] 梳理文件 I/O 边界：key/join bundle/config/state 读写保留在 app 层，`pkg/core/*` 继续保持纯模型和协议逻辑
  - [ ] 保持重构边界克制：不要把签名验证、snapshot、record put 等 core 逻辑塞进大对象；struct 只负责生命周期、依赖注入和运行态协调
  - [ ] 增加针对 runtime 的单元测试：config 只加载一次、state path/env 覆盖优先级、trusted root 校验、sync limits 派生、debug log env/config 优先级
  - [ ] 重构后跑通 `make check`、`make phase2-smoke`、`make multi-node-smoke`、`make chain-relay-smoke`

- [ ] **2.13 Delegation 撤销 / Zone 删除语义**
  - [ ] 明确删除模型：父 Zone 中的 delegation 是子 Zone 授权的唯一权威来源；删除子 Zone 必须由父 Zone 写入 signed revocation/tombstone，而不是仅从本地 map 中移除
  - [ ] 定义 revocation/tombstone 数据结构：包含 child zone、parent zone、revoked authority epoch/hash、reason、revoked_at、ttl/grace、signer，并由父 Zone authority 签名
  - [ ] 定义父 Zone snapshot 的优先级：同一 child 的有效 delegation 与 revocation 冲突时，以父 Zone 中版本/epoch 更新且签名有效的状态为准；子 Zone 的 `ParentProof` 只是缓存，不可覆盖父 Zone 撤销
  - [ ] 撤销后，本地 active state 将该 Zone 及其子树标记为 revoked/quarantined：停止接受该 Zone 新 record、停止 relay 其新 announce、停止将其 endpoints 加入 known peer table
  - [ ] 保留已撤销 Zone 的历史数据用于审计和冲突排查，但默认查询、配置生成、peer discovery、route authorization 不再使用其 active records
  - [ ] 清理撤销子树相关 sync peer 状态、discovered endpoints、relay fanout 队列，避免已撤销节点继续通过 relay 恢复活跃状态
  - [ ] 增加 CLI：`higgs delegate revoke <zone>` 由父 Zone 管理者签发撤销；`higgs debug zone <zone>` 显示 revoked 状态、撤销来源、撤销时间和影响子树
  - [ ] 增加 gossip 同步语义：revocation/tombstone 必须进入 zone digest/snapshot，传播优先级高于普通 record，节点收到后立即触发 outbound sync/relay fanout
  - [ ] 增加测试：撤销普通节点 Zone 后，其他节点拒绝其新 record 和 endpoint；撤销中间管理 Zone 后，其整个子树失效；重启后 revoked 状态仍持久化
  - [ ] 增加 smoke：A/B/C 已建立同步后，管理员撤销 node-b delegation，A/C 收敛后不再信任 B 的 record、endpoint、route announcement

- [x] **2.14 Bootstrap 准入死锁 / 新节点首次接入问题**
  - [x] 问题：Transport.validatePeer() 仅接受有 endpoint record 的 peer，新节点 B 首次向 A 发 Ping 时被拒（ErrUnknownPeer），B 的 endpoint 永远无法传播给 A，形成死锁
  - [x] 根因：传输层 `knownPeers` 混淆了「准入控制（身份）」与「地址发现（可达性）」两个角色
  - [x] 修复：拆分准入与地址概念
    - [x] `Transport.AddKnownPeerID(peerID)`：只写入 `knownPeers` 入站白名单，不写 `outboundAddrs`
    - [x] `addVerifiedZonePeers()`：扫描 active state 中所有 `VerifyChain` 通过的 zone，调用 `AddKnownPeerID` 加入白名单
    - [x] `openSyncTransport` / `updateDiscoveredPeers`：初始化时先执行 `addVerifiedZonePeers`，有 endpoint record 的再追加 `SetPeerAddrs`
    - [x] `Transport.lastSeenAddrs`：Send() 无静态 outbound 地址时，回退到最近 inbound 包的 UDP 源地址，使 A 能在无 B 的 endpoint record 时仍回复首条 Pong
  - [x] 安全边界：入站白名单放宽到「有合法 delegation chain」的 zone，但消息内容仍经过完整 `VerifyChain` / `VerifyRecord` 验证，信任根不变
  - [x] 增加 `pkg/core/gossip/transport_test.go`：AddKnownPeerID / lastSeenAddrs 单元测试
  - [x] 增加 `app/higgs/sync_test.go`：openSyncTransport / updateDiscoveredPeers 单元测试（构造 root→catofes→node-b delegation chain）
  - [x] 增加 `make bootstrap-join-smoke`：验证全新节点 B 只配置 bootstrap A、A 有 B 的 zone 但无 endpoint record 时，双向 gossip 同步成功建立

## Phase 3: WireGuard 建链（预计 2-3 周）

**目标：** 两个节点能根据同步后的 Zone 配置自动建立 WG 隧道。

- [ ] **3.0 最小节点 daemon / 单 writer 边界**
  - [ ] 增加 `higgs daemon` 常驻模式，复用 `sync run` 的 UDP serve + outbound sync 循环，并为后续 WG/Babel/firewall apply 提供统一事件循环
  - [ ] 明确 daemon 是本节点 state DB 的唯一长期 writer；`record put`、`sync trigger`、未来 WG apply 等写操作应通过 daemon 进入同一串行写入路径
  - [ ] CLI 在检测到 daemon control socket 存在时，优先作为 client 提交写命令；daemon 不存在时保留当前直接写 DB 的开发模式，并输出明确提示
  - [ ] 提供最小 Unix domain socket 控制接口：status、record put、sync trigger、shutdown/reload 预留；只要求本机使用，不做远程管理
  - [ ] `sync status --verbose` / `debug peer` 优先读取 daemon live 状态；daemon 不存在时 fallback 到 bbolt 快照
  - [ ] 将 `sync run` 标记为开发/兼容入口，内部可委托 daemon service 实现，避免 Phase 3 后出现两套长期运行路径
  - [ ] 增加 smoke：daemon 运行时 CLI `record put` 通过 control socket 提交，daemon 写 DB、触发 gossip sync，远端收敛
  - [ ] 增加并发安全测试：daemon 运行期间多个 CLI 写命令串行处理，不出现旧 state snapshot 覆盖新写入

- [ ] **3.1 WireGuard 控制模块**
  - 通过 `wgctrl-go` 操作内核 WG 接口
  - 由 daemon 监听 active state 变更并触发 WG apply，避免独立 CLI 进程直接修改运行中状态
  - 监听 `*.<parent_zone>./wireguard/*` Record 变更
  - 从 Zone 推导 PeerView：`PublicKey`、`Endpoints`、`TunnelAllowedIPs`、`AnnouncedRoutes`
  - 应用 WG 配置（add/remove/update peer）
  - 当 peer Zone 被撤销或其父 delegation 被 tombstone 时，立即从 WireGuard device 移除对应 peer、AllowedIPs、endpoint 与 keepalive 配置
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
  - 节点 Zone 被撤销后标记 revoked，高优先级触发传输层/路由层/防火墙 apply，不等待普通健康检查超时

- [ ] **5.5 防火墙规则同步**
  - 基于已同步的 Zone 中所有合法节点的 TunnelAllowedIPs
  - 通过 `nftables` netlink 接口生成 accept 规则，默认 drop
  - 节点或子树被撤销后立即移除对应 allow rules，避免已撤销节点继续访问 overlay

- [ ] **5.6 撤销后的传输与路由清理**
  - WireGuard：删除被撤销 peer 的 public key、endpoint、AllowedIPs、persistent keepalive，并撤销相关 tunnel address
  - IKEv2/StrongSwan：删除被撤销 peer 的 connection/child SA 配置，主动 terminate 已建立 SA，移除对应 secret/cert/key reference
  - Babeld/BIRD：移除被撤销 peer/interface 的邻居关系、import filter whitelist、已学习路由，必要时触发 route flush
  - 防火墙：移除该 peer/subtree 的 nftables accept rules、set entries、rate-limit exceptions
  - IPAM/route authorization：被撤销 Zone 及其子树发布的 IP assignment、route announcement 立即从有效配置中剔除；历史记录仅用于审计
  - 增加 apply dry-run 输出：撤销某 Zone 会删除哪些 WG/IKEv2/Babel/firewall/IPAM 对象，便于管理员确认影响范围
  - 增加集成测试：撤销节点后，控制平面状态先收敛，随后本机 WG/IKEv2/Babel/firewall 配置全部清理完成

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

- [ ] **6.6 可选 Global Discovery Server**
  - 作为独立公网服务提供 peer rendezvous，只用于无稳定 bootstrap、IP 频繁变化、复杂 NAT 等场景；默认 peer discovery 仍以 signed endpoint record + gossip 传播为主
  - 服务端不成为信任根，不持有 root/admin/zone 私钥；客户端仍以 signed endpoint record 和 Zone trust chain 为准
  - 支持最小 HTTP/JSON API：`POST /v1/announce` 上报本机 signed endpoint，`GET /v1/peers/{peer_id}` 查询候选 endpoints、observed addr、ttl 和 source
  - 服务端负责 ttl cache、observed remote addr、限流、防重放和基础滥用防护；不替客户端做最终信任裁决
  - 支持配置多个 discovery server URL，客户端合并查询结果并按 endpoint 可信度/连接成功率排序

- [ ] **6.7 可选 Relay Bootstrap Server**
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

- [ ] **6.8 Daemon / 本地控制接口生产化**
  - [ ] 在 Phase 3 最小 daemon 基础上完善运行形态：`higgs daemon` 常驻负责 gossip 同步、active state 更新、WG/IKEv2/Babel/firewall apply
  - [ ] CLI 默认作为 daemon client，通过本地控制接口查询状态或提交操作；直接写 DB 模式仅保留为 debug/recovery
  - [ ] 完善 Unix domain socket 控制接口，默认仅本机 root/admin 用户可访问
  - [ ] 预留 TCP control listener，用于受控远程管理；默认关闭，必须显式配置监听地址与认证
  - [ ] 定义控制 API：status、peers、zones、records、history、conflicts、sync trigger、reload config、apply dry-run
  - [ ] `sync status --verbose` / `debug peer` 优先通过本地控制接口查询正在运行的 daemon，显示 live relay 队列、最近更新来源、relay 抑制原因、backoff 和下一次 sync 计划；daemon 不可用时 fallback 到 DB 快照
  - [ ] 控制 API 输出结构化 JSON，CLI 负责格式化成人类可读输出
  - [ ] 加入认证与授权边界：Unix socket 文件权限、token/mTLS 预留、只读/管理操作分级
  - [ ] daemon 生命周期：启动、优雅停止、reload、状态持久化、崩溃恢复
  - [ ] systemd service 示例和 socket 路径约定，如 `/run/higgs/higgs.sock`

- [ ] **6.9 运维与可观测性**
  - Prometheus metrics 导出（节点数、链路状态、Gossip 流量、Zone 数量）
  - 结构化日志（slog）
  - CLI 调试工具：`higgs status`, `higgs zones`, `higgs peers`, `higgs sync`

## 下一步

1. 开始 Phase 2 双节点端到端同步验证：node-admin root init → catofes. join → node-a/node-b join → record put → gossip sync → verify
2. 增加三节点传播 smoke：A-B-C 拓扑中 B 写入的 Zone/Record 能传播到 C
3. 强化 `sync status`：输出 per-peer / per-zone / history / last error，方便排查同步状态
3. Phase 0 闭环验证：单机完成 `init` → `record put` → `verify chain` 的 CLI 流程
