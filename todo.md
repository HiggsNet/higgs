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
  - [x] 配置根信任公钥：`trusted_root_public_key`（hex/base64 ED25519 public key）
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

- [ ] **2.2 多节点传播**
  - [x] 支持 B-A-C bootstrap 拓扑下的 transitive zone propagation
  - [x] 新 Zone/Record 从 B 写入，经 A 传播到 C
  - [ ] 节点离线后重启，能通过摘要比较补齐缺失 Zone
  - [x] 增加 `make multi-node-smoke`，覆盖 3 节点本机流程

- [x] **2.3 同步状态可观测性**
  - [x] `higgs sync status` 输出每个 peer 的最近同步时间、已知 Zone 数、pending record 数
  - [x] 显示 local root hash / per-zone root hash / last error
  - [x] 扩展 `sync status` 用于排查 bootstrap 与 allowlist

- [ ] **2.4 Pending / FetchRecord 闭环**
  - 构造高版本 record 先到达的测试场景
  - 验证 pending store 中的缺前驱 record 会触发 `FETCH_RECORD`
  - 前驱补齐后自动提升 active
  - 为 stale/conflict/pending 增加明确 CLI 输出

- [ ] **2.5 同步协议收敛**
  - 明确 JSON wire format 的兼容边界和版本字段
  - 为 message size、zone count、record count 增加可配置限制
  - 梳理是否需要在 Phase 2 末尾切 protobuf；默认仍不引入 `protoc`

- [ ] **2.6 文档与操作手册**
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

- [ ] **6.6 运维与可观测性**
  - Prometheus metrics 导出（节点数、链路状态、Gossip 流量、Zone 数量）
  - 结构化日志（slog）
  - CLI 调试工具：`higgs status`, `higgs zones`, `higgs peers`, `higgs sync`

## 下一步

1. 开始 Phase 2 双节点端到端同步验证：node-admin root init → catofes. join → node-a/node-b join → record put → gossip sync → verify
2. 增加三节点传播 smoke：A-B-C 拓扑中 B 写入的 Zone/Record 能传播到 C
3. 强化 `sync status`：输出 per-peer / per-zone / pending / last error，方便排查同步状态
3. Phase 0 闭环验证：单机完成 `init` → `record put` → `verify chain` 的 CLI 流程
