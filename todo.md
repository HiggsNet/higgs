# Higgs Todo

设计文档见 [docs/design.md](docs/design.md)。本文件只保留可执行任务。

## Phase 0: 单机可信状态机（预计 1-2 周）

**目标：** 在单机完成可验证的配置状态机，不依赖网络。

- [ ] **0.1 项目结构**
  - 入口目录：沿用当前 `app/higgs/`；后续如需要标准 Go 布局，再迁移到 `cmd/higgs/`
  - [x] 已创建：`pkg/core/zone/`, `pkg/crypto/`
  - [ ] 待创建：`pkg/core/{identity,merkle,gossip}`, `pkg/transport/wireguard/`, `pkg/routing/babeld/`
  - Go 版本已为 1.22；保持 `go.mod` 的最低版本不低于 1.22
  - 引入依赖：`golang.zx2c4.com/wireguard/wgctrl`, `github.com/vishvananda/netlink`, `go.etcd.io/bbolt`

- [ ] **0.2 身份与密钥系统**
  - ED25519 主密钥生成与本地加密存储（passphrase + bcrypt）
  - NodeID = blake2b(pubkey)

- [ ] **0.3 Zone / Authority / Delegation / Record 基础模型**
  - [x] 定义设计文档中的核心数据结构
  - [x] 实现 `Get(fqkey)`：解析 Zone + Key → 本 Zone 查找 → 向上 fallback 直到根
  - [x] 实现基础 `Put(record)` 写入 active state
  - [ ] 在 `Put(record)` 中接入本地 authority 验证、版本链和 pending record 处理

- [ ] **0.4 签名与验证**
  - [x] 实现 Record / Delegation 的 Sign 和 Verify
  - [x] 实现 ZoneAuthority canonical hash
  - [ ] 实现 VerifyChain
  - [x] 定义并使用 domain separator
  - [x] Phase 0 只接受 `threshold=1`，遇到 `threshold>1` 返回 `unsupported threshold`

- [ ] **0.5 bbolt 持久化**
  - 按 Zone 分 bucket 存储
  - 加载/恢复/版本链审计
  - 保留 `PendingRecords`，补齐版本链后再提升为 active

- [ ] **0.6 CLI 调试**
  - `higgs init`
  - `higgs zone show <zone>`
  - `higgs record put <zone> <key> <value>`
  - `higgs verify <zone>`

## Phase 1: 两节点 Zone 同步（预计 1-2 周）

**目标：** 跑通安全边界明确的同步流程。

- [ ] **1.1 Gossip 传输层**
  - UDP socket 监听（固定端口，如 33434）
  - Protobuf 消息定义：`Ping`, `Pong`, `FetchZone`, `FetchRecord`, `Announce`
  - Anti-replay：64-bit nonce + 时间戳窗口（±5分钟）
  - 限流与配额：每 peer 限制速率/字节/对象数

- [ ] **1.2 节点发现**
  - 通过配置文件中的 bootstrap 列表启动
  - 仅接受已知 peer 的连接

- [ ] **1.3 Whole-Zone 同步**
  - Phase 1A 先不做 Merkle diff，hash 不同直接拉完整 Zone
  - 数据进入 `quarantine store`
  - 逐条验证签名链（VerifyDelegation → VerifyRecord → VerifyChain）
  - 缺失前驱的 Record 进入 `pending store` 并通过 `FETCH_RECORD` 补齐
  - 验证通过后提升到 `active store`

- [ ] **1.4 闭环验证**
  - 节点 A 修改本地 Zone Record
  - Gossip 到节点 B
  - B 验证通过后 active store 可见
  - CLI: `higgs sync status`

## Phase 2: WireGuard 建链（预计 2-3 周）

**目标：** 两个节点能根据同步后的 Zone 配置自动建立 WG 隧道。

- [ ] **2.1 WireGuard 控制模块**
  - 通过 `wgctrl-go` 操作内核 WG 接口
  - 监听 `*.<parent_zone>./wireguard/*` Record 变更
  - 从 Zone 推导 PeerView：`PublicKey`、`Endpoints`、`TunnelAllowedIPs`、`AnnouncedRoutes`
  - 应用 WG 配置（add/remove/update peer）
  - WG AllowedIPs 只放 tunnel /32 或 /128，业务路由交给 Babeld

- [ ] **2.2 链路实例管理**
  - 当 WG peer 建立后，生成 LinkInstance
  - 跟踪链路状态：up/down/stale

- [ ] **2.3 最小闭环验证**
  - 节点 A 和 B 同步配置
  - 自动为对方添加 WG Peer
  - `wg show` 看到握手成功
  - 互相 ping 通 tunnel IP

## Phase 3: Babeld 路由 + Route Authorization Filter（预计 2-3 周）

**目标：** babeld 在 WG 接口上发现邻居、学习路由，且只接受被授权的前缀。

- [ ] **3.1 Babeld 路由适配器**
  - 启动 babeld 并通过控制 socket（`-G` Unix/TCP socket）发送命令
  - 命令封装：`add interface wg0`、`flush interface wg0`
  - 当 WG 接口建立/拆除时，动态通知 babeld 添加/移除接口

- [ ] **3.2 Route Authorization Filter**
  - 根据 active state 中的 `routes/announcements/*` 和 `ipam/assignments/*` 生成 prefix whitelist
  - 为每个 peer/interface 生成 babeld `import filter`
  - 拒绝 `0.0.0.0/0`、未授权前缀、他人网段

- [ ] **3.3 本地路由注入**
  - 通过 babeld 控制 socket 的 `install` / `uninstall` 注入本节点 AnnouncedRoutes
  - 或通过 `redistribute` 配置让 babeld 自动学习

- [ ] **3.4 闭环验证**
  - 3+ 节点组网
  - Babeld 在 wg0 上发现邻居，交换路由
  - 节点 A 尝试宣告未授权前缀时被其他节点过滤掉

## Phase 4: 多节点/IPAM/准入/防火墙（预计 3-4 周）

**目标：** 支持动态准入、IP 分配、链路健康、防火墙规则。

- [ ] **4.1 准入流程**
  - 新节点生成密钥对 → 向管理员申请 delegation
  - 管理员在父 Zone 创建 `nodeX.parent.` delegation
  - Gossip 全网传播后，新节点自动被所有节点识别并建立 WG Peer

- [ ] **4.2 IP 分配管理（IPAM）**
  - 拆分语义：`ipam/pools/*`、`ipam/assignments/*`、`routes/announcements/*`
  - 节点查询自己的 Zone fallback 路径，汇总所有分配到的 IPs
  - 冲突检测：按 ownership + version-chain 裁决，禁止仅按时间戳

- [ ] **4.3 链路健康检测**
  - 在 WG 隧道上周期性发送 ICMP/自定义 keepalive
  - 检测 RTT、丢包率
  - 链路异常时标记 down，从 babeld 接口中移除或降低优先级

- [ ] **4.4 动态 Peer 管理**
  - 节点离线超时后，保留配置但标记 stale
  - 长期离线后自动清理 WG Peer 和路由
  - 节点信息变更（endpoint、pubkey rotate）自动更新 WG 配置

- [ ] **4.5 防火墙规则同步**
  - 基于已同步的 Zone 中所有合法节点的 TunnelAllowedIPs
  - 通过 `nftables` netlink 接口生成 accept 规则，默认 drop

## Phase 5: 健壮性与高级特性（预计 4-6 周）

**目标：** 生产可用，支持多线路、跳频、扩展传输协议。

- [ ] **5.1 多线路并行（Multipath）**
  - 一个 Peer 可建立多条 TransportLink（WG over 公网 + WG over 内网 + GRE）
  - 每条链路独立运行 babeld 接口
  - babeld 自动进行多路径负载均衡（Babel 原生支持 ECMP）

- [ ] **5.2 UDP 端口跳频（Port Hopping）**
  - 先实现多 endpoint / 多 port probe 与质量选择
  - 如需 rotate，必须包含：old-port grace period、clock skew 容忍、fallback static port、失联恢复路径

- [ ] **5.3 IKEv2 (StrongSwan) 传输驱动**
  - 通过 vici 协议控制 StrongSwan
  - 复用 Zone K-V 中的 `ipsec/*` Record

- [ ] **5.4 VXLAN Overlay**
  - 在 WG 三层网络上封装 VXLAN
  - 通过 Zone Record 同步 VNI、VTEP 信息

- [ ] **5.5 SRv6 支持（实验性）**
  - 通过 netlink 配置 SRv6 SID、End.DT4/End.DX6 行为
  - 与 BIRD/FRR 的 SRv6 扩展联动（如后续引入 BGP）

- [ ] **5.6 运维与可观测性**
  - Prometheus metrics 导出（节点数、链路状态、Gossip 流量、Zone 数量）
  - 结构化日志（slog）
  - CLI 调试工具：`higgs status`, `higgs zones`, `higgs peers`, `higgs sync`

## 下一步

1. 开始写 `pkg/core/zone.go`：`ZonePath`、`ZoneAuthority`、`AuthorizedKey`、`Delegation`、`Record`、`ZoneState` 的定义与基础方法
2. 开始写 `pkg/crypto/signer.go`：domain separator 常量、Sign/Verify 函数、VerifyRecord/VerifyDelegation/VerifyChain 逻辑
3. Phase 0 闭环验证：单机完成 `init` → `record put` → `verify chain` 的 CLI 流程
