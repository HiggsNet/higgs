# Higgs Daemon 设计与实现

> **本文档状态：2026-07**
> 描述 `higgs daemon` 的架构、事件循环、单 writer 模式、control socket、reconcile 调度和本机状态管理。不展开 transport、routing、firewall、health 等子模块的内部细节——那些在各自的文档中说明。

Higgs daemon 是长期运行的控制循环。它把所有子系统——gossip、admin 写入、端点发布、object pull、transport reconcile、routing reconcile、firewall reconcile、health 和 observer——放在同一个本机控制边界内。

---

## 目录

1. [架构概览](#1-架构概览)
2. [DaemonService 结构](#2-daemonservice-结构)
3. [事件循环](#3-事件循环)
4. [单 Writer 模式与状态管理](#4-单-writer-模式与状态管理)
5. [Control Socket](#5-control-socket)
6. [Reconcile 调度](#6-reconcile-调度)
7. [子模块集成](#7-子模块集成)
8. [Operator 信息](#8-operator-信息)

---

## 1. 架构概览

Daemon 是 Higgs 中唯一长期运行的系统进程。它不在每次 CLI 调用时重新加载全部状态，而是持续运行一个事件循环，按需调度各子系统的 reconcile。

```
┌──────────────────────────────────────────────────────────┐
│                    Daemon Event Loop                       │
│                                                            │
│  ┌───────────┐    ┌──────────────┐    ┌────────────────┐  │
│  │UDP Receiver│───▶│ Packet Demux│───▶│ Gossip Sync    │  │
│  │(goroutine) │    │              │    │ SyncSession FSM│  │
│  └───────────┘    └──────────────┘    └────────┬───────┘  │
│                                                 │          │
│  ┌───────────┐    ┌──────────────┐              │          │
│  │Control    │───▶│ Events chan  │──────────────┤          │
│  │Socket     │    │ (daemonEvent)│              │          │
│  └───────────┘    └──────┬───────┘              │          │
│                           │                      │          │
│  ┌───────────┐           ▼                      ▼          │
│  │Observer   │    ┌─────────────────────────────────────┐  │
│  │HTTP Server│    │          handleEvent()               │  │
│  └───────────┘    │  ┌─────────┐ ┌──────────┐ ┌──────┐  │  │
│                   │  │ IPsec   │ │ Routing  │ │FW    │  │  │
│                   │  │Reconcile│ │Reconcile │ │Reconc│  │  │
│                   │  └─────────┘ └──────────┘ └──────┘  │  │
│                   │  ┌─────────┐ ┌──────────┐ ┌──────┐  │  │
│                   │  │ Health  │ │ Endpoint │ │Object│  │  │
│                   │  │Reconcile│ │Publish   │ │Pull  │  │  │
│                   │  └─────────┘ └──────────┘ └──────┘  │  │
│                   └─────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────┘
```

**关键分层原则**：
- Gossip 只传播和验证签名 Zone 状态，不执行系统配置。
- IPsec、WireGuard、BIRD、nftables/iptables 都是本机 runtime driver——它们的失败不改变 signed state 的真实性。
- Overlay/link policy 是本机策略，不默认公开到 gossip。
- Debug/Observer 展示"已验证事实 + 本机期望状态 + 实际 runtime 状态"的差异，而不是只展示某一层。

---

## 2. DaemonService 结构

`DaemonService` 定义在 [`app/higgs/daemon.go`](../../app/higgs/daemon.go) 中，是 daemon 的核心结构体。

主要字段：

| 字段 | 类型 | 作用 |
|------|------|------|
| `Sync` | `*SyncRuntime` | gossip sync 运行时封装，持有 `State`、`Config`、`Transport` |
| `Events` | `chan daemonEvent` | 统一事件入口（64 buffer） |
| `Interval` | `time.Duration` | 出站 sync 周期（默认 60s） |
| `ControlSocketPath` | `string` | Unix domain socket 路径 |
| `IPsecDriver` | `ipsec.IPsecDriver` | StrongSwan VICI 驱动 |
| `XFRMDriver` | `ipsec.XFRMDriver` | XFRM interface 驱动 |
| `health` | `*health.Manager` | 链路健康探测管理器 |
| `observerHub` | `*observer.Hub` | Observer SSE 事件广播 |
| `ipsecDirty` | `bool` | IPsec reconcile 待调度标记 |
| `routingDirty` | `bool` | Routing reconcile 待调度标记 |
| `firewallDirty` | `bool` | Firewall reconcile 待调度标记 |
| `syncSessions` | `map[string]*SyncSession` | 活跃的 gossip sync session |
| `objectPullPool` | `*objectPullPool` | TCP object pull 连接池 |
| `timerManager` | `*TimerManager` | Sync session 定时器管理 |

**DaemonEvent 类型**（[`daemon.go:70-91`](../../app/higgs/daemon.go#L70-L91)）：

事件通过 `daemonEvent` 结构体传递，包含 `Type`、`Context`、`Reply` 等字段。`enqueueEvent()` 将事件放入 Events 通道并同步等待 result，确保 admin 操作有明确的完成信号。

主要事件类型：
- `record_put` / `delegate_issue` / `delegate_revoke` — 状态写入
- `authority_grant` / `recovery_import_zone` / `recovery_purge_revoked` — 权限变更
- `join_accept` — 节点加入；`root_init` 只保留 daemon 侧拒绝入口，用来提示停止 daemon 后执行 direct/recovery 初始化
- `packet` — 收到 UDP gossip 包
- `timer_sync` / `timer_endpoint_publish` — 定时 sync 和端点发布
- `sync_trigger` / `reload_config` — 手动触发
- `ipsec_cleanup` / `ipsec_port_rotate` / `ipsec_lifecycle` — IPsec 生命周期
- `shutdown` — 优雅退出

---

## 3. 事件循环

Daemon 启动流程（[`daemonRun()`](../../app/higgs/daemon.go#L1522-L1540)）：

```
daemonRun()
 ├─ NewRuntime()          加载应用配置
 ├─ rt.LoadState()        加载 BoltDB 状态文件
 ├─ newDaemonService()    创建 DaemonService
 ├─ configureIPsecDriversFromConfig()
 └─ service.Run()         进入事件循环
```

`Run()` 方法（[`daemon.go:177-385`](../../app/higgs/daemon.go#L177-L385)）：

1. **初始化驱动**：配置 IPsec (StrongSwan VICI + XFRM) 驱动
2. **启动子服务**：
   - `openTransport()` — 开启 UDP gossip 监听
   - `startObjectPullServer()` — 启动 TCP object pull 服务
   - `startControlServer()` — 启动 Unix domain socket 控制服务器
   - `startObserverServer()` — 启动 HTTP observer 服务器
   - `startIPsecLifecycleEventWatcher()` — 监听 StrongSwan VICI 生命周期事件
3. **启动恢复**：在锁定状态下执行 `recoverIPsecLinksOnStart()`、`recoverRoutingOnStart()`、`recoverFirewallOnStart()`
4. **进入主循环**：

```
for {
    // 1. 处理所有已排队的事件（非阻塞 drain）
    processEvents(ctx)
    
    // 2. 检查磁盘状态文件是否被外部修改
    reloadStateIfChanged()
    
    // 3. 检查端点发布定时器
    handleEvent(endpointTimer)
    
    // 4. 检查 sync 定时器
    handleEvent(syncTimer) + flush IPsec + flush Routing
    
    // 5. 检查 IPsec reconcile 定时器
    flushIPsecReconcile()
    
    // 6. 检查 Routing reconcile 定时器
    flushRoutingReconcile()
    
    // 7. 阻塞等待：事件 / UDP packet / sync event / object pull result / 定时器超时
    select {
        case event:  handleEvent(event)
        case packet: handlePacketEvent → SyncSession FSM
        case syncEvent: handleSyncEvent
        case pullResult: enqueueObjectPullResult
        case timer.C: 继续循环
    }
}
```

**processEvents() 阶段**（[`daemon.go:769-802`](../../app/higgs/daemon.go#L769-L802)）：

非阻塞 drain 所有已排队事件，处理完后以 **Phase 6.5 拒绝优先顺序**执行 flush：
1. `flushRevocationCleanup()` — 清理已吊销 zone 的 gossip peer cache
2. `flushFirewallReconcile()` — 刷新防火墙规则
3. `flushRoutingReconcile()` — 刷新路由
4. `flushIPsecReconcile()` — 刷新 IPsec 链路
5. `flushRevocationCleanup()` — 再次清理（flush 中可能发现新的吊销路径）

这个顺序确保吊销的 prefix 和 peer entry 在任何层可能重新接受流量之前从 allow set 中移除。

---

## 4. 单 Writer 模式与状态管理

### 4.1 核心原则

Daemon 是 **本机唯一的状态 writer**。CLI admin 操作（record put、delegate issue 等）不直接修改 BoltDB 文件，而是通过 control socket 向 daemon event loop 发送请求，由 event loop 串行执行。

这避免了多个命令同时写本地状态的竞争问题。

### 4.2 状态锁管理

`stateFile` 内嵌 `sync.RWMutex`（[`state.go:19`](../../app/higgs/state.go#L19-L34)），daemon 的事件循环在 `handleEvent()` 执行期间持有**写锁**。

- `lockState()` — 获取当前 `Sync.State` 的写锁，将 unlock 函数存入 `d.stateUnlock`
- `setState()` — 原子替换状态指针，同时将写锁从旧状态转移到新状态
- `releaseStateLock()` — 释放当前跟踪的锁（用于子操作需要自行加锁的场景）
- `currentState()` — 在 `stateMu` 下稳定读取当前 `Sync.State` 指针；它不锁住返回的 `stateFile` 内容，调用方读取 map/结构体时仍需要持有 state 的读锁或先复制快照

### 4.3 状态文件

状态持久化在 BoltDB 文件中（路径由 `config.yaml` 的 `state_path` 指定，默认 `<data_dir>/state.db`）。

`stateFile` 结构包含（[`state.go:18-34`](../../app/higgs/state.go#L18-L34)）：

| 字段 | 作用 |
|------|------|
| `ManagedZone` | 本机管理的 Zone |
| `IdentityKeyPath` | 身份密钥路径 |
| `RootPrivateKey` | Root zone 私钥（仅 root 节点持有） |
| `ZonePrivateKey` | 本 zone 私钥 |
| `Network` | 完整的 Zone 数据库（`*zone.NetworkState`） |
| `SyncPeers` | 每个 peer 的 sync 状态、观测地址、backoff |
| `IPsecTransportKey` | IPsec 传输密钥 |
| `IPsecPortRecord` | IPsec 端口记录状态 |
| `LinkInstances` | IPsec 链路实例 |
| `IPsecReconcile` | IPsec reconcile 结果快照 |
| `RoutingReconcile` | Routing reconcile 结果快照 |
| `FirewallReconcile` | Firewall reconcile 结果快照 |
| `BirdInstances` | BIRD 进程实例状态 |
| `Admission` | Auto-join 准入诊断 |

### 4.4 状态变化通知

`notifyStateChanged()`（[`daemon.go:1289-1323`](../../app/higgs/daemon.go#L1289-L1323)）：

当状态变化时（sync 成功应用了 Zone snapshot、admin 写入 record 等），daemon 会：
1. 调用 `OnStateChanged` hook（测试用）
2. 通知 observer 推送 SSE 事件
3. 执行 `flushRevocationCleanup()`（拒绝优先）
4. 设置所有 dirty 标记并依次 flush：firewall → routing → IPsec
5. 完成后再次清理 gossip peer cache

---

## 5. Control Socket

### 5.1 协议

Daemon 监听一个 Unix domain socket（路径默认 `<data_dir>/higgs.sock`，root 下也可用 `/run/higgs/higgs.sock`，可被 `HIGGS_CONTROL_SOCKET` 环境变量覆盖）。

协议是简单 JSON request/response：客户端发送 `controlRequest`，服务端回复 `controlResponse`。所有通信通过 `json.NewEncoder`/`json.NewDecoder` 完成。

### 5.2 控制方法

| 方法 | 作用 |
|------|------|
| `status` | 查询 daemon 在线状态和链路概览 |
| `record_put` | 写入签名 record |
| `record_get` | 读取 record（含历史版本） |
| `delegate_issue` | 签发 delegation |
| `authority_grant` | 授权权限 |
| `delegate_revoke` | 吊销 delegation |
| `recovery_import_zone` | 导入 Zone snapshot 恢复 |
| `recovery_purge_revoked` | 清理已吊销 Zone |
| `join_accept` | 接受 join bundle |
| `root_init` | 拒绝执行并提示停止 daemon 后 direct/recovery 初始化 |
| `sync_trigger` | 立即触发一轮 sync |
| `reload` | 重新加载配置 |
| `ipsec_cleanup` | 清理孤儿 IPsec 链路 |
| `ipsec_rotate_port` | 触发 IPsec 端口轮换 |
| `shutdown` | 优雅关闭 daemon |
| `bird_status` | 查询 BIRD 实例状态 |
| `routes_dump` | 导出授权路由集 |
| `admission_status` | 查询 auto-join 准入状态 |
| `firewall_status` | 查询防火墙 reconcile 状态 |
| `links_status` | 查询 IPsec 链路状态 |
| `peers_status` | 查询 peer lifecycle 状态 |
| `revoke_status` | 查询吊销影响范围 |
| `health_status` | 查询链路健康探测状态 |

> 注：control socket **没有应用层的权限校验**，所有 methods 对任何能连接 socket 的进程同等开放。唯一的安全边界是 Unix socket 文件权限（`chmod 0600`），只有 socket owner 用户（或 root）可以连接。客户端侧名为 `sendAdminControlRequest` 的辅助函数只是命名约定，daemon 侧一视同仁。

### 5.3 客户端调用

CLI 命令（`higgs daemon`、`higgs record put`、`higgs debug links` 等）通过 `sendControlRequest()` 与 daemon 通信。当 daemon 不存在时（control socket 不可用），客户端自动回退到直接操作本地状态文件。

---

## 6. Reconcile 调度

Daemon 使用**三级调度策略**：事件驱动 + 周期性 + 标记脏。

### 6.1 标记脏（Dirty Flag）

每个子系统有一个 dirty 标记：
- `ipsecDirty` — IPsec 链路需要刷新
- `routingDirty` — 路由需要刷新
- `firewallDirty` — 防火墙需要刷新

标记在以下情况被设置：
1. `notifyStateChanged()` — 任何状态变化后
2. `processEvents()` — 处理完事件队列后
3. IPsec lifecycle 事件到达时

### 6.2 Flush 方法

每个子系统有对应的 flush 方法：

- `flushIPsecReconcile(ctx)` — 检查 `ipsecDirty`，调用 `reconcileIPsecLinks(ctx)`，之后调用 `reconcileHealth(ctx)` 刷新健康探测目标
- `flushRoutingReconcile(ctx)` — 检查 `routingDirty`，调用 `reconcileRouting(ctx)`
- `flushFirewallReconcile(ctx)` — 检查 `firewallDirty`，调用 `reconcileFirewall(ctx)`

Flush 方法返回 `bool` 表示是否确实执行了 reconcile。

### 6.3 周期性定时器

即使没有事件触发，IPsec 和 routing 也有周期性 reconcile：

- IPsec reconcile 周期：默认 60s，可通过 `overlays[*].reconcile.interval` 配置
- Routing reconcile 周期：30s（由 `defaultRoutingReconcileInterval` 定义）
- 当 link group 数为 0 且没有链路实例时，IPsec reconcile 定时器关闭（返回 0）
- 当 routing 实例数为 0 时，routing reconcile 定时器关闭

### 6.4 Phase 6.5：拒绝优先顺序

```
flushRevocationCleanup()  // 1. 清理 gossip peer cache
flushFirewallReconcile()   // 2. 防火墙（allow set）
flushRoutingReconcile()    // 3. 路由
flushIPsecReconcile()      // 4. IPsec
flushRevocationCleanup()   // 5. 再次清理
```

吊销优先于任何允许操作：被吊销 zone 的 peer 必须先从 endpoint cache、observed path、object-pull 候选中被清除，才能在防火墙/routing/IPsec reconcile 中不被考虑。

### 6.5 同一事件队列的 sync-trigger 链

```
record_put
  → handleRecordPutEvent: 写入签名 record
  → notifyStateChanged: 设置 dirty 标记 + flush 子系统
  → processEvents drain 中: flush revocation → firewall → routing → ipsec

sync timer
  → handleSyncTimerEvent: 加载新状态 + 为每个出站 peer 启动 SyncSession
  → SyncSession FSM 完成 → completeSyncSession
    → notifyStateChanged（如果有变化）
    → relaySyncToPeers: 通知其他 peer

endpoint publish timer
  → handleEndpointTimerEvent: 发布 endpoint、IPsec transport、routing netns 记录
  → notifyStateChanged
```

---

## 7. 子模块集成

Daemon 作为编排器，各子模块通过清晰的接口与 daemon 集成：

### 7.1 Gossip Sync

- **输入**：UDP 包（从 transport.Receive() 接收）、定时器事件、object pull 结果
- **输出**：更新 `Sync.State.Network`（Zone 数据库）
- **集成点**：`SyncRuntime` 结构持有 state、config、transport。`handleSyncEvent()` 在 event loop 中驱动 `SyncSession` FSM，通过 `executeSyncActions()` 执行 apply snapshot / send message / start object pull / start timer 等动作
- **状态范围**：gossip 操作的是全网 verified signed state，进入 `Network` 字段

### 7.2 IPsec Transport

- **输入**：`d.Sync.State.Network` 中的 endpoint、transport key 记录，本地 `overlays[]` mesh policy
- **输出**：StrongSwan IKE child SA、XFRM interface、network namespace 内接口
- **集成点**：`reconcileIPsecLinks(ctx)` 在 daemon.go 中调用，使用 `ipsec.PlanTransportLinks()` → `ipsec.ReconcileLinkInstances()` → `ipsec.ApplyReconcileAction()`
- **状态范围**：LinkInstances、IPsecReconcile 仅存在于本机 state file，不进入 gossip

### 7.3 Routing

- **输入**：`d.Sync.State.Network` 中的 route announcement / authorization 记录
- **输出**：BIRD 配置文件、Babel 邻居发现、路由导入/导出 filter
- **集成点**：`reconcileRouting(ctx)` 在 routing_reconcile.go 中，构建 `AuthorizedRouteSet`，生成 BIRD 配置并 reconfigure
- **状态范围**：BirdInstances、RoutingReconcile 仅存在于本机 state file

### 7.4 Firewall

- **输入**：`d.Sync.State.Network` 中的授权路由，本地 firewall 配置
- **输出**：nftables/iptables 规则（netns ingress、host ingress、redirect grace）
- **集成点**：`reconcileFirewall(ctx)` 通过 `firewall.BuildDesiredState()` → driver.Apply() 
- **状态范围**：FirewallReconcile 仅存在于本机 state file

### 7.5 Health

- **输入**：IPsec reconcile 结果中的期望链路和实际 SAs
- **输出**：ICMP/UDP probe、RTT/loss/jitter 指标；后续可作为 rotate cutover gate 的输入
- **集成点**：`flushIPsecReconcile()` 完成后调用 `reconcileHealth(ctx)`，刷新 health manager 的 probe target 并触发到期的 probe
- **状态范围**：health 结果不写入 gossip active state；后续如需要 signed health hint 需单独设计

### 7.6 Observer

- **输入**：daemon 状态（state 指针 + runtime snapshot）
- **输出**：HTTP API（/api/v1/...）、SSE 事件推送
- **集成点**：`newObserverServer()` 在启动时创建，`observerProvider` 从 daemon 读取数据。状态变化时 daemon 通过 `d.observerHub` 广播 SSE 事件
- **状态范围**：observer 是纯只读的，不修改任何状态

---

## 8. Operator 信息

### 8.1 启动与关闭

```bash
# 前台运行
higgs daemon [--interval seconds]

# 后台运行（通过 systemd 等）
higgs daemon &

# 优雅关闭
higgs daemon --shutdown     # 通过 control socket
# 或向进程发送 SIGTERM（context cancel）
```

### 8.2 常用诊断命令

```bash
# 检查 daemon 在线状态
higgs sync status
higgs sync status --verbose

# 检查链路状态
higgs debug links
higgs debug links --filter <peer-or-link>

# 检查路由
higgs debug routes
higgs debug route <prefix>

# 检查防火墙
higgs debug firewall

# 检查健康探测
higgs debug health

# 检查 BIRD 状态
higgs debug babel

# 检查 peer lifecycle
higgs debug peers

# 检查 auto-join 准入
higgs debug admission

# 检查吊销影响
higgs debug revoke-impact

# 查询节点状态（通过 control socket）
higgs record get <zone> <key>
```

### 8.3 关键日志与事件

Daemon 使用结构化日志，通过 `Log` 字段（`*appLogger`）输出 `component`、`event`、`fields` 三个维度：

| 组件 | 事件 | 含义 |
|------|------|------|
| `daemon` | `started` | Daemon 启动，包含 peer_id、addr、interval |
| `sync` | `zone_applied` | Zone snapshot 被成功应用 |
| `sync` | `zone_apply_failed` | Zone snapshot 应用失败（含 reject reason） |
| `sync` | `hinted_sync_started` | 收到 announce hint 后启动 sync session |
| `sync` | `send_failed` | 发送 UDP 消息失败 |
| `sync` | `event_dropped` | Sync event 因队列满被丢弃 |
| `ipsec` | `vici_lifecycle_event` | StrongSwan 生命周期事件 |
| `ipsec` | `reconcile_failed` | IPsec reconcile 失败 |
| `routing` | `reconcile_failed` | Routing reconcile 失败 |
| `firewall` | `no_backend_available` | 无可用防火墙后端 |
| `endpoint` | `publish_failed` | 端点发布失败 |
| `endpoint` | `reflector_failed` | 公网地址反射器查询失败 |
| `auto_join` | `adopted` | 该节点被父 zone 采纳 |
| `auto_join` | `adopt_failed` | 采纳失败（含原因） |
| `state` | `save` | 状态文件保存（含 records 数） |

### 8.4 关键状态文件路径

- 状态数据库：`<data_dir>/state.db`（BoltDB，含 Network、meta）
- Control socket：`<data_dir>/higgs.sock` 或 `/run/higgs/higgs.sock`
- 配置文件：`<data_dir>/config.yaml`
- BIRD 配置：`<data_dir>/bird-<instance>.conf`

### 8.5 Observer 只读控制台

当 observer 启用时（`config.yaml` 中 `observer.enabled: true`），daemon 会在配置的端口启动 HTTP 只读 API：

- `/api/v1/...` — JSON API，展示与 CLI debug 命令相同的 read model
- SSE 事件流 — 状态变化时推送 `state_changed`、`route_changed`、`link_updated`、`peer_updated`、`health_updated` 等事件
- observer 不直接操作 daemon 状态，不实现自己的诊断逻辑——它消费 daemon 已经收敛好的 runtime snapshot

### 8.6 注意事项

- **daemon 是单 writer**：不要同时运行多个 `higgs daemon` 实例操作同一个 state 文件。
- **reload**：`reload` 命令会重新加载配置和状态文件，但不允许切换 state_path、control socket 路径或 identity key。
- **root init 不能通过 daemon 执行**：root zone 初始化需要在 daemon 启动前以 recovery 方式执行。
- **状态文件修改**：`reloadStateIfChanged()` 在事件循环每次迭代时检查磁盘状态文件是否被外部修改，检测到变化后自动加载并触发 reconcile。
