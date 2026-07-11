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
   - 4.1 [核心原则](#41-核心原则)
   - 4.2 [DaemonStateStore](#42-daemonstatestore)
   - 4.3 [写路径](#43-写路径)
   - 4.4 [Reconcile 与 StateStore](#44-reconcile-与-statestore)
   - 4.5 [状态文件](#45-状态文件)
   - 4.6 [状态变化通知](#46-状态变化通知)
5. [Control Socket](#5-control-socket)
   - 5.1 [systemd 运行约定](#51-systemd-运行约定)
6. [Reconcile 调度](#6-reconcile-调度)
7. [子模块集成](#7-子模块集成)

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
| `StateStore` | `*DaemonStateStore` | 状态中心：committed snapshot + revision + dirty 标记 |
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

**DaemonEvent 类型**（[`daemon.go:70-95`](../../app/higgs/daemon.go#L70-L95)）：

事件通过 `daemonEvent` 结构体传递，主要字段包括 `Type`（事件类型）、`Context`（上下文）和 `Reply`（结果通道）。`enqueueEvent()` 把事件放进 `Events` 通道，然后阻塞等待 `Reply` 返回结果。这样，control socket 侧的 admin 操作能拿到明确的完成或失败信号。

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

`Run()` 方法（[`daemon.go:183-417`](../../app/higgs/daemon.go#L183-L417)）：

1. **初始化驱动**：配置 IPsec (StrongSwan VICI + XFRM) 驱动
2. **启动子服务**：
   - `openTransport()` — 开启 UDP gossip 监听
   - `startObjectPullServer()` — 启动 TCP object pull 服务
   - `startControlServer()` — 启动 Unix domain socket 控制服务器
   - `startObserverServer()` — 启动 HTTP observer 服务器
   - `startIPsecLifecycleEventWatcher()` — 监听 StrongSwan VICI 生命周期事件
3. **启动恢复**：

```
// 1. 短暂加锁更新 discovered peers，然后释放写锁
d.Sync.State.Lock()
d.Sync.updateDiscoveredPeers()
d.Sync.State.Unlock()

// 2. 发布本机记录
d.Sync.publishEndpointRecord()
d.Sync.publishIPsecRecords()
d.publishRoutingNetnsRecord()

// 3. 数据面恢复
d.recoverIPsecLinksOnStart(ctx)
d.recoverRoutingOnStart(ctx)
d.recoverFirewallOnStart(ctx)
```

提前释放写锁可避免恢复阶段长时间阻塞 control socket 与 Observer

4. **进入主循环**：

```
for {
    // 1. 处理所有已排队的事件（非阻塞 drain）
    processEvents(ctx)
    
    // 2. 检查磁盘状态文件是否被外部修改
    reloadStateIfChanged()
    
    // 3. 检查端点发布定时器；记录无变更时跳过下游 flush
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

**processEvents() 阶段**（[`daemon.go:860-895`](../../app/higgs/daemon.go#L860-L895)）：

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

Daemon 是 **本机唯一的状态 writer**。CLI admin 操作（如 record put、delegate issue）不会直接修改 BoltDB 文件，而是通过 control socket 把请求发给 daemon 的事件循环，由事件循环串行提交到 `DaemonStateStore`。

这样可以避免多个写者同时修改同一份本地状态。

### 4.2 DaemonStateStore

`DaemonStateStore` 是 daemon 的状态中心，定义在 [`daemon_state_store.go`](../../app/higgs/daemon_state_store.go)。它维护：

| 字段 | 作用 |
|------|------|
| `committed` | 当前已提交的 `*stateFile` 快照 |
| `revision` | 单调递增的版本号 |
| `dirty` | IPsec / routing / firewall 的 dirty 标记 |
| `reconcileProgress` | 各层 reconcile 是否在进行中 |

主要接口：

- `Snapshot()` — 返回 committed 状态的深拷贝 + 当前 revision。只读路径（control socket、observer、debug）都走这里，不会阻塞事件循环。
- `Meta()` — 返回 revision、snapshot time、dirty 标记、reconcile progress。
- `BeginUpdate()` — 基于当前 committed 状态创建一个 workspace 克隆，不阻塞其他 reader。
- `Update(fn)` / `CommitIfRevision(rev, fn)` — 在 workspace 上执行变更，然后以乐观锁方式提交。只有 committed revision 仍等于 base rev 时才替换成功，否则返回 stale revision 错误。
- `ReplaceCommitted(state)` — 用外部加载的最新状态无条件替换 committed 快照。

`stateFile` 本身仍内嵌 `sync.RWMutex`，但它现在主要保护单个克隆在本地修改时的并发安全；跨 goroutine 的同步由 `DaemonStateStore` 的版本号 + 快照机制负责。

### 4.3 写路径

事件循环中的写事件 handler（`record_put`、`delegate_issue`、`join_accept` 等）通过 `runStateStoreWrite()` 执行：

1. 从磁盘加载最新状态（`Sync.loadState()`）
2. 用 `ReplaceCommitted()` 刷新 StateStore
3. 通过 `StateStore.Update(fn)` 在 workspace 上完成业务修改
4. 调用 `installAndSaveCommittedState()` 把 committed 快照同步到 `Sync.State` 并保存回磁盘
5. 通知 observer，设置 dirty 标记并触发 reconcile

可能 no-op 的周期性写入（如 endpoint timer）使用 `runStateStoreWriteIfChanged()`：只有 `fn` 报告状态确实变化时，才会提交、递增 revision 并触发下游 flush。

### 4.4 Reconcile 与 StateStore

IPsec、routing、firewall 的 reconcile 不再长时间持有 live state 写锁：

1. `snapshotState()` 从 `StateStore.Snapshot()` 拿到 committed 快照和 revision
2. reconcile 基于快照计算 desired state 并执行数据面操作
3. 结果通过 `StateStore.CommitIfRevision(rev, fn)` 写回；如果期间状态已被其他写者更新，本轮 reconcile 结果会被丢弃，由下一轮重新计算

这样长 reconcile 不会阻塞 control socket、observer 和其他只读诊断路径。

### 4.5 状态文件

状态持久化在 BoltDB 文件中（路径由 `config.yaml` 的 `state_path` 指定，默认 `<data_dir>/higgs.db`）。

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

### 4.6 状态变化通知

`notifyStateChanged()`（[`daemon.go:1426-1462`](../../app/higgs/daemon.go#L1426-L1462)）：

当状态变化时（sync 成功应用了 Zone snapshot、admin 写入 record 等），daemon 会：
1. 调用 `OnStateChanged` hook（测试用）
2. 通知 observer 推送 SSE 事件
3. 执行 `flushRevocationCleanup()`（拒绝优先）
4. 设置所有 dirty 标记并依次 flush：firewall → routing → IPsec
5. 完成后再次清理 gossip peer cache

---

## 5. Control Socket

Daemon 通过 Unix domain socket 暴露控制接口。

- root 默认路径 `/run/higgs/higgs.sock`，非 root 默认 `<data_dir>/higgs.sock`，`HIGGS_CONTROL_SOCKET` 可覆盖
- 协议是简单 JSON request/response
- 安全边界只有 Unix 文件权限（父目录 `0700`，socket `0600`），**没有应用层方法级鉴权**

CLI 通过 `sendControlRequest()` 与 daemon 通信。daemon 在线时，写操作进入事件循环由单 writer 串行执行；读操作从当前状态快照返回。

当 socket 不存在或连接被拒绝（`ECONNREFUSED`）时，只读诊断命令可回退到本地 DB 离线视图，持久状态写入命令可走 direct/recovery 路径。超时、权限错误、连接重置、协议错误等不会触发 fallback，因为这些错误可能来自仍在线但异常的 daemon。

状态写入类命令和恢复类命令支持显式 `--direct`，跳过 control socket 直接写本地 DB。使用 direct 时调用者需自行保证没有 daemon 在管理同一状态文件或 IPsec/XFRM 对象；direct 只持久化 signed record，不会触发 routing reconcile。

控制方法覆盖状态读写、delegation 管理、节点加入、恢复操作、runtime 触发（`sync_trigger`/`reload`/`routing_reload`/`shutdown`）以及各类诊断接口。完整列表见 `app/higgs/daemon.go` 中 `handleControlConn` 的 switch。

### 5.1 systemd 运行约定

仓库提供 [`contrib/systemd/higgs.service`](../../contrib/systemd/higgs.service) 示例。service 使用 `RuntimeDirectory=higgs` 创建 `/run/higgs`，因此不需要预先手工创建运行目录，也不需要单独的 `.socket` unit。当前 daemon 自己创建并管理 Unix socket，尚不支持 systemd socket activation。

安装后至少需要确认：

- `ExecStart` 指向实际安装的 `higgs` 二进制；
- `/etc/higgs/config.yaml` 和 identity/private key 仅允许运行用户读取；
- 如果启用 StrongSwan/XFRM、netns 或防火墙 apply，service 需要相应的 root/capability 权限；
- root CLI 与 daemon 使用相同的 `HIGGS_CONFIG`，从而共同定位 `/run/higgs/higgs.sock` 和同一份状态。

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

吊销优先于任何允许操作。被吊销 zone 的 peer 必须先从 endpoint cache、observed path、object-pull 候选中被清除，这样后续的防火墙 / routing / IPsec reconcile 才不会继续考虑它。

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
  → 记录无变更时直接返回，不触发 notifyStateChanged / flush
  → 有变更时 notifyStateChanged
```

---

## 7. 子模块集成

Daemon 作为编排器，各子模块通过清晰的接口与 daemon 集成：

### 7.1 Gossip Sync

- **输入**：UDP 包（从 transport.Receive() 接收）、定时器事件、object pull 结果
- **输出**：通过 `StateStore.Update()` / `CommitIfRevision()` 更新 `Network`（Zone 数据库）和 peer runtime 状态
- **集成点**：`SyncRuntime` 结构持有 state、config、transport。`handleSyncEvent()` 在 event loop 中驱动 `SyncSession` FSM，通过 `executeSyncActions()` 执行 apply snapshot / send message / start object pull / start timer 等动作
- **状态范围**：gossip 操作的是全网 verified signed state，进入 `Network` 字段

**稳态 unsolicited ping 短路**：收到对端主动发来的 `MessagePing` 时，如果 ping 携带的 catalog root 与本端一致，`maybeShortcutSyncFromPingSummary` 直接记录 peer sync 状态并返回，不再创建 SyncSession。只有 root 不一致或 summary 生成失败时，才回退到完整 sync round。respondPing 仍正常回复 PONG，让对端拿到本端 summary。

### 7.2 IPsec Transport

- **输入**：`StateStore.Snapshot()` 中的 endpoint、transport key 记录，本地 `overlays[]` mesh policy
- **输出**：StrongSwan IKE child SA、XFRM interface、network namespace 内接口；结果通过 `StateStore.CommitIfRevision()` 写回
- **集成点**：`reconcileIPsecLinks(ctx)` 在 daemon.go 中调用，使用 `ipsec.PlanTransportLinks()` → `ipsec.ReconcileLinkInstances()` → `ipsec.ApplyReconcileAction()`
- **状态范围**：LinkInstances、IPsecReconcile 仅存在于本机 state file，不进入 gossip

**XFRM 维护短路**：在 `maintainExistingXFRMInterfaces` 中，如果 observed 状态与期望状态已经匹配，则跳过 `EnsureInterface`/`AssignAddress` 等冗余命令，只保留诊断地址分配。这减少了 reconcile 周期中对已有接口的无意义重写。

### 7.3 Routing

- **输入**：`StateStore.Snapshot()` 中的 route announcement / authorization 记录
- **输出**：BIRD 配置文件、Babel 邻居发现、路由导入/导出 filter；结果通过 `StateStore.CommitIfRevision()` 写回
- **集成点**：`reconcileRouting(ctx)` 在 routing_reconcile.go 中，构建 `AuthorizedRouteSet`，生成 BIRD 配置并 reconfigure
- **状态范围**：BirdInstances、RoutingReconcile 仅存在于本机 state file

### 7.4 Firewall

- **输入**：`StateStore.Snapshot()` 中的授权路由，本地 firewall 配置
- **输出**：nftables/iptables 规则（netns ingress、host ingress、redirect grace）；结果通过 `StateStore.CommitIfRevision()` 写回
- **集成点**：`reconcileFirewall(ctx)` 通过 `firewall.BuildDesiredState()` → driver.Apply()
- **状态范围**：FirewallReconcile 仅存在于本机 state file

### 7.5 Health

- **输入**：IPsec reconcile 结果中的期望链路和实际 SAs
- **输出**：ICMP/UDP probe、RTT/loss/jitter 指标；后续可作为 rotate cutover gate 的输入
- **集成点**：`flushIPsecReconcile()` 完成后调用 `reconcileHealth(ctx)`，刷新 health manager 的 probe target 并触发到期的 probe
- **状态范围**：health 结果不写入 gossip active state；后续如需要 signed health hint 需单独设计

### 7.6 Observer

- **输入**：`StateStore.Snapshot()` / `StateStore.Meta()` 提供的 committed snapshot
- **输出**：HTTP API（/api/v1/...）、SSE 事件推送
- **集成点**：`newObserverServer()` 在启动时创建，`observerProvider` 从 `StateStore` 读取数据。状态变化时 daemon 通过 `d.observerHub` 广播 SSE 事件
- **状态范围**：observer 是纯只读的，不修改任何状态


