# Phase 6: Event-Driven Daemon / Sync State Machine Design

> **文档状态（2026-06）**  
> 本文档描述 Phase 6 对 Higgs daemon 同步层的事件驱动重构设计。wire 协议（`PING`/`PONG`/`FETCH_ZONE`/`FETCH_RECORD`/`ANNOUNCE`/`object_chunk`）本身不变，变的是 daemon 内部如何收发、调度和管理同步过程。

## 1. 背景与问题

当前 daemon 里有两个 goroutine 同时从同一个 UDP socket 读包：

1. `startGossipPacketReceiver`：专门收包 goroutine，把包推到 `packetCh`。
2. `SyncRuntime.syncRound`：在等 `PONG`/`ANNOUNCE` 时直接调用 `transport.Receive()`。

这带来三类问题：

- **并发数据 race**：`ReplayWindow.prune()` 遍历 map 时，另一个 goroutine 在 `Check()` 里写 map，触发 `fatal error: concurrent map iteration and map write`。
- **响应被抢**：`syncRound` 等的 `PONG` 可能被专门收包 goroutine 拿走、塞进 `packetCh`；而 `syncRound` 阻塞时 daemon 主循环无法处理 `packetCh`，导致无意义 timeout。
- **主循环被阻塞**：`syncRound` 里混着 UDP 收发、TCP object pull、状态 apply、持久化；object pull 等 I/O 会卡住整个 daemon。

Phase 6 的结构性修复是：**单一 UDP reader + 显式 per-peer 同步会话状态机 + 事件驱动主循环**。

## 2. 总体架构

```text
┌─────────────────────────────────────────────────────────────┐
│                     UDP Socket (one)                        │
└───────────────────────────┬─────────────────────────────────┘
                            │ ReadFromUDP
┌───────────────────────────▼─────────────────────────────────┐
│              startGossipPacketReceiver                      │
│  (single goroutine; replay/quota/allowlist check here)      │
└───────────────────────────┬─────────────────────────────────┘
                            │ *Packet
┌───────────────────────────▼─────────────────────────────────┐
│                    Packet Demuxer                           │
│  - route to active SyncSession by peer_id                   │
│  - or enqueue as UnsolicitedPacket event                    │
└───────────────────────────┬─────────────────────────────────┘
                            │ events
┌───────────────────────────▼─────────────────────────────────┐
│              Daemon Event Loop (single goroutine)           │
│  selects on:                                                │
│    packetCh, d.Events, syncEventCh, timerCh,                │
│    objectPullResultCh                                       │
│  dispatches events to SyncSession FSMs                      │
└───────────────────────────┬─────────────────────────────────┘
                            │ actions
┌───────────────────────────▼─────────────────────────────────┐
│              SyncSession per target peer                    │
│  Idle → PingSent → AwaitingAnnounce → ObjectPulling → ...   │
└─────────────────────────────────────────────────────────────┘
```

关键约束：

- **只有 `startGossipPacketReceiver` 调用 `transport.Receive()`**。
- 所有 UDP 包通过 `Packet Demuxer` 分发。
- daemon 主循环只做事件分发，不阻塞在 I/O。
- 每个目标 peer 同时最多只有一个 `SyncSession`。

## 3. SyncSession 状态机

### 3.1 状态

| 状态 | 含义 |
|------|------|
| `Idle` | 该 peer 没有活跃同步会话 |
| `PingSent` | 已发 `PING`，等 `PONG` |
| `AwaitingAnnounce` | 需要从对方拉 zone/record，已发 `FETCH_ZONE` 或对方 `PONG` 承诺有数据 |
| `FetchingLocal` | 对方请求了本节点的 zone，正在发送 snapshots |
| `ObjectPulling` | UDP 静默期已到，正在异步 TCP object pull |
| `ChunkFallback` | TCP pull 失败或不可达，已发 `FETCH_ZONE{ChunkFallback:true}`，等 UDP chunk |
| `Completed` | 本轮同步成功结束 |
| `Failed` | 超时、错误或被 backoff |

### 3.2 事件

| 事件 | 来源 |
|------|------|
| `SyncTimerEvent{peerID}` | daemon 周期 timer / manual trigger / relay 唤醒 |
| `PacketEvent{session, packet}` | demuxer 把包路由给活跃 session |
| `UnsolicitedPacketEvent{packet}` | demuxer 把包路由给通用处理路径 |
| `PacketQuietTimeoutEvent{peerID}` | UDP 静默期 timer 触发；基于该 peer 估计 RTT 动态计算，给对端留 burst 窗口，避免过早切 TCP/object-pull 或结束 round |
| `RoundTimeoutEvent{peerID}` | 整轮超时 timer 触发；基于该 peer 估计 RTT 动态计算 |
| `ObjectPullResultEvent{sessionID, zone, snapshot, err}` | 异步 TCP object pull 完成 |
| `ObjectChunkEvent{sessionID, zone, chunk}` | 收到 `object_chunk` 且匹配活跃 transfer |

### 3.3 状态转换表

| 事件 | 当前状态 | 下一状态 | 动作 |
|------|----------|----------|------|
| `SyncTimerEvent` | `Idle` | `PingSent` | 发送 `PING`；启动 `RoundTimeout` |
| `PongReceived` | `PingSent` | `AwaitingAnnounce` | 计算缺失 zones，发送 `FETCH_ZONE` |
| `PongReceived` | `PingSent` | `FetchingLocal` | 对方请求本节点 zones，发送 snapshots |
| `PongReceived` | `PingSent` | `Completed` | 无差异，无需拉取 |
| `FetchZoneReceived` | `Idle`/`AwaitingAnnounce` | `FetchingLocal` | 按预算打包发送 snapshots |
| `AnnounceReceived` | `AwaitingAnnounce` | `AwaitingAnnounce` | apply；若仍有 pending zones 继续等 |
| `AnnounceReceived` | `AwaitingAnnounce` | `Completed` | apply；全部补齐 |
| `PacketQuietTimeout` (1st) | `AwaitingAnnounce` | `ObjectPulling` | 已发 `FETCH_ZONE`/snapshots，UDP 静默期满且仍有缺失，启动异步 TCP pull |
| `ObjectPullResultEvent{ok}` | `ObjectPulling` | `AwaitingAnnounce` | apply snapshot；若还有 pending 继续等 |
| `ObjectPullResultEvent{err}` | `ObjectPulling` | `ChunkFallback` | 发送 `FETCH_ZONE{ChunkFallback:true}` |
| `ObjectChunkEvent{complete}` | `ChunkFallback` | `AwaitingAnnounce`/`Completed` | 重组完成、apply |
| `PacketQuietTimeout` (2nd) | `AwaitingAnnounce`/`ObjectPulling`/`ChunkFallback` | `Completed`/`Failed` | 第二静默期结束（等待 object-pull 后的迟到 UDP / chunk），结束本轮 |
| `RoundTimeoutEvent` | 任意活跃状态 | `Failed` | 记录 backoff、last_error、save state |
| `UnsolicitedPacketEvent` | 任意 | 不变 | 路由到通用 `handlePacketUntil` |

### 3.4 动作（Actions）

`SyncSession.OnEvent` 返回的动作由 daemon 事件循环执行：

- `SendPing{peerID}`
- `SendPong{peerID, zones, fetchZones}`
- `SendFetchZone{peerID, zone, chunkFallback}`
- `SendAnnounce{peerID, snapshots, records}`
- `StartObjectPull{sessionID, peerID, zone}`
- `ApplySnapshot{snapshot}` / `ApplyRecordSnapshot{record}`
- `SaveState{reason}`
- `RecordBackoff{peerID, err}`
- `StartTimer{peerID, kind, deadline}` / `CancelTimer{peerID, kind}`

动作执行顺序由事件循环保证：先全部 apply，再 save，再 send，避免在错误中间状态落盘。

## 4. 关键模块

### 4.1 Packet Demuxer

```go
// app/higgs/packet_demux.go
func routePacket(
    packet *gossip.Packet,
    sessions map[string]*SyncSession,
) SyncEvent {
    if session, ok := sessions[packet.Message.PeerID]; ok {
        return PacketEvent{Session: session, Packet: packet}
    }
    return UnsolicitedPacketEvent{Packet: packet}
}
```

- 只按 `peer_id` 路由，不解释 message type。
- `SyncSession` 内部再按 message type 处理。
- 未命中活跃 session 的包走通用 unsolicited 路径（`handlePacketUntil`）。

### 4.2 Timer Manager

```go
// app/higgs/timer_manager.go
type TimerManager struct {
    clock Clock
    timers map[timerKey]*time.Timer
}

type timerKey struct {
    peerID string
    kind   string // "round", "packet_quiet", "backoff"
}

func (tm *TimerManager) Start(peerID, kind string, deadline time.Time, fn func())
func (tm *TimerManager) Cancel(peerID, kind string)
```

- timer 触发后向 `syncEventCh` post 对应事件，而不是直接回调。
- session 进入 `Completed`/`Failed` 时取消该 peer 所有 timer。
- 支持 fake clock 注入测试。

### 4.3 Async Object Pull

```go
// app/higgs/objectpull.go
func startObjectPullWorker(
    ctx context.Context,
    requests <-chan ObjectPullRequest,
    results chan<- ObjectPullResultEvent,
    maxInflight int,
)
```

- 每个 `StartObjectPull` action 塞入 worker pool。
- worker 完成 TCP pull 后把结果事件发回事件循环。
- `SyncSession` 跟踪每个 zone 的 inflight pull，防止重复请求同一对象。

### 4.4 State Mutation Boundary（状态变更边界）

为了后续并发安全，必须明确：**所有状态变更只允许在 daemon 事件循环 goroutine 中发生**。`SyncSession` 的 `OnEvent` 返回动作列表，但动作本身由事件循环统一执行；FSM 核心只读当前状态、输出下一状态和动作，不直接触碰可变状态。

**必须在事件循环内串行执行的状态变更：**

- `NetworkState` apply：`ApplySnapshot`、`ApplyRecordSnapshot`
- peer state 更新：`recordPeerSyncAt`、`recordVerifiedObservedPath`、backoff、last error
- `saveState()` 落盘
- `Transport` 运行时表更新：`AddKnownPeerID`、`SetPeerAddrs`、`SetObservedPeerPaths`、`lastSeenAddrs`
- IPsec / BIRD / routing 的 desired-state 计算与 reconcile 触发
- `udpChunkAssemblies`、`rejectedDigests` 等运行时缓存

**可以在 worker goroutine 中执行、但结果必须以事件回注的：**

- UDP 读包（单 reader，已在事件循环入口）
- TCP object pull 的网络 I/O
- DNS 解析
- 较重的批量 crypto verify（可选，结果以 `VerifyDoneEvent` 回注）

事件循环是唯一的 single writer。任何 worker 都不应直接持有 `stateFile`、`NetworkState` 或 `Transport` 的可变引用。后续若引入 read-only snapshot 并发验证，也只在事件循环把验证结果 apply 到 mutable state 时才写状态。

### 4.5 MTU / UDP Chunk / TCP Pull 的状态机集成

发送侧：

1. `sendSnapshots()` 不再阻塞，而是根据 `max_datagram_bytes` 预算生成 `SendAction` 列表：
   - 小 snapshot → `SendAnnounce`
   - 大 snapshot → `SendAnnounce{digestOnly=true}` + `StartObjectPull`（对端会走 TCP pull）
   - 大 snapshot 且允许 chunk → `SendAnnounce{digestOnly=true}` + 等对端发 `FETCH_ZONE{ChunkFallback:true}` 后再 `SendObjectChunk`
2. 事件循环按顺序执行 action；UDP send 失败不影响状态机，只记录统计。

接收侧：

1. 收到 `ANNOUNCE`，`handleAnnounceUntil` 直接 apply 小数据；遇到缺失/超预算 zone 则 emit `ObjectPullNeeded`。
2. FSM 进入 `ObjectPulling`，启动异步 TCP pull。
3. TCP 失败 → 进入 `ChunkFallback`，发送 `FETCH_ZONE{ChunkFallback:true}`。
4. 收到 `object_chunk` → `ObjectChunkEvent`；在 `ChunkFallback` 状态重组；完整后 apply。

## 5. RTT-Aware 超时设计（回答：250ms 是否太短）

固定 250ms 静默期对高 RTT 链路（跨国、卫星、无线回传）显然不够。设计改为**按 peer 估计 RTT 动态计算**。

### 5.1 估计 RTT

每个 `SyncSession` / peer 状态维护一个 `estimatedRTT`：

```
RTT_sample = PONG_received_at - PING_sent_at
estimatedRTT = (1 - α) * estimatedRTT + α * RTT_sample   (α = 0.125)
RTTVariance  = (1 - β) * RTTVariance  + β * |RTT_sample - estimatedRTT| (β = 0.25)
```

- 首次同步时 RTT 未知，用保守初始值 `initialRTT`（可配置，默认 1s）。
- 收到 `PONG` 后立即校准，后续所有 timer 用新值。
- 若连续丢包/超时，estimatedRTT 不衰减，避免在拥塞链路上误判。

### 5.2 静默期 `PacketQuietTimeout`

```
PacketQuietTimeout(peer) = max(
    MinPacketQuietTimeout,          // 可配置，默认 250ms；给本地/同机房链路留最小 burst 窗口
    kQuiet * estimatedRTT(peer) + jitter  // kQuiet 默认 3，jitter 0~200ms
)
```

示例：

| 链路 RTT | PacketQuietTimeout |
|----------|-------------------|
| 5ms（同机架） | 250ms |
| 50ms（同城） | 350ms + jitter |
| 200ms（跨洲光纤） | 850ms + jitter |
| 600ms（跨国/拥塞） | 2.0s + jitter |

含义：发出 `FETCH_ZONE` 后，若在 `PacketQuietTimeout` 内没再收到任何该 peer 的 UDP 包，才认为 burst 结束。高 RTT 链路不会过早进入 TCP object-pull。

### 5.3 整轮超时 `RoundTimeout`

```
RoundTimeout(peer) = max(
    MinRoundTimeout,                // 可配置，默认 5s
    kRound * estimatedRTT(peer) + ObjectPullBudget + jitter  // kRound 默认 5
)
ObjectPullBudget 默认 5s（单个大 zone 的 TCP 传输预算）
```

示例：

| 链路 RTT | RoundTimeout |
|----------|--------------|
| 5ms | 5s + jitter |
| 200ms | 6s + jitter |
| 600ms | 8s + jitter |

`RoundTimeout` 是整轮（包括 object-pull）的硬上限；`PacketQuietTimeout` 只是 burst 间停顿检测。二者独立 timer。

### 5.4 与旧代码 250ms 读超时的区别

旧代码 `receiveWithDeadline` 把 UDP socket 每次 read 限制在 250ms，是为了在阻塞 read 里能检查 context 取消。事件驱动重构后：

- 只有 `startGossipPacketReceiver` 读 socket；
- 它收到包后直接通过 channel 交给事件循环；
- 自身停止通过 `stopCh` / `ctx` 控制，不再需要 250ms 轮询 read deadline。

因此 **250ms 这个读超时将消失**，取而代之的是基于 RTT 的 timer 事件。

## 6. Daemon Event Loop 语义（回答：本地更新、落盘、并发安全）

### 5.1 单 goroutine 串行处理

daemon 主循环每次从 channel 取出一个事件，处理到完成，再取下一个。因此：

- 同一时刻只有一个事件在修改状态。
- 读取本地 digest/records 构造 `PING`/`ANNOUNCE` 时，状态不会被并发修改。
- 不需要对 `NetworkState` 加锁；事件循环就是锁。

### 5.2 本地 endpoint / record 更新如何触发 announce

以公网 IP 变化为例：

1. `endpointPublishTimer` 事件到达事件循环。
2. 事件处理函数在循环 goroutine 内：扫描 interface/reflector → 签名新 `sync/endpoint/udp` → 写入 `NetworkState` → `saveState()`。
3. digest 变化 → 调用 `notifyStateChanged()`，向事件循环 post 多个 `SyncTimerEvent{peerID}`。
4. 每个 peer 的 `SyncSession` 后续发 `PING` 携带最新 digest，把更新传播出去。

整个流程从 IP 发现、签名、写 state、落盘到触发 outbound sync，全在事件循环里完成。

### 5.3 收到远端 ANNOUNCE 如何落盘

1. UDP reader 把包交给 Packet Demuxer。
2. Demuxer 路由到对应 `SyncSession`。
3. `SyncSession` 生成 `ApplySnapshot` action。
4. 事件循环执行 `ApplySnapshot`，在循环 goroutine 内修改 `NetworkState`。
5. 若 digest 变化 → 事件循环执行 `saveState()`。
6. 同时触发 `notifyStateChanged`，向其他 peer post relay session。

### 5.4 发送时如何保证本地数据不被同时改

事件循环构造 `PING`/`ANNOUNCE` 时，读取的是当前 `NetworkState` 的一致视图。因为：

- 事件循环是单 goroutine；
- worker（object pull、DNS 等）不直接改状态；
- 本地 `record put`、timer 事件、远端 packet 事件都排队处理。

如果本地更新事件在「构造 PING」之前被处理，PING 携带新 digest；如果在之后被处理，则本轮 PING 携带旧 digest，下一轮或 relay 会传播新状态。这是最终一致性，不是 bug。

## 7. 与现有组件的关系

| 组件 | 变化 |
|------|------|
| `Transport.Receive()` | 只由 `startGossipPacketReceiver` 调用 |
| `Transport.Send()` | 不变，事件循环中调用 |
| `ReplayWindow` | 加互斥锁作为安全网；单 reader 后理论上无并发，但保留锁和 race 测试 |
| `PeerQuotas` | 仍在 `Transport.Receive()` / `Send()` 中检查，无需大改 |
| `objectPullTCPServe` | 不变，仍是独立 TCP server goroutine |
| `handlePacketUntil` | 保留给 unsolicited / cross-traffic 包；不再用于同步轮次 |
| `relaySync` | 改为 post `SyncTimerEvent` 创建独立 session |
| `sync once` CLI | 仍可工作：创建 session，block on `session.Done()` channel |

## 8. 状态持久化边界

旧代码在 `handlePacketUntil` 和 `syncRound` 里用 `defer saveState()`，导致落盘时机隐式且分散。新设计明确：

- **落盘时机**：
  - `SyncSession` 进入 `Completed` 或 `Failed`
  - 应用 `ANNOUNCE` 后 digest 发生变化
  - control/admin 事件处理完成后
- **不落盘**：
  - 单纯收到 `PING`/`PONG` 且状态未变
  - chunk 接收但未完整重组
  - timer 触发但状态未变
- daemon 主 goroutine 串行执行所有 `SaveState`，避免并发写 DB。

## 9. Race 修复清单

本次重构顺带修复以下已有 race（`go test -race ./...` 暴露）：

1. `ReplayWindow` map 并发读写 → 加 `sync.Mutex`。
2. `NetworkState.ConfigureRecordValidation` 被多 goroutine 写 → 改为 load 时初始化或加锁。
3. `recordPeerSyncAt` / `recordDatagramTooLarge` / `isRejectedDigestActive` 对 `syncPeerState` map 并发读写 → 在 daemon 单 writer 边界内序列化，或对 map 加锁。
4. `ApplySnapshot` 写 map 与 `VerifyChain` 读 map 并发 → 应用 snapshot 前先做深度拷贝或冻结读取视图。

## 10. 测试策略

1. **SyncSession 单元测试**：表驱动，覆盖所有状态转换，无网络/I/O。
2. **Demuxer 单元测试**：验证包路由到活跃 session 或 unsolicited。
3. **Timer Manager 单元测试**：fake clock，验证取消、重入、并发安全。
4. **Daemon 事件循环测试**：fake transport + fake clock，验证单 reader、session 生命周期、cross-traffic。
5. **RTT-aware timeout 测试**：fake clock 下模拟 RTT 600ms，验证 `PacketQuietTimeout` 自动放大到 2s 左右，不提前触发 TCP object-pull。
6. **Race 回归测试**：启动两个 goroutine 同时 `Receive()` 应该不再发生；已有 `TestReplayWindowConcurrentCheck`。
7. **现有 smoke 全量回归**：`phase1/2/multi-node/chain-relay/object-pull/nat-daemon-observed/ipsec-*/routing-dry-run`。

## 11. 验收标准

- [ ] 全仓库只有一个 goroutine 调用 `transport.Receive()`。
- [ ] `go test -race ./...` 通过。
- [ ] 所有现有 smoke 测试通过。
- [ ] 新增 `SyncSession` 单元测试覆盖：Ping/Pong、FetchZone、Announce、object-pull、chunk fallback、timeout、backoff、RTT-aware timeout。
- [ ] `docs/phase6-event-driven-design.md` 存在且与实现一致。
- [ ] `todo.md` Phase 6 已更新。
