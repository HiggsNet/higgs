# SyncSession 时序警告

> **文档状态：2026-07**  
> 记录已知的 SyncSession FSM 时序问题，供后续 review 或流程重构时参考。

---

## W-001: ServingPeerFetch 导致 PONG 被丢弃

> **定位**：这是当前实现的时序风险记录，不是推荐按最小补丁实现的方案。后续应把它作为 gossip 读写分离重构的一个验证用例：`FETCH_*` 响应路径不应改变 active pull FSM 状态，`ANNOUNCE` 回到 hint 语义。

### 问题描述

当 SyncSession 处于 `PingSent` 状态时，如果对方先发来 `FETCH_ZONE` 请求，FSM 会将 state 切换为 `ServingPeerFetch`。这导致对方后续回复的 `PONG` 被 `onPongReceived` 丢弃，因为该 handler 只接受 `PingSent` / `SummarySent` 状态。

### 时序推演

```
我（已发 PING）                       对方
  │──── PING(我的 catalog) ──────────▶│
  │                                    │ 对方收到 PING，发现我需要他的 zone
  │◀──── FETCH_ZONE(要我的 zone) ─────│ 对方先发请求（要我的数据）
  │                                    │
  │  → onFetchZoneReceived             │
  │  → state = ServingPeerFetch        │
  │  → 我发 ANNOUNCE 响应              │
  │                                    │
  │◀──── PONG(含他的 catalog + FetchZones) │
  │  → onPongReceived                  │
  │  → state(ServingPeerFetch) 不在    │
  │    [PingSent, SummarySent]         │
  │  → return nil, nil  ← PONG 被丢弃 ❌  │
  │                                    │
  │  → PacketQuietTimeout              │
  │  → state = Completed               │
  │  → 这轮结束，没拿到对方 catalog     │
```

### 影响

| 影响 | 严重程度 | 说明 |
|------|----------|------|
| 本轮 PONG 丢失 | ⚠️ 轻度 | 对方的 FetchZones 和 catalog 未处理 |
| 对方拿到的数据 | ✅ 正常 | 我发的 ANNOUNCE 已送达 |
| 最终一致性 | ✅ 保证 | 下一轮周期 sync timer（默认 60s）会重新发起 |
| 数据丢失 | ❌ 不会 | Gossip 多轮收敛特性保证最终到达 |

### 涉及代码

- [sync_session.go:482-486](app/higgs/sync_session.go#L482-L486) — `onFetchCatalogPageReceived` 在 Idle 等状态将 state 改为 ServingPeerFetch
- [sync_session.go:501-517](app/higgs/sync_session.go#L501-L517) — `onFetchZoneReceived` 在 PingSent 等状态将 state 改为 ServingPeerFetch
- [sync_session.go:355-357](app/higgs/sync_session.go#L355-L357) — `onPongReceived` 只接受 PingSent / SummarySent，其他状态忽略

### 触发条件

触发窗口较窄，需要同时满足：

1. 本节点发了 PING（进入 PingSent）
2. 对方在处理 PING 过程中先发 FETCH_ZONE（而不是等 PONG 之后的 announce 路径）
3. FETCH_ZONE 在 PONG 之前到达本节点

### 旧修复思路（不作为主线）

**方案 A（最小改动，不推荐作为主线）**：`onPongReceived` 放宽 state 判断，支持 ServingPeerFetch：

```go
func (s *SyncSession) onPongReceived(e *PongReceivedEvent, now time.Time) ([]SyncAction, error) {
    // 放宽判断：ServingPeerFetch 也接受 PONG
    if s.State != SyncSessionPingSent && s.State != SyncSessionSummarySent && s.State != SyncSessionServingPeerFetch {
        return nil, nil
    }
```

但需要确认 ServingPeerFetch 状态下收到 PONG 后，`PendingZones` 是否被正确初始化（PingSent 时可能已被 FETCH_ZONE 路径覆盖）。

**方案 B（语义清晰）**：`onFetchZoneReceived` 在 PingSent 时不改 state，只记录 pendingZones，等 PONG 处理完后再统一发送 announce。但和现有 FSM 的事件驱动模型冲突——action 必须由 `OnEvent` 返回，不能延迟。

**方案 C（主线方向）**：拆分 FSM，让"我要拉的数据"和"对方要拉的数据"不共享一个 state。进一步说，响应对方读取请求不应该是一个会话子状态，而应该是 daemon 的只读 responder 路径。

目标设计见 [`gossip.md`](gossip.md#15-目标重构读写分离与-hint-语义)。

### 重构验收点

- `FETCH_CATALOG_PAGE` 到达时，若本地 active session 正在等待 `PONG`，session 仍保持等待 `PONG` 的状态。
- 普通 `FETCH_ZONE` 或 TCP object pull 响应不进入 `ServingPeerFetch` / `FetchingLocal`。
- `ANNOUNCE` 不直接承担完整对象同步；它只唤醒 catalog diff + object pull。
- 删除旧 `Pong.FetchZones` 兼容路径后，W-001 的时序窗口自然消失。

### 状态

- [ ] 已确认
- [ ] 已修复
- [ ] 已验证

---

## 附录：其他潜在时序问题

### (空)—待补充
