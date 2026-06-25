# Higgs Gossip 协议

> **文档状态（2026-06）**
> 本文是 Higgs gossip 的 canonical 文档。它描述当前实现、已确认的问题，以及 bounded UDP control + catalog sync 规则。若现有代码与本文冲突，应以已通过测试的当前协议规则为准，然后回头修本文。

本文面向两类读者：
- 人类 operator / reviewer：理解 Higgs 如何同步 signed Zone state，如何处理 NAT、MTU 和大对象。
- 实现者 / AI agent：明确哪些语义不能再混在一起，避免继续把 unbounded list 或 bulk payload 塞进单个 UDP datagram。

---

## 1. 核心边界

Higgs gossip 只传播已签名的 Zone 状态。进入 active state 的数据必须通过 Zone authority、parent delegation、record signature 和 root digest 验证；传输路径只负责把对象交到验证层。

当前和目标协议都遵守三层传输角色：

| 层 | 载体 | 角色 | 不能承担的职责 |
|----|------|------|----------------|
| UDP control | `ping` / `pong` / `fetch_catalog_page` / `catalog_page` / `announce` / `fetch_zone` | 交换 bounded summary、分页 catalog、请求对象、发送变更 hint | 不依赖 IP fragmentation，不承载 unbounded list，不把多 datagram record 流作为正确性前提 |
| TCP object pull | 短连接 MessagePack | 拉取完整 Zone snapshot 或完整 record object | 不改变 trust boundary，不跳过签名验证 |
| UDP chunk fallback | `object_chunk` | TCP object pull 不可达时的兜底完整对象传输 | 不作为默认 bulk path，不承载未验证的部分状态 |

硬规则：

- UDP datagram 默认预算是 `1200` bytes；任何 UDP message 都必须先按 wire size 预算打包。
- 所有 list 都必须 bounded：Zone digest list、FetchZones、announce digest、records、catalog page 都不能假设一包装得下。
- `announce` 是 hint，可以携带小而完整的 payload；不能依赖多条 UDP record announce 才完成一个 Zone。
- 大对象默认走 TCP object pull；UDP chunk fallback 只在 TCP pull 明确失败或不可达后使用。
- relay 只在本地 verified active state 实际变化后触发；收到 hint 本身不是 relay 条件。

---

## 2. Wire 格式

默认 UDP wire codec 是 MessagePack，消息以 magic prefix 开头：

```text
higgs.gossip.m1\n<msgpack payload with version=1>
```

短期兼容读取旧 JSON magic `higgs.gossip.v1\n`。未知 magic 返回 `unsupported_codec`，未知 `version` 返回 `unsupported_wire_version`。

消息通用字段：

```go
type Message struct {
    Version   int
    Type      MessageType
    PeerID    string
    Nonce     uint64
    Timestamp int64

    Ping             *Ping
    Pong             *Pong
    FetchCatalogPage *FetchCatalogPage
    CatalogPage      *CatalogPage
    FetchZone        *FetchZone
    FetchRecord      *FetchRecord
    Announce         *Announce
    ObjectChunk      *ObjectChunk
}
```

接收端必须拒绝：
- magic / version 不支持。
- `peer_id`、`nonce`、`timestamp` 为空。
- body 字段数量不等于一。
- wire size 超过本地 `max_datagram_bytes`。

`FetchCatalogPage` / `CatalogPage` 已在当前 wire schema 中实现，用于替代 `PING` / `PONG` 上的完整 digest list。

---

## 3. Catalog 同步

### 3.1 为什么需要 catalog

旧实现把完整 `ZoneDigest[]` 放进 `PING` / `PONG`。这在小网络可用，但 Zone 数增多后会超过 1200-byte datagram 预算，导致 `ErrMessageTooLarge`。当前实现已经把主同步入口改为 `CatalogSummary` + bounded catalog page；兼容字段仍可被旧路径读取，但新发送路径不再承诺完整 digest list。`PONG.FetchZones` 和 `ANNOUNCE` digest / record 列表也会按 `max_datagram_bytes` 分页或降级为 hint / object pull。

因此 gossip v1 的下一步规则是引入 **Catalog**：

```text
Catalog = sorted list of ZoneDigest
CatalogRoot = hash(sorted(zone_path + zone_root))
```

`PING` / `PONG` 只交换 bounded summary，不再承诺携带完整 digest list。

### 3.2 Summary round

当前形态：

```text
PING { catalog_root, zone_count, optional first_page }
PONG { catalog_root, zone_count, optional first_page }
```

字段含义：

```go
type CatalogSummary struct {
    CatalogRoot []byte
    ZoneCount   int
    FirstPage   *CatalogPage // optional, currently not emitted by default
    NextCursor  string       // optional
}
```

如果双方 `catalog_root` 相同，round 可以直接完成。若不同，进入 catalog page diff。

### 3.3 Page diff

第一版采用简单分页，不直接上 Merkle range tree：

```text
FETCH_CATALOG_PAGE { cursor }
CATALOG_PAGE       { catalog_root, entries[], next_cursor }
```

`cursor` 第一版是稳定的 sorted catalog offset，空 cursor 表示第一页。`entries[]` 必须按 `max_datagram_bytes` 打包，不能超过预算；如果单条 entry 都装不进一页，发送方 fail closed 并记录诊断。

接收方对每页做本地 diff：

- 本地没有该 Zone：加入 `FETCH_ZONE` 候选。
- root 不同：加入 `FETCH_ZONE` 候选。
- 对端缺少本地 Zone：本端后续通过 relay/announce hint 让对端发现，或等待对端反向 round。

page diff 是 correctness baseline。后续大规模优化可以引入 Merkle range tree，但不是第一版必需。

### 3.4 Merkle range tree 作为后续优化

Merkle range tree 是把按 ZonePath 排序的 catalog 分成范围，每个范围有 hash。双方先比较大范围 hash，相同范围整段跳过，只递归不同范围。

它适合非常多 Zone 且只有少量变化的网络，但需要额外定义 range 切分、range id、空 range hash、恶意 peer 限流和超预算 range response。当前优先实现 sorted digest pages。

---

## 4. Object 同步

发现不同 Zone 后，接收方拉取完整对象：

```text
FETCH_ZONE { zone, expected_root }
TCP object pull { zone, expected_root }
OBJECT_PULL_RESPONSE { full ZoneSnapshot }
```

`FETCH_ZONE` 是兼容控制请求和 UDP chunk fallback 请求，不要求发送方把完整 snapshot 塞进 UDP。当前 catalog 主路径在 page diff 得出不同 Zone 后立即启动 TCP object pull；发送方可以用 `ANNOUNCE` 返回 digest hint 或小 payload，但接收方只在本地 root 对账成功后才算完成。

如果 TCP object pull 不可达，接收方可以请求：

```text
FETCH_ZONE { zone, expected_root, chunk_fallback: true }
```

发送方再用 `object_chunk` 发送完整对象 fallback。chunk 必须带 object type、Zone、root hash、content hash、total/index 和 payload。接收端只在所有 chunk 到齐、content hash 匹配、root/signature 验证通过后 apply。

---

## 5. Announce 与 Relay

`announce` 的目标语义：

```go
type Announce struct {
    Summary   *CatalogSummary  // optional, preferred for state-change hint
    Zones     []ZoneDigest     // bounded hint, optional
    Snapshots []ZoneSnapshot   // optional, small and complete only
    Records   []RecordSnapshot // optional, small optimization only
}
```

约束：

- `announce` 可以唤醒对端做 catalog diff。
- `announce` 不承诺携带完整 Zone。
- 小 snapshot / record 可以作为优化，但 correctness 仍由 root digest 对账决定。
- 多条 UDP record announce 不能组成事务。
- relay fanout 只在 apply 后本地 active digest 变化时触发，并排除来源 peer。

---

## 6. Endpoint 与 NAT

节点通过 signed endpoint record 传播长期可拨地址：

```text
<node-zone>/sync/endpoint/udp
```

endpoint record 是普通 Zone record，通过 gossip 同步和签名验证进入 active state。reflector、interface scan、manual advertise 都只是本节点生成 endpoint record 的输入。

NAT / observed path 规则：

- signed endpoint record 表示长期、可传播、由 Zone 签名的候选地址。
- observed UDP path 是本地 runtime reachability cache，不写入 signed endpoint record。
- `publish_endpoints: false` 的 NAT/outbound-only 节点不发布 direct endpoint；公网 peer 可用 verified observed path 回复它。
- 可达性不替代身份；transport source address 不参与 Zone trust 验证。

---

## 7. 运行形态

推荐长期运行入口是 `higgs daemon`：

- 单一 UDP reader：只有 `startGossipPacketReceiver` 调用 `transport.Receive()`。
- packet demux：按 `peer_id` 分发给活跃 `SyncSession`，未命中则走 unsolicited path。
- 单 writer：control socket 写入、sync apply、endpoint publish、relay、object pull result 都经 daemon event loop 串行处理。
- object pull worker 只能产生事件，不能直接写 `stateFile` 或 `NetworkState`。

`sync run` 是兼容入口，内部复用 daemon service。`sync serve` / `sync once` 保留用于 smoke 和排查，但长期节点应使用 daemon。

---

## 8. 安全与资源限制

- Anti-replay：`nonce + timestamp` 窗口。
- Allowlist：入站 `peer_id` 必须来自 bootstrap 或本地 verified Zone chain。
- Quota：按 peer 计 byte/object token。
- UDP size：发送前 preflight，接收时拒绝超预算。
- Object pull：短超时、响应大小上限、全局和 per-peer inflight 上限。
- Chunk fallback：短 TTL 重组缓存、最大对象大小、hash 校验、quota 计费。
- Rejected cache：坏 digest/object 在 TTL 内不重复拉取。

---

## 9. 当前实现差距

当前代码已经实现：

- MessagePack UDP framing 和 1200-byte budget。
- `PING` / `PONG` 的 `CatalogSummary`、`FETCH_CATALOG_PAGE` / `CATALOG_PAGE` bounded catalog page。
- `FETCH_ZONE` / `ANNOUNCE` / `OBJECT_CHUNK` 基础消息。
- `PONG.FetchZones`、`ANNOUNCE.Zones`、`ANNOUNCE.Records` 的发送预算保护；单项超预算时 fail closed 并记录 datagram diagnostics。
- TCP object pull 与 UDP chunk fallback。
- daemon 单 reader、事件循环和 per-peer `SyncSession` FSM；状态已包含 `SummarySent`、`CatalogDiffing`、`ServingPeerFetch`、`ObjectPulling`、`ChunkFallback`。
- `sync status --verbose` / `debug peer` 输出最近 catalog root、zone count、page cursor、page entries 和 rejected reason。

仍需向本文收敛：

- 后续大规模 catalog 可评估 Merkle range tree，当前第一版使用 sorted page cursor。
- `announce` 应逐步从 payload carrier 收敛为 state-change hint + optional small payload。

对应执行项见 `../todo.md` Phase 3.6.8。
