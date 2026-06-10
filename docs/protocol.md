# Higgs Gossip 协议

> **文档状态（2026-06）**  
> 本文档描述当前已实现的协议与 daemon 运行形态（Phase 1–3）。Phase 4+ 规划内容单独标注。

本文档描述 Higgs 用于在节点间传播区域状态的 gossip 同步协议，包括：传输格式、消息交换模式、最终一致性模型、节点发现机制以及传输层的安全防护。

---

## 1. 概述

Higgs 使用基于 UDP 的 gossip 层来维护动态节点网格中的区域状态最终一致性。每个节点持有一份全局区域图的本地视图（`NetworkState`）。节点通过定期比对轻量级的**区域摘要**（根哈希）来检测数据分歧，通过 `ANNOUNCE` 消息交换缺失的数据，并将变更转发给其他节点以实现传递式收敛。

节点通过稳定的 `peer_id` 标识（通常为其管理的区域名，如 `node-a.catofes.`）。传输层维护一个**允许列表**（allowlist）来记录已知节点。初始列表来自静态的 `bootstrap` 配置，但随着节点通过签名端点记录相互发现，允许列表会在运行时动态扩展。

---

## 2. 传输层与线路格式

### 2.1 UDP 传输

Gossip 层绑定一个 UDP 套接字，所有消息以单播数据报形式发送到特定节点。

| 默认值 | 数值 |
|---------|-------|
| 默认端口 | `33434` |
| UDP datagram 预算 | `1200` 字节 |
| 线路版本 | `1` |

### 2.2 消息帧格式

线路上每条消息都以 ASCII 魔术前缀开头，后跟一个 MessagePack payload：

```
higgs.gossip.m1\n<msgpack payload with version=1>
```

默认发送路径使用 MessagePack；短期兼容读取旧 JSON magic `higgs.gossip.v1\n`。未知 magic 会被拒绝为 `unsupported_codec`，未知 `version` 会被拒绝为 `unsupported_wire_version`。

UDP 小包默认不启用通用压缩。当前常见控制消息依靠 MessagePack 短字段名和二进制 `bytes` 字段保持在 1200-byte datagram 预算内；超过预算的 zone snapshot / record 不通过 UDP 发送完整对象，而是发送 digest-only announce，并由接收端走 TCP object pull 拉取完整对象。当前 object pull 使用 length-prefixed MessagePack，暂不压缩。后续若引入 zstd 等压缩，只允许用于大 object pull 响应，并必须同时定义压缩阈值、最大解压大小和 CPU/内存上限；UDP 控制面仍默认不压缩，避免小包负收益和解压放大风险。

反序列化时会拒绝以下消息：
- 不以已支持的 magic 前缀开头。
- `version` 不等于 `1`。
- `peer_id`、`nonce` 或 `timestamp` 为空。
- 携带的 body 字段（`ping`、`pong`、`fetch_zone`、`fetch_record`、`announce`）数量**不等于一**。

### 2.3 消息类型

```go
type Message struct {
    Version   int         `json:"version"`    // 始终为 1
    Type      MessageType `json:"type"`       // ping | pong | fetch_zone | fetch_record | announce
    PeerID    string      `json:"peer_id"`    // 发送者身份
    Nonce     uint64      `json:"nonce"`      // 反重放
    Timestamp int64       `json:"timestamp"`  // Unix 秒，反重放窗口

    Ping        *Ping
    Pong        *Pong
    FetchZone   *FetchZone
    FetchRecord *FetchRecord
    Announce    *Announce
}
```

| 类型 | 方向 | 用途 |
|------|-----------|---------|
| `ping` | 出站 | "这是我的区域摘要。" |
| `pong` | 入站（回复 `ping`） | "这是我的区域摘要；请拉取这些区域。" |
| `fetch_zone` | 出站 | "发送该区域的全量快照给我。" |
| `fetch_record` | 出站 | "发送指定记录（按 key/version）。" |
| `announce` | 入站 | "这是完整的区域快照和/或独立记录。" |

---

## 3. 同步模式

CLI 提供四种与同步相关的命令，分别对应不同的运行时模式：

### 3.1 `sync serve` — 被动入站

```
higgs sync serve
```

打开 UDP 套接字，打印本地身份和绑定地址，然后循环接收数据包。每个有效的入站数据包都会分发给 `handleSyncPacket` 处理。没有定期出站同步，节点仅响应远程节点发起的请求。

适用场景：只需接受推送更新而无需主动轮询的边缘节点。

### 3.2 `sync once` — 单次往返

```
higgs sync once <peer-id>
```

打开传输层，向指定节点发送一个 `PING`，等待最多 `5s` 接收 `PONG`（以及可能的后续 `ANNOUNCE` / object pull），然后退出。适用于临时同步或脚本编排。

### 3.3 `daemon` — 本机长期运行与单 writer

```
higgs daemon --interval 5
```

这是 Phase 3 后推荐的本机长期运行模式，结合了入站服务、定期出站同步、节点发现、endpoint publish 和本机 control socket。daemon 是本节点 state DB 的唯一长期 writer：CLI 写入、同步 apply、endpoint publish、manual trigger 和 timer tick 都经由同一个事件处理边界串行执行。

1. **事件队列** — `record_put`、UDP packet、remote announce applied、endpoint publish timer、outbound sync timer、manual `sync_trigger`、`shutdown` 都进入 daemon event handler。事件处理函数负责串行落盘、更新 peer state、触发 relay 或唤醒下一轮 outbound sync。
2. **状态重载** — 每次出站同步前，如果磁盘上的区域摘要与上次观察到的不同，节点会重新加载状态。这样 daemon 停止期间的恢复写入、新委托或外部修复可以在 daemon 重启后生效。
3. **端点发布** — 每隔 `reflector_interval`（默认 `5m`），节点收集自身网络端点，签名一份 `sync/endpoint/udp` 记录，并写入其管理的区域。
4. **出站同步轮次** — 每隔 `interval`（默认 `5s`），节点遍历所有已知节点（bootstrap + 发现），对未处于退避状态的每个节点执行 sync round。由 local `record_put` 或 manual trigger 唤醒的轮次会绕过旧 backoff 一次，确保本地新写入能立即尝试传播。
5. **入站接收** — 出站轮次之间，节点以 `250ms` 的超时轮询套接字，处理任何数据包。如果数据包包含的 `ANNOUNCE` 改变了本地状态，则记录来源 peer 并触发**中继**（见 §4.3）。
6. **Control socket** — daemon 默认监听 Unix domain socket，路径为 `HIGGS_CONTROL_SOCKET`、root 下 `/run/higgs/higgs.sock`，或 `<data_dir>/higgs.sock` fallback。API 包含 `status`、`record_put`、`delegate_issue`、`delegate_revoke`、`join_accept`、`sync_trigger`、`shutdown`；`reload` 已预留但当前返回错误。socket 文件权限为 `0600`，第一版只作为本机控制面，不提供远程管理入口。

CLI 在检测到 daemon control socket 可用时，会优先作为 client 提交写命令。例如 `record put` 会由 daemon 签名、写 DB 并触发 outbound sync；`delegate issue` 会把 join request 交给持有父 Zone 私钥的 daemon，由 daemon 签发 delegation、写 DB，并把 bundle 作为结构化响应返回给 CLI 写入文件。join bundle 只携带 root 到目标 Zone 的最小 authority chain 和每一跳 direct delegation proof；父 Zone 的 records、record history、兄弟 delegation table 不进入 bundle，后续通过普通同步获取。`delegate revoke` 由 daemon 串行写入 signed revocation/tombstone、清理 peer state 并触发后续同步；`join accept` 在 daemon 已运行时通过 control API 导入 bundle，避免运行态旧 snapshot 覆盖。daemon 不存在时这些命令保留直接写 DB 的开发/恢复模式，并输出明确提示。`root init` 是 daemon 启动前的离线初始化；如果已有 daemon 加载了 state，control API 会拒绝重置 root state。

### 3.4 `sync run` — 兼容长运行入口

```
higgs sync run --interval 5
```

`sync run` 保留为开发/兼容入口，当前内部委托给 daemon service，避免维护两套长期运行主循环。语义与 `daemon` 的 gossip 主路径保持一致，但新的本机单 writer/control socket 运行形态应优先使用 `higgs daemon`。

daemon / `sync run` 的核心循环包括：

1. **状态重载** — 每次出站同步前，如果磁盘上的区域摘要与上次观察到的不同，节点会重新加载状态。
2. **端点发布** — 每隔 `reflector_interval`（默认 `5m`），节点收集自身网络端点，签名一份 `sync/endpoint/udp` 记录，并写入其管理的区域。
3. **出站同步轮次** — 每隔 `interval`（默认 `5s`），节点遍历所有已知节点（bootstrap + 发现），对未处于退避状态的每个节点执行 sync round。
4. **入站接收** — 出站轮次之间，节点以 `250ms` 的超时轮询套接字，处理任何数据包。如果数据包包含的 `ANNOUNCE` 改变了本地状态，则触发**中继**（见 §4.3）。

### 3.5 MTU-safe object pull

公网 gossip 不依赖 IP fragmentation。发送端会在写 UDP 前按 `max_datagram_bytes` 预算预估 MessagePack wire size；超预算的 Zone skeleton 或 record 不会直接塞进 UDP datagram。

同步主路径只用 UDP 传播 digest、fetch request、小 metadata 和小 record。若 digest 显示本地缺少完整对象，节点会通过短连接 TCP object pull 拉取完整 Zone snapshot 或单条 record。默认 TCP pull 使用 signed/bootstrap UDP endpoint 的同一个数字端口；TCP 与 UDP 可以绑定同一端口号。

如果 TCP object pull 不可达，但双方已经通过 bootstrap、verified Zone/delegation 或 observed UDP path 建立了可用 UDP 通道，发送端可在 `fetch_zone` 后把完整 Zone snapshot 拆成多个 `object_chunk` UDP datagram 作为 fallback。每个 chunk 绑定 object type、Zone、root hash、content hash、total/index 和 payload；接收端只在所有 chunk 到齐且 content hash 匹配后解码完整对象，再按原有 root/delegation/record signature 验证并 apply。chunk 缓存有短 TTL 和最大对象大小，chunk 消息仍计入 per-peer quota。

TCP object pull 和 UDP chunk 都只是传输优化：收到的 snapshot / record 仍按 root/delegation/record signature 验证，不能绕过 trust boundary。

---

## 4. 最终一致性模型

### 4.1 摘要交换

核心一致性机制是轻量级哈希比对，随后进行选择性数据传输。

`ZoneDigest` 的结构为：

```go
type ZoneDigest struct {
    Zone     zone.ZonePath
    RootHash []byte  // 对 authority + delegations + records 的确定性哈希
}
```

`ZoneRoot` 按排序顺序对以下内容进行确定性哈希计算：
1. 区域 authority 哈希。
2. 每个委托（路径、authority 哈希、签名）。
3. 每个活跃记录（键、记录哈希）。

**一次同步轮次的过程如下：**

```
节点 A                                    节点 B
------                                    ------
PING  { Zones: [A 的摘要] }
          ──────────────────────────>

                                      PONG  { Zones: [B 的摘要],
                                              FetchZones: [B 想从 A 拉取的区域] }
          <──────────────────────────

FETCH_ZONE { Zone: z }
          ──────────────────────────>

                                      ANNOUNCE { Snapshots: [区域 z 的全量数据] }
          <──────────────────────────
```

1. **PING** — 节点 A 发送其完整的区域摘要列表。
2. **PONG** — 节点 B 回复自己的摘要列表。同时设置 `FetchZones` 为 B 缺失或与 A 状态不同的区域列表。（如果 `FetchZones` 为空，B 会退而基于摘要差异通过 `FETCH_ZONE` 请求单个区域。）
3. **FETCH_ZONE** — A 请求 B 声明需要的每个区域。
4. **ANNOUNCE** — B 回复一个或多个 `ZoneSnapshot` 对象，包含完整的 authority、委托、记录和父证明链。

应用快照后，A 再次比对摘要。如果有任何变化，A 触发**中继**（见 §4.3）。

### 4.2 快照验证与应用

接收到的快照**绝不**被盲目信任。接收方执行两阶段验证：

1. **候选验证** — 创建本地 `NetworkState` 的临时副本，将传入的快照嫁接到其上，然后对临时树运行 `VerifyChain`。如果区域无法追溯到受信任的根节点，整个快照将被拒绝（`ErrUntrustedZone`）。
2. **委托验证** — 快照内的每个子委托都独立针对区域 authority 进行验证。
3. **记录应用** — 记录按版本顺序通过 `ns.PutAt` 应用到**活跃**存储中。陈旧记录（`ErrStaleRecord`）和版本冲突（`ErrRecordConflict`）会被静默跳过；其他错误会中止应用过程。

只有在所有检查通过后，活跃状态才会更新并持久化到本地 bbolt 数据库。

### 4.3 中继与传递收敛

当节点应用了改变其本地摘要的 `ANNOUNCE` 时，它会向**所有其他已知节点**（排除更新的来源）发起轻量级同步轮次：

```go
relaySync(ctx, state, transport, sourcePeerID)
```

中继受每节点节流限制：
- 处于**退避**状态（同步失败后）的节点会被跳过。
- 距离上次中继时间不足 `relayMinInterval`（`1s`）的节点会被跳过。

这种 gossip 式中继确保单次写入可以在整个网格中传播，而无需每对节点直接通信。在连通且无分区的图中，所有诚实节点最终会持有相同的活跃状态。

### 4.4 冲突解决

Gossip 传播的是**带单调版本号的签名记录**。如果两个节点对同一区域/键产生冲突值，较高版本获胜。`Timestamp` 字段仅用于审计，不参与冲突解决。这意味着：

- 时钟偏差不会导致状态抖动。
- 恶意或回溯的时间戳无法覆盖更新的有效数据。
- 覆盖记录的唯一有效方式是使用区域 authority 的签名发布新版本。

---

## 5. 节点发现

Higgs 节点不需要将所有节点都列在静态的 `bootstrap` 配置中。协议通过签名端点记录支持**运行时节点发现**。

### 5.1 发布本地端点

每个节点定期（默认 `5m`）调用 `publishEndpointRecord`：

1. 合并 `config.yaml` 中显式配置的 `advertise_addrs`（最高优先级）。
2. 按配置顺序查询 `reflectors`，接受纯文本 IP、HTML/普通文本中嵌入的 IP，或常见 JSON 字段（如 `ip`、`origin`、`query`、`address`、`public_ip`），并把有效 IPv4/IPv6 作为 `source=reflector` 候选。
3. 扫描本地网络接口（跳过回环、链路本地和容器接口，如 `docker*`、`veth*`、`cali*`、`flannel*`、`wg*`）。
4. 构建一个 `EndpointRecord` JSON 值。
5. 以记录形式签名，键为 `sync/endpoint/udp`，存储到节点自身管理的区域中。
6. 存入本地活跃状态（后续同步轮次会将其包含在内）。

```json
{
  "endpoints": [
    {
      "address": "192.168.1.10",
      "port": 33434,
      "protocol": "udp",
      "scope": "site",
      "source": "interface",
      "priority": 20,
      "last_observed": 1717171717
    }
  ],
  "ttl_seconds": 3600,
  "grace_seconds": 600,
  "source": "local",
  "updated_at": 1717171717
}
```

由于这只是普通区域中的普通签名记录，它通过与其他数据相同的 `PING`/`PONG`/`ANNOUNCE` 流程传播。

当本机 endpoint 发生变化时，节点会在新记录中继续保留最近观测到的旧 endpoint，直到 `endpoint_grace` 窗口结束。远端解析记录时根据 `ttl_seconds`、`grace_seconds` 和每个 endpoint 的 `last_observed` 过滤过期地址；如果某个已发现地址刚刚成功完成过同步，也会在本地地址簿中短暂保留作为回退地址。静态 bootstrap 地址始终作为发现地址之后的 fallback。

Reflector 只参与本节点自发现：第三方 HTTP 响应不会直接进入其他节点的 allowlist。节点必须先用自己的 Zone 私钥签名 endpoint record；其他节点只解析 verified active state 中的记录。

默认 `peer_id` 等于节点授权 Zone FQDN。只有同一个授权 Zone 下确实存在多个独立 gossip 实例或角色时，才允许引入 alias/instance id；该 alias 必须由对应 Zone 的签名记录显式授权，并且不能绕过 Zone FQDN 到 endpoint record 的绑定关系。

### 5.2 提取已发现节点

每次同步轮次（以及每次状态变更后），每个节点都会扫描其活跃 `NetworkState`，调用 `ExtractPeerEndpoints`：

- 遍历所有区域。
- 查找以 `sync/endpoint/` 为前缀的键。
- 反序列化 JSON 值。
- 返回 `peer_id -> []EndpointEntry` 映射，按优先级排序。

节点随后将每个发现节点的全部地址（按优先级排序）注册到传输层的出站地址簿：

```go
transport.SetPeerAddrs(peerID, addrs)
```

发送消息时，传输层会按顺序尝试每个地址，直到有一个成功写入 UDP socket。这确保了即使某个 endpoint 暂时不可达（例如内网地址在 NAT 场景下不通），节点仍有机会通过其他地址建立通信。

这动态扩展了出站节点列表，无需重启节点或重写配置文件。

### 5.3 允许列表验证

传输层对每个入站数据包执行两层校验：

**入站身份校验（`knownPeers` 白名单）：**  
`peer_id` 必须存在于运行时 `knownPeers` 集合中，否则丢弃并返回 `ErrUnknownPeer`。  
`knownPeers` 包含两类来源：
- **Bootstrap 配置**：`config.yaml` 中的 `bootstrap` 列表，节点启动时注册。
- **已验证 Zone 列表**：凡是本地 active state 中能通过 `VerifyChain` 的 Zone，其 Zone path 即作为合法 `peer_id` 加入白名单（通过 `AddKnownPeerID` 写入，不含出站地址）。

这防止了任意互联网主机通过知道魔术前缀就向 gossip 网格注入数据，同时解决了新节点首次接入的死锁问题（详见 §5.5）。

**传输层不再检查 UDP 源地址是否与注册地址匹配** — 身份真实性完全交给上层签名链验证（`VerifyChain` / `VerifyRecord`）。

### 5.4 CLI 发现诊断

```bash
# 显示所有 bootstrap 和已发现节点及其状态
higgs sync status --verbose

# 显示特定节点的端点条目
higgs debug peer <peer-id>

# 显示所有提取的端点记录
higgs debug endpoints
```

### 5.5 Bootstrap 首次接入死锁修复

**问题根因：**  
若传输层仅对持有 `sync/endpoint/udp` Record 的 peer 开放入站，新节点 B 首次向 A 发 Ping 时会被拒绝（`ErrUnknownPeer`）。而 B 的 endpoint 永远无法传播给 A——形成死锁。

**根本原因** 是传输层 `knownPeers` 混淆了「准入控制（身份）」与「地址发现（可达性）」两个角色。

**修复方案：**

```
Transport.AddKnownPeerID(peerID)   // 只写入 knownPeers 入站白名单，不写 outboundAddrs
Transport.SetPeerAddrs(peerID, []) // 写入出站地址簿（endpoint record 来源）
Transport.lastSeenAddrs            // Send() 无静态出站地址时，回退到最近 inbound 包的 UDP 源地址
```

- `openSyncTransport` 初始化时先对所有能通过 `VerifyChain` 的 Zone 调用 `AddKnownPeerID`。
- 有 endpoint record 的 peer 额外调用 `SetPeerAddrs`。
- B 首次向 A 发 Ping 时，A 可通过 `lastSeenAddrs` 回复 Pong，B 的 endpoint record 随后通过正常 gossip 流程传播。

**安全边界不变：**  
入站白名单放宽到「有合法 delegation chain」的 zone，但消息内容仍经过完整 `VerifyChain` / `VerifyRecord` 验证，信任根不变。

---

## 6. Phase 4 IPsec / Overlay 公告协议（规划）

本节描述 Phase 4 规划中的 IPsec/StrongSwan mesh 控制面记录。它们仍然是普通 Zone Record，通过本文前述 gossip 协议同步和验证；gossip 只负责传播 signed state，不直接解释或执行 StrongSwan 配置。真正的建链由本机 daemon 的 LinkPlanner 和 `provider=strongswan` 驱动完成。

Phase 4 的关键边界：
- 公开记录只表达节点的 IPsec 能力、accept intent、地址候选、端口公告和 transport key。
- 本地 MeshPolicy 规则不通过 gossip 公开；它属于本节点拓扑和安全策略。
- 地址与端口分离公告。远端运行时把 AddressCandidate 与 PortAdvertisement 组合成 ContactPoint 后再拨号。
- StrongSwan/VICI/XFRM apply 永远以 verified active state 为输入；discovery server、reflector、DNS 响应不能绕过 Zone trust chain。
- VICI socket、`charon`、XFRM interface、`CAP_NET_ADMIN`/root、UDP 端口可用性等 preflight 只决定本机是否能 apply；它们不是 gossip 记录，也不参与 Zone trust chain。

### 6.1 Record key 与类型

`pkg/transport/ipsec` 已实现这些 record 的 Go 结构、解析/校验、ContactPoint 组合逻辑和本机 StrongSwan/XFRM preflight 检测；daemon 仍必须只在记录已经通过 Zone trust chain 验证后使用它们。

规划 record：

| Key | Type | 用途 |
|-----|------|------|
| `ipsec/profile` | `ipsec.profile.v1` | 公开本节点 IPsec 能力、IKE identity、accept intent、NAT/reachability hint |
| `ipsec/addresses` | `ipsec.addresses.v1` | 公开地址来源与当前候选；包括 DNS 源、手工 IP、discovery、reflector、local |
| `ipsec/ports` | `ipsec.ports.v1` | 公开 IKE/NAT-T 端口策略、当前端口、旧端口 grace、observed external port |
| `ipsec/transport-key` | `ipsec.transport_key.v1` | 将 IKE public key / cert fingerprint 绑定到节点 Zone trust chain |

这些记录必须由节点自身 Zone 签名，例如 `node-a.catofes.` 只能为自己的 `ipsec/*` 记录签名。父 Zone 的 delegation/revocation 仍然决定该节点是否被全网信任；一旦 Zone 被撤销，远端必须停止使用其 IPsec records，并 teardown 对应 LinkInstance。

### 6.2 `ipsec/profile`

示例：

```json
{
  "version": 1,
  "enabled": true,
  "provider": "strongswan",
  "ike_identity": "node-a.catofes.",
  "transport_key_fingerprint": "b2:...",
  "accept": "inbound",
  "address_families": ["ipv6", "ipv4"],
  "path_modes": ["family-redundant", "exhaustive"],
  "nat": {
    "hint": "unknown",
    "inbound_reachable": "unknown"
  },
  "updated_at": 1717171717
}
```

字段语义：
- `enabled`：是否允许自动 IPsec mesh 使用该 profile。
- `provider`：第一版只接受 `strongswan`。
- `ike_identity`：IKE 层身份，默认等于 Zone FQDN。
- `transport_key_fingerprint`：引用 `ipsec/transport-key` 中的 public key/cert。
- `accept`：`none`、`inbound`、`bidirectional`。它是公开的连接意图摘要，不是完整拓扑。
- `address_families`：该节点愿意用于 IPsec 的地址族。
- `path_modes`：该节点可接受的 path mode。
- `nat.hint`：`public`、`behind_nat`、`unknown`。它只是 hint，不是安全事实。
- `nat.inbound_reachable`：`true`、`false`、`unknown`。只有配合已验证 ContactPoint 才能作为拨入依据。

### 6.3 `ipsec/addresses`

地址记录不包含端口。daemon 会从多个来源生成 AddressCandidate，远端按本地优先级和 rule 过滤。

```json
{
  "version": 1,
  "addresses": [
    {
      "id": "dns-main",
      "source": "manual-dns",
      "host": "node-a.example.com",
      "families": ["ipv6", "ipv4"],
      "refresh_seconds": 60,
      "priority": 90,
      "reachability": "public",
      "ttl_seconds": 300
    },
    {
      "id": "manual-v6",
      "source": "manual-address",
      "address": "2001:db8::10",
      "family": "ipv6",
      "priority": 100,
      "reachability": "public",
      "ttl_seconds": 3600
    },
    {
      "id": "reflector-v4",
      "source": "reflector",
      "address": "203.0.113.10",
      "family": "ipv4",
      "priority": 60,
      "reachability": "nat-observed",
      "last_observed": 1717171717,
      "ttl_seconds": 600
    }
  ],
  "updated_at": 1717171717
}
```

地址来源：
- `manual-address`：管理员显式配置的 IP。
- `manual-dns`：管理员显式配置的域名。记录必须保留域名本身；运行时按 `refresh_seconds` 解析 A/AAAA。
- `discovery`：可选 discovery server 返回的候选地址或域名。
- `reflector`：反射服务看到的外部地址，常用于 NAT/公网变化场景。
- `local`：本机接口扫描结果。公网场景默认应允许禁用。

实现上，`pkg/transport/ipsec` 将 DNS/discovery host 解析作为运行时输入处理：signed record 保留 `host`，`ResolveAddressCandidates` / `ResolveContactPoints` 在传入 resolver 时才把 `manual-dns` 或 `discovery` host 的 A/AAAA 展开为可拨号的 `AddressCandidate` / `ContactPoint`，并保留原始域名、family、TTL/refresh 元数据。没有 resolver 的 dry-run 仍可读取域名记录，但不会把未解析域名误当成 IP endpoint。

DNS 不是天然最高优先级。动态 DNS 很多时候只是 public reflector/discovery 的另一种外壳，因此本地配置必须允许调整 source order 或在 MeshPolicy rule 中限制 source。当前 Go 实现通过 `AddressCandidateOptions.SourceOrder` 和 `AllowedSources` 做来源排序/过滤，先按 source order，再按单条 priority 排序；`AllowPrivateLocal` 默认 false，公网默认不会把 local 私网、loopback、link-local 或 ULA 候选用于 IPsec 拨号。

### 6.4 `ipsec/ports`

端口记录不包含 IP。节点可以固定端口，也可以在配置范围内选择端口并公告。端口轮换时同时保留 current 与 previous grace，远端在 grace 内可回退旧端口。

```json
{
  "version": 1,
  "mode": "range",
  "range": {"from": 30000, "to": 30999},
  "current": {
    "generation": 42,
    "ike": {"local": 30412, "advertised": 30412, "observed": 30412},
    "natt": {"local": 30413, "advertised": 30413, "observed": 30413},
    "valid_until": 1717175317
  },
  "previous": [
    {
      "generation": 41,
      "ike": {"advertised": 30100},
      "natt": {"advertised": 30101},
      "valid_until": 1717172017
    }
  ],
  "updated_at": 1717171717
}
```

端口字段：
- `local`：本机 StrongSwan/charon 监听端口。
- `advertised`：希望远端拨入的端口。
- `observed`：reflector/discovery 看到的外部端口。NAT 后可能不同于 `local`。
- `generation`：端口选择代数，用于判断新旧公告。
- `valid_until`：端口公告过期时间；过期后远端不得继续尝试。

`pkg/transport/ipsec.PlanPortRecord` 是第一版本地端口选择边界：未配置时发布标准 500/4500；固定端口按配置发布；范围端口按 `generation` 稳定选择一组 IKE/NAT-T 端口；轮换时把上一代 `current` 带入 `previous` 并设置 grace `valid_until`。peer 端只把未过期的 `current` / `previous` 与 address candidates 组合成 `ContactPoint`，不把端口写死到地址里。

UDP 500/4500 是 IKE/NAT-T 的传统默认值，但 Higgs 协议层不能把它们写死。StrongSwan 当前的实际边界是：`charon.port` / `charon.port_nat_t` 控制本地监听端口，`swanctl.conf` connection 的 `remote_port` 可指定远端端口；自定义 server port 通常走 NAT-T socket，MOBIKE 默认可能把会话漂移到 NAT-T 端口。Phase 4 先支持 current/previous grace 与明确 reestablish，Phase 7 再考虑高频 port hopping、多实例或 DNAT 风格的更激进方案。

### 6.5 `ipsec/transport-key`

IPsec/IKE 认证材料不得复用 Zone signing key。节点应生成独立 IKE key/cert 或 raw public key，再用 Zone record 把该 transport key 绑定到信任链。

transport private key 是 daemon 本地持久化材料，不进入 gossip。`ipsec/transport-key` 只发布 public key、algorithm、fingerprint 和有效期；生成 record 时必须显式拒绝与当前 Zone signing public key 相同的 raw public key。第一版 fingerprint 使用 `higgs.ipsec.transport-key.v1` domain-separated BLAKE2b-256，对 algorithm 和 public key 一起取 hash，并以冒号分隔 hex 输出。

示例：

```json
{
  "version": 1,
  "kind": "raw-public-key",
  "algorithm": "ed25519",
  "public_key": "base64...",
  "fingerprint": "b2:...",
  "not_before": 1717170000,
  "not_after": 1722440400,
  "updated_at": 1717171717
}
```

优先使用 Ed25519。若 StrongSwan/部署环境兼容性不足，可退到 ECDSA P-256。RSA 长 key 会显著增加 record 和控制面体积，不作为默认路线。

### 6.6 LinkPlanner 组合语义

LinkPlanner 输入：
- verified active state 中的 peer Zone 和 `ipsec/*` records。
- 本机 MeshPolicy rule。
- 本机 address source order、端口策略、连接成功/失败历史。
- delegation revocation/tombstone 状态。

处理流程：

```text
1. 扫描 verified peer zones。
2. 读取 peer ipsec/profile；过滤 enabled=false、accept 不匹配、本地 deny rule 命中的 peer。
3. 读取 ipsec/addresses；解析 DNS 源，过滤过期/来源不允许/地址族不允许的候选。
4. 读取 ipsec/ports；过滤过期端口，优先 current，grace 内保留 previous fallback。
5. 组合 AddressCandidate + PortAdvertisement => ContactPoint。
6. 根据 path mode 选择 ContactPoint：
   - family-redundant：每个地址族最多一条。
   - exhaustive：尽量保留所有允许候选。
7. 输出 TransportLinkSpec 给 provider=strongswan。
```

provider apply 的第一版可审计边界已经固定在 `ApplyTransportLink` / `ApplyPlan`：先确保目标 namespace，再加载 StrongSwan connection，然后确保 XFRM interface，最后分配本地 tunnel address。dry-run driver 记录同一顺序，使非 root 环境也能验证 desired config 推导和错误路径；真实 VICI/netlink provider 后续实现时应保持同一操作顺序和 plan 输出。

方向组合：

| 本地 direction | 远端 accept | 结果 |
|----------------|-------------|------|
| `outbound` | `inbound` / `bidirectional` | 主动拨号 |
| `inbound` | 任意 | 只加载接收配置 |
| `bidirectional` | `inbound` | 主动拨号 |
| `bidirectional` | `bidirectional` | 用 peer id/zone 的稳定排序决定首拨方 |
| `outbound` | `none` | 不自动建链 |

NAT 组合：
- 公网 inbound 节点 + NAT/outbound-only 节点：NAT 后节点主动拨公网节点是第一版主路径。
- 公网节点主动拨 NAT 后节点：只有在远端有 IPv6、静态映射、已验证 observed external port、打洞或 relay 时才可尝试。
- 两端都在 NAT 后且没有可验证公网 ContactPoint：LinkInstance 进入 `degraded`，debug 输出说明不可达原因。

### 6.7 本地 MeshPolicy 规则

MeshPolicy 本地持久化，不进入 gossip。为了保持配置简单，第一版使用 URI 规则：

```yaml
overlays:
  - name: ipsec-main
    provider: strongswan
    connect:
      - "strongswan://*.catofes.?accept=inbound&family=dual&source=manual-dns,discovery&mode=family-redundant&direction=outbound"
      - "strongswan://role=edge?accept=bidirectional&family=dual"
    deny:
      - "strongswan://tag=lab"
```

第一版支持的 predicate：
- zone glob / exact。
- `role` / `tag`。
- `accept`。
- `direction`。
- `family`。
- `source`。
- `mode`。
- `max_peers`。

规则应先处理 deny，再按 connect 顺序选择。正则表达式不是第一版默认能力；glob/suffix/label 更容易审计。

---

## 7. 安全机制

### 7.1 节点身份验证

传输层维护两个集合：

- **`knownPeers`**（入站白名单）：包含 bootstrap 配置中的 peer ID + 本地 active state 中所有 `VerifyChain` 通过的 Zone path。每个接收到的数据包检查 `peer_id` 是否在此集合中，否则丢弃（`ErrUnknownPeer`）。
- **`outboundAddrs`**（出站地址簿）：来自 `config.bootstrap` 中的静态地址 + 从 `sync/endpoint/udp` record 中动态发现的地址。发送时按优先级依次尝试。
- **`lastSeenAddrs`**（临时入站反向地址）：`Send()` 在无出站地址时，回退使用最近一次收到该 peer 数据包的 UDP 源地址。

节点在启动时从 `bootstrap` 配置注册，在运行时从发现的 Zone 和端点记录动态扩展。

### 7.2 反重放窗口

每条消息都携带随机 `nonce` 和 `timestamp`。接收方检查两者：

- **时间戳窗口** — 消息时间戳必须落在接收方本地时钟的 `±5 分钟` 内。否则拒绝并返回 `ErrMessageExpired`。
- **Nonce 唯一性** — 窗口内不得存在相同的 `(peer_id, nonce)` 对。否则拒绝并返回 `ErrReplay`。

发送方在 `nonce` 和 `timestamp` 为零时自动填充（64 位随机数 / Unix 秒）。

### 7.3 速率配额

每个节点都有令牌桶配额，在发送和接收时强制执行：

| 资源 | 默认速率 | 默认突发 |
|----------|-------------|---------------|
| 字节 | `256 KiB/s` | `256 KiB` |
| 对象（区域） | `128/s` | `128` |

超过任一限制将返回 `ErrQuotaExceeded`，数据包被丢弃。

### 7.4 签名验证

所有区域数据（authority、委托、记录）都经过密码学签名。Gossip 层本身不验证签名，而是委托给 `zone` 和 `crypto` 包：

- `VerifyChain` — 确保区域的委托链追溯到配置的根公钥。
- `VerifyRecord` — 确保每条记录由区域 authority 签名。
- `VerifyDelegation` — 确保子委托由父 authority 签名。

任何密码学检查失败的数据都会在到达活跃存储之前被拒绝。

---

## 8. 配置参考

影响 gossip 行为的 `config.yaml` 关键配置项：

```yaml
peer_id: node-a
listen_addr: 127.0.0.1:33434
max_datagram_bytes: 1200
max_sync_zones: 16
max_sync_records: 1024
log_level: info

# 静态 bootstrap 节点（始终允许）
bootstrap:
  - id: node-b
    addr: 127.0.0.1:33435

# 可选：显式公告地址（覆盖接口扫描）
advertise_addrs: "10.0.0.1,10.0.0.2"

# 可选：公网 IP 反射器；auto 展开内置 ddns-go 风格 reflector 列表
reflectors: auto
reflector_interval: 5m
reflector_timeout: 3s
endpoint_ttl: 1h
endpoint_grace: 10m
```

| 键 | 默认值 | 含义 |
|-----|---------|---------|
| `listen_addr` | `:33434` | UDP 绑定地址 |
| `max_datagram_bytes` / `target_datagram_bytes` | `1200` | 单个 gossip UDP datagram 的安全预算；旧 `max_message_bytes` 仍兼容读取 |
| `max_sync_zones` | `16` | 每个 `ANNOUNCE` 快照的最大区域数 |
| `max_sync_records` | `1024` | 每个 `ANNOUNCE` 的最大记录数 |
| `advertise_addrs` | （自动） | 以逗号分隔的 IP，发布到端点记录 |
| `reflectors` | `[]` | 公网 IP reflector URL 列表；设为 `auto` 使用内置列表，设为 `none`/`off` 禁用 |
| `reflector_interval` | `5m` | 重新发布本地端点的间隔 |
| `reflector_timeout` | `3s` | 单个 reflector HTTP 请求超时；失败会尝试后续 reflector |
| `endpoint_ttl` | `1h` | 写入端点记录的 TTL |
| `endpoint_grace` | `10m` | endpoint 变化后继续保留旧地址的窗口 |

Phase 4 规划中的 IPsec/overlay 配置示例。字段名在实现前仍可调整，但语义边界应保持：

```yaml
ipsec:
  enabled: true
  provider: strongswan
  accept: inbound
  default_netns:
    kind: name
    name: h2
    create: true

  address_source_order:
    - manual-address
    - manual-dns
    - discovery
    - reflector
    - local

  addresses:
    - source: manual-dns
      host: node-a.example.com
      families: [ipv6, ipv4]
      refresh: 60s
    - source: manual-address
      address: 2001:db8::10

  ports:
    mode: range
    range: 30000-30999
    grace: 10m

overlays:
  - name: ipsec-main
    id: ipsec-main
    provider: strongswan
    netns:
      kind: name
      name: h2
      create: true
    default_path_mode: family-redundant
    direction: outbound
    max_peers: 64
    max_links_per_peer: 2
    tunnel_address_pool: fd00:1234::/64
    reconcile:
      interval: 30s
      backoff:
        initial: 1s
        max: 60s
    connect:
      - "strongswan://*.catofes.?accept=inbound&family=dual&source=manual-dns,discovery&mode=family-redundant&direction=outbound"
    deny:
      - "strongswan://tag=lab"
```

配置语义：
- `ipsec.accept` 会发布到 `ipsec/profile`，表示远端可以怎样尝试连接本节点。
- `ipsec.default_netns` 是本机默认 LinkGroup namespace；默认 `name:h2, create:true`，让 StrongSwan/XFRM tunnel interface 明确落在 Higgs 管理的 namespace，而不是隐式进入 host ns。
- `ipsec.addresses` 是本节点可公告地址来源；DNS 源保留域名并定期 refresh。
- `ipsec.ports` 控制本节点选择和公告 IKE/NAT-T 端口；端口与地址分离。
- `overlays[]` 是本地 `LinkGroupSpec` / MeshPolicy desired-state 边界，包含 provider、netns、path mode、方向、peer/link 上限、tunnel address pool 和 reconcile/backoff 策略，不发布到 gossip。
- `overlays[].netns` 可以覆盖默认 namespace；`kind: host` 明确表示不隔离，`kind: path` 只引用已有 namespace path，不隐式创建。
- `overlays[].connect/deny` 是 link group 内的本地 MeshPolicy rule，不发布到 gossip。
- `address_source_order` 只影响本地选择和排序；远端也会按自己的本地配置重新排序。

---

## 9. 总结

| 关注点 | 机制 |
|---------|-----------|
| **状态传播** | 基于摘要的选择性同步（`PING` → `PONG` → `FETCH_ZONE` → `ANNOUNCE`） |
| **收敛** | 每次应用变更后中继；gossip 式传递 |
| **冲突解决** | 单调版本号；时间戳仅用于审计 |
| **信任** | 完整委托链验证，追溯到受信任的根公钥 |
| **节点发现** | 每个节点自身区域中的签名 `sync/endpoint/udp` 记录 |
| **IPsec mesh 规划** | signed `ipsec/profile`、`ipsec/addresses`、`ipsec/ports`、`ipsec/transport-key` + 本地 MeshPolicy |
| **访问控制** | `knownPeers`（bootstrap + 已验证 Zone）；签名链验证身份 |
| **首次接入** | `AddKnownPeerID` 开放入站；`lastSeenAddrs` 回外地址；防死锁 |
| **反重放** | Nonce 唯一性 + 5 分钟时间戳窗口 |
| **DoS 缓解** | 每节点字节与对象速率配额；最大消息大小限制 |
