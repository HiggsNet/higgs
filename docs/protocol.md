# Higgs Gossip 协议

> **文档状态（2026-06）**  
> 本文档描述当前已实现的协议（Phase 1–2）。Phase 3+ 规划内容单独标注。

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
| 最大消息大小 | `64 KiB`（`65536` 字节） |
| 线路版本 | `1` |

### 2.2 消息帧格式

线路上每条消息都以 ASCII 魔术前缀开头，后跟一个 JSON 对象：

```
higgs.gossip.v1\n{"version":1,"type":"ping",...}
```

反序列化时会拒绝以下消息：
- 不以精确的魔术前缀 `higgs.gossip.v1\n` 开头。
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

CLI 提供三种与同步相关的命令，分别对应不同的运行时模式：

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

打开传输层，向指定节点发送一个 `PING`，等待最多 `3s` 接收 `PONG`（以及可能的后续 `ANNOUNCE`），然后退出。适用于临时同步或脚本编排。

### 3.3 `sync run` — 主动长运行

```
higgs sync run --interval 5s
```

这是主要的产品模式，结合了入站服务、定期出站同步和节点发现：

1. **状态重载** — 每次出站同步前，如果磁盘上的区域摘要与上次观察到的不同，节点会重新加载状态。这样外部变更（CLI 写入、新委托）可以立即生效。
2. **端点发布** — 每隔 `reflector_interval`（默认 `5m`），节点收集自身网络端点，签名一份 `sync/endpoint/udp` 记录，并写入其管理的区域。
3. **出站同步轮次** — 每隔 `interval`（默认 `5s`），节点遍历所有已知节点（bootstrap + 发现），对未处于退避状态的每个节点执行 `syncRoundWithTransport`。
4. **入站接收** — 出站轮次之间，节点以 `250ms` 的超时轮询套接字，处理任何数据包。如果数据包包含的 `ANNOUNCE` 改变了本地状态，则触发**中继**（见 §4.3）。

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

## 6. 安全机制

### 6.1 节点身份验证

传输层维护两个集合：

- **`knownPeers`**（入站白名单）：包含 bootstrap 配置中的 peer ID + 本地 active state 中所有 `VerifyChain` 通过的 Zone path。每个接收到的数据包检查 `peer_id` 是否在此集合中，否则丢弃（`ErrUnknownPeer`）。
- **`outboundAddrs`**（出站地址簿）：来自 `config.bootstrap` 中的静态地址 + 从 `sync/endpoint/udp` record 中动态发现的地址。发送时按优先级依次尝试。
- **`lastSeenAddrs`**（临时入站反向地址）：`Send()` 在无出站地址时，回退使用最近一次收到该 peer 数据包的 UDP 源地址。

节点在启动时从 `bootstrap` 配置注册，在运行时从发现的 Zone 和端点记录动态扩展。

### 6.2 反重放窗口

每条消息都携带随机 `nonce` 和 `timestamp`。接收方检查两者：

- **时间戳窗口** — 消息时间戳必须落在接收方本地时钟的 `±5 分钟` 内。否则拒绝并返回 `ErrMessageExpired`。
- **Nonce 唯一性** — 窗口内不得存在相同的 `(peer_id, nonce)` 对。否则拒绝并返回 `ErrReplay`。

发送方在 `nonce` 和 `timestamp` 为零时自动填充（64 位随机数 / Unix 秒）。

### 6.3 速率配额

每个节点都有令牌桶配额，在发送和接收时强制执行：

| 资源 | 默认速率 | 默认突发 |
|----------|-------------|---------------|
| 字节 | `256 KiB/s` | `256 KiB` |
| 对象（区域） | `128/s` | `128` |

超过任一限制将返回 `ErrQuotaExceeded`，数据包被丢弃。

### 6.4 签名验证

所有区域数据（authority、委托、记录）都经过密码学签名。Gossip 层本身不验证签名，而是委托给 `zone` 和 `crypto` 包：

- `VerifyChain` — 确保区域的委托链追溯到配置的根公钥。
- `VerifyRecord` — 确保每条记录由区域 authority 签名。
- `VerifyDelegation` — 确保子委托由父 authority 签名。

任何密码学检查失败的数据都会在到达活跃存储之前被拒绝。

---

## 7. 配置参考

影响 gossip 行为的 `config.yaml` 关键配置项：

```yaml
peer_id: node-a
listen_addr: 127.0.0.1:33434
max_message_bytes: 65536
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
| `max_message_bytes` | `65536` | 接受的最大线路消息 |
| `max_sync_zones` | `16` | 每个 `ANNOUNCE` 快照的最大区域数 |
| `max_sync_records` | `1024` | 每个 `ANNOUNCE` 的最大记录数 |
| `advertise_addrs` | （自动） | 以逗号分隔的 IP，发布到端点记录 |
| `reflectors` | `[]` | 公网 IP reflector URL 列表；设为 `auto` 使用内置列表，设为 `none`/`off` 禁用 |
| `reflector_interval` | `5m` | 重新发布本地端点的间隔 |
| `reflector_timeout` | `3s` | 单个 reflector HTTP 请求超时；失败会尝试后续 reflector |
| `endpoint_ttl` | `1h` | 写入端点记录的 TTL |
| `endpoint_grace` | `10m` | endpoint 变化后继续保留旧地址的窗口 |

---

## 8. 总结

| 关注点 | 机制 |
|---------|-----------|
| **状态传播** | 基于摘要的选择性同步（`PING` → `PONG` → `FETCH_ZONE` → `ANNOUNCE`） |
| **收敛** | 每次应用变更后中继；gossip 式传递 |
| **冲突解决** | 单调版本号；时间戳仅用于审计 |
| **信任** | 完整委托链验证，追溯到受信任的根公钥 |
| **节点发现** | 每个节点自身区域中的签名 `sync/endpoint/udp` 记录 |
| **访问控制** | `knownPeers`（bootstrap + 已验证 Zone）；签名链验证身份 |
| **首次接入** | `AddKnownPeerID` 开放入站；`lastSeenAddrs` 回外地址；防死锁 |
| **反重放** | Nonce 唯一性 + 5 分钟时间戳窗口 |
| **DoS 缓解** | 每节点字节与对象速率配额；最大消息大小限制 |
