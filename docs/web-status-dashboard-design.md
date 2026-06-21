# Higgs Web 状态控制台设计

> **文档状态**：MVP 已实现（Phase 6.7，2026-06）
> **目标**：为 Higgs 守护进程提供一套只读为主的 Web 状态可视化面板，降低调试和运维时阅读文本日志 / CLI 输出的门槛，同时为未来可能扩展的远程控制预留接口和交互空间。

> **第一版实现边界（已落地）：**
> - **只读**：不提供 record put、delegate、reload、shutdown、rotate、force sync 等写操作。
> - **本地监听**：默认关闭，启用后默认只监听 `127.0.0.1`；远程访问依赖 SSH tunnel / 反向代理。
> - **无认证**：不在第一版自建公网认证面。
> - **Daemon live snapshot**：所有数据来自 daemon 运行态 `stateFile`，通过 `RLock` 只读访问。
> - **BIRD 深度字段**：第一版只展示 `stateFile.BirdInstances` / `bird_status` 可得字段；`birdc show protocols/routes/neighbors` 解析等后续补齐。
> - **代码位置**：`app/higgs/observer_config.go`、`observer_server.go`、`observer_sse.go`、`web/`。
> - **验证**：`make observer-smoke`（31 个测试覆盖 config/API/SSE/static FS/HTTP handler routing/loopback HTTP start/static UI escaping）。

---

## 1. 背景与目标

### 1.1 问题

Higgs 控制平面目前具备较完整的运行时状态模型，但可观测性仍处于「本地调试工具」阶段：

- 状态分散在 bbolt DB、Unix Domain Control Socket、BIRD/StrongSwan 运行时中。
- 调试依赖 `higgs debug peer/links/zone/routes` 等 CLI 命令，输出为纯文本，跨多个维度关联困难。
- Gossip 同步、Overlay 链路、路由授权三个层面的状态没有统一的实时视图。
- 没有 HTTP/REST 或 gRPC 接口，也没有 Prometheus / OpenMetrics 导出。

当节点数、Zone 数、链路数增加后，文本调试将难以快速定位问题（例如：某条路由为何未授权、某条 IPsec 链路为何未建立、某个 peer 为何未同步）。

### 1.2 目标

1. **状态可视化优先**：在 Web 页面上直观呈现 Gossip（数据库/Zone）、Overlay（链路/IPsec）、Route（授权路由/BIRD）三个层面的实时状态。
2. **只读为主**：当前版本不实现控制/修改功能，但架构和 API 设计要预留扩展空间。
3. **低侵入**：尽量复用已有 `control socket` 和内部状态模型，不破坏现有事件循环和锁模型。
4. **可离线/可在线**：既能在守护进程运行时通过 HTTP 拉取 live 状态，也能在守护进程停止时读取本地 DB 做静态诊断。
5. **轻量可内嵌**：前端不依赖重型框架，默认作为 daemon 可选子服务启动，也可单独部署为静态文件。

---

## 2. 现状与可复用能力

### 2.1 已有状态来源

| 层级 | 数据结构 | 当前暴露方式 | 可视化可直接复用程度 |
|------|----------|--------------|----------------------|
| **Gossip / Zone DB** | `stateFile.Network` (`*zone.NetworkState`) | `higgs debug zone`、CLI `zone show`、control `routes_dump` | 高：Zone 树、Record、Delegation、Revocation 均可导出 |
| **Peer 同步状态** | `stateFile.SyncPeers` (`map[string]syncPeerState`) | `higgs sync status --verbose`、`higgs debug peer` | 高：同步时间、backoff、observed path、datagram/object pull 统计均已结构化 |
| **Overlay / IPsec** | `stateFile.LinkInstances`、`IPsecReconcile` | `higgs debug links` | 高：desired/actual SA、rotate/takeover、reconcile actions 均已结构化 |
| **链路健康** | `HealthState`（规划）+ 本地 TSDB / SQLite spool（规划） | `higgs debug health`（规划）、6.6 metrics datasource | 中：当前状态可来自 daemon，历史趋势可从本地 datasource 只读查询 |
| **Route 授权** | `routing.AuthorizedRouteSet` | control `routes_dump`、`higgs debug routes/route` | 高：可导出为 JSON |
| **BIRD 路由** | `stateFile.BirdInstances` | control `bird_status`、`higgs debug babel` | 中：当前仅有 BIRD 进程状态，未来需补充 `birdc show route/protocols/neighbors` 解析 |
| **配置** | `appConfig` / `syncConfigFile` | 配置文件、CLI | 中：用于呈现本地 managed zone、listen addr、overlay 分组等 |

### 2.2 已有 Control Socket 方法

当前 daemon 通过 Unix Domain Socket 暴露以下只读方法：

- `status`：peer_id、link_instances 数量、desired_links 数量、last_link_error。
- `bird_status`：BirdInstances map、last_routing_error。
- `routes_dump`：AuthorizedRouteSet 的 JSON 摘要。

写操作（`record_put`、`delegate_issue/revoke`、`join_accept`、`sync_trigger`、`reload`、`shutdown`）当前不在 Web 控制台范围，但 API 层可复用同一 socket 机制。

### 2.3 缺失能力

- 没有 HTTP server / REST API。
- 没有 SSE / WebSocket 实时推送。
- 没有拓扑图、时间线、状态聚合视图。
- 没有统一的事件流（daemon event、sync event、reconcile event）。
- 没有 BIRD 运行时路由/邻居解析（todo.md 后续计划）。

---

## 3. 设计原则

1. **分层清晰**：页面按照 Gossip（数据/信任）、Overlay（链路/IPsec）、Health（链路质量）、Route（路由/BIRD）组织，每层内部再细分列表、详情、拓扑。
2. **状态优先于控制**：第一版所有按钮/操作均为「查看详情」、「复制 JSON」、「刷新」、「过滤」，不触发任何状态变更。
3. **实时但不强制**：默认通过 SSE 推送增量事件；页面首次加载和手动刷新时通过 REST 拉取全量快照；SSE 断开后可自动降级为轮询。
4. **本地优先、远程可选**：HTTP server 默认监听 localhost，管理员可通过反向代理或 SSH tunnel 远程访问；未来可补充 TLS / mTLS / 静态 token。
5. **前端轻量、后端简单**：前端使用原生 Web Components / 轻量框架 + Canvas/WebGL 拓扑库；后端在现有 daemon 中增加一个只读 HTTP handler，避免引入新依赖。
6. **为控制留空间**：API 路径、权限中间件、操作审计日志在设计上预留，但第一版不实现写接口。

---

## 4. 总体架构

```text
┌─────────────────────────────────────────────────────────────────────┐
│                        Browser / Web Dashboard                       │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │
│  │ Overview │ │ Gossip   │ │ Overlay  │ │ Health   │ │ Route    │  │
│  │ Dashboard│ │ View     │ │ View     │ │ View     │ │ View     │  │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘  │
└───────┼────────────┼────────────┼────────────┼────────────┼────────┘
        │            │            │            │            │
        └────────────┴────────────┴────────────┘            │
                         REST API / SSE                      │
        ┌────────────────────────────────────────────────────┘
        │
┌───────▼─────────────────────────────────────────────────────────────┐
│                    Higgs Daemon HTTP Observer                        │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────┐  │
│  │ REST Handlers   │  │ SSE Hub           │  │ State Snapshotter   │  │
│  │ /api/v1/...     │  │ /events           │  │ (live from daemon)  │  │
│  └────────┬────────┘  └────────┬────────┘  └──────────┬──────────┘  │
│           │                    │                       │             │
│  ┌────────▼────────────────────▼───────────────────────▼─────────┐   │
│  │              Daemon Control Socket / State Lock               │   │
│  │   (复用 d.Sync.State.RLock/RUnlock, control socket, DB load)  │   │
│  └───────────────────────────────────────────────────────────────┘   │
│  ┌───────────────────────────────────────────────────────────────┐   │
│  │ Optional Health Metrics Query                                 │   │
│  │ local VictoriaMetrics/Prometheus-compatible API or SQLite spool│   │
│  └───────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────┘
```

### 4.1 组件职责

| 组件 | 职责 | 备注 |
|------|------|------|
| **HTTP Observer** | 可选子服务，监听 `127.0.0.1:<port>`（默认 8080） | 通过 `config.yaml` 中的 `observer` 段启用；未配置则不启动 |
| **REST Handlers** | 提供 `/api/v1/status`、`/api/v1/zones`、`/api/v1/peers`、`/api/v1/links`、`/api/v1/health`、`/api/v1/routes`、`/api/v1/events` 等端点 | 返回 JSON，字段与内部结构保持一致 |
| **SSE Hub** | 维护客户端长连接，将 daemon 内部事件（state changed、sync、reconcile、health change）转发为 SSE | 事件类型：`state_changed`、`peer_updated`、`link_updated`、`health_updated`、`route_changed` |
| **State Snapshotter** | 在事件触发时读取 `stateFile` 并生成视图模型 | 必须持有 RLock，避免阻塞事件循环 |
| **Health Metrics Query** | 可选只读查询 6.6 本地 VictoriaMetrics/Prometheus-compatible datasource 或 SQLite spool | 未配置时 API 返回 `not_configured`，不影响 live dashboard |
| **Static File Server** | 托管前端静态资源（HTML/JS/CSS/WASM） | 可与 HTTP Observer 同端口，前缀 `/` 或 `/ui` |

### 4.2 与现有代码的集成点

1. **状态读取**：通过 `DaemonService.Sync.State.RLock()` 读取 `stateFile` 的各个字段；与 CLI 命令保持一致。
2. **路由授权**：调用 `routing.BuildAuthorizedRouteSet(state.Network, now)` 生成授权视图（与 `routes_dump` 相同）。
3. **健康历史**：如果 6.6 配置了本地 query datasource，Observer 只读查询 link health series；如果只有 SQLite spool，则只查询 spool 保留窗口。
4. **事件订阅**：复用 `DaemonHooks.OnStateChanged` 或在事件循环中向 SSE hub 发送通知；不侵入业务事件处理。
5. **配置加载**：在 `appConfig` 中新增 `observerConfig` 段，解析后传给 `newDaemonService`。

---

## 5. 后端 API 设计

### 5.1 配置扩展

在 `config.example.yaml` 中新增 `observer` 段：

```yaml
observer:
  disabled: true
  listen: "127.0.0.1:8080"
  ui_path: "/ui"          # 静态资源前缀，空字符串表示根路径
  # 未来控制接口预留：
  # auth:
  #   mode: "none"        # none | static_token | mtls
  #   static_token: "..."
  # event_buffer_seconds: 300
```

### 5.2 REST 端点（只读）

所有 API 返回统一包装：

```json
{
  "ok": true,
  "error": "",
  "data": { ... }
}
```

#### 5.2.1 全局状态

```text
GET /api/v1/status
```

返回守护进程整体摘要：

```json
{
  "peer_id": "node1.catofes.",
  "managed_zone": "node1.catofes.",
  "listen_addr": ":51820",
  "daemon_online": true,
  "known_zones": 12,
  "known_peers": 5,
  "link_instances": 3,
  "desired_links": 4,
  "last_link_error": "",
  "last_routing_error": "",
  "last_sync_unix": 1718600000,
  "last_reconcile_unix": 1718600030
}
```

#### 5.2.2 Gossip / Zone 层

```text
GET /api/v1/zones
GET /api/v1/zones/:zone
GET /api/v1/zones/:zone/records
GET /api/v1/zones/:zone/delegations
GET /api/v1/zones/:zone/revocations
GET /api/v1/peers
GET /api/v1/peers/:peer_id
```

`/api/v1/zones` 返回 Zone 树摘要：

```json
{
  "zones": [
    { "path": ".", "records": 3, "delegations": 1, "revoked": false, "root_hash": "abc..." },
    { "path": "catofes.", "records": 12, "delegations": 3, "revoked": false, "root_hash": "def..." }
  ],
  "global_root": "0123..."
}
```

`/api/v1/peers` 返回 peer 同步状态列表（来自 `state.SyncPeers` + 发现的 endpoints）：

```json
{
  "peers": [
    {
      "peer_id": "node2.catofes.",
      "source": "bootstrap",
      "status": "healthy",
      "configured_addr": "2.3.4.5:51820",
      "discovered_addr": "10.0.0.2:51820",
      "observed_addr": "192.168.1.2:51820",
      "last_sync_unix": 1718600000,
      "backoff_until_unix": 0,
      "failure_count": 0,
      "datagram_stats": { "too_large_dropped": 0, "chunk_fallbacks": 1 },
      "object_pull_stats": { "attempts": 5, "successes": 5 }
    }
  ]
}
```

#### 5.2.3 Overlay / IPsec 层

```text
GET /api/v1/links
GET /api/v1/links/:link_id
GET /api/v1/link-groups
```

`/api/v1/links` 返回链路实例与 reconcile 状态：

```json
{
  "last_run_unix": 1718600030,
  "desired_links": 4,
  "actual_sas": 3,
  "instances": [
    {
      "id": "node2.catofes./overlay-a",
      "peer_zone": "node2.catofes.",
      "group_id": "overlay-a",
      "state": "established",
      "actual_state": "established",
      "interface": "xfrm_a_1",
      "xfrm_if_id": 101,
      "endpoint": "2.3.4.5:4500",
      "local_tunnel_addr": "10.200.0.1/30",
      "peer_tunnel_addr": "10.200.0.2/30",
      "rotate_phase": "none",
      "takeover_phase": "none",
      "failure_count": 0,
      "sa": {
        "established": true,
        "local_endpoint": "0.0.0.0:4500",
        "remote_endpoint": "2.3.4.5:4500"
      }
    }
  ],
  "actions": [...],
  "skipped": [...]
}
```

#### 5.2.4 Health 层

```text
GET /api/v1/health
GET /api/v1/health/:link_id
GET /api/v1/health/:link_id/series?metric=rtt|loss|jitter|babel_rtt|babel_metric&range=1h&step=30s
```

`/api/v1/health` 返回 daemon 当前窗口中的链路健康状态：

```json
{
  "datasource": {
    "configured": true,
    "type": "victoriametrics",
    "local": true,
    "series_window": "24h"
  },
  "links": [
    {
      "link_id": "ipsec-a-b",
      "peer_zone": "node-b.catofes.",
      "group_id": "h2",
      "state": "healthy",
      "probe_type": "icmp",
      "rtt_ms": 42.5,
      "loss_ratio": 0.0,
      "jitter_ms": 3.1,
      "babel_rtt_ms": 45,
      "babel_metric": 128,
      "cutover_ready": true,
      "last_error": ""
    }
  ]
}
```

`/series` 只读查询 6.6 配置的本地 datasource。优先查询本机 VictoriaMetrics / Prometheus-compatible API；未配置外部 datasource 时，可退化读取 SQLite spool 的短期样本。该接口不得把前端传入的任意 PromQL 直接透传给 TSDB；第一版只允许固定 metric 枚举、固定 label filter 和受限 time range，避免 Observer 变成通用 TSDB proxy。

#### 5.2.5 Route 层

```text
GET /api/v1/routes
GET /api/v1/routes/summary
GET /api/v1/routes/errors
GET /api/v1/bird
```

`/api/v1/routes` 复用 `routesDumpResponse`：

```json
{
  "local_zone": "node1.catofes.",
  "export_set": ["10.0.1.1/32", "10.0.2.0/24"],
  "authorized": {
    "node1.catofes.": ["10.0.1.1/32"],
    "node2.catofes.": ["10.0.2.0/24"]
  },
  "assignments": {
    "10.0.1.1/32": { "source": "catofes.", "assigned_to": "node1.catofes." }
  },
  "errors": []
}
```

`/api/v1/bird` 返回 BIRD 实例状态：

```json
{
  "instances": {
    "default": {
      "netns_name": "default",
      "state": "running",
      "router_id": 16909060,
      "overlays": ["overlay-a"],
      "last_error": ""
    }
  },
  "last_routing_error": ""
}
```

> 未来补充：周期性调用 `birdc show protocols`、`birdc show route`、`birdc show neighbors` 并将解析结果缓存到 `stateFile.BirdInstances` 或内存中，再通过 `/api/v1/bird/protocols`、`/api/v1/bird/routes`、`/api/v1/bird/neighbors` 暴露。

### 5.3 SSE 事件流

```text
GET /api/v1/events
```

返回 `text/event-stream`，事件类型设计：

| 事件类型 | 触发条件 | payload 建议 |
|----------|----------|--------------|
| `connected` | 客户端连接成功 | `{ "client_id": "..." }` |
| `state_changed` | daemon 检测到 Zone digest 变化 | `{ "global_root": "...", "changed_zones": [...] }` |
| `peer_updated` | SyncPeers 中某 peer 状态更新 | `{ "peer_id": "..." }` |
| `link_updated` | IPsec reconcile 完成 | `{ "link_id": "...", "state": "..." }` |
| `health_updated` | 链路健康状态跨阈值或 datasource 状态变化 | `{ "link_id": "...", "state": "..." }` |
| `route_changed` | routes_dump 结果变化 | `{ "export_set_count": N }` |
| `bird_updated` | BIRD reconcile 完成 | `{ "netns": "...", "state": "..." }` |

实现要点：

- SSE hub 维护一组 `chan sseEvent`；每个 HTTP handler 对应一个 subscriber。
- daemon 事件循环在 `notifyStateChanged()`、`flushIPsecReconcile()`、`flushRoutingReconcile()` 后向 hub 发送轻量通知（只发事件类型 + key，由客户端再按需拉取详情）。
- 连接断开后自动重连，使用 `Last-Event-ID` 做简单续传（可选）。

---

## 6. 前端页面设计

### 6.1 整体布局

参考 Tailscale Admin Console + Consul UI 的「左侧导航 + 主内容区」布局：

```text
┌────────────────────────────────────────────────────────────┐
│  Higgs Observer          [全局搜索] [刷新] [连接状态]        │
├──────────┬─────────────────────────────────────────────────┤
│          │                                                 │
│  Overview│  主内容区：                                       │
│  Gossip  │  - 统计卡片                                       │
│  Overlay │  - 列表 / 表格                                    │
│  Health  │  - 短历史趋势                                     │
│  Route   │  - 拓扑图                                         │
│  Zones   │  - 详情抽屉                                       │
│  Events  │                                                 │
│          │                                                 │
└──────────┴─────────────────────────────────────────────────┘
```

### 6.2 页面划分

| 页面 | 核心内容 | 可视化形式 |
|------|----------|------------|
| **Overview** | 节点身份、Zone 数量、Peer 健康数、链路建立数、路由数量、最近事件 | 统计卡片 + 最近事件时间线 |
| **Gossip** | Peer 列表、同步状态、Observed path、backoff、统计 | 表格 + 单 peer 详情抽屉 |
| **Zones** | Zone 层级树、Record 列表、Delegation / Revocation 链 | 树形图 + 详情面板 |
| **Overlay** | Link 实例、desired vs actual、SA 状态、rotate/takeover、group 过滤 | 表格 + 拓扑图（节点=peer，边=link，颜色=状态） |
| **Health** | Link 当前健康、RTT/loss/jitter、BIRD RTT/metric、cutover gate、本地 TSDB/spool 短历史 | 表格 + sparkline/折线图 + 详情抽屉 |
| **Route** | 授权路由表、本地 export、IPAM assignments、授权错误 | 表格 + 前缀树/拓扑 + 错误列表 |
| **BIRD** | BIRD 实例状态、协议/邻居/路由（未来） | 表格 + 状态徽章 |
| **Events** | 实时事件流、过滤、时间线 | 滚动时间线 |

### 6.3 关键交互

1. **实时指示器**：顶部显示 SSE 连接状态（connected / disconnected / polling）。
2. **时间范围**：事件页和 Health 页支持最近 5min / 30min / 1h / 24h 过滤；Health 历史受本地 datasource/spool 保留窗口限制。
3. **状态徽章**：healthy、degraded、error、pending、missing 等状态使用颜色编码。
4. **详情抽屉**：点击表格行或拓扑节点，右侧滑出详情面板，展示原始 JSON 和结构化字段。
5. **过滤与搜索**：按 Zone、peer、link group、route prefix、health 状态、错误原因过滤。
6. **原始数据**：每个页面提供「View JSON」按钮，可直接查看后端 API 返回。
7. **预留操作位**：详情抽屉底部预留操作按钮区（如「Force Sync Peer」、「Rotate Link」、「Reload Config」），第一版置灰并显示 tooltip「控制功能未启用」。

### 6.4 拓扑图设计

**Overlay 拓扑图**：

- 节点：本节点 + 已知 peer（来自 bootstrap 和 discovered endpoints）。
- 边：实际建立的 IPsec link，粗细或颜色表示 SA established / present / missing。
- 悬停：显示 peer zone、link group、endpoint、tunnel addr。
- 点击：打开 link 详情抽屉。

**Route / Zone 拓扑图（可选）**：

- Zone 树：节点为 Zone，边为 delegation，颜色标识 revoked / healthy。
- 路由图：节点为 Zone，边为「announce prefix」关系，可展示 anycast ECMP。

---

## 7. 数据模型映射

将内部状态映射到前端视图模型的建议：

| 内部结构 | API 字段 | 前端视图 |
|----------|----------|----------|
| `stateFile.ManagedZone` | `status.managed_zone` | 节点身份卡片 |
| `stateFile.SyncPeers` | `peers[].*` | Gossip peer 表格 |
| `stateFile.Network.Zones` | `zones[].*` | Zone 树、Record 列表 |
| `stateFile.Network.Zones[*].Delegations` | `zones[*].delegations` | Zone 详情中的信任链 |
| `stateFile.Network.Zones[*].Revocations` | `zones[*].revoked` | Zone 树颜色/徽章 |
| `stateFile.LinkInstances` + `IPsecReconcile` | `links[].*` | Overlay 表格、拓扑图 |
| `routing.BuildAuthorizedRouteSet(...)` | `routes.*` | Route 表格、错误列表 |
| `stateFile.BirdInstances` | `bird.instances` | BIRD 状态卡片 |

---

## 8. 技术选型

### 8.1 后端

- **HTTP Server**：Go 标准库 `net/http`，不引入 gin/echo 等框架，保持依赖最小。
- **SSE**：基于 `http.Flusher` 实现，轻量可控。
- **状态读取**：复用 `stateFile.RLock()` 和已有 helper（`desiredIPsecLinks`、`lastIPsecReconcileError`、`routing.BuildAuthorizedRouteSet`）。
- **静态文件内嵌**：使用 Go 1.16+ `embed` 将前端构建产物打包进 `build/higgs`，通过 `//go:embed` 注入。

### 8.2 前端

| 模块 | 选型建议 | 理由 |
|------|----------|------|
| 框架 | **原生 Web Components** 或 **Vue 3 / React**（若团队熟悉） | 轻量、无需构建也可运行 |
| UI 组件 | 轻量 CSS 框架（如 **Picocss**、**Water.css**）+ 少量自定义组件 | 减少依赖 |
| 拓扑图 | **Sigma.js + graphology** | WebGL 渲染性能好，类型安全，适合节点数较多场景 |
| 路由/分析图 | **Cytoscape.js**（可选） | 图算法丰富，适合做路径分析 |
| 图表 | **ECharts** 或 **Chart.js** | 统计图表成熟 |
| 实时通信 | **SSE**（EventSource） | 单向推送足够，自动重连简单 |

> 推荐默认方案：**原生 JS + Sigma.js + Picocss**，不引入构建工具，降低维护成本；若后续功能复杂再迁移到 Vue/React。

### 8.3 数据格式

- API 统一 JSON。
- 时间戳使用 Unix 秒或 RFC3339，前端统一格式化为本地时间。
- Zone path、prefix 等使用字符串表示，与现有 CLI 一致。

---

## 9. 安全与部署

### 9.1 默认安全

- 未声明 `observer:` 时 HTTP Observer 默认禁用；声明后可用 `observer.disabled: true` 临时关闭。
- 启用后默认监听 `127.0.0.1:8080`，不暴露到公网。
- 第一版不实现认证；管理员通过本地访问、SSH tunnel、或反向代理的 mTLS 保护。
- 所有 API 只读，不写状态。

### 9.2 未来控制接口预留

当后续需要支持 Web 控制时，建议分阶段：

1. **静态 Token**：`observer.auth.mode: static_token`，请求头 `Authorization: Bearer <token>`。
2. **Unix Socket 模式**：HTTP server 可改为监听 Unix Domain Socket，与 control socket 类似，便于 Nginx/反向代理接入。
3. **mTLS**：通过 `client_ca_file` 验证浏览器证书。
4. **审计日志**：所有写操作记录到结构化日志，包含操作人、来源 IP、操作内容摘要。

### 9.3 部署形态

| 形态 | 说明 |
|------|------|
| **内嵌模式**（默认） | HTTP server 与 daemon 同进程，通过 `higgs daemon` 启动，配置启用即可。 |
| **独立只读模式** | 提供一个 `higgs observer` 子命令，只读本地 DB 并启动 HTTP server，用于 daemon 停止时的离线诊断。 |
| **静态文件模式** | 前端可单独构建为静态文件，由 Nginx/Caddy 托管，通过反向代理访问后端 API。 |

---

## 10. 实施路线图

### Phase 1：只读状态 API 与基础页面（MVP）

1. 在 `appConfig` 中新增 `observerConfig` 与 YAML 解析。
2. 在 `DaemonService` 中新增可选 HTTP observer，启动时绑定 `startObserverServer(ctx)`。
3. 实现 REST 端点：
   - `/api/v1/status`
   - `/api/v1/zones`、`/api/v1/zones/:zone`
   - `/api/v1/peers`、`/api/v1/peers/:peer_id`
   - `/api/v1/links`、`/api/v1/links/:link_id`
   - `/api/v1/routes`
   - `/api/v1/bird`
4. 实现静态文件服务，内嵌基础前端页面。
5. 前端实现：Overview、Gossip、Zones、Overlay、Health、Route、BIRD 基础表格视图。
6. Health 页面第一版展示当前窗口；若 datasource 已配置，再展示 link 级 sparkline。

### Phase 2：实时事件与拓扑图

1. 实现 SSE hub，监听 daemon 状态变更事件。
2. 前端接入 EventSource，实现页面自动刷新和事件时间线。
3. 在 Overlay 页面集成 Sigma.js 拓扑图。
4. 在 Health 页面接入 `/api/v1/health/:link_id/series`，展示 RTT/loss/jitter/Babel metric 短历史。
5. 增加详情抽屉和原始 JSON 查看。

### Phase 3：路由与 BIRD 深度集成

1. 实现 birdc 输出解析（protocols / neighbors / routes）。
2. 新增 `/api/v1/bird/protocols`、`/api/v1/bird/neighbors`、`/api/v1/bird/routes`。
3. 在 Route 页面增加「控制面路由 vs 数据面学习路由」对比视图。
4. 在 Health 页面把 BIRD neighbor RTT/metric 与 Higgs probe RTT/loss 放在同一 link 详情里对比。
5. 增加前缀树 / 路径分析图。

### Phase 4：控制与安全（未来）

1. 增加认证中间件（static token / mTLS）。
2. 在 UI 上开放受控操作：sync trigger、reload、shutdown、rotate link、force reconcile。
3. 操作审计日志。
4. 多节点集中视图（类似 bird-lg）可选实现。

---

## 11. 风险与注意事项

1. **锁竞争**：状态快照必须持有 `RLock` 并尽快释放，避免阻塞 daemon 事件循环。复杂查询（如构建全量路由集）可改为后台缓存。
2. **内存与连接数**：SSE 长连接数需限制；大量客户端时考虑事件聚合或外部消息队列。
3. **敏感信息泄露**：API 应避免返回私钥、完整签名、IPsec 密钥等敏感字段。当前结构已避免序列化私钥，但需 review。
4. **兼容性**：新增 `observer` 配置段完全可选，不影响现有 CLI 和 daemon 行为。
5. **前端依赖**：优先使用原生技术，避免引入 Node.js 构建链，除非明确需要。

---

## 12. 参考资料

- 项目已有实现：`app/higgs/state.go`、`app/higgs/control.go`、`app/higgs/daemon.go`、`app/higgs/diagnostics.go`、`app/higgs/debug_routing.go`、`pkg/core/zone/types.go`、`pkg/routing/authorization.go`。
- BIRD 生态：[birdwatcher](https://github.com/alice-lg/birdwatcher)、[bird-lg](https://github.com/alice-lg/bird-lg)、[bird_exporter](https://github.com/czerwonk/bird_exporter)。
- babeld 监控：[babelweb2](https://github.com/Vivena/babelweb2)。
- Overlay 面板参考：Tailscale Admin Console、ZeroTier Central、Headscale、Nebula Admin。
- Gossip 集群 UI 参考：HashiCorp Consul UI、Serf CLI。
- 图可视化库：[Sigma.js](https://www.sigmajs.org/)、[Cytoscape.js](https://js.cytoscape.org/)、[ECharts Graph](https://echarts.apache.org/)。

---

## 13. 待决策问题（MVP 已决策）

1. ~~前端技术栈是否接受原生 JS + Sigma.js，还是坚持使用 Vue/React？~~ **已决策**：第一版采用原生 HTML/CSS/JS，不引入 Node.js 构建链；拓扑图库后续增强时再引入。
2. ~~HTTP observer 是否默认启用？建议默认禁用，由用户显式开启。~~ **已决策**：未声明 `observer:` 时默认关闭；声明后默认监听 `127.0.0.1:8080`，可用 `disabled: true` 暂停。
3. ~~是否需要独立的 `higgs observer` 离线诊断子命令？~~ **延后**：第一版只提供 daemon 内嵌 observer；离线 DB viewer 放到后续阶段。
4. ~~SSE 事件是否需要持久化/回放，还是仅做实时通知？~~ **已决策**：仅做实时通知，不持久化；前端 EventSource 断开后自动降级为轮询。
5. ~~拓扑图是否需要在第一版就实现，还是先以表格为主？~~ **已决策**：第一版以表格 + raw JSON 为主，可视化拓扑图留到后续增强。
