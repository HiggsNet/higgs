# Phase 6.6 链路健康检测设计

## 1. 目的与定位

链路健康检测是对 BIRD/Babel RTT metric 的**补充**，不替代 Babel 选路，也不写入 gossip active state。它在本机对每条 `TransportLink`/XFRM interface 做低频、可限速的主动探测，产出：

- 本地健康状态（`healthy`/`degraded`/`down`/`probe_error`/`unknown`/`suppressed`）
- IPsec rotate cutover gate（`RotateCutoverReady`）
- Prometheus/OpenMetrics 告警指标
- 长期质量样本（rolling window RTT/loss/jitter）

健康异常只能影响本机 reconcile/metric/告警，**不代表 peer 身份失效**。revocation 仍由 6.4/6.5 的安全路径处理。

## 2. 架构边界

```
┌─────────────────────────────────────────────────────────────┐
│                      daemon event loop                       │
│  ┌─────────────┐   ┌──────────────┐   ┌─────────────────┐   │
│  │ IPsec       │──▶│ health       │──▶│ BIRD metric     │   │
│  │ reconcile   │   │ reconcile    │   │ adjust (future) │   │
│  └─────────────┘   └──────┬───────┘   └─────────────────┘   │
│                           │                                  │
│                    ┌──────▼───────┐                          │
│                    │ health       │                          │
│                    │ Manager      │                          │
│                    │  - targets   │                          │
│                    │  - windows   │                          │
│                    │  - scheduler │                          │
│                    │  - state     │                          │
│                    │    machine   │                          │
│                    └──────┬───────┘                          │
│                           │                                  │
│              ┌────────────┼────────────┐                     │
│              ▼            ▼            ▼                     │
│         ICMP probe   UDP probe    OpenMetrics                │
│         (CAP_NET_RAW) (fallback)   /metrics                  │
└─────────────────────────────────────────────────────────────┘
```

**关键原则：**
- 健康状态是**本地运行态**，不进入 bbolt/JSON stateFile（避免每次 probe sample 都落盘）。
- 只有状态变化或阈值 crossing 才落盘到 `stateFile`。
- probe 在 overlay/data-plane netns 内发出，绑定对应 XFRM interface 或源 tunnel address。
- 双向不强制对称：本机只评价"本机到 peer"的可用性。

## 3. 探测对象与数据源（6.6.1）

### 3.1 ProbeTarget

探测对象以 `LinkInstance` 为主键：

| 字段 | 来源 | 说明 |
|------|------|------|
| `InstanceID` | `LinkInstance.ID` | 稳定主键 |
| `GroupID` | `LinkInstance.GroupID` | overlay/link group |
| `PeerZone` | `LinkInstance.PeerZone` | 对端 Zone |
| `LocalZone` | `stateFile.ManagedZone` | 本机 Zone |
| `Overlay` | `desiredLinkState.GroupID` | overlay ID |
| `NetNS` | overlay netns | 目标网络命名空间 |
| `InterfaceName` | `desiredLinkState.InterfaceName` | XFRM 接口名 (`hgs*`) |
| `LocalTunnelAddr` | `desiredLinkState.LocalTunnelAddr` | 本端 tunnel 地址 |
| `PeerTunnelAddr` | `desiredLinkState.PeerTunnelAddr` | 对端 tunnel 地址（探测目标） |
| `Generation` | `LinkInstance.RemoteGeneration` | 端口/contact generation |
| `Role` | `LinkInstance.InitiatorRole` | primary/standby/takeover |
| `State` | `LinkInstance.ActualState` | connecting/up/degraded/... |
| `Staged` | `LinkInstance.StagedGeneration != 0` | 是否处于 rotate staged |

### 3.2 可探测状态

只探测当前本机策略允许且未 revoked 的 link：

| 状态 | 可探测 | 说明 |
|------|--------|------|
| `connecting` | ✅ | 正在建立 SA |
| `up` | ✅ | SA 已建立 |
| `degraded` | ✅ | 降级但仍承载 |
| `dual_running` | ✅ | rotate 保留窗口 |
| `staged` | ✅ | staged generation 探测 |
| `stale` | ✅ | SA 可能过期 |
| `pending`/`configuring` | ❌ | 尚未到达数据面 |
| `policy_denied`/`revoked`/`removing` | ❌ | 信任/授权失败 |
| `down`/`error` | ❌ | 已知不可用 |

### 3.3 被动数据采集

`BabelObservation` 结构采集来自 BIRD/Babel 的被动数据：

```go
type BabelObservation struct {
    InstanceID string
    Neighbor   bool        // BIRD Babel neighbor 是否存在
    RTT        time.Duration // Babel RTT metric
    Metric     int          // Babel route metric
    Route      bool         // BIRD route 是否可用
}
```

主动探测和 BIRD metric 要分层展示：
- **Babel RTT** 是控制面小包质量
- **Higgs probe** 用于业务路径 RTT/loss/jitter 统计和独立 stuck 检测

## 4. 主动探测机制（6.6.2）

### 4.1 ICMP echo（首选）

```go
type ICMProber struct {
    runner   CommandRunner   // ip netns exec ping/ping6
    fallback Prober          // UDP fallback
}
```

- 使用 raw ICMP socket（`ip4:icmp` / `ip6:ipv6-icmp`）作为快路径
- fallback 到 `ip netns exec <ns> ping -c 1 -W <timeout> -I <iface> <addr>`
- 在指定 netns/interface/source address 发出
- 无 `CAP_NET_RAW` 时返回 `permission denied` 并降级

### 4.2 UDP keepalive（fallback）

```go
type UDPProber struct {
    runner CommandRunner
}
```

- 不需要 `CAP_NET_RAW`
- 发送固定 magic/version/instance_id/nonce/timestamp 小包
- 目标端口 33434（traceroute 默认高位端口）
- 成功 write 视为 L3 可达证据

### 4.3 调度配置

每条 link 独立调度，配置项：

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `interval` | `5s` | 探测间隔 |
| `timeout` | `1s` | 单次探测超时 |
| `burst` | `3` | 每次 tick 发送的探测包数 |
| `loss_window` | `20` | rolling window 容量 |
| `jitter` | `500ms` | 间隔抖动（避免同步探测） |
| `max_concurrent_probes` | `8` | 全局并发探测上限 |

## 5. 健康状态机与阈值（6.6.3）

### 5.1 状态定义

| 状态 | 编码 | 说明 |
|------|------|------|
| `healthy` | 0 | 探测成功，loss < 阈值 |
| `degraded` | 1 | loss 超过 `loss_threshold` |
| `down` | 2 | loss 超过 `down_loss_threshold` 或连续失败翻倍 |
| `unknown` | 3 | 初始状态或数据不足 |
| `probe_error` | 4 | 探测本身失败（permission/netns/interface missing） |
| `suppressed` | 5 | 被抑制（未来用于维护窗口） |

### 5.2 Rolling Window 统计

`RollingWindow` 环形缓冲区保存最近 N 条 probe 结果，计算：

- `sent` / `received` / `lost` / `loss_ratio`
- `last_rtt` / `ewma_rtt` (α=0.3)
- `min_rtt` / `max_rtt`
- `p50_rtt` / `p95_rtt` / `p99_rtt`
- `jitter`（连续 RTT 样本的平均绝对偏差）
- `consecutive_failures`
- `last_success` / `last_error`

### 5.3 迟滞转换

状态转换采用迟滞（hysteresis）避免抖动：

**降级路径（healthy → degraded/down）：**
- 连续失败次数 ≥ `fail_threshold_consecutive`（默认 3）
- 或窗口 loss ratio ≥ `loss_threshold`（默认 0.2）→ degraded
- 或窗口 loss ratio ≥ `down_loss_threshold`（默认 0.6）→ down

**恢复路径（degraded/down → healthy）：**
- 需要连续 `recover_consecutive`（默认 5）次成功
- 单次成功不立即恢复，避免抖动

### 5.4 失败原因分类

| 原因类别 | 触发条件 |
|----------|----------|
| `probe_timeout` | 全部超时，无 error |
| `permission_denied` | error 包含 "permission" |
| `netns_interface_missing` | error 包含 "netns"/"interface"/"missing" |
| `peer_address_missing` | error 包含 "address" |
| `firewall_denied` | error 包含 "firewall" |
| `probe_failure` | 其他 |

## 6. 与 IPsec rotate / BIRD / 防火墙联动（6.6.4）

### 6.1 Rotate cutover gate

```go
func (m *Manager) RotateCutoverReadiness() map[string]bool
```

- staged generation 必须 reach `healthy` 或至少 `degraded-but-better-than-old`，并且 BIRD neighbor/route 收敛后，才允许向 IPsec reconcile 提供 `RotateCutoverReady=true`。
- `CutoverBlocking(instanceID)` 返回 true 当状态不是 healthy/degraded。

### 6.2 BIRD 联动（未来）

- 普通 link degraded/down 先调高 BIRD metric，不直接撤销 peer 或删除 `LinkInstance`。
- BIRD 联动优先通过 metric/filter/config reload 表达。

### 6.3 防火墙

- 防火墙默认不因健康 down 删除授权 allow rule。
- 只在需要隔离异常 link 或避免黑洞转发时，可配置为按 link state 收紧 forward allow。

## 7. 事件驱动与调度边界（6.6.5）

- link create/update/adopt、SA up/down、config reload、revocation cleanup 都触发 probe scheduler 更新。
- health result 进入 daemon event loop，标记 routing/IPsec dirty，但 coalesce 避免每个 probe sample 都触发完整 reconcile。
- 长期无变化时只按 probe interval 采样和写 metrics，不重复写大 debug snapshot。
- 状态变化或阈值 crossing 才落盘到 `stateFile`。

## 8. 测量结果与轻量时序库（6.6.6）

### 8.1 Metrics schema

低 cardinality，稳定维度标签：

| 指标 | 类型 | 说明 |
|------|------|------|
| `higgs_link_probe_rtt_seconds` | gauge | 最近 probe RTT（秒） |
| `higgs_link_probe_loss_ratio` | gauge | rolling window loss ratio |
| `higgs_link_probe_jitter_seconds` | gauge | jitter（秒） |
| `higgs_link_health_state` | gauge | 状态编码（0=healthy...5=suppressed） |
| `higgs_link_babel_rtt_seconds` | gauge | Babel RTT（未来） |
| `higgs_link_babel_metric` | gauge | Babel route metric（未来） |
| `higgs_link_probe_errors_total` | counter | 探测错误总数 |

### 8.2 标签

| 标签 | 说明 |
|------|------|
| `local_zone` | 本机 Zone |
| `peer_zone` | 对端 Zone |
| `overlay` | overlay/group ID |
| `instance_id` | LinkInstance ID |
| `netns` | 网络命名空间 |
| `generation` | 端口/contact generation |
| `probe_type` | icmp/udp |
| `reason` | 失败原因类别 |

**禁止**把 endpoint IP、nonce、error string 放进 label。

### 8.3 配置示例

```yaml
health:
  interval: 5s
  timeout: 1s
  burst: 3
  loss_window: 20
  metrics:
    listen_addr: "127.0.0.1:9717"
    remote_write_url: http://victoriametrics:8428/api/v1/write
    remote_write_queue_capacity: 1024
    local_spool_path: <data_dir>/health-spool
    local_spool_max_age: 6h
```

### 8.4 TSDB 选型

默认推荐 **VictoriaMetrics single-node**：
- 单 binary/容器部署
- 支持 Prometheus scrape/remote write/PromQL-compatible query
- 资源占用适合中小规模

Prometheus server 可作为兼容方案。InfluxDB/TimescaleDB 暂不作为默认主线。

## 9. 操作与诊断面（6.6.7）

### 9.1 `higgs debug health`

展示每条 link 的：
- active/staged 状态
- probe 状态、RTT/loss/jitter
- BIRD RTT/metric（未来）
- 最近错误、下一次探测时间
- 是否影响 route cutover

### 9.2 `higgs debug links`

增加 health summary，但避免输出大量历史样本。

### 9.3 Observer

Observer 只读页面展示当前健康状态、最近窗口；长时间/跨节点图表仍推荐接 Grafana。

## 10. 代码结构

```
pkg/health/
├── types.go          # ProbeTarget, ProbeConfig, LinkHealth, MetricsLabels
├── stats.go          # RollingWindow + WindowSnapshot
├── state.go          # StateMachine (hysteresis + reason classification)
├── probe.go          # Prober interface + nopProber
├── probe_impl.go     # ICMProber + UDPProber + CommandRunner
├── manager.go        # Manager (targets, windows, scheduler, cutover gate)
├── metrics.go        # CollectMetrics + RenderOpenMetrics
└── health_test.go    # 10 个单元测试

app/higgs/
├── health_config.go      # healthConfig + healthConfigYAML + parseHealthConfig
├── health_reconcile.go   # healthTargetsFromState + reconcileHealth + debugHealth
├── daemon.go             # DaemonService.health + configureHealthManager + control handler
├── control.go            # controlResponse.Health + healthLinkJSON
└── cmd.go                # higgs debug health
```

## 11. 验证计划（6.6.8）

### 11.1 已完成

- ✅ 单元测试：probe scheduler、rolling window、状态迟滞、low-cardinality metric labels
- ✅ `make check` + `go test ./pkg/health/` 全绿

### 11.2 后续（root/container smoke）

- netns fake/集成测试：在指定 netns/interface/source address 发 probe，权限不足时降级
- root/container smoke：两节点 XFRM+BIRD 链路上采集 ICMP/UDP probe、BIRD RTT/metric，注入丢包/延迟后状态从 healthy→degraded/down
- metrics smoke：`/metrics` 暴露当前样本；remote write/VictoriaMetrics 可选 smoke 验证
