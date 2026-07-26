# Higgs Link Health 设计与实现

> **本文档状态：2026-07**
> 描述 Higgs 链路健康子系统的当前实现：`pkg/health` 的 probe、rolling window、状态机与 metrics，`app/higgs` 中的 target 推导、reconcile 集成、rotate cutover gate 和本地 spool，以及 debug/observer 诊断面。
> 本文以当前代码为准；与原 Phase 6.6 设计文档（`docs/phase6-link-health-design.md`）的差异在第 10 节显式标注，原设计文档仅作背景参考。

Link Health 是 Higgs 的本机链路质量观测子系统。它对每条 `LinkInstance`（含 rotate 期间的 staged generation）做低频主动探测，产出本地健康状态、RTT/loss/jitter 统计、rotate cutover gate 和时序样本。它是对 BIRD/Babel RTT metric 的**补充**：不替代 Babel 选路，不写入 gossip active state，也不代表 peer 身份失效——revocation 仍由安全路径处理。

完整配置字段见 [config.md](config.md)，daemon reconcile 调度见 [daemon.md](daemon.md)，rotate 生命周期见 [transport-ipsec.md](transport-ipsec.md)，BIRD 观测的采集入口见 [routing.md](routing.md)。

---

## 目录

1. [范围与定位](#1-范围与定位)
2. [核心概念](#2-核心概念)
3. [配置模型](#3-配置模型)
4. [主动探测（Prober）](#4-主动探测prober)
5. [调度与 daemon 集成](#5-调度与-daemon-集成)
6. [Rolling window 与状态机](#6-rolling-window-与状态机)
7. [Rotate cutover gate 与 BIRD 观测](#7-rotate-cutover-gate-与-bird-观测)
8. [Metrics 与本地 spool](#8-metrics-与本地-spool)
9. [Debug 与诊断](#9-debug-与诊断)
10. [已知限制与实现缺口](#10-已知限制与实现缺口)

---

## 1. 范围与定位

### 1.1 职责边界

| 做什么 | 不做什么 |
|---|---|
| 对本机每条 link 的 peer tunnel 地址做主动探测（ICMP ping） | 不替代 Babel 选路、不调 BIRD metric |
| 维护 per-link rolling window（RTT/loss/jitter）与迟滞状态机 | 不写入 gossip active state、不传播到其他节点 |
| 为 IPsec rotate 提供 cutover gate（staged generation 就绪才切换） | 不删除 firewall allow rule、不撤销 LinkInstance |
| 输出 OpenMetrics 样本结构与本地 JSONL 时序 spool | 不内置 TSDB、不做跨节点聚合视图 |

### 1.2 关键原则

- 健康状态是**本机运行态**，只存在于 `health.Manager` 内存中，不落 stateFile。daemon 重启后所有 link 从 `unknown` 重新收敛。
- 双向不强制对称：本机只评价"本机到 peer"的可用性。
- 健康异常只影响本机的 cutover gate、debug 展示和 metrics；peer 的身份与授权状态由 trust chain 独立判定。
- probe 在 overlay/data-plane netns 内发出（`ip netns exec`），源地址绑定本端 tunnel 地址。

### 1.3 架构位置

```text
daemon event loop
  └─ flushIPsecReconcile            # IPsec reconcile 完成后
       └─ reconcileHealth           # app/higgs/health_reconcile.go
            ├─ healthTargetsFromState   # 从 stateFile 推导 ProbeTarget
            ├─ Manager.SetTargets       # 全量替换 target 集合
            ├─ Manager.Tick             # 同步探测所有到期 target
            └─ appendHealthSpool        # 有探测发生时写 JSONL 样本

routing reconcile
  └─ observeBirdForHealth           # app/higgs/routing_reconcile.go
       └─ Manager.SetBabelObservation   # staged link 的 BIRD neighbor/route

IPsec reconcile 输入
  └─ Manager.RotateCutoverReadiness  →  ipsec.ReconcileInputs.RotateCutoverReady
```

---

## 2. 核心概念

### 2.1 ProbeTarget

探测对象以 `LinkInstance` 为主键，由 `healthTargetsFromState`（`app/higgs/health_reconcile.go`）从 stateFile 的 `LinkInstances` + IPsec reconcile desired state 推导：

| 字段 | 来源 | 说明 |
|---|---|---|
| `InstanceID` | LinkInstance ID | 稳定主键 |
| `ProbeID` | 见 2.2 | probe 视角主键，map key |
| `GroupID` / `Overlay` | LinkInstance.GroupID | overlay/link group |
| `PeerZone` / `LocalZone` | LinkInstance / stateFile.ManagedZone | 两端 Zone |
| `NetNS` | scoped tunnel 地址中的 `netns=` 后缀 | 目标 netns |
| `InterfaceName` | （staged 时优先 persisted observation） | XFRM 接口名 |
| `LocalTunnelAddr` / `PeerTunnelAddr` | LinkInstance tunnel 地址 | 源 / 探测目标 |
| `Generation` | RemoteGeneration（staged 时 StagedGeneration） | contact generation |
| `ProbeRole` / `Role` | 运行时角色 | `active` / `old` / `staged` |
| `State` | LinkInstance.ActualState | 用于可探测判定 |
| `Staged` | 是否为 staged 视角 | cutover gate 输入 |

两端 tunnel 地址任一无有效值（未分配/解析失败）的 link 不生成 target。

### 2.2 ProbeID 与 ProbeRole

rotate 期间同一条 link 存在两个 runtime 视角，health 用 `ProbeID` 区分：

| ProbeRole | ProbeID | 含义 |
|---|---|---|
| `active` | `<instanceID>` | 当前承载流量的 generation |
| `old` | `<instanceID>#old` | active 但已有 staged generation（等待 cutover 的旧 SA） |
| `staged` | `<instanceID>#staged` | rotate 出的新 generation，cutover gate 的观测对象 |

`Manager` 内部所有 window/state/nextProbe 都以 ProbeID 为 key；`Snapshot` 输出按 `(InstanceID, ProbeID)` 排序。

### 2.3 可探测状态

`ProbeTarget.ShouldProbe()`（`pkg/health/types.go`）决定哪些 link 进入探测集合：

| LinkInstance 状态 | 可探测 |
|---|---|
| `connecting` / `up` / `degraded` / `stale` / `dual_running` / `staged` | 是 |
| `pending` / `configuring` / `down` / `error` / `policy_denied` / `revoked` / `removing` 等 | 否 |

不可探测的 target 在 `SetTargets` 时被直接剔除，其 window 与状态机记录全部重置。

### 2.4 健康状态

| 状态 | metrics 编码 | 含义 |
|---|---|---|
| `healthy` | 0 | 窗口内无丢包 |
| `degraded` | 1 | 丢包率越 `loss_threshold`，或连续失败越阈值但未达 down 条件 |
| `down` | 2 | 丢包率越 `down_loss_threshold`，或连续失败 ≥ 2×阈值 |
| `unknown` | 3 | 初始状态或数据不足 |
| `probe_error` | 4 | 探测执行本身失败（权限/netns/地址等） |
| `suppressed` | 5 | 保留值；当前代码没有任何产生路径 |

### 2.5 BabelObservation

来自 BIRD/Babel 的被动观测，作为 cutover gate 的辅助输入：

```go
// pkg/health/types.go
type BabelObservation struct {
    ProbeID    string
    InstanceID string
    Neighbor   bool          // BIRD 里存在该接口的 Babel neighbor
    RTT        time.Duration // 当前采集路径未填充
    Metric     int           // neighbor/selected route 的最小 metric
    Route      bool          // 存在该接口的 selected Babel route
}
```

当前只为 **staged** link 采集（见第 7.3 节）；普通 active link 不采集。

---

## 3. 配置模型

### 3.1 启用语义

- 配置文件中**不存在** `health:` 块：子系统整体禁用（默认），`d.health` 为 nil，所有 health 操作退化为 no-op。
- `health:` 块存在：默认启用，除非写 `disabled: true`（或 `enabled: false`）。`enabled` 与 `disabled` 同时给出且一致时报配置错误。

### 3.2 最小配置示例

```yaml
health:
  interval: 5s
  metrics:
    enabled: true
    local_spool_path: /var/lib/higgs/health-spool
```

### 3.3 字段说明

| 字段 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `enabled` / `disabled` | bool | 块存在即启用 | 开关 |
| `interval` | duration | `5s` | 探测间隔（必须为正；实际生效频率见 5.4） |
| `timeout` | duration | `1s` | 单次 ping 超时（必须为正） |
| `burst` | int | `3` | 每次探测发送的 ping 次数 |
| `loss_window` | int | `20` | rolling window 容量（样本数） |
| `jitter` | duration | `500ms` | 间隔抖动，interval ± uniform(0, jitter) |
| `max_concurrent_probes` | int | `8` | 并发上限（**当前不生效**，见 5.3） |
| `fail_threshold_consecutive` | int | `3` | 降级/失败判定的连续失败阈值 |
| `loss_threshold` | string(float) | `0.2` | degraded 丢包率阈值，0.0–1.0 |
| `down_loss_threshold` | string(float) | `0.6` | down 丢包率阈值；必须 ≥ `loss_threshold` |
| `recover_consecutive` | int | `5` | 恢复所需连续成功次数 |
| `metrics.enabled` / `metrics.disabled` | bool | 默认关闭，需显式 `enabled: true` | metrics 开关 |
| `metrics.local_spool_path` | string | `""` | 本地 JSONL spool 目录；为空则 spool 关闭 |
| `metrics.local_spool_max_age` | duration | `6h` | spool 样本保留时长 |
| `metrics.remote_write_url` | string | `""` | 已解析但**无消费者**（见第 10 节） |
| `metrics.remote_write_queue_capacity` | int | `1024` | 同上 |

丢包率字段在 YAML 中是字符串形式（如 `"0.2"`），由 `parseFloatRatio` 解析并校验范围。

---

## 4. 主动探测（Prober）

### 4.1 接口

```go
// pkg/health/probe.go
type Prober interface {
    Probe(ctx context.Context, target ProbeTarget, cfg ProbeConfig) ProbeResult
    Type() string // "icmp" / "udp"
}
```

`ProbeResult` 携带 `RTT`、`Success` 和原始 `Error` 字符串；`Error` 只进入 debug 展示和 reason 分类，**不作为 metrics label**。每次 `Probe` 调用（含整个 burst）只产生 rolling window 中的一条样本。

daemon 在 `configureHealthManager`（`app/higgs/daemon.go`）中优先注入 raw-ICMP prober：

```go
d.health = newHealthManager(cfg,
    health.NewRawICMProber(health.NewICMProber(nil, health.NewUDPProber(nil))))
```

### 4.2 RawICMProber（默认）

Linux 上默认使用进程内 raw ICMP。每个目标 network namespace 有一个固定
OS thread 的 worker；worker 仅在启动时 `setns`，并按协议族、源地址、接口
创建和复用 raw socket。socket 创建后与目标 netns 绑定，不同 socket key
上的 probe 可并发执行；共享同一 socket 的 probe 仍串行，避免互相消费 ICMP
reply。steady state 不再执行 `ip netns exec`、fork `ping` 或创建临时 mount，
因此不会产生 probe 子进程风暴。

- 需要 daemon 自身具备 `CAP_NET_RAW`（创建 raw socket）；进入非 host netns
  还需要 `CAP_SYS_ADMIN`。`UID 0` 通常具有这些 capability，但 systemd 的
  `CapabilityBoundingSet`、`AmbientCapabilities`、`NoNewPrivileges` 或 user
  namespace 仍可能把它们移除。
- IPv4、IPv6 和 IPv6 link-local（以接口 index 作为 scope）均走 raw socket；
  burst 仍以 200ms 间隔发出，成功数超过失败数才健康。
- raw socket / `setns` 的本地 setup 失败会自动退回下述 `ICMProber`；网络
  不可达、丢包和超时不会触发第二次 exec probe，避免误掩盖数据面问题。
- worker 在 daemon 生命周期内持有 namespace 和 socket；netns 被删除并重建
  后需要重启 daemon 才能让 worker 进入新的 namespace（root smoke 覆盖前不
  应将此行为视为已经验收）。

### 4.3 ICMProber（权限受限时回退）

`pkg/health/probe_impl.go`。当前**唯一接线**的 prober，通过 `ip netns exec` 调系统 `ping`：

```text
ip netns exec <netns> ping [-6] -n -c <burst> [-I <local tunnel addr>] <peer tunnel addr>
```

当 `burst > 1` 时，daemon 仍只启动一个 ping 进程，使用 `-c <burst>`
（并以 200ms 间隔发包），而不是为 burst 中的每个 ICMP 包分别启动
`ip netns exec`。这样保留多数成功的聚合语义，同时避免重复 fork、进入
network namespace 和 mount setup。

- 单次 ping 用 context deadline 控制 `timeout`；RTT 取整个命令的 wall time——包含 `ip`/`ping` 进程创建开销，因此是偏粗的测量，亚毫秒级 LAN RTT 会被进程开销淹没。
- IPv6 link-local 地址自动补 `%<interface>` scope（目标和源都补）；若 ping 报 `bind icmp socket: Invalid argument`，去掉 `-I` 源地址重试一次。
- burst 聚合：burst 次 ping 中全部失败 → 返回最后一次错误；部分失败 → `Success = 成功数 > 失败数`（过半才记成功），RTT 取最后一个成功样本。
- `PeerTunnelAddr` 无效时直接返回 `peer address missing` 错误。
- 需要 `ping` 二进制可用且具有相应权限（setuid 或 cap_net_raw）；权限不足时错误归入 `probe_error`。

### 4.4 UDPProber

`NewUDPProber` 存在但**未被 daemon 使用**（仅作为 `NewICMProber` 的兼容参数传入，ICMP 失败不会 fallback 到 UDP）。其语义也很弱：向 `<peer tunnel addr>:33434` 写入带 `HIGGS-HC` magic 和 nonce 的 UDP 包，write 成功即视为 L3 可达，不校验任何回复。不要把它当作可靠健康证据。

### 4.5 nopProber

`NewManager` 传入 nil prober 时使用；所有探测返回 `no prober configured` 错误，全部 link 收敛到 `probe_error`。只用于测试。

---

## 5. 调度与 daemon 集成

### 5.1 集成点

Health 没有独立的定时器。唯一的驱动入口是 `reconcileHealth`（`app/higgs/health_reconcile.go`），它在 `flushIPsecReconcile` 末尾被调用（`app/higgs/daemon.go`）：

```text
flushIPsecReconcile
  ├─ reconcileIPsecLinks   # IPsec reconcile 本体
  └─ reconcileHealth       # 1. healthTargetsFromState 重建 target
                           # 2. Manager.SetTargets 全量替换
                           # 3. Manager.Tick 探测所有到期 target
                           # 4. 有探测时 appendHealthSpool
```

因此 health 的调度节奏完全继承 IPsec reconcile flush 的触发源：

- sync timer（`d.Interval`）到期；
- IPsec reconcile interval timer（各 link group `reconcile.interval_seconds` 的最小值，默认 1 分钟）到期；
- 各类事件 flush（`notifyStateChanged`、VICI lifecycle 事件、config reload 等）。

### 5.2 SetTargets 语义

`Manager.SetTargets` 是**全量替换**：

- 新出现的 target：创建 rolling window，首次探测时间为 `now + jitteredInterval()`（即新 target 至少等一个间隔才首探）。
- 消失的 target（link 删除、状态变为不可探测、地址失效）：window、状态机、错误计数、Babel 观测全部删除重置。

### 5.3 Tick 语义

`Manager.Tick(ctx, now)` 的行为：

1. 收集所有 `nextProbe <= now` 的 target（按 ProbeID 排序）。
2. **同步串行**执行每个 target 的 `Probe`（含 burst 次 ping），逐个把结果写入 window 并评估状态机。
3. 所有到期 target 的 `nextProbe` 重置为 `now + jitteredInterval()`。

两个由此而来的事实：

- **Tick 阻塞 event loop**。每次 flush 会把所有到期 target 一次性探测完，最坏阻塞时间 ≈ target 数 × burst × timeout。target 多、timeout 大时会把 daemon 事件循环拖慢。
- **`max_concurrent_probes` 当前不生效**。Tick 收集 due 列表时 `inFlight` 恒为 0（同步执行，上一 tick 已归零），限流条件永远为真，所有到期 target 都会被探测。

### 5.4 实际探测频率

由于 Tick 只在 IPsec reconcile flush 时运行，稳态下每条 link 的实际探测间隔是：

```text
max(health.interval, IPsec reconcile flush 间隔)
```

默认配置下 flush 间隔约 1 分钟（或 group `reconcile.interval_seconds`），因此 `health.interval: 5s` 在稳态**达不到** 5s——它只在 flush 因事件频繁发生时才可能生效。这与原设计"daemon event loop 以短 timer（约 1s）驱动 Tick"不同，是当前实现最重要的行为差异（见第 10 节）。

### 5.5 失败语义

- 单个 target 的探测错误不影响其他 target；错误累计到 per-link 的 `errorsTotal` 并进入状态机。
- prober 执行报错（权限、netns 缺失、ping 二进制缺失等）→ 记一次窗口失败 + 记录 reason，状态按状态机收敛到 `probe_error`。
- spool 写入失败只记 warning 日志（`spool_write_failed`），不影响探测。

---

## 6. Rolling window 与状态机

### 6.1 RollingWindow

`pkg/health/stats.go`。每条 probe 视角一个环形缓冲（容量 `loss_window`，默认 20），元素为 `{时间, RTT, 成功}`。注意样本粒度是**每次 Probe 调用**（burst 已聚合），不是每个 ping 包。

`Snapshot()` 计算：

| 统计量 | 说明 |
|---|---|
| `Sent` / `Received` / `Lost` / `LossRatio` | 窗口内样本计数与丢包率 |
| `LastRTT` | 最近一条样本的 RTT（失败样本记 0） |
| `EWMARTT` | 指数加权平均，α=0.3，只对成功样本更新 |
| `MinRTT` / `MaxRTT` / `P50RTT` / `P95RTT` / `P99RTT` | 窗口内成功样本的极值与近秩百分位（`idx=(n-1)*pct/100`） |
| `Jitter` | **排序后** RTT 序列相邻差绝对值的均值（见下方注意） |
| `ConsecutiveFails` | 当前连续失败样本数 |
| `LastSuccess` | 最近成功时间 |

> **注意**：`Jitter` 在按大小排序后的 RTT 数组上计算，而不是按时间顺序的连续样本。这与设计文档"连续 RTT 样本的平均绝对偏差"表述不同，排序后的值系统地偏小，只宜作相对参考。

### 6.2 状态机

`pkg/health/state.go` 的 `StateMachine.Evaluate` 按以下顺序判定原始状态（`snap` 为窗口快照，`lastError` 为最近一次原始错误串）：

```text
1. sent == 0 → unknown
2. lastError 非空 且 (prev == probe_error 或 连续失败 >= fail_threshold)
   → probe_error
3. 连续失败 >= fail_threshold → down
4. loss >= down_loss_threshold：
   - sent >= fail_threshold → down
   - 冷启动样本不足 → degraded
5. loss >= loss_threshold → degraded
6. 其他（已有样本且 loss < loss_threshold）→ healthy
```

随后应用恢复迟滞：

- **恢复迟滞**：prev ∈ {degraded, down, probe_error} 且新状态为 healthy 时，需连续 `recover_consecutive`（默认 5）次评估为 healthy 才真正翻回；期间保持 prev，reason 为 `recovering`。

下降方向不再叠加第二层状态转换计数：`ConsecutiveFails` 与 rolling window 本身已经提供失败次数和丢包率证据。这样 `fail_threshold_consecutive`（默认 3）准确表示进入 down/probe_error 所需的连续失败次数，不会再在越过阈值后额外等待 3 次。初始 `unknown` 在首个样本后立即变为 healthy 或 degraded。

### 6.3 失败原因分类

`classifyFailReason` 把原始错误串映射为稳定的 reason 类别（可作 metrics label）：

| reason | 触发条件 |
|---|---|
| `permission_denied` | 错误含 "permission" |
| `netns_interface_missing` | 错误含 "netns"/"interface"/"missing" |
| `peer_address_missing` | 错误含 "address" |
| `firewall_denied` | 错误含 "firewall" |
| `probe_timeout` | 无错误串但窗口内全丢 |
| `probe_failure` | 其他 |

状态机还会产生恢复过渡 reason `recovering`（见 6.2）。原始探测错误保留在 `LastError`；稳定分类和过渡 reason 写入 `LastReason` 与 metrics `reason` label，避免把动态错误串作为 label。

---

## 7. Rotate cutover gate 与 BIRD 观测

### 7.1 gate 数据流

```text
health.Manager.RotateCutoverReadiness()
  → DaemonService.ipsecRotateCutoverReady()        # app/higgs/ipsec_reconcile.go
  → ipsec.ReconcileInputs.RotateCutoverReady       # map[instanceID]bool
  → handleRotate 中决定是否允许 cutover
```

`RotateCutoverReadiness` 只为 **staged** target 产出条目：`instanceID → !blocking`。blocking 条件（`cutoverBlockingLocked`）：

- 健康状态不是 `healthy` 且不是 `degraded`；或
- 该 staged 视角存在 BabelObservation 且（`Neighbor == false` 或 `Route == false`）。

### 7.2 IPsec 侧语义

`rotateCutoverReady`（`pkg/transport/ipsec/instance.go`）对 map 缺失的处理是**放行**：

| 情况 | cutoverReady |
|---|---|
| readiness 为 nil（health 未启用） | true |
| map 中无该 instance（staged target 尚未进入探测集合） | true |
| `readiness[id] == false` | false（阻塞） |

阻塞时 `handleRotate` 的行为：staged SA 已建立且旧 SA 仍 established 时，link 停留/进入 `dual_running`，action 为 noop、原因 `route_cutover_pending`，等下一轮 reconcile 再评估。旧 SA 已不存在时 gate 不再相关，直接 cutover。

也就是说，health gate 是一个**软门**：它延迟"旧 SA 仍健康在线"时的切换，不阻止任何必走的清理路径；health 未启用或 staged 探测还没跑起来时，rotate 行为与没有 gate 完全一致。

### 7.3 BIRD 观测采集

routing reconcile 处理每个 BIRD instance 后调用 `observeBirdForHealth`（`app/higgs/routing_reconcile.go`）：

- 以 2 秒超时查询 BIRD status（`birdHealthObservationTimeout`）。
- 只为 **staged** link（`RuntimeRole == "staged"`）生成观测：按接口名匹配 Babel neighbor 与 selected route，`Metric` 取两者中的最小正值。
- BIRD 查询失败时写入空观测（`Neighbor=false, Route=false`）——这会使对应 staged link 的 cutover gate 阻塞。也就是说 **BIRD 不可达期间 rotate cutover 会被 hold 住**，这是有意为之的保守行为。

普通 active link 的 Babel RTT/metric 当前不采集、不出现在任何输出中（见第 10 节）。

---

## 8. Metrics 与本地 spool

### 8.1 指标定义

`pkg/health/metrics.go` 定义了 OpenMetrics 文本渲染（`CollectMetrics` + `RenderOpenMetrics`）：

| 指标 | 类型 | 说明 |
|---|---|---|
| `higgs_link_probe_rtt_seconds` | gauge | 最近探测 RTT（秒），LastRTT>0 时输出 |
| `higgs_link_probe_loss_ratio` | gauge | 窗口丢包率，Sent>0 时输出 |
| `higgs_link_probe_jitter_seconds` | gauge | jitter（秒），Jitter>0 时输出 |
| `higgs_link_health_state` | gauge | 状态编码 0–5（见 2.4） |
| `higgs_link_probe_errors_total` | counter | per-link 探测错误总数，为 0 不输出 |

label 集合（低基数约束，`writeLabels`）：`local_zone`、`peer_zone`、`overlay`、`probe_id`、`instance_id`、`netns`、`generation`、`probe_role`、`probe_type`、`reason`。空值 label 不输出；endpoint IP、nonce、原始错误串禁止作为 label。

> **注意**：这套渲染当前**没有接线**——daemon 和 observer 都没有 `/metrics` 端点，`RenderOpenMetrics` 只在单元测试中被调用。当前实际可用的时序通道是下方的本地 spool + observer API。

### 8.2 本地 spool

启用条件：`metrics` 块启用且 `local_spool_path` 非空。文件为 `<local_spool_path>/samples.jsonl`，每行一个样本：

```json
{"unix_ms": 1752700000000, "probe_id": "link-a#staged", "instance_id": "link-a",
 "probe_role": "staged", "interface_name": "hgs12", "state": "healthy",
 "probe_type": "icmp", "rtt_ms": 12, "loss_ratio_pct": 0, "jitter_ms": 1,
 "sent": 20, "received": 20, "lost": 0}
```

写入时机：`reconcileHealth` 中只要本轮有探测发生（`dispatched > 0`），就把**当前全部 link 的 snapshot** 各追加一行——包括本轮没被探测的 link。因此 spool 行是以 flush 为单位的批量快照，行间时间间隔跟随 flush 节奏而非 `health.interval`。

每次写入后按 `local_spool_max_age`（默认 6h）prune：读入全文件、丢弃过期样本、整体重写（`.tmp` + rename）。spool 是单机临时时序库，不做压缩和索引，保留窗口内量级可控（行数 ≈ link 数 × flush 次数）。

### 8.3 时序查询

`queryHealthSpoolSeries`（`app/higgs/health_spool.go`）从 spool 聚合单条 link 的时序：

- `metric`：`rtt`（ms，仅正值样本）/ `loss`（百分比）/ `jitter`（ms，仅正值样本）/ `state`（状态编码）。`babel_rtt`、`babel_metric` 显式返回"not available in the local health spool yet"。
- `range`：默认 1h，上限被 clamp 到 `local_spool_max_age`。
- `step`：默认 30s，最小 1s，最大为 range。
- `probe_role`：可选过滤（如只看 `staged`）。
- 聚合方式：按 step 分桶取**算术平均**，输出总序列 `points` 和按 probe 视角拆分的 `lines`。

### 8.4 remote write

`remote_write_url` / `remote_write_queue_capacity` 只被解析进配置，代码中没有任何消费者。需要集中式 TSDB（设计推荐 VictoriaMetrics single-node）时，当前只能自行桥接 spool 或 observer API。

---

## 9. Debug 与诊断

### 9.1 higgs debug health

```bash
higgs debug health
```

输出分两段（`internal/inspect/text/health.go`）：

1. **Target 列表**：从 stateFile 重建的探测目标（不依赖 daemon 存活、不依赖 health 启用）——instance、peer zone、overlay、probe_id、role、interface、两端 tunnel 地址、link 状态、staged 标记。
2. **Live health state**：daemon 存活且 health 启用时，通过 control socket `health_status` 拿到的实时窗口统计——state、probe 类型、sent/received/lost/loss、RTT（last/ewma/p50/p95/p99）、jitter、连续失败、last_error、`cutover_blocking`。

daemon 不在运行或 health 未启用时只有第一段。

### 9.2 higgs debug links 与 control API

- `links_status` control 方法把 `healthStatusResponse()` 并入 link inspection，`higgs debug links` 与 `/api/v1/links` 因此带 per-link health summary。
- `health_status` control 方法返回全量 `healthLinkJSON`（时间字段为毫秒整数，loss 为百分比整数）。

### 9.3 Observer

只读 HTTP API（`internal/observer/server.go`）：

| 端点 | 说明 |
|---|---|
| `GET /api/v1/health` | 全部 link 的健康状态 + link instance/desired 上下文 + datasource 信息 |
| `GET /api/v1/health/{link_id}` | 单条 link 详情（按 InstanceID 或 ProbeID 匹配） |
| `GET /api/v1/health/{link_id}/series?metric=&range=&step=&probe_role=` | 时序（8.3）；spool 未配置返回 503 |

Observer web UI 展示健康状态与最近窗口；health 变化通过 SSE `health_updated` 事件推送（`notifyObserver`，在状态变化 flush 尾部发出）。跨节点、长时间图表仍建议接外部 TSDB + Grafana。

### 9.4 测试入口

- `go test ./pkg/health/`：rolling window、状态机迟滞、probe 聚合、metrics 渲染等单元测试。
- `sudo env PATH="$PATH" make health-smoke`：除 manager/metrics 单测外，还会在
  两个真实 named netns 的 veth 链路上运行 raw-ICMP、BIRD cutover 和 `tc netem`
  故障/恢复验证；需要 root、`ip`、`bird`/`birdc`、`tc` 与 daemon 所需 capability。
- `app/higgs/health_config_test.go`、`health_reconcile_test.go`：配置解析与 daemon 级集成测试。
- `app/higgs/bird_root_smoke_test.go` 含 cutover gate 的 root smoke 用例。

---

## 10. 已知限制与实现缺口

以下条款均以当前代码为准，与原 Phase 6.6 设计存在差异或尚未完成：

| 项 | 设计期望 | 当前实现 | 影响 |
|---|---|---|---|
| 探测执行模型 | 有界并发、不阻塞 loop | 独立 health 协程以约 1s timer 投递任务；固定大小 worker pool 经 channel 执行 ping，完成后以 channel 通知 daemon | 健康 interval 不受 IPsec reconcile 间隔限制，慢 ping 不阻塞 daemon event loop |
| ICMP 快路径 | raw socket（`ip4:icmp`）优先，ping 兜底 | Linux 默认 raw socket；无 capability 时回退 `ip netns exec ping` | raw 成功时 RTT 不含进程创建开销；netns 删除/重建的长期行为仍待 root smoke |
| UDP fallback | ICMP 不可用时降级 UDP keepalive | fallback 未接线；UDPProber 语义弱（write 成功即可达） | 无 ICMP 权限时只能得到 probe_error |
| Babel RTT/metric | 普通 link 也采集被动指标、出 `higgs_link_babel_*` | 只为 staged link 采集 neighbor/route 布尔与最小 metric；series API 显式报未实现 | 被动质量数据基本不可用 |
| BIRD metric 联动 | degraded/down 先调高 BIRD metric | 未实现 | 健康结果不影响选路 |
| 防火墙联动 | 可选按 link state 收紧 forward allow | 未实现 | 健康 down 不改变防火墙 |
| `/metrics` 端点 | daemon 暴露 OpenMetrics | 渲染代码存在但未接线，仅单测覆盖 | 无法被 Prometheus 直接 scrape |
| remote write | 可选推送到 VictoriaMetrics 等 | 配置已解析、无消费者 | 集中式 TSDB 需自行桥接 |
| `suppressed` 状态 | 维护窗口抑制 | 无任何产生路径 | 仅为保留编码 |
| `SetProbeError` | 调度失败直接置 probe_error | 方法定义了但无调用方 | probe_error 只经状态机路径进入 |
| 状态落盘 | 状态变化/阈值 crossing 写 stateFile | 完全内存态 | daemon 重启后从 unknown 重新收敛 |
| Jitter 计算 | 时间序连续样本的平均绝对偏差 | 对**排序后** RTT 序列计算 | 数值系统性偏小，仅作相对参考 |
| spool 写入粒度 | 按 probe sample 写 | 按 flush 批量写全量快照 | 样本时间密度跟随 flush 节奏 |

### 10.1 使用建议

- `health.interval` 独立于 IPsec reconcile 间隔；默认 `5s`、`burst: 3` 时，每条 link 平均约 `0.6 ICMP/s`。`jitter` 会将初始与后续探测错峰。
- 控制 `timeout`、`burst` 与 `max_concurrent_probes`：worker pool 同时最多运行该并发数的 link；`burst` 内的单包请求仍会串行执行，但不会阻塞 daemon 主循环。
- 确认运行环境 `ping` 可用（容器内需要 cap_net_raw 或 setuid ping），否则所有 link 会收敛到 `probe_error`。
- 需要 observer 时序图时务必配置 `metrics.local_spool_path`；不配置则只有实时状态，没有历史。
- 排障 rotate 停滞时先看 `higgs debug health` 的 `cutover_blocking` 与 staged 视角的 BIRD 观测——BIRD 不可达也会 hold 住 cutover。

### 10.2 后续设计方向

原设计中尚未排期、仍作为方向保留的内容：

- **BIRD metric 联动**：普通 link degraded/down 时先调高 BIRD metric 表达劣化，而不是直接动链路或防火墙。
- **signed health hint**：当前 health 是纯本机观测；如需向 mesh 发布健康意图（例如"不要选我做中继"），应单独设计 record 与信任边界，不直接写 gossip active state。
- **防火墙联动**：按 link state 收紧 forward allow，用于隔离异常 link、避免黑洞转发。
- **真正的 metrics 出口**：给 daemon/observer 接 `/metrics`（渲染代码已就绪），或实现 remote write 消费者。
