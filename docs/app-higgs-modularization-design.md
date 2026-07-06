# app/higgs 模块化设计

> **文档状态**：设计草案（Phase 6.7 后续重构）
> **目标**：将 `app/higgs` 从单一巨大 `main` 包逐步拆成清晰的应用模块。`app/higgs` 最终只保留 executable wiring、CLI 命令注册、配置装配和少量 daemon live adapter；health、routing、revocation、peer lifecycle、observer、debug/inspect、firewall、IPsec reconcile、sync runtime 等可复用或相对独立的应用逻辑应下沉到 internal/package 模块中。

---

## 1. 背景

`app/higgs` 目前已经承担了太多角色：

- CLI 命令入口：`cmd.go`、`record.go`、`route.go`、`ipam.go`、`recovery.go` 等。
- daemon 生命周期和事件循环：`daemon.go`、`daemon_sync.go`。
- sync/gossip runtime：`sync.go`、`sync_session.go`、`packet_demux.go`、`objectpull.go`。
- data-plane reconcile：`ipsec_reconcile.go`、`routing_reconcile.go`、`firewall_reconcile.go`、`health_reconcile.go`。
- 状态与配置：`state.go`、`config.go`、`*_config.go`。
- 诊断和 observer：`diagnostics.go`、`debug_*.go`、`observer_server.go`。
- 安全和生命周期辅助：`peer_state.go`、`revocation_cleanup.go`、`admission_diagnostics.go`。

这些文件都在 `package main` 中，导致几个问题：

1. 子系统可以直接读写 `stateFile`、`appConfig`、`DaemonService` 和其他私有类型，边界不明显。
2. debug/observer/control/CLI 经常重复解释同一份状态。
3. health、routing、firewall、IPsec、revocation、peer lifecycle 的 reconcile 逻辑互相调用或共享私有状态，难以独立测试。
4. 新功能倾向继续加到 `app/higgs` 文件里，而不是形成稳定模块。

模块化目标不是一次性把所有类型导出，也不是机械移动文件，而是逐步把“领域纯逻辑、应用服务、读侧诊断、presenter、source adapter”拆开，让 `app/higgs` 成为 thin executable layer。

---

## 2. 分层目标

推荐目标结构：

```text
app/higgs
  - main / cmd registration
  - config loading + runtime assembly
  - daemon live adapters for unexported state
  - command-service wiring
        |
        v
internal/higgsapp/* or internal/*
  - sync service
  - reconcile services
  - lifecycle / revocation / admission
  - inspect/readmodel
  - CLI text presenters
  - control API DTOs
        |
        v
pkg/*
  - stable domain libraries
  - wire/protocol/model/planner/driver logic
```

分层规则：

1. `pkg/*` 继续放稳定领域模型和底层能力，例如 zone、gossip、routing authorization、firewall planner、health manager、transport/ipsec provider。
2. `internal/*` 放 Higgs 应用层模块：它可以组合 `pkg/*`，但不应该依赖 CLI 框架、stdout、环境变量散读或 `main` 包未导出类型。
3. `app/higgs` 保留 executable glue：命令注册、配置入口、daemon assembly、需要访问未导出状态的临时 adapter。
4. 所有写路径仍通过 daemon commit 流程：`DaemonStateStore.BeginUpdate` / workspace 变更 / `Commit` 或 control command service 的 single-writer 路径；readmodel/inspect 不执行写操作，也不读取未提交 workspace。
5. 每次迁移都要先定义输入/输出结构，避免把 `stateFile` 原样搬进 internal 后形成新的大泥团。

---

## 3. 建议模块

| 模块 | 候选位置 | 可迁移内容 | 暂留 `app/higgs` 的内容 |
|------|----------|------------|-------------------------|
| Observer HTTP | `internal/observer` | HTTP routing、SSE、static、API envelope（已部分完成） | daemon 启动接线、provider adapter |
| Inspect / diagnostics | `internal/inspect`, `internal/inspect/text`, `internal/inspect/source` | 共享诊断 view、reason code、CLI text presenter、HTTP/CLI 共用 readmodel | 从 committed snapshot、health/reconcile runtime snapshot、control socket 构造 input 的 live adapter |
| Peer lifecycle | `internal/peerstate` 或 `internal/lifecycle` | `PeerStatusInfo`、stale/offline/revoked 推理、cleanup decision | 将 `stateFile.SyncPeers` 拷贝成 input |
| Revocation impact | `internal/revocation` | revoked subtree impact、layer status、diagnostic view | daemon flush 顺序和实际 cleanup 调用 |
| Admission diagnostics | `internal/admission` | pending/adopted diagnosis、reason code、join hint view | daemon 中更新 admission state 的 adapter |
| Health app layer | `internal/healthapp` | health status view、spool query/parser、CLI/observer presenter | probe 调度和 daemon manager lifecycle |
| Routing app layer | `internal/routingapp` | route dump/explanation、BIRD summary view、debug presenter | BIRD process/client lifecycle、daemon reconcile timer |
| Firewall app layer | `internal/firewallapp` | config-to-spec conversion、debug view、reconcile summary presenter | privileged apply scheduling、driver construction with runtime config |
| IPsec app layer | `internal/ipsecapp` | publish record planning, reconcile summary/view helpers, debug config redaction | provider lifecycle, VICI subscription wiring |
| Sync app layer | `internal/syncapp` | SyncSession FSM、packet demux、peer address ranking、object pull client/pool where possible | daemon event loop integration and state persistence adapter |
| Control API | `internal/controlapi` | control request/response DTOs and client helpers | daemon handler registration touching live service |
| Config parsing | `internal/config` or focused packages | per-subsystem YAML parsing once stable | top-level env/path/default assembly |

模块名可以在实现时微调；重点是先按职责分开，而不是按当前文件名一比一搬迁。

---

## 4. 迁移原则

### 4.1 不直接搬 `stateFile`

`stateFile` 仍是当前耦合中心，但 daemon 读侧事实源已经变成 committed snapshot。迁移时优先定义小 input：

```go
type PeerLifecycleInput struct {
    Now         time.Time
    ManagedZone zone.ZonePath
    Peers       []PeerInput
    Links       []LinkInput
    Revoked     map[zone.ZonePath]bool
}
```

internal 模块吃 input，输出 view/decision。`app/higgs` adapter 负责从 `DaemonStateStore.Snapshot()`、离线 DB snapshot 或 control socket response 拷贝 committed state；health、BIRD、actual SA、reconcile progress 等 live 诊断作为单独 source 汇入 input。adapter 不应把未提交 workspace 或 `stateFile` 锁本身传入 internal。

### 4.2 写侧和读侧分开

- 写侧：daemon event loop、control command service、reconcile apply；对 state 的修改先落在 workspace，只有 commit 成功后才成为读侧事实。
- 读侧：inspect/readmodel、debug/observer/control status；默认读取 committed snapshot，再合并只读 runtime diagnostics。

readmodel 可以输出 `SuggestedAction` / `CommandHint`，但不能直接调用 apply、record put、delegate、reload、cleanup 或 reconcile，也不能通过频繁诊断计数推进 committed state revision。

### 4.3 Presenter 不做推理

CLI text、HTTP JSON、control response 都不应该各自判断 `revoked/stale/offline/up/degraded`。这些状态解释应来自共享 view。

### 4.4 先抽纯逻辑，再抽 adapter

如果某段代码大量依赖 `DaemonService` 或未导出状态，先把纯函数和输出结构抽走，live adapter 暂留 `app/higgs`。这样迁移可控，测试也能先落地。

---

## 5. 建议迁移顺序

### 5.1 Inspect/debug/observer 读侧

优先级高，因为它横跨 observer、debug、control status，同时风险较低：

1. 建立 `internal/inspect`、`internal/inspect/text`、`internal/inspect/source` 骨架。
2. 先抽 links：`debug links` 与 `/api/v1/links` 重合最高；links input 优先使用最近一次 committed reconcile snapshot，只有离线/显式 dry-run 才重新 plan desired。
3. 再抽 peer/endpoints：`debug peer`、`sync status --verbose`、`debug peers`、`/api/v1/peers` 共用 endpoint merge 和 lifecycle reason。
4. 再抽 zone/records/admission/revocation。
5. 最后抽 routes/BIRD/firewall/health 的 view 和 presenter。

### 5.2 Peer lifecycle + revocation

`peer_state.go` 和 `revocation_cleanup.go` 已经像独立模块，但仍依赖 `stateFile`。下一步应：

1. 把 `derivePeerStatus`、cleanup decision、revoked subtree impact 改成 input -> decision。
2. `app/higgs` 保留 `stateFile` adapter 和 daemon flush ordering。
3. debug/observer/control 都消费同一 decision/view。

### 5.3 Health / routing / firewall app 层

这些子系统都有 config、reconcile、debug、observer/control 状态：

1. 先迁移 view/presenter 和 config-to-spec helper。
2. 再迁移不触碰 daemon lifecycle 的 planner input builder。
3. privileged apply、probe manager、BIRD process lifecycle 暂留 app adapter，待接口稳定后再下沉。

### 5.4 Sync runtime

`sync.go` 仍是最大文件，且耦合传输、状态、CLI 输出、object pull、peer discovery。建议较晚处理：

1. 先保留 event loop wiring 在 `app/higgs`。
2. 抽 `SyncSession`、timer、packet demux、peer address ranking、object pull client/pool 到 `internal/syncapp`。
3. 将 `sync status` 输出改为 inspect/text。
4. 再拆旧 `sync.go` 的 transport open、packet handling、state apply adapter。

### 5.5 State/config/control

这是最后处理的核心边界：

1. 先把 control DTO/client helper 下沉到 `internal/controlapi`。
2. 把 per-subsystem config parser 移到对应 internal module，顶层 `appConfig` 只做组合。
3. 评估是否将 `stateFile` 类型移到 `internal/appstate`。这一步影响面最大，必须等上面模块已经通过 input/view 降耦合后再做。

---

## 6. 验证策略

每个迁移批次至少保留：

- 原有 focused smoke，例如 `make observer-smoke`、routing/firewall/health 相关 smoke。
- 相关 package 单测：新 internal module 的 pure tests 应多于 app wiring tests。
- CLI golden/output 测试迁到 presenter 层，app 层只保留参数解析和 fallback/source 选择。
- `go test ./app/higgs` 用于验证 executable wiring 未断。
- 对涉及 shared behavior 的迁移，补一组 HTTP/CLI 双入口使用同一 view 的测试。

---

## 7. 非目标

- 不一次性把 `app/higgs` 改成很多微包。
- 不为了移动文件而导出所有内部状态。
- 不把写命令放进 readmodel。
- 不把 `pkg/*` 变成应用运行时包；`pkg/*` 仍保持稳定领域/协议/driver 边界。
