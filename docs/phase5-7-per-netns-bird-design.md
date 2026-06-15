# Phase 5.7: BIRD 从 per-overlay 改为 per-netns（设计文档）

> **状态：** 调研完成，待实现
> **创建日期：** 2026-06-15
> **关联：** `docs/design.md` Phase 5 netns 章节、`docs/phase6-ipam-design.md` 第 13 章、`todo.md` Phase 5.7

## 1. 背景与目标

### 1.1 问题

当前 Phase 5 的 BIRD 实例模型是 **per-overlay**：每个 overlay（link group）对应一个独立的 BIRD 进程。这意味着：

- 同一 netns 下的多个 overlay 会启动多个 BIRD 实例，各自维护独立的路由表
- 多个 overlay 的 XFRM interface 无法共享 Babel 邻居和 ECMP 路径
- routing 配置（table、metric、filter、control socket）分散在 `overlays[].routing` 中，无法统一管理

### 1.2 目标

改为 **per-netns** 模型：一个 netns 内只运行一个 BIRD 实例，同一 netns 下的所有 overlay 共享该实例。routing 配置从 `overlays[].routing` 上提到 `routing.instances[]` / `netns` 层级。

## 2. 当前架构（per-overlay 模型）

### 2.1 涉及的核心组件

| 组件 | 文件 | 当前状态 |
|------|------|----------|
| **配置入口** | `app/higgs/config.go:175,180-196` | `overlays[].routing` 嵌入在每个 overlay/link group 中 |
| **运行时配置** | `pkg/transport/ipsec/link.go:72-88,106` | `LinkGroupSpec.Routing` (`RoutingSpec` 类型) |
| **State 持久化** | `app/higgs/state.go:32,85-94` | `BirdInstances map[string]*BirdInstanceState`，key 为 overlay ID |
| **Reconcile 逻辑** | `app/higgs/routing_reconcile.go:42-222` | 按 overlay group 迭代，每个 group 一个 BIRD 实例 |
| **BIRD Spec** | `pkg/routing/bird/types.go:47-102` | `BirdInstanceSpec.OverlayID` 标识实例 |
| **Config 生成** | `pkg/routing/bird/generator.go:37-60,94-100` | table/protocol/filter 名称用 `sanitizeOverlayID(OverlayID)` 派生 |
| **Debug 输出** | `app/higgs/debug_routing.go:63-99` | 按 overlay group ID 查找 BIRD 实例 |
| **Debug Links** | `app/higgs/diagnostics.go:260-281` | `debugLinkRoutingState()` 按 groupID 查找 BIRD |
| **Control API** | `app/higgs/daemon.go:490-506`, `app/higgs/control.go:67` | `bird_status` 返回 overlay-keyed instances |

### 2.2 当前配置示例

```yaml
overlay:
  default_netns:
    kind: name
    name: h2
    create: true

overlays:
  - id: ipsec-main
    routing:
      enabled: true
      protocol: bird
      mode: managed
      control_socket: /run/higgs/bird-ipsec-main.ctl
      pid_file: /run/higgs/bird-ipsec-main.pid
      table: main
      metric_base: 100
```

### 2.3 当前 Router-ID 派生

```go
// pkg/routing/bird/routerid.go
func StableRouterID(localZone zone.ZonePath, rootTrust []byte, overlayID string) uint32 {
    digest := higgscrypto.Hash(
        []byte(localZone),
        rootTrust,
        []byte(overlayID),
    )
    id := binary.BigEndian.Uint32(digest[:4])
    if id == 0 { id = 0x80000001 }
    return id
}
```

## 3. BIRD 版本确认

项目依赖的是 **BIRD 2.x**（非 BIRD 1.x）：

- `docs/bird-babel-alternative-findings.md`："BIRD 2.x 起支持 Babel"、"IPv4+IPv6 同一实例双 channel — BIRD 2.x 起同时支持"
- `docs/babel-tunnel-quality-measurement.md`："调研范围：BIRD 2.16+/3.x"
- 生成的 config 使用 BIRD 2.x 语法：`ipv4 table`、同一 Babel protocol 内同时 `ipv4 {}` 和 `ipv6 {}` channel
- `link quality yes;` 为 BIRD 2.16+ 特性

### 注意事项

当前 `pkg/routing/bird/preflight.go` 只检查 `bird` 二进制存在，不检查版本。Phase 5.7 应增强 preflight，运行 `bird --version` 并断言 >= 2.0。

## 4. 目标配置模型（per-netns）

### 4.1 新配置示例

```yaml
# 顶层 netns 定义
netns:
  default:
    kind: name
    name: h2
    create: true

# 顶层 routing 实例定义（每个 netns 一个 BIRD）
routing:
  instances:
    - id: main
      netns: default            # 引用 netns.default
      enabled: true
      protocol: bird
      mode: managed
      control_socket: /run/higgs/bird-main.ctl
      pid_file: /run/higgs/bird-main.pid
      config_file: /run/higgs/bird-main.conf
      table: main
      metric_base: 100
      metric_staged: 200
      metric_draining: 500
      interface_pattern: "hgs*"

# overlays 只引用 netns，不再嵌套 routing
overlays:
  - id: ipsec-main
    netns: default
    provider: strongswan
    # ... 其他 overlay 参数
  - id: ipsec-backup
    netns: default              # 与 ipsec-main 共享同一个 BIRD 实例
    provider: strongswan
```

### 4.2 设计原则

- 一个 netns = 一个 BIRD 实例 = 一个 Router-ID
- 同一 netns 下的所有 overlay 共享 Babel 邻居和路由表
- 多个 overlay 的 XFRM interface 通过 `interface_pattern`（如 `hgs*`）自动被 BIRD 发现
- routing 配置（table、metric、filter）在 netns 层级统一管理

## 5. Router-ID 派生方案

### 5.1 核心分析

Babel 协议（RFC 8966）中的 Router-ID 用于：
- **环路检测**：feasibility condition 使用 `router-id + sequence number`
- **路由区分**：同一前缀来自不同节点时，用 router-id 区分来源
- **不用于授权**：Router-ID 通过 Hello/IHU TLV 动态交换，其他节点在协议运行时实时学习，不需要预先知道对端的 router-id

但在 Higgs 控制面审计中，我们需要从 Router-ID 反推路由来源的 zone 和 netns。

### 5.2 推荐方案

改为 `StableRouterID(localZone, rootTrust, netnsName)`，**第三个参数从 overlayID 改为 netns 标识**：

```go
func StableRouterID(localZone zone.ZonePath, rootTrust []byte, netnsName string) uint32 {
    digest := higgscrypto.Hash(
        []byte(localZone),
        rootTrust,
        []byte(netnsName),
    )
    id := binary.BigEndian.Uint32(digest[:4])
    if id == 0 { id = 0x80000001 }
    return id
}
```

其中 `netnsName` 使用 `NetNSSpec.Target()`：
- `host` → `"host"`
- `name: h2` → `"h2"`
- `path` netns 需要配置中显式指定 `router_id_label`

**理由：**
- per-netns 模型下，一个 netns = 一个 BIRD 实例 = 一个 Router-ID
- 同一节点内不同 netns 的 BIRD 必须有不同 Router-ID，否则当 netns 通过 host 路由互通时会产生 Babel Router-ID 冲突
- 两个不同节点即使配置了相同的 netns name（如都用 `h2`），因为 zone 不同，Router-ID 也不同
- Router-ID 依赖 zone、root trust 和 netns name，全局稳定且可被信任链推导
- 控制面交叉审计可以通过 announced netns name 反推 Router-ID 对应的 zone/netns

### 5.3 多 netns 边界情况

#### host netns

host netns 的 `netnsName` 为 `"host"`，必须作为独立的 Router-ID 输入。

#### path netns

path netns 没有稳定名称，需要配置中显式指定 `router_id_label`，否则无法用于 BIRD Router-ID 推导。

```yaml
netns:
  custom:
    kind: path
    path: /var/run/netns/foo
    router_id_label: foo-netns
```

### 5.4 `routing/netns` Record

为了让对端能够从 Router-ID 反推 zone + netns，每个 zone 需要 announce 本节点使用的 routing netns 列表。

**Record Key**: `routing/netns`

**Record Type**: `routing.netns.v1`

**Value**:
```json
{
  "version": 1,
  "netns": ["h2", "host"]
}
```

**审计流程：**
1. 节点 A 从 BIRD 学到路由，看到 Router-ID R
2. 遍历已同步 zone，读取每个 zone 的 `routing/netns` record
3. 对每个 `(zone, netns)` 计算 `expected = StableRouterID(zone, rootTrust, netns)`
4. 找到 `expected == R` 的 `(zone, netns)`
5. 用该 zone 的 `AuthorizedRouteSet` 验证前缀权限

## 6. 安全设计：per-peer import filter

### 6.1 攻击场景

```
攻击场景：
1. catofes. 的 IPAM pool: fd00:1234::/48
2. node-a.catofes. 被 assigned: fd00:1234:1::/48  
3. node-b.catofes. 被 assigned: fd00:1234:2::/48
4. node-b 恶意在本地 BIRD 手工宣告 fd00:1234:1::/48（属于 node-a）
5. 通过 Babel 传播到 node-c
```

### 6.2 当前防护层次与缺口

| 防护层 | 位置 | 作用 | 缺口 |
|--------|------|------|------|
| **Export filter** | BIRD 本地生成 | 只发布本节点 `AuthorizedRouteSet` 中的前缀 | ❌ 只对诚实节点有效；恶意节点可绕过 BIRD config 手工注入 |
| **Import filter** | BIRD 接收端 | 接受所有落在 IPAM assignment 范围内的前缀 | ❌ **不检查来源**！任何 peer 宣告的前缀只要在 IPAM pool 范围内就被接受 |

当前 import filter（`routing_reconcile.go:135`）只生成全局 prefix whitelist：

```go
importSet := assignmentPrefixes(ars)  // 所有 IPAM assignment 前缀
```

`filter.go` 的 `RenderFilter` 只做 `net ~ [ prefix+ ]` 匹配——任何来自任何 peer 的路由，只要前缀落在授权空间内就接受。

### 6.3 关键矛盾：per-peer import filter 与 Babel 多跳传播冲突

**⚠️ 直接 per-peer import filter 不可行。** Babel 是距离向量协议，路由需要多跳传播。

考虑 `A -> B -> C` 拓扑：
1. C 宣告 `fd00:1234:3::/48`（C 被授权的前缀）
2. B 通过 `hgs3c4d`（连到 C）收到，通过 C 的 per-peer filter ✅
3. B 把路由加入本地路由表，通过 export filter 转发给 A
4. A 通过 `hgs1a2b`（连到 B）收到 `fd00:1234:3::/48`

**问题在第 4 步**：A 的 `hgs1a2b` 接口的 per-peer import filter 只接受 "B 有权宣告的前缀"。但 `fd00:1234:3::/48` 是 C 的前缀，不是 B 的——per-peer filter 会拒绝这条多跳路由，**破坏全网可达性**。

### 6.4 推荐方案：全局 import filter + 控制面交叉审计

由于 Babel 的多跳特性，安全防护不能仅靠 BIRD import filter。推荐分层方案：

#### 第一层：全局 import filter（BIRD 层面）

import filter 仍基于全局授权前缀集（所有 IPAM assignment 范围），**不区分来源 peer**。这保证了多跳路由传播：

```bird
filter higgs_import_h2 {
    if net ~ [ 0.0.0.0/0, ::/0 ] then reject;       # 拒绝 default route
    if net ~ [ bogon_prefixes+ ] then reject;         # 拒绝 bogon
    if net ~ [ authorized_assignment_prefixes+ ]      # 接受所有授权前缀范围
    then accept;
    reject;                                           # 拒绝未授权前缀
}
```

#### 第二层：Higgs 控制面交叉审计（Daemon 层面）

Higgs daemon 定期从 BIRD 读取学到的路由并验证来源：

```
1. birdc show route all protocol higgs_babel_h2
   → 每条路由返回 prefix, from(邻居), via(下一跳), interface, metric, source
2. Higgs 通过 LinkInstance 映射 interface → peer zone
3. 对于每条学到的路由，检查：
   - 直连路由（metric ≈ metric_base）：peer zone 必须有权宣告该前缀
   - 多跳路由（metric > metric_base）：最终来源必须在 AuthorizedRouteSet 中
4. 发现异常 → 告警 + 主动 flush（birdc 命令删除恶意路由）
```

**为什么控制面审计比 BIRD filter 更适合这个场景：**

| 维度 | BIRD per-peer filter | Higgs 控制面审计 |
|------|---------------------|-----------------|
| 多跳路由支持 | ❌ 破坏传播 | ✅ 不影响传播 |
| 实时阻断 | ✅ 实时 | ⚠️ 有短暂窗口 |
| 来源信息获取 | 受限于 BIRD filter 语言 | 可访问完整 route + LinkInstance |
| 多跳来源追溯 | 困难（BIRD filter 不暴露原始 router-id 给 filter） | 可通过 metric + interface 推断 |
| 复杂度 | 低（纯 BIRD config） | 中（需要 daemon 定期轮询） |
| 响应能力 | 静态 reject | 动态 flush + 告警 + 撤销联动 |

#### 第三层：Zone 签名链（已实现）

保证 IPAM assignment 和 route announcement 的真实性。恶意节点即使能绕过本地 BIRD config 注入路由，其 zone 签名链上的 IPAM/announcement record 仍然是可验证的。

### 6.5 BIRD filter 基于 Router-ID 来源验证的现状（不可行）

**理论上有可能：** Babel 协议（RFC 8966 §2.7）在多跳传播时保留原始宣告者的 Router-ID，路由内部数据结构中确实携带了 64 位 `router_id`。

**但实际不可行（BIRD 2.x 当前版本）：** 经源码级调研确认，BIRD 2.x 存在以下限制：

1. **`babel_router_id` 未注册为 filter 可用属性：** `proto/babel/config.Y` 中只注册了 `BABEL_METRIC` 作为 filter 动态属性，没有注册 `BABEL_ROUTER_ID`。无法在 filter 配置中使用 `babel_router_id` 做比较或过滤。

2. **属性类型是 `EAF_TYPE_OPAQUE`：** 即使注册了属性名，`babel_router_id` 使用的是不透明字节串类型（64 位），BIRD filter 表达式对 OPAQUE 类型的数值比较是受限制的。

3. **`router_id` 是只读的：** `babel_store_tmp_attrs()` 注释明确标记 "EA_BABEL_ROUTER_ID is read-only"。

**如果要实现 filter 中按 Router-ID 过滤，需要 patch BIRD 源码：**

```c
// proto/babel/config.Y 中新增动态属性注册
dynamic_attr:
    BABEL_METRIC { $$ = f_new_dynamic_attr(EAF_TYPE_INT, T_INT, EA_BABEL_METRIC); }
  | BABEL_ROUTER_ID { $$ = f_new_dynamic_attr(EAF_TYPE_OPAQUE, T_QUAD, EA_BABEL_ROUTER_ID); } ;
```

此外还需要处理 64 位 router_id 与 32 位 filter 数值类型的映射问题（拆分为高低 32 位或新增 64 位支持）。

**结论：** 在不 patch BIRD 源码的前提下，**控制面交叉审计是唯一可行的恶意前缀检测方案**。

### 6.6 实现路径（修订）

| 阶段 | 目标 | 依赖 |
|------|------|------|
| **Phase 5.7** | 保持全局 import filter（所有 IPAM 授权前缀），不区分来源 | 无新依赖 |
| **Phase 7 后续** | 实现 Higgs 控制面交叉审计：daemon 定期 `birdc show route` + flush 恶意路由 | `birdc show route all` 输出中携带 router_id（CLI 显示可用，即使 filter 不可用） |
| **可选后续** | Patch BIRD 源码注册 `babel_router_id` filter 属性，实现实时来源验证 | 维护 BIRD fork 或提交上游 PR |

### 6.7 安全防护总结（修订）

| 防护层 | 机制 | 状态 | 多跳兼容 |
|--------|------|------|----------|
| **Export filter** | 防止诚实节点误配置 | ✅ 已实现 | ✅ |
| **全局 import filter** | 拒绝未授权前缀范围 | ✅ 已实现 | ✅ |
| **Zone 签名链** | 保证 IPAM/announcement 真实性 | ✅ 已实现 | ✅ |
| **控制面交叉审计** | daemon 定期 `birdc show route` 检测恶意宣告并 flush | ❌ 待实现（Phase 7 后续，**唯一可行方案**） | ✅ |
| **BIRD Router-ID filter** | filter 内实时来源验证 | ❌ 需要 patch BIRD 源码 | ✅ |

### 6.8 Router-ID 与安全 filter 的关系（修订）

- Router-ID **理论上**是安全 filter 的理想依据，但 BIRD 2.x filter 语言当前不支持
- `birdc show route all` 的 CLI 输出中**可以显示**每条路由的 `router_id`（`babel_get_attr()` 已实现显示），因此控制面审计方案可以获取到原始 Router-ID
- 控制面审计流程：daemon 从 `birdc show route all` 解析 `(prefix, router_id, interface, metric)` → 通过 `routing/netns` record 反推 `(zone, netns)` → 通过 `AuthorizedRouteSet` 验证该 zone 是否有权宣告该前缀 → 异常时 flush
- `StableRouterID(localZone, rootTrust, netnsName)` 的全局可推导性仍然是控制面审计方案的核心前提

## 7. 实现计划

### 7.1 需要修改的文件清单

#### 数据结构变更

| 文件 | 变更 |
|------|------|
| `pkg/transport/ipsec/link.go` | 移除 `LinkGroupSpec.Routing` 字段；保留 `TransportLinkSpec.NetNS` |
| `pkg/routing/bird/types.go` | `BirdInstanceSpec.OverlayID` → `NetNSName`；增加 `InterfacePatterns []string` |
| `pkg/routing/bird/routerid.go` | `StableRouterID` 第三个参数改为 `netnsName` |
| `pkg/routing/records.go` | 新增 `routing.netns.v1` record 类型和解析函数 |
| `app/higgs/ipsec_publish.go`（或新文件） | daemon 发布本节点 `routing/netns` record |
| `app/higgs/state.go` | `BirdInstanceState.OverlayID` → `NetNSName`；`BirdInstances` key 改为 netns name |

#### 配置模型重构

| 文件 | 变更 |
|------|------|
| `app/higgs/config.go` | 新增 `netns:` / `routing.instances[]` 配置段；移除 `overlays[].routing`；移除 `overlay.default_netns` / `ipsec.default_netns` |
| `config.example.yaml` | 更新示例 |

#### 核心逻辑

| 文件 | 变更 |
|------|------|
| `app/higgs/routing_reconcile.go` | 按 netns 分组 overlays，每个 netns 生成一个 BIRD 实例；合并 interface pattern |
| `pkg/routing/bird/generator.go` | table/protocol/filter 命名改用 netns name；支持多 interface pattern |

#### 诊断输出

| 文件 | 变更 |
|------|------|
| `app/higgs/debug_routing.go` | `debug babel` 按 netns 展示，列出该 netns 下的 overlays |
| `app/higgs/diagnostics.go` | `debugLinkRoutingState()` 按 netns 查找 BIRD |
| `app/higgs/daemon.go` / `control.go` | `bird_status` 返回 netns-keyed instances |

#### 测试

| 文件 | 变更 |
|------|------|
| `app/higgs/routing_reconcile_test.go` | 断言改为 netns 维度 |
| `pkg/routing/bird/generator_test.go` | `OverlayID` → `NetNSName` |
| `app/higgs/debug_routing_test.go` | BIRD 实例查找改为 netns 维度 |

#### 文档

| 文件 | 变更 |
|------|------|
| `docs/design.md` | 更新 Phase 5 netns 章节 |
| `docs/phase5-route-record-design.md` | 更新配置示例 |

### 7.2 建议实现顺序

1. **`pkg/routing/bird/routerid.go`** — `StableRouterID` 改为 `(localZone, rootTrust, netnsName)`
2. **`pkg/routing/records.go`** — 新增 `routing.netns.v1` record 类型和解析
3. **`app/higgs/ipsec_publish.go`（或新文件）** — daemon 发布 `routing/netns` record
4. **`pkg/routing/bird/types.go` 和 `generator.go`** — `OverlayID` → `NetNSName`，支持多 interface pattern
5. **`pkg/transport/ipsec/link.go`** — 移除 `LinkGroupSpec.Routing`
6. **`app/higgs/config.go`** — 新配置模型解析
7. **`app/higgs/state.go`** — `BirdInstanceState` 字段和 key 含义
8. **`app/higgs/routing_reconcile.go`** — 核心 reconcile 逻辑按 netns 分组
9. **`app/higgs/debug_routing.go` / `diagnostics.go` / `daemon.go` / `control.go`** — 输出适配
10. **所有测试** — 断言改为 netns 维度
11. **`config.example.yaml` 和文档** — 更新
12. **扩展 smoke** — 多 overlay 共享 netns 场景
13. **（可选）per-peer import filter 基础框架**

### 7.3 影响范围统计

| 变更类型 | 文件数 | 预估改动量 |
|----------|--------|------------|
| 配置模型 | 2 | 大（config.go ~200 行变更） |
| 数据结构 | 4 | 中（types.go, link.go, state.go, routerid.go） |
| 核心逻辑 | 2 | 大（routing_reconcile.go, generator.go） |
| 诊断输出 | 4 | 中（debug_routing.go, diagnostics.go, daemon.go, control.go） |
| 测试 | 4+ | 大（routing_reconcile_test.go 1462 行需大量改写） |
| 配置/文档 | 4 | 中（config.example.yaml, design.md 等） |
| **总计** | ~20 文件 | **大型重构** |

### 7.4 风险与注意事项

1. **配置兼容性**：这是 breaking change。todo.md 明确要求移除旧配置，不做向后兼容。需要提供清晰的迁移文档。

2. **Interface pattern 合并**：同一 netns 下的多个 overlay 可能使用不同的 XFRM interface 命名前缀。BIRD config 需要支持多个 `interface "hgs*" { }` 段或合并为一个。

3. **State 迁移**：已持久化的 `BirdInstances`（overlay-keyed）需要迁移为 netns-keyed。简单方案是启动时清空旧实例状态，让 reconcile 重建。

4. **Import/Export filter**：改为 per-netns 后，需要合并同一 netns 下所有 overlay 的 import/export prefix set。

5. **preflight 版本检查**：应增强为检查 BIRD >= 2.0。

6. **StrongSwan 与 netns 的关系**：当前一个 higgs daemon 只连接一个 StrongSwan charon 实例（通过单个 VICI socket），因此 StrongSwan 能力是 per-node 的。netns 只决定 XFRM interface 创建在哪个 namespace。这与 BIRD 的 per-netns 模型不同，设计文档中应明确区分。

7. **path netns 的 Router-ID 标签**：path netns 没有稳定名称，必须要求配置中显式设置 `router_id_label`，否则无法生成稳定的 Router-ID 和 `routing/netns` record。

## 8. 与 Phase 5.3 per-peer import whitelist 的关系

**⚠️ 原计划 per-peer import filter 因多跳传播问题已废弃。**

`todo.md` Phase 5.3 中的 `[ ] per-peer/interface import whitelist` 在 Babel 距离向量协议下不可行（见 6.3 节分析）。该任务应重新定义为：

- ~~per-peer/interface import whitelist~~ → **控制面交叉审计**（Phase 7 后续）：daemon 定期从 `birdc show route all` 读取路由、通过 Router-ID 验证来源、flush 恶意宣告

Phase 5.7 的安全模型保持为：
1. 全局 import filter（BIRD 层面，已实现）— 拒绝未授权前缀
2. Zone 签名链（已实现）— 保证 IPAM/announcement 真实性
3. 控制面交叉审计（Phase 7 后续待实现）— 检测并 flush 恶意宣告

## 9. Future Compatibility

### 9.1 IPv6 Source Routing（SRv6 / Segment Routing）

per-netns BIRD 模型不排斥未来引入 IPv6 Source Routing。SRv6 的部署单位仍然是节点/接口/netns，一个 netns 内的 BIRD 实例可以同时维护 Babel 路由和 SRv6 SID 路由。

未来需要新增的能力：
- 新增 `routing/srv6/*` records（如 SID、segment list、policy）
- BIRD config 生成 SRv6 static routes 或扩展 protocol
- 可能依赖较新 BIRD 版本或 patch

Router-ID 推导不需要改变。

### 9.2 Anycast / 多节点同 IP 高可用

从 Babel 协议层面看，当前设计可以支持多个节点宣告同一前缀：每个节点有独立的 Router-ID（因 `localZone` 不同），Babel 会把它们作为不同来源处理，ECMP 可以实现负载均衡，节点失效后路由撤回实现故障切换。

**但当前 Phase 6 IPAM 设计禁止多个 Zone 持有重叠 assignment**，因此 Anycast 在 IPAM 授权链上无法通过。需要未来在 IPAM 层引入 shared/anycast assignment 语义，例如：
- 新增 `ipam.anycast` 或 `assignment.shared` 字段
- 允许同一前缀分配给多个 Zone，但这些 Zone 必须被共同策略显式授权

详见 `docs/phase6-ipam-design.md` 后续补充。

### 9.3 Multicast

真正的多播路由（如 `ff02::/16`）超出 Babel 单播路由范围，未来需要叠加 PIM-SM/MLD 等协议。per-netns BIRD 模型不阻碍这种扩展。
