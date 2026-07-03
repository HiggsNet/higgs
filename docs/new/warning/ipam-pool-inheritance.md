# IPAM Pool 继承漏洞与严格模型设计

> **发现日期：2026-07-03 | 更新日期：2026-07-03**

## 问题描述

当 root zone（`.`）创建一个 `delegated_to: "."` 的 IPAM pool 时，任何子 zone 都可以绕过明确的 pool delegation，直接用这个 pool 来做 assign。

这不是显示问题——是真能被这样用。`higgs ipam mine` 里显示 `usable_by_managed_zone` 反而是诚实的，因为代码真允许这么干。

## 适用范围：任意父子层级

问题不是根节点特有的，**任意父子节点之间都有这个问题**。

假设 zone `parent.` 有一个 pool，`delegated_to: "parent."`，则所有子孙 zone 都能直接用这个 pool 做 assign：

```
parent. pool: 10.0.0.0/8,  delegated_to: "parent."
  → 能被 child.parent. 用 ✓（bug）
  → 能被 grandchild.child.parent. 用 ✓（bug）
```

### 影响矩阵

| Pool 所在 zone | delegated_to | 能绕过委托直接用这个 pool 的 zone |
|---|---|---|
| `.` | `.` | 所有 zone |
| `catofes.` | `catofes.` | `catofes.` 所有子孙 |
| `pek.catofes.` | `pek.catofes.` | `pek.catofes.` 所有子孙 |
| `pek.catofes.` | `catofes.` | `catofes.` 所有子孙 |

## 根因

[`pkg/routing/authorization.go:283`](pkg/routing/authorization.go#L283)

```go
func isAssignmentPoolValid(ars *AuthorizedRouteSet, ns *zone.NetworkState, assignment *AssignmentEntry) bool {
    z := assignment.Source
    for _, ancestor := range z.Ancestors() {
        for _, pool := range ars.Pools {
            if pool.Source != ancestor { continue }
            if !containsPrefix(pool.Prefix, assignment.Prefix) { continue }
            if IsZoneAncestor(pool.DelegatedTo, z) {     // ← 问题：隐式继承
                return true
            }
        }
    }
    return false
}
```

`IsZoneAncestor` 只做 zone 路径字符串比较（[authorization.go:212](pkg/routing/authorization.go#L212)），不看 delegation 记录。当 `pool.DelegatedTo = "."` 时，它对**任何** `z` 都返回 true。

### 同步问题：`localIPAMPoolRelation`

[`app/higgs/ipam.go:587`](app/higgs/ipam.go#L587) 用了同样的 `IsZoneAncestor` 判断，导致 `mine` 命令显示 `usable_by_managed_zone`。

## 现存冲突检测为什么没拦住

三层流水线用**不同的授权语义**造成了不一致：

| 层 | 函数 | 授权检查 | 结果 |
|---|---|---|---|
| Layer 1 (Pool 校验) | `isAssignmentPoolValid` | `IsZoneAncestor` — 隐式继承 | ❌ 绕过 |
| Layer 2 (Assignment 重叠) | `isAssignmentOverlapAllowed` | `IsInDelegationChain` — 严格链检查 | ✅ 拦住兄弟姐妹碰撞 |
| Layer 3 (路由重叠) | `resolveOverlaps` | `IsInDelegationChain` — 严格链检查 | ✅ 拦住兄弟姐妹碰撞 |

Layer 2 和 Layer 3 用 `IsInDelegationChain` 挡住了最极端的情况（两个 sibling 同时从 root pool 里 assign 同一个地址段），但结构性问题还在：

1. **授权在前，冲突检测在后**——记录被创建了才被拒绝，不优雅
2. **父子重叠不会被拦住**——`IsInDelegationChain` 对父子返回 true
3. **没有主动地址划分机制**——只有"先写先得"，没有 partition/配额/谁拿哪一段的约定

## 修正方案：严格所有权模型（推荐）

### 核心原则

`delegated_to` 的语义从当前模糊的"谁可以用"改为精确的**"谁拥有这个地址段"**。

**一个 zone 能做以下事情的前提是它精确拥有（`delegated_to == z`）一个覆盖目标前缀的 pool：**

| 操作 | 前提 | 效果 |
|---|---|---|
| 创建 pool (委托子池) | zone 拥有覆盖新 pool 的更大 pool | 子 zone 获得这个子段的所有权 |
| assign 地址 | zone 拥有覆盖 assignment 的 pool | 目标 zone 可以使用该地址（不可再分发） |

**关键区分：** assign 的 `--to` 目标没有限制。只要 zone `.` 拥有 pool，它可以把地址 assign 给 `pek.catofes.` 甚至 `deep.pek.catofes.`——这就是**跨层 assign**。Pool 校验检查的是 **assign 的 source zone 是否拥有覆盖 pool**，而不是 target zone。

```
严格模型示例：

.       创建 pool 10.0.0.0/8,  delegated_to: "."         → . 拥有 /8
.       创建 pool 10.0.0.0/16, delegated_to: "catofes."  → catofes. 拥有 /16
catofes.创建 pool 10.0.1.0/24, delegated_to: "pek.catofes." → pek.catofes. 拥有 /24

跨层 assign（无需中间 pool）：
.       assign 10.0.0.1/32 --to server.deep.pek.catofes.  → ✓ . 拥有 /8
catofes. assign 10.0.1.0/24 --to server.pek.catofes.     → ✓ catofes. 拥有 /16
```

### `isAssignmentPoolValid` 修改

```go
func isAssignmentPoolValid(ars *AuthorizedRouteSet, ns *zone.NetworkState, assignment *AssignmentEntry) bool {
    z := assignment.Source
    for _, ancestor := range z.Ancestors() {
        for _, pool := range ars.Pools {
            if pool.Source != ancestor {
                continue
            }
            if !containsPrefix(pool.Prefix, assignment.Prefix) {
                continue
            }
            // 严格所有权：只有 pool 精确委托给当前 zone 才可用
            if pool.DelegatedTo == z {
                return true
            }
        }
    }
    return false
}
```

`z.Ancestors()` 循环保留——pool 可能发布在 `.` 而 `delegated_to: "catofes."`，`catofes.` 需要能通过祖先 `.` 找到这个 pool。但 `pool.DelegatedTo == z` 确保了只有被精确命名的 zone 能用。

### `localIPAMPoolRelation` 修改

去掉 `usable_by_managed_zone` 这个模糊分类。三种关系归为两种：

```go
func localIPAMPoolRelation(entry *routing.PoolEntry, managed zone.ZonePath) []string {
    var relation []string
    if entry.Source == managed {
        relation = append(relation, "published_by_managed_zone")
    }
    if entry.DelegatedTo == managed {
        relation = append(relation, "delegated_to_managed_zone")
    }
    // 不再有 usable_by_managed_zone——delegated_to 就是精确所有权
    return relation
}
```

### pool 创建也加上覆盖校验

当前 `createIPAMPool` 只检查 `allocate-ip` capability，不检查调用者是否拥有覆盖 pool。应同步修复：

```go
func createIPAMPoolWithRuntime(rt *Runtime, path zone.ZonePath, prefix string, delegatedTo zone.ZonePath) error {
    // 1. 权限检查（保留）
    // 2. 覆盖校验：path 必须拥有一个覆盖 prefix 的池
    //    即存在 pool: source=某祖先, delegated_to=path, prefix 覆盖新 pool
    // 3. 执行写入
}
```

这里有个细节：如果 `path ！= delegatedTo`（为子 zone 创建池），覆盖校验应该用 `path` 而不是 `delegatedTo`——是**创建者**需要有覆盖池，不是子 zone。

## 设计约束

严格模型下，需要三个约束来保证地址空间的一致性和可审计性。

### 1. 前缀重叠必须有明确语义

Pool 记录的 `source` 表示"这条记录由谁发布"，`delegated_to` 表示"这个地址段由谁拥有"。因此，同一 source zone 内允许出现父池和子池重叠，但这个重叠必须表达清楚的所有权切分：创建者拥有覆盖父池，并把其中一个子段委托给另一个 owner。

不允许的是多个 owner 在同一地址空间上产生冲突，或 pool 与 assignment 抢同一段地址。

| 场景 | 约束 | 示例（source=`.`） |
|---|---|---|
| Pool vs Pool | 允许 owner 从自己拥有的覆盖 pool 中切出子 pool；拒绝 sibling/unrelated owner 的重叠 | ✅ `10.0.0.0/8 DT=.` + `10.0.0.0/16 DT=catofes.`<br>❌ `10.0.0.0/16 DT=catofes.` + `10.0.0.0/24 DT=other.`<br>✅ `10.0.0.0/16 DT=catofes.` + `10.16.0.0/16 DT=other.` |
| Assignment vs Assignment | 不允许前缀重叠，除非两者都是 Shared（anycast）或 `AssignedTo` 存在层级关系 | ❌ `10.0.1.0/24 →foo.` + `10.0.1.0/24 →bar.`<br>✅ `10.0.1.0/24 →pek.catofes.` + `10.0.1.0/24 Shared →bar.`（anycast） |
| Pool vs Assignment | 不允许前缀重叠——assign 出去的地址段不应再被作为 pool 委托，反之亦然 | ❌ `10.0.1.0/24 DT=catofes.` + `10.0.1.0/24 →server.foo.` |

**Pool 重叠的含义：** 重叠本身不是问题；问题是重叠是否表达了合法的所有权转移。`. DT=.` 的 `/8` 与 `. DT=catofes.` 的 `/16` 是合法的父池切子池。`. DT=catofes.` 的 `/16` 与 `. DT=other.` 的 `/24` 是冲突，因为 `other.` 没有从 `catofes.` 拿到这段地址的所有权。

跨层继续切分时，下一层应由当前 owner 发布新 pool。例如 `. → catofes.` 后，如果要把 `10.0.1.0/24` 给 `pek.catofes.`，应由 `catofes.` 创建：

```
catofes. pool: 10.0.1.0/24, delegated_to: "pek.catofes."
```

### 2. 最细粒度不需要再分

`/32`（IPv4）或 `/128`（IPv6）是最小分配单位。拥有 `/32` 的 zone 可以完整地把它 assign 出去，不需要子划分为 `/33`。

这由 `containsPrefix` 保证——`outer.Bits() > inner.Bits()` 仅在 outer 更短时失败，`/32` contains `/32` 返回 true。

### 3. Anycast 例外：允许重叠

标记为 `Shared=true` 的 assignment 用于 anycast。多个 zone 可以持有相同的 anycast IP，由 Babel ECMP 做多路径负载均衡。

在重叠检测中，如果两个 assignment 都是 `Shared=true`，允许任意程度的重叠——包括完全相同的 prefix、不同 source zone、不同 assigned_to。

这是 BGP anycast / DNS anycast 等场景的基础能力，现有代码的 `isAssignmentOverlapAllowed` 第一行已经处理了这个逻辑，严格模型保留不动。

### 约束的实现层次

上述约束需要在两个层次落地：

1. **写入时检查（CLI/higgs ipam create/assign）：** 在记录写入本地 state 前做一次快速检查，尽早拒绝明显冲突的操作。不要求覆盖所有场景（比如跨 zone 的冲突需要全局状态）。
2. **Reconciliation 时检查（`BuildAuthorizedRouteSet`）：** 保底的全面校验，覆盖所有跨 zone 场景。写入时没拦住的这里会被拒绝并报错。

## 具体实现设计

### 数据结构调整

当前 `AuthorizedRouteSet.Pools map[netip.Prefix]*PoolEntry` 只能按 prefix 保留一个 pool。严格模型需要同时分析同 prefix / 重叠 prefix / 不同 source / 不同 `delegated_to` 的多条 pool 记录，因此需要增加完整列表：

```go
type AuthorizedRouteSet struct {
    ...
    Pools    map[netip.Prefix]*PoolEntry // 保留代表项，兼容现有读路径
    AllPools []*PoolEntry                 // 所有通过 pool validation 的 pool
}
```

`pendingPools` 收集后先进入 pool validation；只有 valid pool 才进入 `AllPools` 和 `Pools`。后续 assignment validation 必须遍历 `AllPools`，不能只查 prefix map。

### Pool validation 顺序

Pool validation 应在 assignment validation 前执行：

1. 收集 active pool / active assignment / active route announcement。
2. 校验 pool ownership 与 pool-overlap，生成 `validPools`。
3. 用 `validPools` 校验 assignment 是否由 source 精确拥有的覆盖 pool 支撑。
4. 校验 assignment overlap。
5. 用 valid assignment 授权 route announcement。
6. 校验 route overlap。

### Pool ownership 规则

一条 active pool 记录 `P` 合法，当且仅当：

1. `P.Source` 有权发布该 record：现有 signed state / authority / `allocate-ip` capability 继续负责。
2. `P.Source == "." && P.DelegatedTo == "."` 时允许作为 root bootstrap pool。它没有上级 owner，是地址空间根声明。
3. 其他 pool 必须存在一个已经合法的 covering owner pool：
   - `cover.DelegatedTo == P.Source`
   - `containsPrefix(cover.Prefix, P.Prefix)`
   - `cover` 不是 `P` 自身

这个规则表达的是：只有当前 owner 才能从自己拥有的地址段里切出子 pool。root 给 `catofes.` 切 `/58` 前，root 自己必须已经有覆盖 `/58` 的 root-owned pool；`catofes.` 再给 `pek.catofes.` 切 `/64` 前，`catofes.` 必须已经通过 root pool 记录拥有覆盖 `/64` 的地址段。

实现上可用固定点迭代，而不是递归：

```go
valid := map[*PoolEntry]bool{}
for changed := true; changed; {
    changed = false
    for _, pool := range pendingPools {
        if valid[pool] {
            continue
        }
        if isRootBootstrapPool(pool) || hasValidCoveringOwnerPool(valid, pendingPools, pool) {
            valid[pool] = true
            changed = true
        }
    }
}
```

迭代结束后仍 invalid 的 pool 记录加入 error，code 建议为 `ipam_pool_owner_mismatch`。

### Pool overlap 规则

Pool ownership 合法之后，再检查 pool 之间的重叠：

1. 不重叠：允许。
2. 一个 pool 包含另一个 pool，包括 prefix 完全相同：
   - 如果外层/父 pool 的 `DelegatedTo == 内层/子 pool.Source`，允许。这是 owner 切子池或把整个 pool 显式委托给下一层 owner。
   - 否则拒绝，code `ipam_pool_overlap`。
3. 两个 pool 部分重叠但互不包含：拒绝，code `ipam_pool_overlap`。

示例：

```
. pool 10.0.0.0/8  DT=.          ✓ root bootstrap
. pool 10.0.0.0/16 DT=catofes.   ✓ . 从自己的 /8 切给 catofes.
. pool 10.0.0.0/8  DT=catofes.   ✓ . 把整个 /8 显式委托给 catofes.
catofes. pool 10.0.1.0/24 DT=pek.catofes. ✓ catofes. 从自己的 /16 切给 pek

. pool 10.0.0.0/16 DT=catofes.
. pool 10.0.0.0/24 DT=other.     ✗ other. 没有从 catofes. 获得覆盖 ownership
. pool 10.0.0.0/16 DT=catofes.
. pool 10.0.0.0/16 DT=other.     ✗ sibling owner 抢同一段
```

当一条 pool 因 overlap 被拒绝时，它不应进入 `AllPools`，也不应支撑后续 assignment。

### Assignment ownership 规则

`isAssignmentPoolValid` 改成精确 owner 检查：

```go
func isAssignmentPoolValid(ars *AuthorizedRouteSet, assignment *AssignmentEntry) bool {
    for _, pool := range ars.AllPools {
        if pool.DelegatedTo != assignment.Source {
            continue
        }
        if containsPrefix(pool.Prefix, assignment.Prefix) {
            return true
        }
    }
    return false
}
```

`assignment.AssignedTo` 不参与 pool ownership 校验。它只表示这个 assignment 给谁使用；root / parent 可以跨层 assign 给任意 leaf，但前提是 assignment 的 source 精确拥有覆盖 pool。

### Assignment overlap 规则

现有 `isAssignmentOverlapAllowed` 可以保留第一版语义：

- 两边都是 `Shared=true`：允许 anycast overlap。
- 同 source 且 `AssignedTo` 存在父子关系：允许层级 assignment。
- 不同 source 时要求 prefix containment 且 source 在 delegation chain 内。

严格 pool ownership 修复的是“谁能从哪个 pool 发 assignment”；assignment overlap 仍是“多个 assignment 之间能否共存”。这两个层次不要合并，否则会误伤跨层 assign 和 anycast。

### CLI 写入前检查

`app/higgs/ipam.go` 的写入前检查分两层：

- `createIPAMPoolWithRuntime`：在 `submitIPAMRecord` 前加载 state，基于当前 state + 待写 pool 做一次 pool validation dry-run；拒绝明显的 owner mismatch / pool overlap。
- `assignIPAMWithRuntime`：基于当前 state + 待写 assignment 做一次 authorized route set dry-run；拒绝 `ipam_assignment_pool_mismatch` / `ipam_assignment_overlap`。

CLI 检查只是早失败体验；最终正确性仍以 `BuildAuthorizedRouteSet` 为准，因为 offline root import、历史记录、daemon single-writer 和跨 zone 同步都可能绕过本地 CLI。

### `higgs ipam mine` 输出

`localIPAMPoolRelation` 删除 `usable_by_managed_zone`。严格模型下只保留：

- `published_by_managed_zone`：这条 pool record 由本 managed zone 发布。
- `delegated_to_managed_zone`：这段地址由本 managed zone 精确拥有，可用于继续切子池或 assign。

如果一个 ancestor pool 只是 `delegated_to` ancestor，不再显示为本 zone usable。

### `higgs ipam get <addr block>` 诊断命令

新增只读诊断命令：

```
higgs ipam get <addr-or-prefix>
```

`<addr-or-prefix>` 可以是单个地址或 CIDR prefix：

- `higgs ipam get 10.212.0.42`
- `higgs ipam get 10.212.0.0/24`
- `higgs ipam get 2a0d:2905::1`
- `higgs ipam get 2a0d:2905::/64`

命令目标是回答三个问题：

1. 这个地址/地址段来自哪个 pool。
2. 它的 pool ownership / delegation chain 是什么。
3. 当前是否已经 assignment，分配给了谁，以及是否有 route announcement。

实现应基于 `BuildAuthorizedRouteSet` 的结果，不直接遍历 raw records 得出结论。这样 `ipam get` 展示的是已经通过严格模型校验后的授权事实；invalid pool / invalid assignment 只作为 diagnostics 展示，不作为有效来源。

#### 查询匹配规则

输入归一化为 `netip.Prefix`：

- 单个 IPv4 地址视为 `/32`。
- 单个 IPv6 地址视为 `/128`。
- CIDR prefix 先 masked 成 canonical prefix。

匹配时按最长前缀优先：

1. 在 valid `AllPools` 中找所有覆盖 input prefix 的 pool，按 prefix bits 从长到短排序。
2. 在 valid `AllAssignments` 中找所有覆盖 input prefix 或被 input prefix 覆盖的 assignment：
   - 地址查询通常找 covering assignment。
   - prefix 查询既要显示覆盖它的 assignment，也要显示它下面更具体的 assignment，方便看一个 pool 内已经切给谁。
3. 在 authorized route announcements 中找与 input prefix 相同、覆盖 input prefix、或被 input prefix 覆盖的 route。
4. 在 `AuthorizedRouteSet.Errors` 中筛出同 prefix、覆盖 input prefix、或被 input prefix 覆盖的 IPAM 相关错误，作为 `diagnostics`。

#### 输出形态

默认 CLI 输出必须是 human-readable 文本，适合直接在终端排查；同时提供 `--json` 输出，便于测试、脚本和后续 Observer 复用同一套结构化 view。

默认文本示例：

```text
query: 10.212.0.42/32

pool chain:
  10.212.0.0/14  source=.         delegated_to=.          relation=root_owner
  10.212.0.0/18  source=.         delegated_to=catofes.   relation=delegated

best pool:
  10.212.0.0/18  source=.  delegated_to=catofes.

assignment:
  10.212.0.42/32  source=catofes.  assigned_to=node-a.catofes.

routes:
  10.212.0.42/32  source=node-a.catofes.

diagnostics: none
```

`--json` 示例：

```json
{
  "query": "10.212.0.42/32",
  "pool_chain": [
    {
      "prefix": "10.212.0.0/14",
      "source": ".",
      "delegated_to": ".",
      "relation": "root_owner"
    },
    {
      "prefix": "10.212.0.0/18",
      "source": ".",
      "delegated_to": "catofes.",
      "relation": "delegated"
    }
  ],
  "best_pool": {
    "prefix": "10.212.0.0/18",
    "source": ".",
    "delegated_to": "catofes."
  },
  "assignments": [
    {
      "prefix": "10.212.0.42/32",
      "source": "catofes.",
      "assigned_to": "node-a.catofes.",
      "shared": false
    }
  ],
  "assigned_to": "node-a.catofes.",
  "routes": [
    {
      "prefix": "10.212.0.42/32",
      "source": "node-a.catofes."
    }
  ],
  "diagnostics": []
}
```

字段语义：

| 字段 | 含义 |
|---|---|
| `query` | canonical 查询 prefix；单地址也显示为 `/32` 或 `/128` |
| `pool_chain` | 从最宽 owner pool 到最具体 covering pool 的有效授权链 |
| `best_pool` | 最具体的 covering pool；没有时为 `null` |
| `assignments` | 与查询相关的有效 assignment；地址查询通常最多一个，anycast 可多个 |
| `assigned_to` | 非 shared 且唯一 assignment 时的快捷字段；无或多值时为 `null` |
| `routes` | 与查询相关的 authorized route announcement |
| `diagnostics` | IPAM 相关错误，如 owner mismatch、pool overlap、assignment mismatch |

如果查询地址只有 pool、没有 assignment，默认文本应明确显示未分配：

```text
query: 10.212.0.42/32

best pool:
  10.212.0.0/18  source=.  delegated_to=catofes.

assignment: none
routes: none

diagnostics:
  ipam_unassigned  no assignment covers 10.212.0.42/32
```

对应 `--json`：

```json
{
  "query": "10.212.0.42/32",
  "best_pool": {
    "prefix": "10.212.0.0/18",
    "source": ".",
    "delegated_to": "catofes."
  },
  "assignments": [],
  "assigned_to": null,
  "routes": [],
  "diagnostics": [
    {
      "code": "ipam_unassigned",
      "detail": "no assignment covers 10.212.0.42/32"
    }
  ]
}
```

如果查询地址没有任何 valid pool，默认文本应直接给出 no pool：

```text
query: 10.99.0.1/32

pool chain: none
best pool: none
assignment: none
routes: none

diagnostics:
  ipam_no_pool  no valid pool covers 10.99.0.1/32
```

对应 `--json`：

```json
{
  "query": "10.99.0.1/32",
  "pool_chain": [],
  "best_pool": null,
  "assignments": [],
  "assigned_to": null,
  "routes": [],
  "diagnostics": [
    {
      "code": "ipam_no_pool",
      "detail": "no valid pool covers 10.99.0.1/32"
    }
  ]
}
```

`ipam get` 与 `debug route` 的边界：

- `higgs ipam get` 从 IPAM 视角解释地址来源、pool 授权链和 assignment。
- `higgs debug route` 从路由视角解释某个 prefix 是否被 route authorization 接受、BIRD 是否学习/安装、为什么被拒绝。

### 错误码与诊断

建议新增或明确以下 error code：

| Code | 含义 |
|---|---|
| `ipam_pool_owner_mismatch` | pool source 没有覆盖该 prefix 的 owner pool，且不是 root bootstrap pool |
| `ipam_pool_overlap` | pool 与其他 valid pool 产生非法重叠 |
| `ipam_assignment_pool_mismatch` | assignment source 没有精确拥有覆盖 assignment prefix 的 pool |
| `ipam_assignment_overlap` | assignment 与其他 assignment 非法重叠 |
| `ipam_no_pool` | `ipam get` 查询没有任何 valid pool 覆盖 |
| `ipam_unassigned` | `ipam get` 查询有 pool 但没有 valid assignment 覆盖 |

`debug routes` / `higgs ipam assigned` 后续可以展示这些 code；第一版至少保证 `BuildAuthorizedRouteSet.Errors` 可见。

### 测试设计

核心单测放在 `pkg/routing/authorization_test.go`：

1. `TestIPAMPoolRootBootstrapValid`：`. DT=.` root pool 合法。
2. `TestIPAMPoolDelegationRequiresOwnedCoveringPool`：没有 owner covering pool 时，`. DT=catofes.` 子池非法。
3. `TestIPAMPoolDelegationFromOwnedPoolValid`：root `/8 DT=.` + root `/16 DT=catofes.` 合法。
4. `TestIPAMPoolNestedDelegationFromCurrentOwnerValid`：root `/16 DT=catofes.` + `catofes. /24 DT=pek.catofes.` 合法。
5. `TestIPAMPoolSiblingOverlapRejected`：root `/16 DT=catofes.` + root `/24 DT=other.` 拒绝。
6. `TestIPAMAssignmentDoesNotInheritAncestorPool`：root `/8 DT=.` 时，`catofes.` 直接 assign `/24` 被拒绝。
7. `TestIPAMAssignmentUsesExplicitDelegatedPool`：root `/16 DT=catofes.` 时，`catofes.` assign `/24` 合法。
8. `TestIPAMMineNoUsableAncestorPool`：`higgs ipam mine` 不再输出 `usable_by_managed_zone`。
9. `TestIPAMGetExplainsPoolChainAndAssignment`：`higgs ipam get <addr>` 返回 pool chain、best pool、assignment 和 assigned_to。
10. `TestIPAMGetReportsUnassignedAddress`：有 pool 但没有 assignment 时返回 `ipam_unassigned`。
11. `TestIPAMGetReportsNoPool`：无 valid covering pool 时返回 `ipam_no_pool`。

CLI 层测试放在 `app/higgs/ipam_test.go` 或现有相关测试文件：

1. `createIPAMPoolWithRuntime` 拒绝没有 covering owner pool 的子池。
2. `assignIPAMWithRuntime` 拒绝隐式继承 assignment。
3. root bootstrap pool 仍可创建。
4. offline root export/import 相关测试保持通过，确保 root-owned pool 迁移不被 CLI-only 逻辑误判。
5. `higgs ipam get` 的默认文本输出有 golden 覆盖，`--json` 输出结构稳定；两者都覆盖地址查询、prefix 查询、anycast/shared assignment 和 error diagnostics。

验证命令优先使用 focused lane：

```
GOCACHE=/tmp/higgs-gocache GOMODCACHE=/tmp/higgs-gomodcache go test ./pkg/routing ./app/higgs -run 'Test(IPAM|Pool|Assignment|Recovery|Authority)'
```

最后再跑：

```
make check
```

## 当前实例的影响

看实际输出：

```
root pool: 10.212.0.0/14,  source=".", delegated_to="."   ← 修复后仅 `.` 可用
root pool: 10.212.0.0/18,  source=".", delegated_to="catofes."  ← 不变，catofes. 精确拥有
root pool: 2a0d:2905::/32, source=".", delegated_to="."   ← 修复后仅 `.` 可用
root pool: 2a0d:2905::/58, source=".", delegated_to="catofes."  ← 不变
```

如果需要让 `catofes.` 也能使用 `10.212.0.0/14`，需要显式创建：

```
higgs ipam pool create . 10.212.0.0/14 --delegated-to catofes.
```

## 迁移策略

从旧模型过渡到严格模型：

```
旧模型：. pool 10.0.0.0/8, delegated_to="."
  → 被 catofes. / pek.catofes. 隐式继承使用

迁移到严格模型：
1. root 为每个子 zone 创建显式 delegation pool
   higgs ipam pool create . 10.0.0.0/16 --delegated-to catofes.
   higgs ipam pool create . 10.16.0.0/16 --delegated-to other.

2. 发布修复后的代码
3. 隐式继承不再生效，但显式 delegation 已经就位
```

## 为什么选严格模型

| | 隐式继承（当前） | 严格模型（方案） |
|---|---|---|
| 授权粒度 | "祖先的 pool 全能用" | "精确所有权，显式声明" |
| Pool 语义 | 模糊（祖先开放→子孙可用） | 精确（`delegated_to`=所有者） |
| 冲突检测一致性 | Layer 1 vs Layer 2/3 不一致 | 统一校验语义 |
| 地址空间管控 | 无主动划分 | 每一层可精确控制 |
| 跨层 assign | ✅ 支持 | ✅ 支持 |
| 运维成本 | 低（一个 pool 全树可用） | 高一些（每层显式创建） |
| 审计/追溯 | 难（隐式继承无记录） | 易（每笔授权都有记录） |

严格模型修复了`delegated_to`的语义模糊——它不再同时表示"对外开放起点"和"精确所有者"，变成只表示"精确所有者"。跨层 assign 天然支持，因为 pool 校验只看 assign 的 source zone 的所有权，不限制 target zone。
