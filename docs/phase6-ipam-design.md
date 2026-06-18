# Phase 6.1 IPAM 闭环设计

相关设计：

- Phase 6.3 firewall 规则同步见 [phase6-firewall-design.md](phase6-firewall-design.md)。Firewall planner 消费本文件定义的 `AuthorizedRouteSet`、`AllAssignments`、route announcements 和 anycast/shared assignment 派生结果。

## 1. 目标

补齐 Phase 5 路由授权中未完成的 IPAM 语义，实现：

- `ipam/pools/*` 对 `ipam/assignments/*` 的强制 enforcement。
- `ipam/assignments/*` 之间的重叠冲突检测。
- 一阶 `higgs ipam` CLI，替代手工拼 `record put`。
- 节点自查询本 Zone 分配到的 IP，并可选自动发布 `routes/announcements/*`。

## 2. 核心原则

- **pool 是分配权，assignment 是使用权，两者严格分离。**
  - 持有 pool 的 Zone 可以写 assignment，也可以把 pool 继续委派给子 Zone。
  - assignment 获得者只能自己用或宣告，**默认不能再继续细分**，除非它另外持有覆盖该前缀的 pool。
- **路由宣告必须被 assignment 授权，assignment 必须被 pool 授权。**
- **重叠检测在 IPAM 层完成**，不要把冲突留到路由层才发现。

## 3. 三层模型

```
ipam/pools/*           → 地址空间分配权委派（谁能分）
ipam/assignments/*     → 具体前缀使用权分配（分给谁用）
routes/announcements/* → 被授权 Zone 宣告前缀可达
```

## 4. Record Schema

### 4.1 ipam.pool

- **Key**: `ipam/pools/<canonical_prefix_with_underscore>`
- **Type**: `ipam.pool`
- **Value**:

```json
{
  "version": 1,
  "prefix": "10.0.0.0/16",
  "delegated_to": "pek.catofes."
}
```

**语义**：Zone Z 声明前缀 `prefix` 的分配权属于 `delegated_to` 这个 Zone 及其子树。

**例子**：

```
. (根)
└── ipam/pools/fd00::/48 → delegated_to: catofes.
        ← 根把 fd00::/48 的分配权委派给 catofes.

catofes.
└── ipam/pools/fd00:1234::/56 → delegated_to: pek.catofes.
        ← catofes 继续把其中一块分派给 pek
```

### 4.2 ipam.assignment

- **Key**: `ipam/assignments/<canonical_prefix_with_underscore>`
- **Type**: `ipam.assignment`
- **Value**:

```json
{
  "version": 1,
  "prefix": "10.0.0.0/24",
  "assigned_to": "node1.pek.catofes."
}
```

**语义**：Zone Z 把前缀 `prefix` 的使用权分配给 `assigned_to`。assignment 是终端授权，获得者不能继续细分，除非它另外持有覆盖该前缀的 pool。

**例子**：

```
pek.catofes.
└── ipam/assignments/fd00:1234::/64 → assigned_to: node1.pek.catofes.
        ← pek 把具体 /64 分配给 node1
```

### 4.3 route.announcement

沿用 Phase 5 设计，不再赘述。

## 5. Pool Enforcement 规则

Zone Z 下的 `ipam/assignments/<prefix>` 有效，当且仅当存在 Z 或 Z 的某个祖先 Zone A 的 `ipam/pools/<pool_prefix>`，满足：

1. `pool_prefix` 包含 `prefix`（pool 更大或相等）。
2. pool 的 `delegated_to` 是 Z 或 Z 的祖先（即分配权被委派到了 Z 所在的子树）。

否则该 assignment 无效，记录错误 `ipam_assignment_pool_mismatch`。

**合法示例**：

```
catofes.
├── ipam/pools/10.0.0.0_16 → delegated_to: pek.catofes.
│
pek.catofes.
└── ipam/assignments/10.0.0.0_24 → assigned_to: node1.pek.catofes.

验证：
- assignment 所在 Zone = pek.catofes.
- 祖先 catofes. 的 pool 10.0.0.0/16 覆盖 10.0.0.0/24
- pool.delegated_to = pek.catofes.，等于 assignment 所在 Zone
- 合法
```

**非法示例**：

```
catofes.
├── ipam/pools/10.0.0.0_16 → delegated_to: pek.catofes.
│
sh.catofes.
└── ipam/assignments/10.0.0.0_24 → assigned_to: node1.sh.catofes.

验证：
- assignment 所在 Zone = sh.catofes.
- catofes. 的 pool 10.0.0.0/16 覆盖 10.0.0.0/24
- 但 pool.delegated_to = pek.catofes.，不是 sh.catofes. 的祖先
- 非法 → ipam_assignment_pool_mismatch
```

## 6. Assignment 重叠检测规则

### 6.1 同 Zone 内

同一个 Zone Z 下的两条 assignment，如果前缀重叠：

- **合法**：其中一条的 `assigned_to` 是另一条的 `assigned_to` 的祖先 Zone（层级分配）。
- **非法**：否则，记录 `ipam_assignment_overlap`。

**合法示例**：

```
catofes.
├── ipam/pools/10.0.0.0_16 → delegated_to: catofes.
├── ipam/assignments/10.0.0.0_16 → assigned_to: pek.catofes.
└── ipam/assignments/10.0.1.0_24 → assigned_to: sh.catofes.
    ← sh.catofes. 是 pek.catofes. 的子 Zone

验证：
- 两条 assignment 都在 catofes. 下
- 10.0.0.0/16 包含 10.0.1.0/24
- sh.catofes. 是 pek.catofes. 的后代
- 合法（解释：pek 拿大段，其中一小段由 catofes 直接指定给 sh）
```

**非法示例**：

```
catofes.
├── ipam/assignments/10.0.1.0_24 → assigned_to: pek.catofes.
└── ipam/assignments/10.0.1.0_24 → assigned_to: sh.catofes.
    ← pek 和 sh 都是 catofes. 的直接子 Zone

验证：
- 前缀完全相同，属于重叠
- pek 和 sh 是兄弟关系
- 非法 → ipam_assignment_overlap
```

### 6.2 跨 Zone

不同 Zone 下的两条 assignment，如果前缀重叠：

- **合法**：两个 Zone 在同一条委派链上（祖先/后代关系），且前缀是包含关系。
- **非法**：否则，记录 `ipam_assignment_overlap`。

**合法示例**：

```
catofes./ipam/assignments/10.0.0.0_16 → assigned_to: pek.catofes.
pek.catofes./ipam/assignments/10.0.1.0_24 → assigned_to: node1.pek.catofes.

验证：
- 两个 Zone 是父子关系
- 10.0.0.0/16 包含 10.0.1.0/24
- 合法
```

**非法示例**：

```
pek.catofes./ipam/assignments/10.0.1.0_24 → assigned_to: node1.pek.catofes.
sh.catofes./ipam/assignments/10.0.1.0_24 → assigned_to: node1.sh.catofes.

验证：
- pek 和 sh 都是 catofes. 的子 Zone，互相不是祖先/后代
- 前缀完全相同
- 非法 → ipam_assignment_overlap
```

## 7. Route Announcement 重叠 vs IPAM Assignment 重叠

| 场景 | IPAM assignment | Route announcement |
|---|---|---|
| 同 Zone 包含关系 | 仅允许层级（父→子） | 允许（父聚合、子具体） |
| 跨 Zone 包含关系 | 仅允许祖先/后代链 | 仅允许祖先/后代链 |
| 兄弟 Zone 重叠 | 非法 | 非法 |

区别在于：assignment 是“授权谁可以用”，必须严格避免权限冲突；announcement 是“我宣告可达”，允许父 Zone 作为聚合点宣告子 Zone 的分配。

## 8. 权限模型

- `ipam.pool` 记录类型映射到 capability `PermAllocateIP`。
- `ipam.assignment` 记录类型也映射到 `PermAllocateIP`。
- `route.announcement` 记录类型继续映射到 `PermWriteRoute`。

只有 Zone authority 具备 `PermAllocateIP` 时，才能写入 pool/assignment 记录。

## 9. 节点自查询分配 IP

节点启动或 state 变化时，从本 Zone 到 root 的 fallback 路径中查询所有 `assigned_to` 等于本 Zone 的 assignment，汇总为本节点分配到的前缀集合。

### 9.1 自动发布 route announcement（可选）

配置项：

```yaml
ipam:
  auto_announce_assigned_ips: false  # 默认关闭
```

当开启时，节点自动为每个分配到的前缀发布 `routes/announcements/*`。

**默认关闭**，因为：
- 业务 IP 的宣告应该由管理员显式控制。
- 某些 assignment 可能用于非路由用途（如 SRv6 SID、服务监听地址）。

### 9.2 自动发布 route announcement 的详细设计

#### 9.2.1 触发时机

节点在以下时刻执行自查询与自动宣告：

1. daemon 启动或 state 加载完成后首次 reconcile。
2. 本地或远端 record 变化导致 `NetworkState` 更新后。
3. 配置 reload 后（`ipam.auto_announce_assigned_ips` 状态变化）。
4. 周期性的 routing reconcile（默认 30s）作为兜底。

触发点统一收敛在 `app/higgs/routing_reconcile.go` 的 `reconcileRouting()` 中，在 `BuildAuthorizedRouteSet` 之后插入 `autoAnnounceAssignedIPs` 步骤。

#### 9.2.2 自查询逻辑

1. 调用 `routing.BuildAuthorizedRouteSet(ns, now)` 获取 `AuthorizedRouteSet`。
2. 遍历 `ars.Assignments`，筛选出 `AssignedTo == d.Sync.State.ManagedZone` 的 assignment。
3. 对每个有效 assignment，检查其是否已被 pool 授权且无重叠错误。非法/无效的 assignment 不参与自动宣告。
4. 将结果前缀集合记为 `localAssignedPrefixes`。

#### 9.2.3 与现有 announcements 的差集处理

1. 从本 Zone 的 `routes/announcements/*` 记录中读取当前已发布的前缀集合 `localAnnouncedPrefixes`。
2. 计算差集：
   - **新增**：`localAssignedPrefixes - localAnnouncedPrefixes` → 自动发布 route announcement。
   - **撤回**：`localAnnouncedPrefixes - localAssignedPrefixes` → 自动撤回（发布 `active=false` 或更高版本的无效记录）。
3. 已存在且一致的前缀不重复写入，避免无意义版本递增。

#### 9.2.4 写入路径与单 writer 边界

自动宣告必须通过 daemon 单 writer 路径执行：

- daemon 运行时：直接由 `DaemonService` 内部调用 record 写入逻辑，复用 `record put` 的签名与版本比较逻辑。
- CLI 模式下（daemon 不存在）：`higgs ipam assigned` 只读查询；不自动写 announcement，避免多个 CLI 进程竞争写 DB。

建议新增内部方法 `putRouteAnnouncement(zone, prefix, active bool)`，与 CLI `higgs route announce/withdraw` 共享同一 record builder。

#### 9.2.5 配置项

```yaml
ipam:
  auto_announce_assigned_ips: false   # 默认关闭
```

该配置是**本节点本地行为开关**：
- 开启只影响本节点是否自动发布 announcements。
- 不影响 assignment 的授权有效性，也不影响其他节点是否接受该 announcement（仍由 `BuildAuthorizedRouteSet` 决定）。
- 配置变化时，daemon 在下一轮 reconcile 中按新状态补齐/撤回 announcements。

#### 9.2.6 与手动 route announce 的共存

- 手动通过 `higgs route announce` 发布的前缀如果恰好也是本节点分配到的前缀，自动宣告不会重复发布。
- 手动发布的前缀若不在 `localAssignedPrefixes` 中，不会被自动撤回（只撤回由自动机制创建的 announcements）。
- 建议通过 record 的 metadata 或来源标记区分自动/手动 announcement，便于后续审计。

## 10. CLI 设计

```bash
# 创建 pool
higgs ipam pool create <zone> <prefix> --delegated-to <zone>

# 分配 assignment
higgs ipam assign <zone> <prefix> --to <zone>

# 撤回 assignment（对同一 key 发 active=false 或更高版本）
higgs ipam revoke assignment <zone> <prefix>

# 撤回 pool
higgs ipam revoke pool <zone> <prefix>

# 查看本节点分配到的 IPs
higgs ipam assigned [--zone <zone>]
```

所有写操作在 daemon 运行时通过 control socket 提交，由 daemon 单 writer 落盘。

## 11. 与 Tunnel Address 的关系

- **Tunnel address 默认使用 `derived-link-local`**，不走路 IPAM。
- **业务地址 / SRv6 SID 完全由 IPAM 分配**。
- 这样 tunnel address 只是点对点链路邻接地址，业务可达性由 IPAM + route authorization 负责。

## 12. 实现顺序与测试

1. `pkg/routing/authorization.go`：实现 pool enforcement 和 assignment 重叠检测。
2. `pkg/crypto/sign.go`：将 `ipam.pool` / `ipam.assignment` 映射到 `PermAllocateIP`。
3. `app/higgs/ipam.go`：实现 `higgs ipam` CLI。
4. `app/higgs/routing_reconcile.go`：接入节点自查询分配 IP 和自动发布 route announcement。
5. 测试：
   - unit test: pool enforcement（合法/非法案例）
   - unit test: assignment 重叠检测（同 Zone 层级、兄弟冲突、跨 Zone 合法/非法）
   - unit test: `PermAllocateIP` capability 校验
   - smoke: `higgs ipam pool create` / `assign` / `route announce` + BIRD filter
   - unit test: `auto_announce_assigned_ips` 开启/关闭、前缀补齐/撤回
   - smoke: 开启 `auto_announce_assigned_ips` 后 BIRD export filter 自动包含本节点分配前缀

## 13. veth 上行与主网络集成（可选）

整个 mesh data-plane 通常运行在一个独立的 network namespace（如 `h2`）中。为了把 mesh 内的业务前缀暴露给主网络（init netns 或其他用户网络），或让主网络把可达信息注入 mesh，需要保留一个 **veth pair** 作为 mesh netns 与主网络之间的出入口。

### 13.1 两层语义

| 层面 | 作用 | BIRD 中对应机制 |
|---|---|---|
| **数据面 veth** | 把 mesh netns 内的前缀暴露给主网络，让主网络/other users 可达 | `protocol static` + kernel export / Babel export |
| **控制面 Babel peering** | 让 BIRD 通过 veth 与主网络中的另一个 BIRD/babeld 交换路由 | Babel `interface "hgs-upstream*" { ... }` |

### 13.2 veth 生命周期与配置

BIRD 以 netns 为边界运行，veth 上行配置属于 netns 级别的 routing 实例，而不是某个 overlay。建议在 `routing.instances[].upstream` 下增加可选配置段：

```yaml
netns:
  default:
    kind: name
    name: h2
    create: true

routing:
  instances:
    - netns: h2
      enabled: true
      protocol: bird
      mode: managed
      control_socket: /run/higgs/bird-h2.ctl
      pid_file: /run/higgs/bird-h2.pid
      table: main
      metric_base: 100
      interface_pattern: "hgs*"            # XFRM tunnel 接口
      upstream:
        enabled: true
        interface: "hgs-upstream0"         # mesh netns 内的 veth 端
        create_veth: true                  # 是否由 Higgs 创建并维护 veth pair
        peer_interface: "hgs-upstream1"    # 主网络端（init netns 或其他 ns）
        peer_netns: ""                     # 空表示主网络（init netns）
        ipv4_ll: "169.254.0.1/30"          # 可选：veth 两端 IPv4 link-local
        ipv6_ll: "fe80::1/64"              # 可选：veth 两端 IPv6 link-local

overlays:
  - id: ipsec-main
    netns: h2
    # routing 不再在 overlay 层级配置
```

- `interface` 与 `peer_interface` 组成一对 veth；Higgs 在 reconcile 时确保存在、up、地址正确。
- 如果管理员已手工创建 veth，可设置 `create_veth: false`，Higgs 只负责在 BIRD config 中引用它。
- veth 上的 Babel 邻居发现需要接口具备 IPv6 link-local 地址；若只有 IPv4 地址，需改用单播 `neighbor` 配置或额外分配 link-local。
- 同一 netns 下的所有 overlay 共享同一个 BIRD 实例和同一个 `upstream` 配置。

### 13.3 BIRD 多接口监听

当前 BIRD 配置只生成一个 `interface` 段。为了同时监听 XFRM tunnel 和 veth，需要支持多个接口模式：

```bird
protocol babel higgs_babel_xxx {
    ipv4 { table higgs_xxx; import filter higgs_import_xxx; export filter higgs_export_xxx; };
    ipv6 { table higgs_xxx; import filter higgs_import_xxx; export filter higgs_export_xxx; };

    interface "hgs*" { type tunnel; rxcost 100; hello interval 4 s; update interval 4 s; };
    interface "hgs-upstream*" { rxcost 100; hello interval 4 s; update interval 4 s; };
}
```

关键区别：

- `hgs*` 是 XFRM/IPsec tunnel，必须使用 `type tunnel`。
- `hgs-upstream*` 是 veth，使用默认多播/单播邻居模式，**不要**加 `type tunnel`。

### 13.4 用 static protocol 宣告分配前缀

当 `ipam.auto_announce_assigned_ips` 开启且需要让主网络/other users 可达时，除了发布 `routes/announcements/*` 给 mesh 内其他节点，还要在本节点 BIRD 中生成 static route：

```bird
protocol static higgs_static_xxx {
    ipv4;
    route 10.0.0.0/24 via "hgs-upstream0";
}
```

对于只做聚合宣告、本节点不实际承载业务的 prefix，可用 blackhole 兜底：

```bird
route 10.0.0.0/24 blackhole;
```

static protocol 的路由需要被 export filter 显式允许，才能进入 Babel 和 kernel。

### 13.5 Filter 设计

#### 13.5.1 Import filter（从 veth/主网络学路由）

```bird
filter higgs_import_xxx {
    if net = 0.0.0.0/0 then reject;              # 不接受默认路由
    if net = ::/0 then reject;
    if ! net ~ [ assigned_prefix_set+ ] then reject;  # 只接受已分配前缀内的路由
    if source !~ [ RTS_BABEL, RTS_STATIC ] then reject; # 只接受 Babel/Static 来源
    accept;
}
```

`assigned_prefix_set` 由 `BuildAuthorizedRouteSet` 中的 `Assignments` 汇总生成。

#### 13.5.2 Export filter（向 veth/主网络宣告）

```bird
filter higgs_export_xxx {
    if net = 0.0.0.0/0 then reject;
    if net = ::/0 then reject;
    if net ~ [ my_assigned_prefixes+ ] then accept;      # 本节点分配到的前缀
    if net ~ [ mesh_authorized_prefixes+ ] then accept;  # mesh 内其他节点授权可达的前缀
    reject;
}
```

`my_assigned_prefixes` 是本节点 `assigned_to == localZone` 的 assignment 集合；`mesh_authorized_prefixes` 是 `BuildAuthorizedRouteSet` 中所有授权前缀（含本节点和其他 Zone 的 announcements）。

#### 13.5.3 Kernel export filter（把路由写入主网络 FIB）

如果要把 mesh 路由注入主网络路由表，需要独立的 kernel export filter：

```bird
protocol kernel higgs_kern_xxx {
    ipv4 { table higgs_xxx; export filter higgs_kernel_export; };
    ipv6 { table higgs_xxx; export filter higgs_kernel_export; };
}

filter higgs_kernel_export {
    if net ~ [ my_assigned_prefixes+ ] then accept;
    if source = RTS_BABEL && net ~ [ assigned_prefix_set+ ] then accept;
    reject;
}
```

注意：默认不建议把 mesh Babel 学习到的全部路由直接注入主网络 main table，除非管理员显式开启并通过 filter 限制。

### 13.6 安全边界

1. **绝不接受默认路由**：import/export filter 必须显式 reject `0.0.0.0/0` 和 `::/0`，避免主网络把默认路由注入 mesh，也避免 mesh 把默认路由泄露到主网络。
2. **严格白名单**：veth 上学习到的路由必须落在 `assigned_prefix_set+` 内，未授权前缀直接丢弃。
3. **来源限制**：只接受 `RTS_BABEL` 和 `RTS_STATIC` 来源；`RTS_DEVICE`、`RTS_KERNEL` 等不应直接进入 mesh。
4. **owner 与清理**：veth pair、static route、filter 列表都属于 Higgs 管理资源，teardown/revocation 时按 owner token 清理，避免误删管理员手工配置。

### 13.7 实现顺序

1. **先实现 `ipam.auto_announce_assigned_ips`**：产生可宣告的前缀来源。
2. **再实现 veth 创建与 BIRD 多接口监听**：让 BIRD 能通过 veth 与主网络建立 Babel 邻居。
3. **最后加入 static route 与精细化 filter**：完成 mesh ↔ 主网络的双向路由控制。

### 13.8 风险与注意事项

- **veth link-local 地址**：Babel 需要接口有 IPv6 link-local 才能发多播 hello。如果 veth 只有 IPv4 地址，需要额外分配 `fe80::/64` 或改用单播 `neighbor` 配置。
- **主网络 BIRD 配置冲突**：主网络中如果已有 BIRD/babeld 实例，需确保 router-id、interface、port 不冲突，filter 方向正确。
- **多 overlay 场景**：每个 overlay 的 BIRD 实例是否共享同一个 veth？建议先按 overlay 独立，避免路由表和 Babel 邻居互相污染。
- **type tunnel 不要应用到 veth**：BIRD 的 `type tunnel` 会让 Babel 把邻居视为单向 tunnel，veth 上应使用默认模式。

## 14. Anycast / 共享前缀分配

### 14.1 问题

当前 IPAM assignment 重叠检测禁止多个 Zone 持有同一前缀。这与 Anycast（多节点同 IP 高可用）冲突。

### 14.2 目标

在 IPAM 层引入 shared/anycast 语义，允许多个 Zone 合法持有同一前缀的 assignment，同时保持现有防冲突规则对非 anycast 场景有效。

### 14.3 Schema 变更

`ipam.assignment` record 新增 `shared` 字段（可选，默认 `false`）：

```json
{
  "version": 1,
  "prefix": "10.0.0.1/32",
  "assigned_to": "node-a.catofes.",
  "active": true,
  "shared": true
}
```

- `shared=false`（默认）：行为与之前完全一致，不允许多 Zone 重叠。
- `shared=true`：该 assignment 被标记为 anycast，允许与其他同样标记为 `shared=true` 的 assignment 重叠。

向后兼容：旧 record 不含 `shared` 字段，解析时默认为 `false`，行为不变。

### 14.4 重叠检测规则

在 `BuildAuthorizedRouteSet` 的 `validateAssignmentOverlaps` 中：

1. 如果两个 assignment 前缀重叠，且**双方都标记为 `shared=true`**，则允许重叠（跳过兄弟 Zone 检查）。
2. 如果只有一方标记为 `shared`，或双方都未标记，则继续应用现有重叠检测规则（同 Zone 层级、跨 Zone 委派链）。

### 14.5 Route Announcement 重叠

在 `resolveOverlaps` 中，如果两个 route announcement 前缀重叠，且它们**都由 shared assignment 授权**（`RouteEntry.SharedAssignment == true`），则允许重叠。Babel ECMP 会自动处理多路径到同一前缀的流量分发。

### 14.6 CLI 支持

```bash
# 创建 anycast assignment
higgs ipam assign <zone> <prefix> --to <zone> --shared

# 撤销 anycast assignment（与普通撤销相同）
higgs ipam revoke assignment <zone> <prefix>
```

`--shared` 标志默认为 `false`。撤销操作会保留原 record 的 `shared` 字段值。

### 14.7 授权模型

Anycast assignment 的授权模型与普通 assignment 完全一致：
- 必须由具备 `PermAllocateIP` 的 Zone authority 签名。
- 必须被同 Zone 或祖先 Zone 的 pool 覆盖。
- Pool enforcement 规则不变。

`shared` 字段只是一个语义标记，不影响权限验证，只影响重叠检测。

### 14.8 AllAssignments

`AuthorizedRouteSet` 新增 `AllAssignments []*AssignmentEntry` 字段，包含所有有效的 assignment（包括 anycast 重复）。原有的 `Assignments map[netip.Prefix]*AssignmentEntry` 保留一个前缀一个代表条目（用于快速查找）。需要枚举所有 assignment 的消费者（CLI 列表、自动宣告、BIRD static route）应遍历 `AllAssignments`。

### 14.9 与 Babel ECMP 的关系

Babel 原生支持 ECMP（`ecmp on limit 16` 已在 bird.conf 中启用）。当多个 Zone 宣告同一 anycast 前缀时，BIRD 自动学习到多条路由并通过 ECMP 分发流量。节点故障后 Babel 自动收敛，流量切换到剩余的 anycast 节点。
