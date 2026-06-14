# Phase 6.1 IPAM 闭环设计

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
