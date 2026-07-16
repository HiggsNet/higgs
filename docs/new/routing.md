# Higgs Routing 与 IPAM

> **本文档状态：2026-07**
> 描述当前 routing / IPAM 实现：地址授权、route announcement、per-netns BIRD/Babel，以及 mesh netns 通过 veth 接入 host 或其他 namespace 的方式。

Routing 把已经建立的 overlay 接口接入 BIRD/Babel，使 mesh 自动学习可达前缀。它不建立 IPsec、WireGuard 或其他 tunnel；也不把本机 BIRD 状态写进 gossip。Routing 只消费已验证的 Zone state 和本机配置，并把结果收敛为 BIRD 配置、内核路由和观测状态。

---

## 目录

1. [架构概览](#1-架构概览)
2. [IPAM 与 route announcement](#2-ipam-与-route-announcement)
3. [授权、继承与冲突](#3-授权继承与冲突)
4. [BIRD/Babel 运行时](#4-birdbabel-运行时)
5. [veth upstream：把 mesh 接到 host](#5-veth-upstream把-mesh-接到-host)
6. [自动宣告、配置与诊断](#6-自动宣告配置与诊断)
7. [实现边界](#7-实现边界)

---

## 1. 架构概览

### 1.1 控制面与运行时的边界

```text
signed Zone records                         local runtime
───────────────────                         ─────────────
pool / assignment / announcement ──verify──> AuthorizedRouteSet
                                                    │
transport interfaces ──────────────────────────────┼──> BIRD config
local routing / netns / forwarding policy ─────────┘        │
                                                             ├──> Babel neighbors
                                                             ├──> kernel routes
                                                             └──> BirdInstanceState / health
```

| 层 | 负责什么 | 不负责什么 |
|---|---|---|
| Gossip / Zone | 传播并验证签名的 authority、delegation、IPAM 和 route records | 不启动 BIRD、不修改路由表。 |
| IPAM authorization | 判断谁有地址分配权、谁可以使用一段地址、哪些 announcement 有效 | 不探测节点是否真的在线。 |
| Routing reconcile | 按每个 netns 生成 BIRD 配置、管理进程和 veth/upstream 路由 | 不改变 signed record 的真实性。 |
| BIRD/Babel | 交换、选择并安装路由 | 不验证 Zone 签名链。 |

这也符合 [Daemon](daemon.md) 的通用原则：gossip state 与本机 runtime 是两层状态。某节点的 BIRD 崩溃只影响它自身的转发能力，不会撤销其他节点看到的 signed announcement。

### 1.2 per-netns BIRD 模型

一个 network namespace 对应一个 BIRD 实例；该 netns 内所有 overlay 接口共享 Babel 邻居、BIRD table 和 kernel table。

| 项目 | 当前行为 |
|---|---|
| 实例配置 | `routing.instances[]`，每项引用一个 `netns`。 |
| tunnel 接口 | 默认匹配 `hgs*`；同一实例可合并多个 interface pattern。 |
| Router-ID | 由 managed Zone、trusted root hash 与稳定 netns label 派生。 |
| 路由表 | 默认写目标 netns 的 `main` table，也可指定数字 table ID。 |
| forwarding | `netns.*.forwarding` 同时约束 BIRD export 与 firewall 的 transit 行为。 |

## 2. IPAM 与 route announcement

### 2.1 三种 record，三种含义

这里的 **pool** 是地址池，不是 pull。三者解决的是连续但不同的问题：

```text
pool                         assignment                         announcement
────                         ──────────                         ────────────
谁可以继续分配地址      ──> 谁可以使用一段地址          ──> 谁当前宣告它可达
```

| Record | Key | 核心字段 | 语义 |
|---|---|---|---|
| `ipam.pool` | `ipam/pools/<prefix>` | `delegated_to` | 将一段前缀的下一层分配权交给目标 Zone。 |
| `ipam.assignment` | `ipam/assignments/<prefix>` | `assigned_to` | 将前缀的使用与 route 发布基础交给目标 Zone。 |
| `route.announcement` | `routes/announcements/<prefix>` | `prefix`, `active` | 发布者现在声称该前缀可经自己到达。 |

CIDR 会 canonicalize；例如 `10.0.1.1/24` 与 `10.0.1.0/24` 都使用 `10.0.1.0/24` 和对应的 `_24` key。撤回使用相同 key 的更高版本 `active: false`，不会删除 record。

### 2.2 两层授权：写 record 与使用地址

不要把 capability 和 IPAM 混为一谈：

| 检查 | 回答的问题 | 当前规则 |
|---|---|---|
| 签名 capability | 这把私钥能不能写这类 record？ | pool / assignment 需要通用 `write` 或 `allocate-ip`；announcement 使用通用 `write`。 |
| Pool chain | 此 Zone 是否有资格发布一条 assignment？ | assignment 的 `source` 必须是覆盖它的有效 pool 的 `delegated_to`。 |
| Assignment | 这个 announcer 是否有资格发布该 prefix？ | 见第 3 节的使用与继承规则。 |

默认 delegation 发给普通节点的是通用 `write, delegate`，因此它能发布 route announcement。`assigned_to` 本身不发放私钥或 capability；它只是 IPAM 语义授权。relay 则不需要 Zone authority 或写权限，它只转发已验证 gossip state。

### 2.3 从 pool 到可达路由

下面是一个普通的管理层级。根 ZonePath 是 `.`：

```text
.
  pool 10.0.0.0/8  delegated_to=.
  pool 10.42.0.0/16 delegated_to=pek.catofes.

pek.catofes.
  assignment 10.42.1.0/24 assigned_to=node-a.pek.catofes.

node-a.pek.catofes.
  announcement 10.42.1.0/24 active=true
```

这条链的阅读方式是：

1. 根保留 `/8` 的分配权，并把 `/16` 的下一层分配权交给 `pek.catofes.`。
2. `pek.catofes.` 在自己获得的 pool 内，把 `/24` 的使用权交给 `node-a`。
3. `node-a` 以自己的 Zone 签名宣告 `/24` 可达；只有这时它才会进入 `AuthorizedRouteSet` 和 BIRD。

`shared: true` 表示 Anycast。它不是一个隐式的“所有节点均可使用”开关，而是由多个 assignment record 表示明确成员：每个允许成员各有一条 `assigned_to=<member>`、`shared:true` 的 assignment。`tag` 只是该 Anycast group 的稳定选择器；它不授予地址或 route 权限。

## 3. 授权、继承与冲突

### 3.1 为什么 assignment 允许向下发布

当前模型有意允许管理 Zone 管理一段地址而不必为每一个子节点预先写 assignment。

若管理 Zone `M` 有一条 `P` 的 assignment，且 `assigned_to=M`，则 `M` 与它的下属 Zone 都可以宣告 `P` 内的更具体 prefix。目的不是让任意节点抢地址，而是让管理者先分配一个地址域，之后让叶节点按自身生命周期发布实际可达的 `/24`、`/64` 或 service 前缀。

```text
M 有 assignment 10.42.0.0/16 assigned_to=M
├── node-a.M  可宣告 10.42.1.0/24
└── node-b.M  可宣告 10.42.2.0/24
```

这种继承减少了大量 per-node assignment 操作。若某个子 Zone 需要把地址**再分配**给别人，仍应使用 pool；assignment 提供的是使用和发布基础，不是新的 pool record 发布资格。

### 3.2 announcement 的精确判定

对 announcer `Z` 的 prefix `R`，authorization 会寻找覆盖 `R` 的有效 assignment `A`。它必须满足：

1. `A.source` 是 `Z` 自身或 `Z` 的祖先；
2. `A.prefix` 覆盖 `R`；
3. 下面任一关系成立：
   - `A.assigned_to == Z`：分给自己，自己发布；
   - `A.assigned_to` 是 `Z` 的祖先：分给管理 Zone，其子树发布更具体前缀；
   - `A.assigned_to` 是 `Z` 的后代，且 `A.source == Z`：分配者保留该 assignment 的聚合发布权。

最后一条支持常见的父子聚合：父 Zone 把 `/16` 交给子 Zone 使用，同时仍可宣告 `/16`；子 Zone 再宣告 `/24` 时，内核按最长前缀匹配优先使用 `/24`。

### 3.3 冲突不是靠“最后写入者胜出”解决

两个子节点可以在断网或离线状态下各自签出 announcement；签名有效不代表它们可以同时进入路由表。gossip 收敛后，`BuildAuthorizedRouteSet` 会统一裁决：

| 两条 announcement 的关系 | 收敛后的结果 |
|---|---|
| 兄弟 / 无关 Zone 宣告同一或重叠前缀 | 两条都拒绝，报 `route_overlap_unauthorized`。 |
| 父 Zone 与子 Zone 宣告包含关系 | 保留两条；数据面由最长前缀匹配处理更具体路由。 |
| 同一管理子树但两个叶节点宣告不重叠前缀 | 都保留。 |
| 双方都由 shared assignment 支撑 | 允许并存，Babel 可用 ECMP 做 Anycast。 |

因此，“管理 Zone assignment 给自己”不会让两个兄弟节点的同一 `/24` 同时成为授权路由；它的代价是发生冲突时 fail-closed，两个 announcement 都不可用。在网络分区尚未收敛时，每一侧只能根据自己已知的 state 决策，短暂 split-brain 无法由纯 gossip 消除；合并后会回到上述 fail-closed 结果。

普通 assignment 的重叠会更早在 IPAM 层拒绝：只有前缀包含关系和 Zone delegation 链都成立时才允许。shared assignment 用于 Anycast，但当前实现中 `shared && shared` 会跳过重叠检查；生产上应只把它用于相同 prefix 的明确成员组。

## 4. BIRD/Babel 运行时

### 4.1 Reconcile 流程

`reconcileRouting()` 由 daemon 在 state/config/transport 变化和周期性 safety sweep 时调度：

1. 从 committed snapshot 建立 `AuthorizedRouteSet`。
2. 按 `ipam.announce` 选择器维护本节点自动 announcement；有变更时重读 snapshot。
3. 为每个 routing instance 计算 Router-ID、接口 pattern、static route 和 import/export set。
4. 可选地确保 upstream veth 与 external 路由存在。
5. 生成配置，并按 `managed` / `external` / `disabled` 模式管理或观测 BIRD。
6. 将 BIRD process、协议、邻居和路由观测提交回本机 state，供 health 和 observer 使用。

### 4.2 三个前缀集合

| 集合 | 来源 | BIRD 用途 |
|---|---|---|
| Import set | 全网已授权 announcement | 限制从 Babel 接收的 prefix。 |
| Export set，非 transit | 本 Zone 已授权 announcement | 只发布本机声明的路由。 |
| Export set，transit | 全网已授权 announcement，再过 `allow_prefixes` / `deny_prefixes` | 允许中继节点继续传播的范围。 |
| Local static route | `assigned_to == managed_zone` 的有效 assignment | 让 BIRD 知道本节点拥有的前缀；无 upstream 时为 blackhole。 |

Import filter 不验证“这个 Babel 邻居正是 announcement 的 owner”。Babel 是多跳协议：A 从 B 学到 C 的路由时，B 是直接邻居而不是原始 owner。当前防护是 signed control-plane 给出可接受范围，后续可增加 Router-ID 交叉审计。

### 4.3 前缀长度策略

即使 announcement 是 exact prefix，BIRD filter 也会接受它的一段更具体范围：

| 地址族 | 对 announcement `/n` 接受的范围 |
|---|---|
| IPv4 | `max(n, /18)` 到 `/28`；`n > /28` 时只接受 exact。 |
| IPv6 | `max(n, /48)` 到 `/96`；`n > /96` 时只接受 exact。 |

例如 announcement `10.42.1.0/24` 使 BIRD 接受 `/24` 至 `/28`。这是数据面 prefix-length policy，不表示每一个 learned 更具体路由都有一条 exact signed announcement。

## 5. veth upstream：把 mesh 接到 host

### 5.1 何时需要 upstream

overlay 与 BIRD 通常位于独立 mesh netns，例如 `h2`。host 上的容器、服务进程或另一个 namespace 若要访问 mesh 前缀，就需要一个明确的出入口。`routing.instances[].upstream` 用一对 veth 连接两个网络边界：

```text
host / external netns                         mesh netns (h2)
─────────────────────                         ───────────────
services / containers                         BIRD + Babel + overlay tunnels
       │                                                  │
 hgs-2higgs  ───────────── veth pair ─────────────  hgs-2host
       │                                                  │
external kernel routes                           BIRD static / Babel interface
```

它不是另一条 overlay，不进入 gossip，也不改变 IPAM 授权；它只是本机或相邻 namespace 的数据面接入点。

### 5.2 配置示例

```yaml
netns:
  default:
    kind: name
    name: h2
    create: true
    forwarding:
      transit: false

routing:
  instances:
    - id: main
      netns: default
      provider: bird
      mode: managed
      table: main
      interface_pattern: hgs*
      upstream:
        mode: static             # 默认值
        create_veth: true        # 默认值
        mesh:
          interface: hgs-2host
          ipv4_ll: 169.254.254.1/30
          ipv6_ll: fe80::a1:1/64
        external:
          interface: hgs-2higgs
          # netns: ""            # 省略/空值 = init host netns
          ipv4_ll: 169.254.254.2/30
          ipv6_ll: fe80::a1:2/64
```

启用 upstream 而未显式配置端点时，默认使用：

| 字段 | 默认值 |
|---|---|
| `mesh.interface` | `hgs-2host` |
| `external.interface` | `hgs-2higgs` |
| `mesh.ipv4_ll` / `external.ipv4_ll` | `169.254.254.1/30` / `169.254.254.2/30` |
| `mesh.ipv6_ll` / `external.ipv6_ll` | `fe80::a1:1/64` / `fe80::a1:2/64` |
| `create_veth` | `true` |
| `mode` | `static` |

`external.netns` 可以引用另一个 namespace；省略或空值表示 init/main host netns。`create_veth: false` 时 Higgs 仍会按配置使用该接口，但管理员必须保证 veth、地址、up 状态与两端 namespace 已准备好。

### 5.3 `static`：Higgs 同时管理两侧的最小路由

这是默认模式。Higgs 会：

1. 在 `create_veth: true` 时创建或修复 veth pair、配置两端 link-local 地址并启用接口 forwarding；
2. 让 mesh 内 BIRD 在 `hgs-2host*` 上运行 Babel；此接口**不是** tunnel，不使用 BIRD `type tunnel`；
3. 对本机 `assigned_to == managed_zone` 的前缀，在 mesh 内生成 BIRD static route，下一跳为 `mesh.interface`；
4. 在 external 一侧为已授权的远端 announcement 写 kernel static route，下一跳为 mesh 端 link-local 地址，并排除本机自己持有的 assignment；
5. 在 external 接口上配置本机 assignment 的首个可用地址，供这些回程路由选择 source address。

结果是：host/service 发往远端 mesh prefix 时，走 `hgs-2higgs` 进入 mesh；远端发往本节点的 assigned/service prefix 时，BIRD 在 mesh 内将它送往 `hgs-2host`，再由 host 的本地路由或 container connected route 接收。

`static` 的 BIRD static route 表示“本机拥有该前缀且其实际承载在 external 一侧”，不等于扩大 BIRD export 权限。一个前缀仍须有有效 announcement 才会被 export。

### 5.4 `external`：只提供 Babel 接口

```yaml
upstream:
  mode: external
  create_veth: false
  mesh:
    interface: hgs-2host
  external:
    interface: hgs-2higgs
```

`external` 模式让 Higgs 保留 mesh 侧的 BIRD/Babel veth interface，但不生成本机 static route，也不在 external 一侧写 kernel route。它适合 host 或另一个 namespace 已由管理员运行 BIRD/FRR/babeld，或有自定义策略路由的场景。两端地址、路由、转发和 firewall 都由管理员负责。

### 5.5 使用 upstream 时的边界

- 业务 prefix 仍由 IPAM + announcement 决定；veth 不会让 host 自动获得未授权前缀。
- `transit: false` 只禁止 mesh overlay 间中继，不等于关闭 host ↔ mesh 的 veth 接入。
- host 侧 Docker connected route 与更宽的 host → mesh route 会按最长前缀匹配；服务子网应避开与本地 connected subnet 的意外重叠。
- `external` 模式不是“自动接入 host”的简写：它只交出接口，必须由外部路由守护进程或管理员完成数据面。

## 6. 自动宣告、配置与诊断

### 6.1 自动 announcement

```yaml
ipam:
  announce:
    - non-shared
    # - tag:edge.c
```

选择器只挑选 `assigned_to == managed_zone` 的有效 assignment：`all`、`non-shared`、`shared`、`tag:<tag>`、`assignment:<CIDR>`。

- selector 模式写入 `controller: auto`，只撤回自己创建的 announcement；手动或 service 控制的 record 不会被 selector 撤回。
- `auto_announce_assigned_ips: true` 仍兼容，但会管理本 Zone 的全部 announcement，适合旧配置，不建议新部署使用。
- shared service Anycast 通常由服务生命周期决定，除非该 group 确实需要长期静态宣告，否则不应放进通用 selector。

完整字段说明见 [配置文档](config.md) 和根目录 `config.example.yaml`。

### 6.2 常用诊断

| 命令 | 用途 |
|---|---|
| `higgs ipam get <addr-or-prefix>` | 查看 pool chain、assignment、announcement 与 IPAM 诊断。 |
| `higgs ipam mine` | 查看本 managed Zone 持有的 assignment / pool。 |
| `higgs debug routes` | 查看 `AuthorizedRouteSet` 与拒绝原因。 |
| `higgs debug babel` | 查看每个 BIRD instance 的运行状态。 |
| `higgs debug bird dump --command "show babel neighbors"` | 查看实际 Babel 邻居。 |
| `higgs debug bird dump --command "show route all"` | 查看 BIRD learned / installed route。 |

优先按以下顺序排障：先看 assignment / announcement 是否在 `AuthorizedRouteSet`，再看 tunnel 或 veth 接口，最后看 BIRD 邻居和内核路由。BIRD 正常不代表前缀已获授权；record 已获授权也不代表本机数据面已经起来。

## 7. 实现边界

| 行为 | 位置 |
|---|---|
| record schema、canonical key | `pkg/routing/records.go` |
| pool / assignment / route authorization | `pkg/routing/authorization.go` |
| record type capability 验证 | `pkg/crypto/sign.go` |
| CLI IPAM / route 写入 | `app/higgs/ipam.go`、`app/higgs/route.go` |
| routing reconcile、auto announcement、external routes | `app/higgs/routing_reconcile.go`、`app/higgs/routing_upstream_routes.go` |
| BIRD config、filter、process、veth | `pkg/routing/bird/` |

旧的 Phase 设计文档保留为实现历史；本文是 `docs/new/` 迁移后的 routing 当前行为入口。迁移完成后，应先更新仓库内引用，再删除被替代的旧文档，避免设计历史与现行实现同时充当规范。
