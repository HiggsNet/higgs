# Phase 8：应用层服务与代理

Phase 8 的目标是在 Higgs L3 mesh 上提供“可发现、可授权、可诊断”的应用层服务。第一种服务是节点本地的 SOCKS5 代理；共享 Anycast 地址和应用层 relay 属于后续独立能力，不会混入第一版。

本文描述已经落地的 Phase 8.1，以及它与后续阶段之间的边界。完整任务清单见 [`../todo.md`](../todo.md)。

## 1. 当前实现范围：Phase 8.1

Phase 8.1 只建立以下基础：

- 定义 host Docker service network 与本地 service instance 配置；
- 定义 `services/<id>` / `service.socks5.v1` 签名 record；
- 增加最小写入权限 `write:service`；
- 校验服务地址是否属于当前节点有效的非共享 IPAM assignment；
- 提供 `higgs service validate`，作为后续生成和发布动作的统一准入门槛。

Phase 8.1 **不会**：

- 创建、启动或停止 Docker 容器；
- 调用 Docker API 或执行 `docker compose up/down/pull`；
- 修改主机路由、Babel 宣告或防火墙规则；
- 自动发布 service record；
- 探测 SOCKS5 进程是否已经启动或可达。

因此，“配置通过验证”只表示配置、签名权限和地址归属正确，不表示服务已经运行或已对外发布。

## 2. 网络拓扑与本地配置

旧 `share/networks` 与 `share/socks5` 的关键分工是：

1. `share/networks` 单独创建 host netns 中的 Docker bridge，声明 subnet、可分配范围和 gateway；
2. SOCKS5 Compose 不重复创建这个网络，而是把它作为 external network 引用；
3. SOCKS5 容器在该 external network 上使用固定地址。

Phase 8 延续这个分工。配置分成 `services.networks` 和 `services.instances[]` 两层；所有 network 最终写入同一份 network Compose 文件：

```yaml
services:
  compose:
    output_dir: /etc/higgs/services/networks
    project_name: higgs-networks
  networks:
    main:
      ipv4: "local;172.30.0.0/24;172.30.0.128/28;172.30.0.1"
      ipv6: "auto;::/112;::100/120;::1"
  instances:
    - id: egress-cn
      type: socks5
      region: cn-east
      network: main
      address: "::20"
      port: 1080
      allow_zones:
        - clients.catofes.
        - "*.partners.catofes."
      compose:
        output_dir: /etc/higgs/services/egress-cn
        project_name: higgs-egress-cn
        image: ghcr.io/example/socks5:stable
        container_name: higgs-egress-cn
```

### 2.1 `services.networks`

这里描述的是 **host netns 中的 Docker network**，不是 Higgs overlay netns。

map 的 key 就是网络 ID。例如 `main` 的 Docker network 名默认为 `higgs-main`，`routing_instance` 也默认为 `main`，因此常用配置不再重复写 `id`、`name` 和 `routing_instance`。如果路由实例不同，只需显式覆盖：

```yaml
services:
  networks:
    proxy:
      routing_instance: main
      ipv6: "assignment:fd42:1::/64;::/112;::100/120;::1"
```

`ipv4` 和 `ipv6` 使用相同的四段描述符，分号不会与 IPv6 地址中的冒号冲突：

```text
来源;Docker subnet;Docker 动态分配范围;Docker gateway
```

来源支持：

| 写法 | 含义 |
|---|---|
| `local` | 纯 host Docker 网络，不使用 Higgs IPAM。其后三段必须写完整地址。 |
| `auto` | 选择当前 Zone 唯一的 active、非 shared、地址族相同的 assignment；没有或多于一个都会报错。IPv6 后三段可以写 `::` 开头的相对值。 |
| `assignment:<CIDR>` | 明确选择当前 Zone 的某个 active、非 shared assignment，适合存在多个 assignment 的节点。 |
| `shared:<CIDR>` | 为后续 Anycast 保留的语法；Phase 8.1 会明确拒绝执行。当前 IPAM assignment 没有 allocation 名称，因此不支持 `allocation:socks-cn`。 |

网络必须引用一个启用了 `upstream.mode: static`、且 `upstream.external.netns` 为空或 `host` 的 routing instance。不同网络在运行时解析出的同地址族 subnet 不得重叠。

`services.compose` 是所有 network 共用的输出设置，默认目录为 `<data_dir>/services/networks`，project name 为 `higgs-networks`。Phase 8.2 会在该目录生成唯一的 `docker-compose.yml`，其中包含全部 IPv4/IPv6 network；不会为每个 network 各生成一份 Compose。

旧的 sequence/长格式仍可读取，便于平滑迁移：

```yaml
services:
  networks:
    - id: svcnet
      name: old-name
      routing_instance: main
      ipv6:
        subnet: fd42:1::/112
        ip_range: fd42:1::100/120
        gateway: fd42:1::1
```

### 2.2 `services.instances[]`

| 字段 | 是否必填 | 含义 |
|---|---:|---|
| `id` | 是 | 节点内唯一的服务 ID，也是 record key 的一部分。规范形式为 1–63 位小写字母、数字、点、下划线或连字符，首字符必须是字母或数字。 |
| `type` | 是 | Phase 8.1 只接受 `socks5`。 |
| `region` | 是 | 服务选择属性，例如 `cn-east`；它不会推导地址、Zone 或共享范围。 |
| `network` | 是 | 引用 `services.networks` 的 map key。服务容器将通过该 host Docker network 接入。 |
| `address` | 是 | 固定地址或 IPv6 相对地址。`::20` 表示所选 network IPv6 subnet 起点加 `::20`；完整地址仍兼容。地址必须位于 subnet 内，不能是 gateway，也不能落入 Docker 动态分配范围。 |
| `port` | 是 | SOCKS5 监听端口，范围为 1–65535。 |
| `allow_zones` | 否 | 本机访问控制策略输入。它不会进入公开 record；具体前缀解析和防火墙落地属于 Phase 8.3。 |
| `compose` | 否 | 后续 SOCKS5 Compose artifact 的渲染参数。Phase 8.1 只解析并保存这些参数，不生成文件。 |

服务 ID 和解析后的服务地址均不能重复，`allow_zones` 中的每一项都必须是合法的 Zone selector。这里不使用 Docker 自动地址：公开签名 record 必须包含一个稳定、可预先验证的精确 IP，而 Phase 8 不通过 Docker API 反查租约。把动态池从 `::100` 开始、把固定服务地址放在它之前，可以简单地避免冲突。

`allow_zones` 支持三种规则：

| 写法 | 匹配范围 |
|---|---|
| `node-a.catofes.` | 只匹配这个精确 Zone，不包含它的子 Zone。 |
| `*.catofes.` | 匹配 `catofes.` 本身以及任意层级的子 Zone。 |
| `*.` | 匹配所有非 root Zone；不会把信任根 `.` 当作普通来源节点。 |

通配符只允许作为最左侧的完整 `*.` 标签，不支持 `node-*.catofes.`、`*catofes.` 或多段 glob。由于 `*` 在 YAML 中有 alias 语义，通配规则应使用引号，例如 `"*.catofes."`。

Phase 8.1 负责解析、规范化和测试这些 selector；Phase 8.3 会在每次 firewall reconcile 时，用 selector 匹配当前网络状态中的 Zone，再提取这些 Zone **当前 active 且已授权**的 route announcement 前缀。announce、withdraw、IPAM 撤销或 Zone revoke 引起状态变化后，daemon 已有的 `firewallDirty` 机制会触发规则重算；不会把首次解析出的 IP 永久固化。

### 2.3 host 与 overlay 的路由关系

`routing_instance` 不是 Docker network 所在的 netns。Docker bridge 始终位于 init/main host netns；routing instance 则通常运行在 Higgs overlay netns。两者由 `routing.instances[].upstream` veth 连接：

```text
远端 Higgs 节点
      │ Babel / overlay
      ▼
Higgs routing netns
      │ 本节点授权前缀的 static upstream route
      ▼
host netns ── Docker bridge /112 ── SOCKS5 container
      │
      └── 其他 Higgs 前缀经 upstream 返回 overlay
```

host 上可能同时存在“指向 Higgs routing netns 的较大聚合/授权前缀路由”和“Docker bridge 的较小 connected prefix”。Linux 最长前缀匹配保证本机 service subnet 命中 Docker bridge，其余 Higgs 地址命中 upstream 路由。

## 3. 公开 service record

SOCKS5 服务使用：

- record key：`services/<id>`，例如 `services/egress-cn`；
- record type：`service.socks5.v1`；
- record value：只包含 `type`、`region`、`address` 和 `port`。

示例：

```json
{"type":"socks5","region":"cn-east","address":"fd42:1::20","port":1080}
```

record value 不包含以下信息：

- 节点 ID 或 Zone：由已签名的 `zone.Record` 的 `Zone`、`SignedBy` 和信任链推导；
- `allow_zones`：这是服务提供节点的本机策略；
- Docker network、routing instance、Compose 镜像、目录或容器名称：这些是本机部署细节；
- readiness：服务是否启动、是否可达将在 Phase 8.3 单独表达。

解析器采用严格 schema。出现未知字段、错误类型、非规范地址、零端口或不合法的 key 时，record 会被拒绝。这样可以避免把本地授权策略或部署细节意外传播到 gossip 网络。

## 4. 写入权限

`service.socks5.v1` 对应最小权限 `write:service`。持有该权限的 Zone key 可以写 service record，但不能因此写 route、IPAM 或 WireGuard record。

通用 `write` 权限仍然可以写 service record，这与现有其他类型化 record 的权限规则一致。若 capability 配置了 `key_prefix`，还必须同时覆盖对应的 `services/<id>` key。

Phase 8.1 的验证命令会使用本机私钥构造 record 投影，再通过当前 ZoneAuthority 验证签名和 capability；它不会只检查“Zone 中是否存在某个有权限的 key”。

## 5. 地址归属与 IPAM 校验

通过 `auto`、`assignment:<CIDR>` 或旧长格式得到的 Docker service subnet，以及最终公开的服务地址，都必须被当前节点独占授权。`local` 网络本身不要求 IPAM 授权，但若要把其中的地址发布为 service record，地址仍必须通过 service record 的 IPAM 归属校验；因此它主要适合作为容器的辅助、本机地址族。验证会复用 `routing.BuildAuthorizedRouteSet`，无效 pool、越权 assignment 和非法重叠不会被当作有效归属。

一项 service network 与 service instance 配置只有同时满足以下条件才会通过：

1. 对非 `local` 网络，存在 active、有效的 IPAM assignment 完整覆盖 Docker network subnet；
2. 存在 active、有效的 IPAM assignment 覆盖具体服务地址；
3. 两项 assignment 的 `assigned_to` 都与 service record 的 Zone **完全相同**；
4. assignment 不是 shared assignment；
5. 如果有多个合法 assignment 覆盖目标，报告最具体、前缀最长的一个。

Phase 8.1 明确拒绝 shared assignment。共享地址的成员关系、宣告权和撤销语义必须由 Phase 8.6 Anycast allocation 明确定义，不能提前用现有 `shared: true` 绕过。

IPAM 归属通过也不等于路由已经可达。Babel route 的生成、授权和宣告仍遵循现有 routing 配置，不由 service record 隐式触发。

## 6. 验证命令

验证全部本地服务：

```text
higgs service validate
```

只验证一个服务：

```text
higgs service validate egress-cn
```

输出 JSON：

```text
higgs service validate egress-cn --json
```

命令会执行以下检查：

1. 读取 host Docker network 描述符与 service instance 配置；
2. 根据当前 IPAM assignment 解析 `auto`、相对 subnet、gateway 和 service address，并校验 static-upstream routing instance；
3. 构造但不持久化 `service.socks5.v1` 签名 record；
4. 验证本机签名 key 是否具有 `write:service` 或通用 `write` 权限；
5. 基于已验证网络状态计算 AuthorizedRouteSet；
6. 验证 Docker subnet 与服务地址归属，并输出匹配的最具体 assignment prefix。

常见失败包括：

- `write authorization`：本机签名 key 缺少 service 写权限；
- `service_address_unauthorized`：地址不属于当前 Zone、assignment 无效，或只有 shared assignment；
- `service_network_unauthorized`：整个 Docker subnet 没有被当前 Zone 的非共享 assignment 覆盖；
- `service "..." is not configured`：指定的服务 ID 不存在；
- `unknown network`：service instance 引用了未声明的 service network；
- `unknown routing_instance`：service network 引用了未声明的 routing instance；
- `must be enabled with static upstream`：routing instance 未提供通往 host 的 static upstream。

## 7. 后续阶段边界

- **Phase 8.2**：把 `services.networks` 中全部 IPv4/IPv6 network 生成到同一份 Docker network Compose，再让 SOCKS5 Compose 以 external network 引用它；同时处理 upstream 当前可能占用 assignment 首地址与 Docker gateway `::1` 冲突的问题。只生成文件并提示管理员命令，不管理容器生命周期。
- **Phase 8.3**：把 `allow_zones` 转换为来源前缀并生成防火墙计划；区分 configured、started、ready 和 published 状态，只有满足显式 enable/readiness 条件时才发布 record。
- **Phase 8.4**：通过真实 container/root smoke 验证跨 mesh SOCKS5、负向授权和最长前缀路由闭环。
- **Phase 8.5**：在唯一地址稳定后增加按类型、region、健康和 Babel metric 的服务选择。
- **Phase 8.6**：独立设计 shared Anycast allocation、成员资格、相同地址宣告权和撤销流程。
- **Phase 8.7**：独立设计应用层源路由 relay 协议，不把 relay 语义塞入第一版 SOCKS5 record。
