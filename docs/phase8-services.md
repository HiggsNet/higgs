# Phase 8：应用层服务与代理

Phase 8 的目标是在 Higgs L3 mesh 上提供“可发现、可授权、可诊断”的应用层服务。第一种服务是节点本地的 SOCKS5 代理；共享 Anycast 地址和应用层 relay 属于后续独立能力，不会混入第一版。

本文描述已经落地的 Phase 8.1，以及它与后续阶段之间的边界。完整任务清单见 [`../todo.md`](../todo.md)。

## 1. 当前实现范围：Phase 8.1

Phase 8.1 只建立以下基础：

- 定义本地 `services[]` 配置；
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

## 2. 本地服务配置

服务在 `config.yaml` 的顶层 `services[]` 中声明：

```yaml
services:
  - id: egress-cn
    type: socks5
    region: cn-east
    netns: default
    address: fd42:1::20
    port: 1080
    allow_zones:
      - clients.catofes.
    compose:
      output_dir: /etc/higgs/services/egress-cn
      project_name: higgs-egress-cn
      image: ghcr.io/example/socks5:stable
      container_name: higgs-egress-cn
```

字段含义：

| 字段 | 是否必填 | 含义 |
|---|---:|---|
| `id` | 是 | 节点内唯一的服务 ID，也是 record key 的一部分。规范形式为 1–63 位小写字母、数字、点、下划线或连字符，首字符必须是字母或数字。 |
| `type` | 是 | Phase 8.1 只接受 `socks5`。 |
| `region` | 是 | 服务选择属性，例如 `cn-east`；它不会推导地址、Zone 或共享范围。 |
| `netns` | 否 | 引用顶层 `netns` 中已声明的网络命名空间；省略时使用默认 netns。 |
| `address` | 是 | 显式、规范化的 IP 地址。Higgs 不会根据服务类型或 IPAM prefix 猜测 `::2` 等约定地址。 |
| `port` | 是 | SOCKS5 监听端口，范围为 1–65535。 |
| `allow_zones` | 否 | 本机访问控制策略输入。它不会进入公开 record；具体前缀解析和防火墙落地属于 Phase 8.3。 |
| `compose` | 否 | 后续 Compose artifact 的渲染参数。Phase 8.1 只解析并保存这些参数，不生成文件。 |

服务 ID 不能重复，`netns` 必须已经声明，`allow_zones` 中的每一项都必须是合法的完整 Zone 名称。

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
- Compose 镜像、目录或容器名称：这些是本机部署细节；
- readiness：服务是否启动、是否可达将在 Phase 8.3 单独表达。

解析器采用严格 schema。出现未知字段、错误类型、非规范地址、零端口或不合法的 key 时，record 会被拒绝。这样可以避免把本地授权策略或部署细节意外传播到 gossip 网络。

## 4. 写入权限

`service.socks5.v1` 对应最小权限 `write:service`。持有该权限的 Zone key 可以写 service record，但不能因此写 route、IPAM 或 WireGuard record。

通用 `write` 权限仍然可以写 service record，这与现有其他类型化 record 的权限规则一致。若 capability 配置了 `key_prefix`，还必须同时覆盖对应的 `services/<id>` key。

Phase 8.1 的验证命令会使用本机私钥构造 record 投影，再通过当前 ZoneAuthority 验证签名和 capability；它不会只检查“Zone 中是否存在某个有权限的 key”。

## 5. 地址归属与 IPAM 校验

服务地址必须被当前节点独占授权。验证时会复用 `routing.BuildAuthorizedRouteSet` 的结果，因此无效 pool、越权 assignment 和非法重叠不会被当作有效归属。

一个地址只有同时满足以下条件才会通过：

1. 存在 active、有效的 IPAM assignment 覆盖该地址；
2. assignment 的 `assigned_to` 与 service record 的 Zone **完全相同**；
3. assignment 不是 shared assignment；
4. 如果有多个合法 assignment 覆盖该地址，报告最具体、前缀最长的一个。

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

1. 读取并解析本地 service 配置；
2. 构造但不持久化 `service.socks5.v1` 签名 record；
3. 验证本机签名 key 是否具有 `write:service` 或通用 `write` 权限；
4. 基于已验证网络状态计算 AuthorizedRouteSet；
5. 验证服务地址归属，并输出匹配的最具体 assignment prefix。

常见失败包括：

- `write authorization`：本机签名 key 缺少 service 写权限；
- `service_address_unauthorized`：地址不属于当前 Zone、assignment 无效，或只有 shared assignment；
- `service "..." is not configured`：指定的服务 ID 不存在；
- `unknown netns`：配置引用了未声明的网络命名空间。

## 7. 后续阶段边界

- **Phase 8.2**：生成 Docker IPv6 network、SOCKS5 Compose 和代理配置 artifact；只生成文件并提示管理员命令，不管理容器生命周期。
- **Phase 8.3**：把 `allow_zones` 转换为来源前缀并生成防火墙计划；区分 configured、started、ready 和 published 状态，只有满足显式 enable/readiness 条件时才发布 record。
- **Phase 8.4**：通过真实 container/root smoke 验证跨 mesh SOCKS5、负向授权和最长前缀路由闭环。
- **Phase 8.5**：在唯一地址稳定后增加按类型、region、健康和 Babel metric 的服务选择。
- **Phase 8.6**：独立设计 shared Anycast allocation、成员资格、相同地址宣告权和撤销流程。
- **Phase 8.7**：独立设计应用层源路由 relay 协议，不把 relay 语义塞入第一版 SOCKS5 record。
