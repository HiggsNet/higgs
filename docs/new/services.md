# Higgs Services 设计与实现

> **本文档状态：2026-07**
> 描述 Higgs 服务发布子系统的当前实现：`pkg/service` 的 record 与授权模型、独立工具 `higgs-services`（`app/higgs-services`）的 manifest 解析、artifact 生成和发布编排，以及 daemon 侧的动态 endpoint ACL。
> 本文以当前代码为准。原 Phase 8 设计文档的内容已并入本文，不再单独保留。

Service 发布把“可信网络状态”和“容器部署”拆开：Higgs daemon 管理 IPAM、路由宣告、签名 service record 和动态防火墙授权，但**不理解镜像、容器或 Compose，也不会调用 Docker API**；独立程序 `higgs-services` 读取 `/etc/higgs/service.yaml`，从 Higgs 运行态解析地址并生成 Docker Compose artifact，再编排 ACL、route announcement 和 service record 的发布顺序。

当前只提供一套固定名为 `socks5` 的服务，由 `socks`、`dns`、`h2` 三个容器组成，不需要实例名、Compose project name 或 container name。

相关文档：IPAM assignment 与路由授权见 [routing.md](routing.md)，endpoint ACL 的规则生成见 [firewall.md](firewall.md)，`ipam.announce` 配置见 [config.md](config.md)，验收入口见 [testing.md](testing.md)。

---

## 目录

1. [范围与定位](#1-范围与定位)
2. [核心概念](#2-核心概念)
3. [配置模型](#3-配置模型)
4. [地址解析与 artifact 生成](#4-地址解析与-artifact-生成)
5. [发布与撤销流程](#5-发布与撤销流程)
6. [动态 endpoint ACL](#6-动态-endpoint-acl)
7. [验证与排障](#7-验证与排障)
8. [已知限制](#8-已知限制)

---

## 1. 范围与定位

### 1.1 职责边界

| 角色 | 做什么 | 不做什么 |
|---|---|---|
| `higgs` daemon / CLI | 保存普通和 shared Anycast assignment；校验服务 endpoint 属于当前 Zone 的 active assignment；显式宣告或撤销整个 assignment prefix；签名、发布和撤销固定的 `services/socks5` record；根据 Zone selector 动态维护 host FORWARD endpoint ACL | 不理解镜像、容器、Compose，不调用 Docker API |
| `higgs-services` | 读取 service manifest；从 `higgs route ipam mine` 解析本地 `auto` 和 shared assignment tag；规划多 network 下三个容器的地址；生成 Compose、SmartDNS 配置和状态锁文件；对待发布 endpoint 做 TCP 就绪检查；编排 ACL、route announcement 和 service record 的发布/撤销顺序 | 不启动容器、不管理容器生命周期 |
| 管理员 | 执行 `docker compose up/down/pull`；负责非 shared assignment 的路由（通常经 `ipam.announce`） | — |

`render` 只生成 artifact；`publish` 也不会启动容器。容器必须先由管理员通过 Compose 拉起，`publish` 的 TCP 就绪检查才有意义。

### 1.2 代码位置

| 位置 | 内容 |
|---|---|
| [`pkg/service`](../../pkg/service) | `service.socks5.v1` record 解析/校验/授权、Zone selector |
| [`app/higgs-services`](../../app/higgs-services) | manifest 解析（`manifest.go`）、Compose/SmartDNS 渲染（`render.go`）、publish/withdraw 编排（`main.go`） |
| [`app/higgs/service.go`](../../app/higgs/service.go) | `higgs service publish/withdraw`，record 签名提交 |
| [`app/higgs/endpoint_acl.go`](../../app/higgs/endpoint_acl.go) | `higgs firewall endpoint` 命令与 daemon 侧 endpoint ACL 事件处理 |

---

## 2. 核心概念

### 2.1 Assignment：本地地址与 Anycast 地址

本地节点地址继续使用普通 assignment，不加 tag。配置里的 `auto` 只选择当前节点同地址族唯一的 active、非 shared assignment，因此节点分配地址时不必预先声明自己运行什么服务。

跨节点共用的 Anycast 地址使用带稳定 tag 的 shared assignment：

```bash
higgs route ipam assign catofes. 2a0d:2905:0:4::/96 \
  --to node-a.catofes. --shared --tag socks5.cn
higgs route ipam assign catofes. 2a0d:2905:0:4::/96 \
  --to node-b.catofes. --shared --tag socks5.cn
```

约束（record 层定义见 [routing.md](routing.md)）：

- `tag` 只能用于 shared assignment；普通本地 assignment 不需要 tag。
- 同一 tag 在同一地址族中必须对应同一个 prefix；IPv4 和 IPv6 可以共用 tag。
- tag 是选择 assignment 的稳定名字，不代表服务类型、region 或节点角色，也**不会自动发布路由**。
- 同一 owner 下的 shared assignment 按成员分别保存，可以精确撤销单个节点：

```bash
higgs route ipam revoke assignment catofes. 2a0d:2905:0:4::/96 --to node-a.catofes.
```

### 2.2 Service record

公开签名 record 类型为 `service.socks5.v1`，key 固定为 `services/socks5`（`pkg/service/records.go`）。多 endpoint 形式：

```json
{
  "type": "socks5",
  "endpoints": [
    {"region": "local", "address": "fd42:1::20", "port": 3128},
    {"region": "cn", "address": "2a0d:2905:0:4::20", "port": 3128}
  ]
}
```

- record 只表达客户端真正需要的 `region`、`address`、`port`；不包含 network 名、assignment tag 或 `allow_zones`——这些是发布节点的本地部署/安全策略。
- `active` 字段可选：缺省视为 active；撤销通过写入 `active: false` 实现，record 本身保留。
- 兼容旧格式：没有 `active` 字段、只有单个 `region/address/port` 的 record 仍可读取；但 legacy 字段与 `endpoints` 不能同时出现。
- 地址必须是 canonical 形式、可用 unicast；同一 `region/address/port` 不允许重复。

### 2.3 Record 授权

发布时（`higgs service publish`）daemon 会对 active record 做授权检查：每个 endpoint 地址必须落在签发 Zone 自己的 active IPAM assignment 内，普通和 shared assignment 都可以授权（`AuthorizeSOCKS5Record`，复用 `routing.BuildAuthorizedRouteSet`，与 Babel 路由发布使用同一授权边界）。`active: false` 的撤销 record 跳过授权，保证服务地址失效后仍能撤销。

### 2.4 Zone selector

`allow_zones` 和 endpoint ACL 使用同一种 selector（`pkg/service/zone_selector.go`）：

| 写法 | 匹配范围 |
|---|---|
| `node-a.catofes.` | 只匹配该 Zone |
| `*.catofes.` | 匹配 `catofes.` 及全部子 Zone |
| `*.` | 匹配全部非 root Zone（不含 trust root 本身） |

通配符只允许完整的最左 `*.` 标签，不是通用 glob。

---

## 3. 配置模型

`higgs-services` 的全部输入是 `/etc/higgs/service.yaml`（可用 `-config` 覆盖）。完整示例见仓库根目录 [`service.example.yaml`](../../service.example.yaml)。一个同时发布本地 endpoint、CN Anycast 和 Asia Anycast 的配置：

```yaml
version: 1

networks:
  node:
    ipv4: "local;172.30.0.0/24;172.30.0.128/28;172.30.0.1"
    ipv6: "auto;::/112;::100/120;::1"
    # Docker direct-routing 的可信 overlay 入接口；按本机实际接口填写。
    trusted_host_interfaces: [hgs0]
  cn:
    ipv6: "tag:socks5.cn;::/112;::100/120;::1"
  asia:
    ipv6: "tag:socks5.asia;::/112;::100/120;::1"

socks5:
  networks:
    node: "::20"
    cn: "::20"
    asia: "::20"
  publish:
    node: local
    cn: cn
    asia: asia
  # allow_zones:
  #   - clients.catofes.
```

- `networks`：容器实际连接的 Docker network。`trusted_host_interfaces` 可选，生成 Compose 时成为 Docker bridge 的 `com.docker.network.bridge.trusted_host_interfaces` driver option；接口名以本机实际、稳定的 XFRM/WireGuard/veth ingress 为准。
- `socks5.networks`：每个已连接 network 的服务相对基址。
- `publish`：`network: region` 映射，只发布列出的 network；本地和 Anycast endpoint 可以同时发布任意多个。为兼容旧配置，标量形式 `publish: main` 和顶层 `region` 仍可读取，新配置应使用映射形式。
- `allow_zones`：可选的 Zone selector 列表，见第 6 节。
- `output_dir`：artifact 根目录，默认 `/etc/higgs/services`。
- `images`：通常省略。固定默认值为 `ginuerzh/gost:2.11.5` 和 `ghcr.io/higgsnet/smartdns:v1.0.4`，只有需要私有仓库或统一升级时才全局覆盖。
- `port`：SOCKS5 端口，默认 3128。

manifest 解析使用 `KnownFields(true)`，未知字段直接报错；network 名必须是小写 canonical service ID。

### 3.1 Network 描述符

IPv4 和 IPv6 使用相同格式：

```text
来源;Docker subnet;Docker 动态范围;Docker gateway
```

| 来源 | 含义 |
|---|---|
| `local` | 纯 host Docker 网络，不使用 Higgs IPAM；后三段必须写完整地址 |
| `auto` | 当前节点同地址族唯一的 active、非 shared assignment；数量不等于 1 时解析失败 |
| `assignment:<CIDR>` | 明确选择当前节点的一个 active assignment |
| `tag:<tag>` | 当前节点同地址族唯一的、带该 tag 的 active shared assignment；数量不等于 1 时解析失败 |

IPv6 assignment 来源允许后三段使用 `::` 开头的相对值。例如 assignment 为 `2a0d:2905:0:4::/96` 时，`::/112`、`::100/120`、`::1` 分别解析为该 `/96` 内的 Docker subnet、动态池和网关。

Docker 可以在动态池中自动分配未指定地址；三个服务容器使用静态相对基址，并要求落在动态池之外。例如 `::20` 产生：

| 角色 | 地址偏移 | 容器 |
|---|---|---|
| `socks` | 基址 +0 | gost，`socks5://` 监听 |
| `dns` | 基址 +1 | SmartDNS |
| `h2` | 基址 +2 | gost，`http://` 监听 |

解析器会检查角色地址位于 Docker subnet 内，且不与 gateway 或动态池冲突；不同 network 的同族 subnet 不允许重叠。

---

## 4. 地址解析与 artifact 生成

`higgs-services` 通过执行 `higgs route ipam mine`（JSON 输出）获取本机 `managed_zone` 和 active assignment 列表，然后按 manifest 做纯函数式解析，产出带 config hash 的 resolved 结构。命令：

```bash
higgs-services validate   # 打印 resolved JSON，便于检查
higgs-services render     # 生成全部 artifact
```

通用 flag：`-config`（默认 `/etc/higgs/service.yaml`）、`-higgs`（higgs CLI 路径）、`-output`（覆盖 `output_dir`）。

生成文件：

```text
/etc/higgs/services/
  networks/docker-compose.yml     # 全部 Docker network，project higgs-networks
  socks5/docker-compose.yml       # 三个服务容器，project higgs-socks5
  socks5/config/smartdns.conf     # 固定内容：bind [::]:53，上游 8.8.8.8 / 1.1.1.1
  resolved.json                   # 整个 resolved manifest
  socks5/resolved.json            # render 锁：config hash、managed zone、endpoints
  socks5/published.json           # publish 锁：上次实际发布状态
```

- Docker network 名自动为 `higgs-<network>`；Compose project name 固定为 `higgs-networks` 和 `higgs-socks5`，无需也无法在 manifest 中配置。
- SOCKS5 Compose 引用 network 为 `external: true`，因此必须先起 networks project。
- 服务端口同时发布到 `127.0.0.1` / `[::1]` loopback：这只是让 Docker 将端口标记为 direct-routing 可访问，overlay 访问仍使用容器 endpoint IP。
- Docker bridge 的 driver option 不能原地更新。修改 `trusted_host_interfaces` 后，先停止依赖该 network 的服务，删除旧 Docker network，再重新执行 Compose 命令。
- 所有文件原子写入（临时文件 + rename）。

---

## 5. 发布与撤销流程

### 5.1 标准流程

```bash
higgs-services validate
higgs-services render
docker compose -f /etc/higgs/services/networks/docker-compose.yml up -d
docker compose -f /etc/higgs/services/socks5/docker-compose.yml up -d
higgs-services publish
```

### 5.2 publish 内部步骤

`publish` 先重新执行 `higgs route ipam mine` 并重新解析 manifest，要求当前解析结果与 `socks5/resolved.json` 的 config hash、managed zone 和 endpoints **完全一致**；assignment 或配置变化后必须先重新 `render`。随后依次：

1. 从本机对每个 endpoint 的地址和端口做 3 秒 TCP 就绪检查；任一失败即终止。
2. 为每个 endpoint 安装或清理独立 ACL：配置了 `allow_zones` 时执行 `higgs firewall endpoint apply socks5-<network> --destination <ip> --protocol tcp --port <port> --allow-zone ...`；未配置时删除同名旧 ACL（表示不使用这套限制）。
3. 对 shared endpoint 执行 `higgs route announce <zone> <assignment>`，宣告整个 assignment prefix；非 shared endpoint 的路由由 `ipam.announce` 或管理员负责，`higgs-services` 不碰。
4. 用一条 `higgs service publish --endpoint region,address,port...` 发布所有 endpoints（daemon 侧做第 2.3 节的授权检查并签名入 gossip）。
5. 对照 `published.json` 清理上一版不再使用的 route 和 ACL，写入新的 `published.json`。

endpoint ACL 名为 `socks5-<network>`；受防火墙对象命名限制，`socks5-` 加 network 名总长不能超过 63 字符，manifest 解析时即报错。

### 5.3 withdraw

```bash
higgs-services withdraw
```

按 `published.json`（不存在时回退 `resolved.json`）记录的上次发布状态执行：先 `higgs service withdraw` 写入 `active: false` 的 service record，再逐个撤销 shared endpoint 的 route（`higgs route withdraw`）并删除全部 endpoint ACL，最后清空 `published.json` 的 endpoints。容器本身仍由管理员用 `docker compose down` 停止。

### 5.4 为什么宣告 assignment 而不是 `/128`

服务容器可以使用 assignment 内较小的 Docker subnet（例如 `/96` assignment 内的 `/112`），但 Babel 宣告的是授权边界，即整个 `/96`：

- 与 IPAM 的路由授权模型一致；
- 不依赖 Babel 传播 host route；
- 同一 Anycast assignment 由多个成员节点同时宣告时，Babel 按 metric/ECMP 选择路径。

当前 mesh export 上限为 IPv6 `/96`、IPv4 `/28`，被 `publish` 的 assignment 不能比该上限更具体（manifest 解析时检查）；Docker subnet 可以更具体。

### 5.5 路由生命周期分工

一个 prefix 只应选择一种生命周期控制方式：

| assignment 类型 | 路由由谁管 |
|---|---|
| 普通非 shared | 通常写入 `ipam.announce: [non-shared]`，由 daemon 持续宣告；服务停止不应撤销它，因为前缀可能同时承载节点地址 |
| 服务 Anycast（如 `tag:socks5.cn`） | 不写入 `ipam.announce`，由 `higgs-services publish/withdraw` 随服务状态宣告和撤销 |
| 长期边缘 Anycast（如 `tag:edge.c`） | 可显式写入 `ipam.announce: [tag:edge.c]`，由 daemon 持续宣告 |

---

## 6. 动态 endpoint ACL

`allow_zones` 不进入公开 service record，而是落实为本机 host firewall 的 forward 规则。链路：

```text
higgs-services publish
  → higgs firewall endpoint apply socks5-<network> ... --allow-zone <selector>
  → daemon 校验并持久化到本机状态文件（EndpointACLs）
  → firewall reconcile 时 resolveEndpointServices() 重新解析 selector
  → host 实例 forward 链生成 per-endpoint allow + 精确 drop
```

daemon 侧约束（`app/higgs/endpoint_acl.go`）：

- 必须存在启用的 host firewall instance，且 `mode: managed`、backend 可解析为 nftables 或 iptables；否则 apply 直接报错。`external` 模式的实例不参与 endpoint ACL enforcement。
- ACL destination 必须属于当前 managed Zone 的 active assignment（普通和 shared 均可）。
- selector 至少一个；对不需要限制的 endpoint 应删除整条 ACL，而不是放空 selector。

reconcile 时，daemon 用 `AuthorizedRouteSet.Announced` 把每个 selector 匹配 Zone 当前 active、已授权的 **overlay route prefix**（不是 IPsec underlay announce IP）解析为来源集合，按地址族过滤后生成规则。每个 endpoint 先生成来源 allow，再生成 destination/protocol/port 的精确 drop；selector 暂时匹配不到有效前缀时仍保留 drop，**不会退化为开放**（fail-closed）。route announcement、IPAM assignment、Zone revoke 或 announce IP 变化都会触发重新解析。规则形状见 [firewall.md](firewall.md) 第 4.4 节。

---

## 7. 验证与排障

Phase 8 的端到端验收入口是显式 root smoke，不在 `root-smoke` 或 `smoke-all` 中：

```bash
sudo make services-smoke
```

它先跑 `app/higgs-services` 单元测试，再以真实 Docker bridge、SOCKS5 与目标 TCP 容器、host 到 overlay 聚合路由、overlay 到 host static upstream、两端 BIRD/Babel 验证端到端代理数据面（包括实际完成一次 SOCKS5 代理 TCP 请求、Docker connected route 优先于更宽聚合路由的断言），并运行 BIRD Anycast 成员故障收敛测试。需要 root、Docker、`ip`、`bird`/`birdc` 和 `nft`；创建的 netns、Docker network 和容器在测试结束时清理。详见 [testing.md](testing.md)。

常见问题：

| 现象 | 检查方向 |
|---|---|
| `publish` 报 “runtime assignment or config changed; run render again” | assignment 或 manifest 在 render 后发生变化，重新 `render` 再 `publish` |
| TCP readiness 失败 | 容器未启动或角色地址冲突；确认先 `docker compose up -d`，且基址避开动态池与 gateway |
| `auto` / `tag:` 解析失败 | `higgs route ipam mine` 中同族 assignment 数量不等于 1，或 assignment 已失效 |
| endpoint ACL apply 报错 | host firewall instance 未启用或不是 `managed` 模式，或 backend 不可用；`higgs firewall endpoint list` 查看现状 |
| 服务已发布但 mesh 内不可达 | shared 路由是否已 announce（`higgs debug routing routes` 方向）、host 聚合路由与 Docker connected route 的优先级、回程 static upstream |
| 修改 `trusted_host_interfaces` 后不生效 | Docker bridge driver option 不能原地更新；停止服务、删除旧 network 后重新 `up` |

---

## 8. 已知限制

- TCP 就绪检查只说明地址可达、端口在监听，不验证 SOCKS5 握手、DNS 或真实代理出口。
- 当前只有固定的 `socks5` 一套服务；通用多服务 record 类型没有实现。
- 客户端 service selection / health policy 与应用层 source-routing relay 不属于本数据面，按产品需求作为独立后续项目评估。
- `published.json`/`resolved.json` 是本机状态锁，不进入 gossip；多节点部署同一 Anycast 服务时各节点独立执行 publish/withdraw。
