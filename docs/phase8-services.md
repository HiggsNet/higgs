# Phase 8：服务发布与独立部署工具

Phase 8 把可信网络状态和容器部署拆开：Higgs 管理 IPAM、路由宣告、签名 service record 和动态网络授权；独立程序 `higgs-services` 读取 `/etc/higgs/service.yaml`，从 Higgs 运行态解析地址并生成 Docker Compose。Higgs daemon 不理解镜像、容器或 Compose，也不会调用 Docker API。

当前只提供一套固定名为 `socks5` 的服务。它由 `socks`、`dns`、`h2` 三个容器组成，不需要额外的实例名、ID、Compose project name 或 container name。

## 1. 职责边界

`higgs` 负责：

- 保存普通和 shared Anycast assignment；
- 校验服务 endpoint 属于当前 Zone 的 active assignment；
- 显式宣告或撤销服务使用的整个 assignment prefix；
- 签名、发布和撤销固定的 `services/socks5` record；
- 根据 Zone selector 动态维护 host FORWARD endpoint ACL。

`higgs-services` 负责：

- 读取 service manifest，解析本地 `auto` 和 shared assignment tag；
- 规划多 network 下三个容器的地址；
- 生成 network Compose、SOCKS5 Compose、SmartDNS 配置和状态锁文件；
- 对所有待发布 endpoint 做 TCP 就绪检查；
- 编排 ACL、route announcement 和 service record 的发布/撤销顺序。

管理员仍负责执行 `docker compose up/down/pull`。`render` 只生成 artifact，不会启动容器；`publish` 也不会管理容器生命周期。

## 2. Assignment：本地地址与 Anycast 地址

本地节点地址继续使用普通 assignment，不加 tag。配置里的 `auto` 只选择当前节点同地址族唯一的 active、非 shared assignment，因此节点分配地址时不必预先声明自己运行什么服务。

跨节点共用的 Anycast assignment 可以增加稳定 tag，例如 `socks5.cn`、`socks5.asia`：

```bash
higgs ipam assign catofes. 2a0d:2905:0:4::/96 \
  --to node-a.catofes. --shared --tag socks5.cn
higgs ipam assign catofes. 2a0d:2905:0:4::/96 \
  --to node-b.catofes. --shared --tag socks5.cn
```

约束如下：

- `tag` 只能用于 `shared` assignment；普通本地 assignment 不需要 tag。
- 同一个 tag 在同一地址族中必须对应同一个 prefix；IPv4 和 IPv6 可以共用 tag。
- tag 是选择 assignment 的稳定名字，不代表服务类型、region 或节点角色，也不会自动发布路由。
- 同一 owner 下的 shared assignment 按成员分别保存，所以可以独立撤销某个节点：

```bash
higgs ipam revoke assignment catofes. 2a0d:2905:0:4::/96 \
  --to node-a.catofes.
```

## 3. `/etc/higgs/service.yaml`

一个同时发布本地 endpoint、CN Anycast 和 Asia Anycast 的示例：

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

`networks` 表示容器实际连接的 Docker network。`trusted_host_interfaces` 是可选的宿主 overlay 入接口列表；生成 Compose 时会成为 Docker bridge 的 `com.docker.network.bridge.trusted_host_interfaces` driver option，接口名以本机实际、稳定的 XFRM/WireGuard/veth ingress 为准。`socks5.networks` 为每个已连接 network 指定相对基址。`publish` 是 `network: region` 映射：只发布列出的 network，也可以同时列出任意数量的本地和 Anycast endpoint。

为了兼容旧配置，标量形式 `publish: main` 和顶层 `region` 仍可读取，但新配置应使用映射形式。

### 3.1 Network 描述符

IPv4 和 IPv6 使用相同格式：

```text
来源;Docker subnet;Docker 动态范围;Docker gateway
```

| 来源 | 含义 |
|---|---|
| `local` | 纯 host Docker 网络，不使用 Higgs IPAM；后三段必须写完整地址。 |
| `auto` | 当前节点同地址族唯一的 active、非 shared assignment。 |
| `assignment:<CIDR>` | 明确选择当前节点的一个 active assignment。 |
| `tag:<tag>` | 当前节点同地址族唯一的、带该 tag 的 active shared assignment。 |

IPv6 assignment 来源允许后三段使用 `::` 开头的相对值。例如 assignment 为 `2a0d:2905:0:4::/96` 时，`::/112`、`::100/120`、`::1` 分别解析为该 `/96` 内的 Docker subnet、动态池和网关。

Docker 可以在动态池中自动分配未指定地址；三个服务容器仍使用静态相对基址，并要求落在动态池之外。例如 `::20` 产生：

| 角色 | 地址偏移 |
|---|---|
| `socks` | `::20` |
| `dns` | `::21` |
| `h2` | `::22` |

解析器会检查它们位于 Docker subnet 内，且不与 gateway 或动态池冲突。

全部 network 写入同一个文件：

```text
/etc/higgs/services/networks/docker-compose.yml
```

SOCKS5 artifact 固定写入：

```text
/etc/higgs/services/socks5/docker-compose.yml
/etc/higgs/services/socks5/config/smartdns.conf
/etc/higgs/services/socks5/resolved.json
/etc/higgs/services/socks5/published.json
```

Docker network 名自动为 `higgs-<network>`，Compose project name 自动为 `higgs-networks` 和 `higgs-socks5`。无需在 manifest 中配置。

### 3.2 镜像默认值

普通配置可以完全省略 `images`。当前固定默认值为：

```yaml
images:
  gost: ginuerzh/gost:2.11.5
  smartdns: ghcr.io/higgsnet/smartdns:v1.0.4
```

只有需要私有仓库或统一升级时才全局覆盖。

## 4. 发布与撤销

标准流程：

```bash
higgs-services validate
higgs-services render
docker compose -f /etc/higgs/services/networks/docker-compose.yml up -d
docker compose -f /etc/higgs/services/socks5/docker-compose.yml up -d
higgs-services publish
```

Docker bridge 的 driver option 不能原地更新。修改 `trusted_host_interfaces` 后，先停止依赖该 network 的服务，删除旧 Docker network，再重新执行上述 Compose 命令。生成的 SOCKS5 Compose 会把服务端口发布到 loopback；这只用于让 Docker 将端口标记为 direct-routing 可访问，overlay 访问仍使用容器 endpoint IP。

`publish` 会重新查询 `higgs ipam mine`，要求当前解析结果与 `resolved.json` 的配置 hash、managed Zone 和 endpoints 完全一致。assignment 或配置发生变化时必须先重新 `render`。

随后它依次：

1. 从本机对每个 endpoint 的 SOCKS5 地址和端口做 3 秒 TCP 就绪检查；
2. 为每个 endpoint 安装或清理独立 ACL；
3. 对 shared endpoint 用 `higgs route announce` 宣告整个 assignment prefix；非 shared endpoint 的路由由 IPAM 配置或管理员负责；
4. 用一条 `service.socks5.v1` record 发布所有 endpoints；
5. 清理上一版不再使用的 route 和 ACL，并写入 `published.json`。

TCP 检查只说明地址可达且端口在监听，不验证 SOCKS5 握手、DNS 或真实代理出口。

撤销使用：

```bash
higgs-services withdraw
```

它先写入 `active:false` 的 service record，再根据 `published.json` 撤销 shared routes 和全部 endpoint ACL。旧版没有 `active` 字段以及只有单个 `region/address/port` 的 record 仍可读取。

### 4.1 为什么宣告 assignment，而不是 `/128`

服务容器可以使用 assignment 内较小的 Docker subnet，例如 `/96` assignment 内的 `/112`。Babel 宣告的是授权边界，也就是整个 `/96`，不是某个容器的 `/128`：

- 与 IPAM 的路由授权模型一致；
- 不依赖 Babel 传播 host route；
- 同一 Anycast assignment 由多个成员节点同时宣告时，Babel 可按 metric/ECMP 选择路径。

当前 mesh export 上限为 IPv6 `/96`、IPv4 `/28`，所以被 `publish` 的 assignment 不能比该上限更具体。Docker subnet 可以更具体。

非 shared assignment 通常由 Higgs 持续宣告；服务停止只撤销 service record，不应撤销可能承载节点地址或其他用途的普通前缀：

```yaml
ipam:
  announce:
    - non-shared
```

`tag:socks5.cn` 之类的服务 Anycast 不写入 `ipam.announce`，由 `higgs-services` 随服务健康状态宣告和撤销。`tag:edge.c` 之类的长期边缘 Anycast 可以显式写入 `ipam.announce`。一个 prefix 应只选择一种生命周期控制方式。

## 5. 多 endpoint service record

新记录以 endpoints 数组同时描述本地和 Anycast 地址：

```json
{
  "type": "socks5",
  "endpoints": [
    {"region": "local", "address": "fd42:1::20", "port": 3128},
    {"region": "cn", "address": "2a0d:2905:0:4::20", "port": 3128},
    {"region": "asia", "address": "2a0d:2905:0:5::20", "port": 3128}
  ]
}
```

record 不包含 network 名、assignment tag 或 `allow_zones`。这些都是发布节点的本地部署/安全策略；公开记录只表达客户端真正需要的 region、address 和 port。每个 endpoint 都必须属于签发 Zone 的 active assignment，普通和 shared assignment 都可以授权。

## 6. `allow_zones` 与动态 ACL

selector 支持：

| 写法 | 匹配范围 |
|---|---|
| `node-a.catofes.` | 只匹配该 Zone。 |
| `*.catofes.` | 匹配 `catofes.` 及全部子 Zone。 |
| `*.` | 匹配全部非 root Zone。 |

`allow_zones` 不进入公开 service record。`higgs-services` 为每个发布 network 创建独立 endpoint ACL；daemon 在 route announcement、IPAM assignment、Zone revoke 或 announce IP 变化时重新解析 selector，将匹配 Zone 当前 active、已授权的 overlay route prefix 同步到 host FORWARD 规则。这里使用 overlay 路由前缀，不是 IPsec underlay announce IP。

容器位于 host Docker bridge，所以 ACL 需要一个启用 `host: true`、`mode: managed` 的 firewall instance。ACL destination 必须属于当前 Zone 的 active assignment；普通和 shared assignment 都支持。

每个 endpoint 先生成来源 allow，再生成 destination/protocol/port 的精确 drop。selector 暂时匹配不到有效前缀时仍保留 drop，不会退化为开放。未配置 `allow_zones` 表示不使用这套限制，publish 会删除同名旧 ACL。

## 7. 验收与范围结论

已完成：

- shared assignment tag、按成员存储和精确撤销；
- `auto` 本地网络和 `tag:` Anycast 网络解析；
- 双栈、多 network 的 Compose 生成；
- 多 endpoint service record 及旧单 endpoint record 兼容；
- publish/withdraw 对 TCP readiness、ACL、整段 route 和 record 的编排；
- endpoint ACL 持久化以及动态 host firewall reconcile；生成的 bridge network 通过 Docker 的 `trusted_host_interfaces` 支持受信任 overlay interface 到已发布 endpoint 的 direct routing。
- 已实现 `services-smoke`：真实 Docker bridge 上的 SOCKS5/目标 TCP 容器、两端
  BIRD/Babel、host 聚合路由和 static upstream 回程组成的 root smoke；它会
  断言 Docker connected route 比更宽的 host→overlay 聚合路由优先，并实际
  完成一次 SOCKS5 代理 TCP 请求。
- 复用 BIRD 的三节点 Anycast failover smoke，验证 shared prefix 的成员故障
  后收敛；服务 shared assignment、route announce 和 publish 编排由单元测试覆盖。

运行完整 Phase 8 验收：

```bash
sudo make services-smoke
```

该目标要求 root、可创建 network namespace 的 Linux 环境、本机 BIRD 和可用的
Docker daemon；不会进入默认 `make test`。它创建的 BIRD、netns、Docker network
和容器均在测试结束时清理。

客户端 service selection/health policy 与应用层 source-routing relay 不属于 SOCKS5
发布数据面，按产品需求作为独立后续项目评估。`services-smoke` 在目标 root 环境
通过后，即可将本阶段归档。
