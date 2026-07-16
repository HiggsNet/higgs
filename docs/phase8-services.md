# Phase 8：服务发布与独立部署工具

Phase 8 把“可信服务发现”和“容器部署”明确拆开：Higgs 只管理 IPAM、签名 service record 和动态网络授权；独立程序 `higgs-services` 负责读取 `/etc/higgs/service.yaml`、规划地址并生成 Docker Compose。Higgs daemon 不理解镜像、容器或 Compose，也不会调用 Docker API。

## 1. 组件边界

`higgs` 负责：

- 提供当前节点有效的 IPAM assignment；
- 校验服务地址属于当前 Zone 的 active、非 shared assignment；
- 签名、发布和撤销 `service.socks5.v1` record；
- 后续根据 Zone selector 动态维护 endpoint ACL。

`higgs-services` 负责：

- 读取独立 service manifest；
- 解析 network 描述符和相对地址；
- 为一套 SOCKS5 服务规划 `socks`、`dns`、`h2` 三个容器；
- 生成 network Compose、每套服务的 Compose、SmartDNS 配置和解析锁文件；
- 发布前重新核对运行态，并进行 TCP 健康检查。

管理员负责执行 `docker compose up/down/pull`。生成 artifact 不等于启动或发布服务。

## 2. `/etc/higgs/service.yaml`

最小示例：

```yaml
version: 1

networks:
  main:
    ipv4: "local;172.30.0.0/24;172.30.0.128/28;172.30.0.1"
    ipv6: "auto;::/112;::100/120;::1"

socks5:
  egress-cn:
    region: cn-east
    publish: main
    networks:
      main: "::20"
```

`egress-cn` 是服务名称，不再额外配置 `id`、`type`、Compose project name 或 container name。一项 `socks5` 配置代表一整套三容器服务，不是单个容器实例。

### 2.1 Network 描述符

IPv4 和 IPv6 使用同一格式：

```text
来源;Docker subnet;Docker 动态范围;Docker gateway
```

来源包括：

| 来源 | 含义 |
|---|---|
| `local` | 纯 host Docker 网络，不使用 Higgs IPAM；后三段写完整地址。 |
| `auto` | 使用当前节点唯一的同地址族 active、非 shared assignment。存在零个或多个都会失败。 |
| `assignment:<CIDR>` | 明确选择当前节点的一个 assignment。 |

IPv6 非 local 网络允许使用 `::` 开头的相对 subnet、动态池和 gateway。例如 assignment 为 `fd42:1::/64` 时，`::/112` 会解析为 `fd42:1::/112`。

每个 network 的 Docker 名固定为 `higgs-<network>`。全部 network 写入同一文件：

```text
/etc/higgs/services/networks/docker-compose.yml
```

### 2.2 三容器服务与多 network

每个 SOCKS5 服务生成三个 Compose service：

| 角色 | 地址 |
|---|---|
| `socks` | network base address |
| `dns` | base address + 1 |
| `h2` | base address + 2 |

例如 `main: "::20"` 解析为 `::20`、`::21` 和 `::22`。三者都必须位于 subnet 内，且不能占用 gateway 或 Docker 动态池。

一套服务可以连接多个 network：

```yaml
socks5:
  egress-cn:
    region: cn-east
    publish: main
    networks:
      main: "::20"
      cn: "::30"
```

当前 `service.socks5.v1` 只发布一个 endpoint，因此 `publish` 必须指定其中一个 network。其他 network 只是容器的额外接入网络。

服务 artifact 默认位于：

```text
/etc/higgs/services/socks5/egress-cn/docker-compose.yml
/etc/higgs/services/socks5/egress-cn/config/smartdns.conf
/etc/higgs/services/socks5/egress-cn/resolved.json
```

Compose project name 自动为 `higgs-<service>`。不设置 `container_name`，由 Compose 使用 project 和 role 名生成。

### 2.3 镜像默认值

默认镜像使用仓库旧模板中已有的固定版本，不使用 `latest`：

```yaml
images:
  gost: ginuerzh/gost:2.11.5
  smartdns: ghcr.io/higgsnet/smartdns:v1.0.4
```

普通配置可以完全省略 `images`。需要私有仓库或统一升级时才全局覆盖，不在每个服务中重复配置。

## 3. 命令流程

检查 manifest 和当前 assignment：

```text
higgs-services validate
```

生成 artifact：

```text
higgs-services render
```

管理员检查并启动：

```text
docker compose -f /etc/higgs/services/networks/docker-compose.yml up -d
docker compose -f /etc/higgs/services/socks5/egress-cn/docker-compose.yml up -d
```

发布 record：

```text
higgs-services publish egress-cn
```

发布前会重新查询 `higgs ipam mine`，并与 `resolved.json` 的 config hash 和地址比较；assignment 或配置发生变化时必须重新 render。随后执行 TCP 健康检查，最后调用：

```text
higgs service publish egress-cn --region cn-east --address fd42:1::20 --port 3128
```

撤销：

```text
higgs-services withdraw egress-cn
```

它调用 `higgs service withdraw egress-cn`，写入 `active:false` 的新版本。旧版没有 `active` 字段的 record 仍按 active 处理，保持向后兼容。

## 4. `allow_zones` 与当前安全边界

`allow_zones` 属于服务提供节点的本地策略，绝不进入公开 service record。selector 支持：

| 写法 | 匹配范围 |
|---|---|
| `node-a.catofes.` | 精确 Zone。 |
| `*.catofes.` | `catofes.` 及全部子 Zone。 |
| `*.` | 全部非 root Zone。 |

最终实现应由 Higgs 的通用 endpoint ACL 接口保存 `{destination, protocol, port, selectors}`，并在 route announcement、IPAM assignment 或 Zone revoke 变化时，把匹配 Zone 当前 active、已授权的 overlay route prefix 原子更新到 nftables set。这里使用的是 overlay 路由前缀，不是 IPsec underlay announce IP。

当前 endpoint ACL apply/reconcile 尚未实现。为了避免配置看似受限但实际对所有来源开放，`higgs-services publish` 遇到非空 `allow_zones` 会 fail-closed。`render` 和 `validate` 仍会解析并保存 selector，便于下一切口直接接入 ACL。

## 5. 已实现与后续切口

当前已实现：

- 独立 manifest 与 `higgs-services validate/render`；
- IPAM 运行态解析、双栈 network Compose 和多 network 三容器 Compose；
- 固定镜像默认值、默认目录和自动 project name；
- resolved lock、发布前新鲜度检查和 TCP 健康检查；
- `higgs service publish/withdraw`、地址归属校验与可传播撤销记录；
- Zone selector 语法。

后续独立实现：

- 通用 `higgs firewall endpoint apply/remove` 与 daemon 动态 reconcile；
- SOCKS5/H2 的真实容器和跨 mesh smoke；
- shared Anycast allocation；
- 多 endpoint record、服务选择和应用层 relay。
