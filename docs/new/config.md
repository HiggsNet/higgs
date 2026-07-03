# Higgs 配置结构

Higgs 默认读取 `/etc/higgs/config.yaml`。本地开发或同一机器多节点运行时，通常用 `HIGGS_CONFIG=/path/to/config.yaml` 指定配置文件。

配置文件描述的是**本机 daemon 如何运行**，不是全网数据库本身。会进入 gossip 的内容必须由本节点签名成 Zone record；本地配置只决定是否发布这些 record，以及如何把 verified active state 收敛成本机 runtime 状态。

完整注释模板见仓库根目录的 `config.example.yaml`。本文只整理主要结构和边界。

## 读取规则

当前配置加载器使用严格 YAML 字段校验。写错字段名会直接报错，不会静默忽略。

几个读取规则需要注意：

- `HIGGS_CONFIG` 覆盖默认配置路径。
- `HIGGS_STATE` 覆盖最终状态数据库路径，优先级高于配置里的 `state_path`。排障时要确认它没有指向另一个节点。
- `trusted_root_public_key` 也兼容 `root_public_key` / `trusted_root_key`。
- gossip 身份、bootstrap、同步限额和 endpoint discovery 必须写在 `gossip:` 下。
- 一些列表字段仍兼容旧的逗号分隔字符串，但新配置应使用 YAML list。
- duration 字段使用 Go duration 写法，例如 `5s`、`10m`、`1h`。

默认状态目录是 `/etc/higgs`，默认数据库是 `<data_dir>/higgs.db`。如果没有显式配置文件，程序会使用内置默认值；真正部署建议始终写明 `data_dir`、`trusted_root_public_key`、`gossip.peer_id` 和必要的 `gossip.bootstrap`。

## 最小节点配置

一个只跑 gossip/daemon 的普通节点大致需要：

```yaml
data_dir: /etc/higgs
trusted_root_public_key: <base64-ed25519-public-key>

gossip:
  peer_id: node-a.catofes.
  listen_addr: "[::]:33434"
  bootstrap:
    - id: node-b.catofes.
      addr: 203.0.113.20:33434
  init:
    managed_zone: node-a.catofes.
    key_path: /etc/higgs/identity.key.json
```

字段含义：

- `trusted_root_public_key`：本机信任根。普通节点必须配置，避免误信任本地残留状态。
- `gossip.init.managed_zone`：本节点负责写入的 Zone，普通节点通常就是自己的 FQDN。
- `gossip.init.key_path`：本节点写 record 用的 ED25519 私钥路径。私钥不写进 YAML。
- `gossip.peer_id`：gossip peer ID。现代配置建议等于 `gossip.init.managed_zone`。
- `gossip.listen_addr`：本地 UDP gossip 监听地址，默认 `[::]:33434`，通常同时接收 IPv4 和 IPv6。
- `gossip.bootstrap`：启动时允许联系的已知 peer。运行中还会从 verified endpoint record 更新 peer 地址。

## Gossip 与发现

Gossip 相关配置控制 UDP 消息大小、对象同步和 endpoint 发布。

常用字段：

```yaml
gossip:
  advertise_addrs:
    - 203.0.113.10:33434

  # max_datagram_bytes: 1200
  # max_sync_zones: 16
  # max_sync_records: 1024

  # endpoint_discovery: all
  # publish_endpoints: true

  # reflectors: auto
  # reflector_interval: 5m
  # reflector_timeout: 3s

  # endpoint_ttl: 3h
  # endpoint_refresh: 30m
  # endpoint_grace: 10m
  # endpoint_source_order:
  #   - advertise
  #   - bootstrap
  #   - reflector
  #   - interface
  # filter_private_ipv4: true
```

字段说明：

- `gossip.advertise_addrs`：管理员显式发布的 gossip endpoint，优先级高于 reflector 和接口扫描；它不是 IPsec endpoint，IPsec 地址使用 `ipsec.announce_addrs` / `ipsec.announce_dns`。
- `gossip.max_datagram_bytes`：单个 gossip UDP datagram 的最大字节预算。公网环境不应依赖 IP fragmentation，大对象和大 snapshot 应通过 object pull 收敛。
- `gossip.max_sync_zones` / `gossip.max_sync_records`：单次 announce/snapshot 携带的 Zone 和 record 数量上限。
- `gossip.endpoint_discovery`：endpoint 发现模式，可设为 `all`、`loopback_only` 或 `advertise_only`。如果未设置且 bootstrap 都是 loopback，daemon 会自动按 `loopback_only` 处理，避免本地 smoke 发布无关接口地址。
- `gossip.publish_endpoints`：是否发布本节点 signed endpoint record。`false` 适合 outbound-only 或 NAT/CGNAT 节点；禁用发布后，本节点仍可主动连接 bootstrap 或已知 peer。
- `gossip.reflectors` / `gossip.reflector_interval` / `gossip.reflector_timeout`：公网 IP reflector 来源、刷新间隔和单次请求超时。`reflectors: auto` 使用内置列表；`off` / `none` 禁用公网 reflector。
- `gossip.endpoint_ttl` / `gossip.endpoint_refresh` / `gossip.endpoint_grace`：signed endpoint record 的可用窗口、地址集合不变时的低频续租间隔，以及 endpoint 变化后继续保留旧地址的窗口。
- `gossip.endpoint_source_order`：出站连接候选地址的来源优先级，常见值是 `advertise`、`bootstrap`、`reflector`、`interface`。
- `gossip.filter_private_ipv4`：是否过滤接口扫描得到的 RFC1918 IPv4，默认 `true`。私网实验需要发布内网地址时再设为 `false`。

## 日志

日志默认输出到 stderr。daemon 部署时可以复制到文件或 syslog：

```yaml
log:
  level: info
  mode: stderr+file
  file: /var/log/higgs.log
```

支持级别是 `debug`、`info`、`warn`、`error`。`HIGGS_LOG_LEVEL=debug` 可以临时覆盖配置，常用于排查 gossip、object pull、relay、IPsec reconcile 和限流原因。

## Netns

`netns` 声明本机会使用的 network namespace。overlay、routing 和 firewall 都通过名字引用这里的定义。

```yaml
netns:
  default:
    kind: name
    name: h2
    create: true
  # edge:
  #   kind: name
  #   name: edge
  #   create: true
```

`default` 是 overlay link group、routing instance 和非 host firewall instance 的默认 netns。其他名字，例如 `edge`，与 `default` 并列声明，供 `overlays[].netns`、`routing.instances[].netns` 和 `firewall.instances[].netns` 引用。

## IPsec Provider

`ipsec:` 配置本机 IPsec provider。它本身不等于“加入 mesh”；只有配置了使用 `provider: strongswan` 的 `overlays[]` 后，daemon 才会发布本节点 signed `ipsec/*` records。

```yaml
ipsec:
  accept: bidirectional
  # driver: strongswan
  vici_socket: /run/charon.vici

  port_mode: fixed
  # port_previous_grace: 2h

  announce_addrs:
    - 203.0.113.10:4500
  announce_dns:
    - vpn-a.example.com
  announce_gossip_endpoints: true
```

主要字段：

- `accept`：`none`、`inbound`、`bidirectional`。表达本节点 IPsec 连接意图。
- `driver`：`strongswan` 或 `dry-run`。默认 `strongswan`；无 root/VICI/XFRM 的开发环境用 `dry-run`。
- `vici_socket`：StrongSwan VICI socket 路径。Higgs 不负责启动 charon。
- `port_mode`：`fixed` 或 `range`。`range` 需要配置 `port_range`。
- `port_rotate_interval`：range 模式下 advertised port 的轮换周期；为 0 时不主动轮换。
- `port_previous_grace`：旧 advertised port 保留窗口，必须覆盖 overlay rotate retention。
- `announce_addrs` / `announce_dns`：IPsec 专用地址或 DNS 发布来源，独立于 `gossip.advertise_addrs`。
- `announce_gossip_endpoints`：是否把 gossip endpoint discovery 的地址也作为 IPsec 地址候选来源，默认 true。

## Overlay Link Policy

`overlays[]` 是本机 mesh policy。它决定本节点想和哪些 peer 建链、用哪个 provider、放入哪个 netns。它不直接进入 gossip。

```yaml
overlays:
  - id: ipsec-main
    provider: strongswan
    netns: default
    default_path_mode: family-redundant
    # max_peers: 256
    # max_links_per_peer: 2

    tunnel_address:
      mode: derived-pool
      family: ipv6
      pool: fd00:4242::/64

    # reconcile:
    #   interval: 1m
    #   rotate_retention: 1h
    #   backoff:
    #     initial: 1s
    #     max: 1m

    connect:
      - "strongswan://*.catofes.?accept=bidirectional&family=dual&source=manual-dns,discovery&mode=family-redundant"
    deny:
      - "strongswan://*.lab.catofes."
```

字段说明：

- `id` / `name`：overlay link group 标识。`id` 是推荐字段，并会用于发布 `ipsec/overlays/<id>` intent；两端要进入同一个 overlay，必须配置相同的 `id`，否则 planner 会认为缺少对应 overlay intent。
- `provider`：数据面 provider，当前主线是 `strongswan`。只有配置了使用 `strongswan` 的 overlay 后，daemon 才会发布本节点 signed `ipsec/*` records。
- `netns`：引用顶层 `netns` 中声明的名字；省略时使用 `netns.default`。
- `default_path_mode`：远端候选地址的建链模式，常用 `family-redundant`，按 IPv4/IPv6 family 选 contact point；`exhaustive` 会保留更多候选。
- `max_peers` / `max_links_per_peer`：限制本 group 参与的 peer 数量和每个 peer 的 link 数量。
- `tunnel_address`：隧道接口地址分配方式。IPv6 默认 `derived-link-local`；显式地址池优先用 `derived-pool`。`sequential-pool` 只适合旧配置迁移或测试。
- `reconcile.interval`：周期安全扫频，用于 SA 观察和恢复；它不是每次变更的唯一触发，daemon 也会按 state/config/VICI 事件触发 reconcile。
- `reconcile.rotate_retention`：staged rotate 成功后，本地继续保留旧 generation 的窗口。
- `reconcile.backoff`：provider apply 失败后的重试退避，不是正常 reconcile 频率。
- `connect` / `deny`：本机 mesh policy 规则，只影响本节点想和哪些 peer 建链，不公开给远端。

## Routing 与 IPAM

Routing 采用 per-netns BIRD/Babel 模型。一个 netns 对应一个 BIRD 实例，同一 netns 内的 overlay 共享 Babel 邻居和路由表。

```yaml
ipam:
  auto_announce_assigned_ips: false

routing:
  instances:
    - id: main
      # netns: default
      provider: bird
      mode: managed
      table: main
      metric_base: 100
      metric_staged: 200
      metric_draining: 500
      interface_pattern: hgs*
```

字段说明：

- `routing.instances[].netns` 引用顶层 `netns`；省略时使用 `netns.default`。
- `provider` 当前只支持 `bird`。
- `mode` 可为 `managed`、`external`、`disabled`。
- 未指定 `control_socket`、`pid_file`、`config_file` 时，默认写到 `<data_dir>/bird/`。
- `upstream` 可让 Higgs 创建 veth，把 mesh netns 接到主网络或另一个 namespace。
- `ipam.auto_announce_assigned_ips` 为 true 时，daemon 会把分配给 `managed_zone` 的 IPAM assignment 自动发布为 route announcement。

## Firewall

Firewall 配置按 instance 声明。instance 可以绑定某个 netns，也可以绑定 host。

```yaml
firewall:
  instances:
    - id: h2
      # netns: default
      mode: managed
      backend: auto
      default_policy: drop
      xfrm_tunnel_pattern: hgs*
      forwarding:
        transit: false
        allow_prefixes:
          - 10.42.0.0/16

    - id: host-ipsec
      host: true
      mode: managed
      backend: auto
```

字段说明：

- `backend` 可为 `auto`、`nft`、`iptables`、`none`。
- `mode` 可为 `managed`、`external`、`disabled`。
- 非 host instance 的 `netns` 引用顶层 `netns`；省略时使用 `netns.default`。
- netns instance 默认匹配 `hgs*` XFRM tunnel interface。
- host instance 用于 ingress、IKE/NAT-T 端口和 range 模式 redirect grace。
- 当 `ipsec.port_mode=range` 且存在 host firewall instance 时，host IPsec ports 和 redirect grace 默认启用；如果这些规则由外部防火墙管理，应显式关闭。

Firewall 规则是本机 runtime 状态，不进入 gossip。

## Health

`health:` 块存在时默认启用，除非写 `disabled: true`。

```yaml
health:
  interval: 5s
  timeout: 1s
  burst: 3
  loss_window: 20
  fail_threshold_consecutive: 3
  loss_threshold: "0.2"
  down_loss_threshold: "0.6"
  recover_consecutive: 5
  metrics:
    local_spool_path: /var/lib/higgs/health-spool
    local_spool_max_age: 6h
```

Health 结果用于本机 debug、observer、metrics 和 rotate/cutover gate。当前第一版不会把 health 直接写入 gossip active state。

`health.metrics.local_spool_path` 会写本地历史样本，Observer 的 health series API 从这里读取。

## Observer

`observer:` 块存在时默认启用，除非写 `disabled: true`。默认监听 `127.0.0.1:8080`。

```yaml
observer:
  listen: 127.0.0.1:8080
  ui_path: ""
  event_buffer_seconds: 0
```

Observer 是只读 HTTP/API 控制台，建议默认绑定 loopback，再由 SSH tunnel、反向代理或内网 ACL 暴露。

## Peer Lifecycle

`peer_lifecycle` 控制本机如何看待长期未同步、未观测到的 peer，以及何时清理 Higgs-owned runtime 资源。它不删除 gossip 数据库里的 Zone records，也不会向全网同步“删除 peer”的状态。

```yaml
peer_lifecycle:
  stale_after: 15m
  offline_after: 12h
  cleanup_after: 48h
  keep_sa_while_stale: true
```

字段说明：

- `stale_after`：超过这个时间未同步/未观测到 peer 后，本机把它标记为 `stale`。默认仍保留已有 SA，避免短暂网络抖动就拆链。
- `offline_after`：超过这个时间后，本机把 peer 标记为 `offline`，新的主动连接和重试会更保守。
- `cleanup_after`：长期 offline 后，本机可以清理 Higgs-owned 数据面资源，例如 IPsec SA、XFRM interface、routing/firewall 状态和 peer cache 里的可达地址。
- `keep_sa_while_stale`：peer 只是 `stale` 时是否保留已有 SA，默认 `true`。

约束是 `stale_after < offline_after < cleanup_after`。被撤销的 peer 会走更主动的本机清理路径；revocation 本身是 signed state，会继续通过 gossip 同步和保留用于验证/审计。

## 常见配置边界

- `gossip.advertise_addrs` 是 gossip endpoint；`ipsec.announce_addrs` / `ipsec.announce_dns` 是 IPsec endpoint。
- `ipsec:` 只配置 provider；`overlays[]` 才是是否参与 mesh 建链的开关。
- `netns` 是本机 runtime 归属，不进入 gossip。
- `overlays[].connect/deny` 是本机策略，不进入 gossip。
- `routing`、`firewall`、`health`、`observer` 都是本机 runtime/观测模块；它们消费 verified state，但不改变 trust chain。
