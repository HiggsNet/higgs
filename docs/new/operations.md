# Higgs 日常操作

本文整理当前实现下最常用的运行、检查和恢复路径。它面向 operator：先让节点安全跑起来，再知道出问题时从哪里看。

命令示例默认使用已安装到 PATH 的 `higgs`。

## 配置选择

默认配置路径是 `/etc/higgs/config.yaml`。多节点实验时应显式指定：

```bash
HIGGS_CONFIG=/tmp/higgs-a/config.yaml higgs sync status
```

如果用 `sudo` 排查系统数据面，注意保留环境变量：

```bash
sudo -E env HIGGS_CONFIG=/tmp/higgs-a/config.yaml higgs debug links
```

否则 root 进程可能读取 `/etc/higgs/config.yaml` 或另一个状态库，导致 debug 输出和你以为的节点不一致。

## 初始化信任链

推荐把 root admin、一级管理 Zone 和普通节点分开。

Root admin 只管理 `.`：

```bash
HIGGS_CONFIG=/tmp/higgs-admin/config.yaml higgs root init
HIGGS_CONFIG=/tmp/higgs-admin/config.yaml higgs root pubkey
```

一级管理 Zone 先生成 key 和 join request：

```bash
HIGGS_CONFIG=/tmp/higgs-catofes/config.yaml higgs keygen /tmp/catofes.key.json
HIGGS_CONFIG=/tmp/higgs-catofes/config.yaml higgs join request catofes. /tmp/catofes.key.json
```

把 request 交给 root admin 签发：

```bash
HIGGS_CONFIG=/tmp/higgs-admin/config.yaml higgs delegate issue --cap write,delegate,allocate-ip <request-payload>
```

再把 bundle 交回管理 Zone：

```bash
HIGGS_CONFIG=/tmp/higgs-catofes/config.yaml higgs join accept <bundle-payload> /tmp/catofes.key.json
HIGGS_CONFIG=/tmp/higgs-catofes/config.yaml higgs verify catofes.
```

普通节点重复同样流程，只是 delegation 由 `catofes.` 管理节点签发，而不是 root admin 直接签发。

当前 CLI 支持复制粘贴 base64 payload；需要落盘时也兼容旧 JSON 文件路径。

`root init` 创建的 root authority 默认拥有当前所有内建权限，包括 `delegate`、`write`、`write:route` 和 `allocate-ip`。子 Zone 默认只获得 `write,delegate`；如果一个管理 Zone 需要分配 IPAM pool/assignment，应在 `delegate issue` 时显式加 `--cap write,delegate,allocate-ip`。已有 delegation 可由父 Zone 管理端原地升级：

```bash
HIGGS_CONFIG=/tmp/higgs-admin/config.yaml higgs authority grant catofes. allocate-ip catofes-authority.b64
HIGGS_CONFIG=/tmp/higgs-catofes/config.yaml higgs join accept catofes-authority.b64
```

首次 `join accept` 仍需要传入 `key.json`；已经加入的管理端接受 authority refresh bundle 时可以省略 key，CLI 会使用本地 state meta 中的 `zone_private_key` 校验并保留原有本地状态。

如果 root admin 保持离线，它写入的 root Zone records 不会自动进入在线 gossip 网络。可以把 root Zone signed snapshot 导出成文件，再交给在线管理端导入：

```bash
HIGGS_CONFIG=/tmp/higgs-admin/config.yaml higgs ipam pool create . 2a0d:2905::/32 --delegated-to .
HIGGS_CONFIG=/tmp/higgs-admin/config.yaml higgs ipam pool create . 2a0d:2905::/58 --delegated-to catofes.
HIGGS_CONFIG=/tmp/higgs-admin/config.yaml higgs recovery export-zone . root-zone.b64

HIGGS_CONFIG=/tmp/higgs-catofes/config.yaml higgs recovery import-zone root-zone.b64
```

`delegated_to` 是精确 owner，不是向下继承开关。第一条 `delegated_to=.` 只让 root 拥有 `/32`；第二条才让 `catofes.` 精确拥有 `/58`，从而可以继续切子池或发布 assignment。子 Zone 不能直接使用 ancestor 的 self pool；缺少显式覆盖 pool 时，CLI 会以 `ipam_pool_owner_mismatch` 或 `ipam_assignment_pool_mismatch` 早失败。

`export-zone` / `import-zone` 搬运的是已签名 Zone snapshot，不搬运 root 私钥；导入端仍会按 trusted root、delegation chain 和 record signature 做验证。`import-zone` 会优先通过本机 daemon control socket 导入，输出里出现 `via daemon` 表示写入已经进入在线 daemon 的内存状态和 DB；如果使用旧版本命令，在线 daemon 可能把直接 DB 写入覆盖掉，先停 daemon 再导入。

排查本机视角时用 `higgs ipam mine` 查看分配给 `managed_zone` 的 assignment 和本 Zone 精确拥有/发布的 pool；排查单个地址或前缀时用 `higgs ipam get <addr-or-prefix>`，必要时加 `--json` 取得 pool chain、best pool、assignment、route 和诊断码。

## 启动 Daemon

推荐长期运行入口是 `higgs daemon`：

```bash
HIGGS_CONFIG=/etc/higgs/config.yaml higgs daemon
```

临时排障时可以指定较短 interval，靠事件触发同步：

```bash
HIGGS_CONFIG=/tmp/higgs-a/config.yaml higgs daemon --interval 60
```

daemon 做这些事：

- 监听 UDP gossip。
- 发布本节点 endpoint 和 transport records。
- 处理 object pull。
- 接收 control socket 上的本机写入请求。
- 执行 IPsec、routing、firewall、health reconcile。
- 提供 Observer API/UI。

CLI 写操作会优先尝试 running daemon 的 control socket；daemon 不在线时，部分命令会回退为直接写本地状态。

## 手动同步

长期运行用 daemon。排障时可用手动同步命令。

查看同步状态：

```bash
HIGGS_CONFIG=/tmp/higgs-a/config.yaml higgs sync status --verbose
```

对某个 peer 执行一次同步：

```bash
HIGGS_CONFIG=/tmp/higgs-a/config.yaml higgs sync once node-b.catofes.
```

启动兼容的被动 UDP 服务：

```bash
HIGGS_CONFIG=/tmp/higgs-b/config.yaml higgs sync serve
```

旧的常驻同步入口仍可用，但 daemon 是推荐入口：

```bash
HIGGS_CONFIG=/tmp/higgs-a/config.yaml higgs sync run --interval 5
```

`sync once` 如果输出 pending zones，通常表示对端已返回摘要，但还有对象需要继续拉取；再跑一轮或交给 daemon 后台收敛。

## 常用 Debug

基础状态：

```bash
higgs sync status --verbose
higgs zone show node-b.catofes.
higgs verify node-b.catofes.
```

Gossip 和 peer：

```bash
higgs debug peer node-b.catofes.
higgs debug peers
higgs debug zone node-b.catofes.
higgs debug records node-b.catofes. --prefix endpoints/
higgs debug endpoints
```

数据面：

```bash
higgs debug links
higgs debug routes
higgs debug route 10.42.0.0/24
higgs debug babel
higgs debug firewall
higgs debug health
higgs debug rotate-port
higgs debug revoke-impact node-b.catofes.
```

底层数据库：

```bash
higgs db stats
higgs db dump
```

`debug` 命令通常会优先读取 daemon live state；daemon 不在线时读取本地状态文件和最近一次 runtime snapshot。

## 开启 Debug Log

临时打开：

```bash
HIGGS_LOG_LEVEL=debug HIGGS_CONFIG=/tmp/higgs-a/config.yaml higgs daemon
```

或写入配置：

```yaml
log:
  level: debug
  mode: stderr+file
  file: /var/log/higgs.log
```

debug log 常见字段包括 peer、message type、zone/record 数量、字节数、耗时、reject reason、object pull、relay、quota、IPsec reconcile action 等。

常见 reject reason：

- `unknown_peer`：对端不在 bootstrap 或 verified peer 集合中。
- `addr_mismatch`：peer ID 与来源地址不匹配。
- `message_too_large`：UDP datagram 超过预算。
- `replay`：nonce/timestamp 防重放拒绝。
- `quota`：peer 触发 byte/object rate limit。
- `verify_failed`：Zone trust chain 或 record 签名验证失败。
- `unsupported_wire_version`：wire version 不兼容。

## Observer

配置 `observer:` 后，daemon 会启动只读 HTTP/API 控制台。默认建议绑定 loopback：

```yaml
observer:
  listen: 127.0.0.1:8080
```

启动 daemon 后访问：

```text
http://127.0.0.1:8080/
```

Observer 适合看当前节点的 zones、peers、links、routes、BIRD、health 和 events。它是只读入口；写操作仍通过 CLI/control socket。

如果要看 health 历史曲线，需要配置本地 spool：

```yaml
health:
  metrics:
    local_spool_path: /var/lib/higgs/health-spool
```

## IPsec / StrongSwan 排障

先从 Higgs 自己的视角看：

```bash
HIGGS_CONFIG=/etc/higgs/config.yaml higgs debug links
HIGGS_CONFIG=/etc/higgs/config.yaml higgs debug endpoints
```

再看系统状态：

```bash
swanctl --list-sas
ip xfrm state
ip xfrm policy
ip link show type xfrm
```

如果使用 netns：

```bash
ip netns exec h2 ip link
ip netns exec h2 ip route
ip netns exec h2 ip -6 route
```

排查时按层分开：

- IKE/CHILD_SA 是否 established。
- XFRM state/policy 和 XFRM interface 是否在预期 namespace。
- tunnel address 和 peer route 是否存在。
- BIRD/Babel 是否看到邻居和路由。
- firewall 是否放行 ingress/forward/output。

不要只凭 `swanctl --list-sas` 判断数据面已经通了。SA established 只说明协商成功，不说明内层 tunnel route、namespace placement 或 firewall 都正确。

## Routing / BIRD 排障

先看 Higgs read model：

```bash
higgs debug routes
higgs debug route 10.42.0.0/24
higgs debug babel
higgs debug links
```

再看 BIRD：

```bash
birdc -s /var/lib/higgs/bird/bird-default.ctl show status
birdc -s /var/lib/higgs/bird/bird-default.ctl show protocols
birdc -s /var/lib/higgs/bird/bird-default.ctl show route all
```

实际 control socket 路径取决于 `routing.instances[].control_socket`，未配置时在 `<data_dir>/bird/` 下。

## Firewall 排障

Higgs 视角：

```bash
higgs debug firewall
```

系统视角：

```bash
nft list ruleset
iptables -S
iptables -t nat -S
```

如果 firewall instance 绑定 netns，要在对应 namespace 中查看：

```bash
ip netns exec h2 nft list ruleset
ip netns exec h2 iptables -S
```

Higgs 只应管理带 owner 边界的规则。发现规则残留时，先确认它是否是 Higgs-owned，再决定是否用 recovery 或手工清理。

## 恢复操作

从 peer 显式拉回某个 Zone：

```bash
higgs recovery pull-zone node-b.catofes. --from node-b.catofes.
```

拉回某个 Zone 及祖先链：

```bash
higgs recovery pull-chain node-b.catofes. --from node-b.catofes.
```

清理本机 Higgs 管理的 IPsec 链路：

```bash
sudo -E env HIGGS_CONFIG=/etc/higgs/config.yaml higgs recovery cleanup-ipsec
```

`cleanup-ipsec` 会优先走 daemon；daemon 不在线时直接读取本地状态并调用配置的 IPsec/XFRM driver。它会拒绝清理无法验证为 Higgs-owned 的 link。

## 常见问题入口

**看不到 peer**

先查：

```bash
higgs sync status --verbose
higgs debug endpoints
higgs debug peer <peer-id>
```

重点确认 `peer_id`、bootstrap 地址、`publish_endpoints`、endpoint discovery mode、trusted root，以及命令是否读了正确的 `HIGGS_CONFIG`。

**record 没传播**

先确认本地是否写入、签名是否有效：

```bash
higgs zone show <zone>
higgs verify <zone>
```

再看同步状态和 debug log。大对象或 UDP 受限环境下，object pull / UDP chunk fallback 可能是关键路径。

**IPsec 记录发布了但不建链**

检查三件事：

- 本机是否有 `overlays[]` link group。
- 远端 `ipsec/profile`、`ipsec/addresses`、`ipsec/ports`、`ipsec/transport-key`、`ipsec/overlays/<id>` 是否都在 verified active state。
- 本机 connect/deny policy、address family、path mode、accept intent 是否匹配。

**sudo 后输出不对**

优先检查环境：

```bash
env | rg 'HIGGS_CONFIG|HIGGS_STATE|HIGGS_CONTROL_SOCKET'
sudo -E env | rg 'HIGGS_CONFIG|HIGGS_STATE|HIGGS_CONTROL_SOCKET'
```

很多“状态不一致”其实是 root 进程读了另一个 config 或另一个 state path。

## 推荐阅读顺序

先读：

1. `docs/new/overall.md`
2. `docs/new/config.md`
3. `docs/new/operations.md`
4. `docs/new/testing.md`

再按问题进入模块文档：gossip、transport、routing、firewall、health、observer。
