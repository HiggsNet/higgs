# Public Internet Daemon Gossip Test

本文档用于在真实公网 Linux 节点之间验证 Phase 3 daemon gossip 收敛。它不是本机 smoke 的替代品，而是一次真实网络演练：真实 UDP、真实公网地址、真实 bootstrap、真实 daemon。

最短路径只需要四类动作：

1. admin 机器初始化 root 和 `catofes.` 管理 Zone。
2. 每个公网节点生成自己的配置和 join request。
3. admin 批量签发 bundle。
4. 各节点接受 bundle、启动 daemon、写 record、验证收敛。

配套脚本：

```bash
docs/scripts/public-gossip-node.sh
```

脚本只是把现有 CLI 命令组合成可重复流程；不会绕过 Higgs 的签名链或信任模型。

## 当前边界

Phase 4.0 已经让 admin 管理写操作优先进入 daemon 单 writer/control API 边界：

- `delegate issue`
- `delegate revoke`
- `join accept`

如果对应目录的 daemon 已运行，CLI 会通过本机 control socket 提交请求，并由 daemon 串行写 DB；如果 daemon 不存在，则保留 direct 写 DB 的开发/恢复模式并输出提示。`root init` 仍是 daemon 启动前的离线初始化；已有 daemon 加载 state 时会拒绝 root 重置。

## 测试拓扑

推荐至少 3 个公网节点，先让它们都能互相 UDP 直连：

| 角色 | Zone | 示例公网地址 | UDP |
|------|------|--------------|-----|
| node-a | `node-a.catofes.` | `203.0.113.10` | `33434` |
| node-b | `node-b.catofes.` | `203.0.113.11` | `33434` |
| node-c | `node-c.catofes.` | `203.0.113.12` | `33434` |

admin 工作目录可以放在你的本机，也可以放在其中一台服务器上。admin 只负责 root / delegation；普通节点不接触 root/admin 私钥。

## Peer ID 与 Zone

公网 gossip 的默认身份模型是：`peer_id` 等于该进程持有私钥并管理的授权 Zone FQDN。短名字只作为人类角色名、目录名或主机名使用：

| 人类角色名 | 配置中的 `peer_id` / Zone |
|------------|---------------------------|
| catofes admin | `catofes.` |
| node-a | `node-a.catofes.` |
| node-b | `node-b.catofes.` |
| node-c | `node-c.catofes.` |

例如 `zone-catofes-admin` 可以作为目录名或 systemd service 名，但不应作为公网 gossip `peer_id`。节点收到包时先按 `peer_id` 查入站 allowlist；allowlist 来自静态 `bootstrap` 和已验证的 Zone/delegation chain。`catofes.` 能通过 root delegation 被自动准入，但 `zone-catofes-admin` 这种别名没有对应的 ZonePath，除非显式放进 `bootstrap`。

## 准备

所有机器：

```bash
git clone <repo> higgs
cd higgs
make build
chmod +x docs/scripts/public-gossip-node.sh
export HIGGS_BIN="$PWD/build/higgs"
```

所有公网节点放通 gossip UDP 端口，以及同数字端口的 TCP object pull：

```bash
sudo ufw allow 33434/udp
sudo ufw allow 33434/tcp
```

云安全组 / nftables 也要放通相同端口。UDP 用于 gossip digest / fetch / announce，小包超过公网 MTU 预算时会通过 TCP object pull 拉取完整 snapshot 或 record；如果 TCP 不通，节点可能反复 `fetch_zone` 直到触发 `quota`。确认时间同步正常；gossip anti-replay 使用时间戳窗口，机器时钟偏差过大会被拒绝。

如果 `catofes.` 管理节点也参与公网 gossip，并使用 `33435`：

```bash
sudo ufw allow 33435/udp
sudo ufw allow 33435/tcp
```

## 1. Admin 初始化

在 admin 机器上：

```bash
cd higgs
export HIGGS_BIN="$PWD/build/higgs"
export HIGGS_BASE="$PWD/.public-test"

mkdir -p "$HIGGS_BASE"
docs/scripts/public-gossip-node.sh admin-init "$HIGGS_BASE" | tee "$HIGGS_BASE/admin-init.log"
```

输出里会有三行关键结果：

```text
root_public_key: <copy-this-to-each-node>
root_admin_dir: .public-test/root-admin
admin_zone_dir: .public-test/catofes-admin
```

其中 `.public-test/catofes-admin/config.yaml` 的 `peer_id` 是 `catofes.`；`catofes-admin` 只是本地目录名。

把 `root_public_key` 复制给每台公网节点。下面用：

```bash
root_key="<paste root_public_key>"
```

## 2. 每个公网节点初始化

node-a：

```bash
cd higgs
export HIGGS_BIN="$PWD/build/higgs"
root_key="<paste root_public_key>"

docs/scripts/public-gossip-node.sh node-init \
  "$HOME/.higgs-public/node-a" \
  node-a.catofes. \
  0.0.0.0:33434 \
  203.0.113.10:33434 \
  "$root_key" \
  node-b.catofes. 203.0.113.11:33434 \
  node-c.catofes. 203.0.113.12:33434
```

node-b：

```bash
cd higgs
export HIGGS_BIN="$PWD/build/higgs"
root_key="<paste root_public_key>"

docs/scripts/public-gossip-node.sh node-init \
  "$HOME/.higgs-public/node-b" \
  node-b.catofes. \
  0.0.0.0:33434 \
  203.0.113.11:33434 \
  "$root_key" \
  node-a.catofes. 203.0.113.10:33434 \
  node-c.catofes. 203.0.113.12:33434
```

node-c 同理，把 Zone 和公网地址改成 `node-c.catofes.` / `203.0.113.12:33434`。

每次 `node-init` 都会输出：

```text
request: /home/.../.higgs-public/node-a/node-a.request.b64
key: /home/.../.higgs-public/node-a/node-a.key.json
```

把每个节点的 `*.request.b64` 传回 admin 机器。只传 request，不传 `*.key.json`。

示例：

```bash
scp node-a:~/.higgs-public/node-a/node-a.request.b64 "$HIGGS_BASE/"
scp node-b:~/.higgs-public/node-b/node-b.request.b64 "$HIGGS_BASE/"
scp node-c:~/.higgs-public/node-c/node-c.request.b64 "$HIGGS_BASE/"
```

## 3. Admin 批量签发

在 admin 机器上：

```bash
docs/scripts/public-gossip-node.sh issue-nodes \
  "$HIGGS_BASE/catofes-admin" \
  "$HIGGS_BASE/node-a.request.b64" \
  "$HIGGS_BASE/node-b.request.b64" \
  "$HIGGS_BASE/node-c.request.b64"
```

脚本会生成：

```text
bundle: .public-test/node-a.bundle.b64
bundle: .public-test/node-b.bundle.b64
bundle: .public-test/node-c.bundle.b64
```

把对应 bundle 发回各节点：

```bash
scp "$HIGGS_BASE/node-a.bundle.b64" node-a:~/.higgs-public/node-a/
scp "$HIGGS_BASE/node-b.bundle.b64" node-b:~/.higgs-public/node-b/
scp "$HIGGS_BASE/node-c.bundle.b64" node-c:~/.higgs-public/node-c/
```

## 4. 启动 daemon

每台节点用一条命令接受 bundle 并启动 daemon。

node-a：

```bash
docs/scripts/public-gossip-node.sh accept-run \
  "$HOME/.higgs-public/node-a" \
  node-a.catofes. \
  "$HOME/.higgs-public/node-a/node-a.bundle.b64" \
  5
```

node-b：

```bash
docs/scripts/public-gossip-node.sh accept-run \
  "$HOME/.higgs-public/node-b" \
  node-b.catofes. \
  "$HOME/.higgs-public/node-b/node-b.bundle.b64" \
  5
```

node-c 同理。测试时可以直接在 tmux / screen 里跑；长期运行再改成 systemd。

临时 systemd service 示例：

```ini
[Unit]
Description=Higgs daemon public gossip test
After=network-online.target

[Service]
WorkingDirectory=/opt/higgs
Environment=HIGGS_CONFIG=/home/higgs/.higgs-public/node-a/config.yaml
ExecStart=/opt/higgs/build/higgs daemon --interval 5
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

## 5. 写入并验证收敛

在 node-a 写入测试 record：

```bash
docs/scripts/public-gossip-node.sh put-identity \
  "$HOME/.higgs-public/node-a" \
  node-a.catofes. \
  node-a-public
```

在 node-b / node-c 验证：

```bash
docs/scripts/public-gossip-node.sh status "$HOME/.higgs-public/node-b"
HIGGS_CONFIG="$HOME/.higgs-public/node-b/config.yaml" build/higgs zone show node-a.catofes.
docs/scripts/public-gossip-node.sh verify "$HOME/.higgs-public/node-b" node-a.catofes.
```

预期：

- `sync status --verbose` 顶部显示 `daemon: online peer_id=...`
- 能看到 bootstrap peer 或 discovered peer
- `zone show node-a.catofes.` 能看到 `identity`
- `verify node-a.catofes.` 成功

反向也跑一次：在 node-b 写 `identity`，在 node-a/node-c 验证。

## 6. NAT / CGNAT 节点

如果有一台节点在家庭 NAT、CGNAT 或没有端口映射的网络后面，把它作为 `node-b` 测试。它只需要能主动连到公网 `node-a`。

初始化时不要给 NAT 节点配置 `advertise_addr`，也不要让它发布 signed endpoint record：

```bash
docs/scripts/public-gossip-node.sh node-init \
  "$HOME/.higgs-public/node-b" \
  node-b.catofes. \
  0.0.0.0:33434 \
  "" \
  "$root_key" \
  node-a.catofes. 203.0.113.10:33434
```

在 `node-b/config.yaml` 里加：

```yaml
publish_endpoints: false
```

这个设置应在 NAT 节点首次启动 daemon 前加入。如果节点已经发布过 `sync/endpoint/udp` record，旧 record 仍会留在本地 Zone snapshot 里；测试时建议重新初始化该节点目录，或先用一个小的、明确可达的 endpoint record 覆盖它。不要把 reflector 得到的公网 IP 当成可被主动拨入的 signed endpoint，除非已经配置端口映射。

当前 object pull 是接收方主动向发送方发起 TCP 连接，TCP 端口默认和对端 UDP gossip 使用同一个数字端口。因此，NAT/内网节点可以做 outbound-only gossip，但不适合做需要被公网节点拉取大对象的 bootstrap/authority 源。如果日志同时出现：

```text
exceeds datagram budget
fetch_zone
quota
```

且该 peer 在 NAT 后面，说明公网节点正在尝试补齐一个 UDP 放不下的对象，但无法通过 TCP object pull 反向连接该 NAT peer。当前 daemon 会在已准入 UDP path 上使用 UDP chunk fallback 兜底；如果仍反复触发 `quota`，短期处理方式是避免 NAT peer 产生超预算对象，尤其是禁用 endpoint 发布。更复杂拓扑仍需要 relay、hole punching 或反向 object push。

接受 bundle 并启动 daemon 后，在公网 node-a 上检查：

```bash
HIGGS_CONFIG="$HOME/.higgs-public/node-a/config.yaml" build/higgs debug peer node-b.catofes.
HIGGS_CONFIG="$HOME/.higgs-public/node-a/config.yaml" build/higgs sync status --verbose
```

预期：

- `observed_addr` 显示 NAT 节点主动发来包时的 UDP 源地址。
- `observed_status` 为 `active`。
- `discovered_addr` 可以为空；这表示当前依赖本地短期 observed UDP path，而不是 signed direct endpoint。

随后在 node-a 写入 record，确认 NAT 后的 node-b 能收到：

```bash
docs/scripts/public-gossip-node.sh put-identity \
  "$HOME/.higgs-public/node-a" \
  node-a.catofes. \
  node-a-to-nat-b

HIGGS_CONFIG="$HOME/.higgs-public/node-b/config.yaml" build/higgs zone show node-a.catofes.
HIGGS_CONFIG="$HOME/.higgs-public/node-b/config.yaml" build/higgs verify node-a.catofes.
```

如果 `observed_status` 很快过期，说明 NAT 映射生命周期较短；缩短 daemon interval，或后续引入 relay / hole punching。

## 7. 重启恢复

停止 node-b daemon：

```bash
pkill -f 'higgs daemon'
```

在 node-a 写入更高版本：

```bash
docs/scripts/public-gossip-node.sh put-identity \
  "$HOME/.higgs-public/node-a" \
  node-a.catofes. \
  node-a-after-b-down
```

重新启动 node-b daemon 后，node-b 应通过摘要比较补齐缺失版本。

## 8. 撤销检查

在 admin 机器上撤销 node-c：

```bash
HIGGS_CONFIG="$HIGGS_BASE/catofes-admin/config.yaml" \
  "$HIGGS_BIN" delegate revoke node-c.catofes. public-test-revoke
```

当前这是 admin 直写 DB 的 recovery/admin 路径。让 `catofes-admin` 或任一已经获得该更新的节点参与 gossip 后，其他节点应逐步看到：

```bash
HIGGS_CONFIG="$HOME/.higgs-public/node-a/config.yaml" build/higgs debug zone node-c.catofes.
HIGGS_CONFIG="$HOME/.higgs-public/node-a/config.yaml" build/higgs verify node-c.catofes.
```

预期：

- `debug zone` 显示 revoked
- `verify node-c.catofes.` 失败
- `sync status --verbose` 不再把 node-c endpoint 作为有效 discovered peer 使用

## 常用底层命令

组合命令覆盖常规测试。需要拆开排查时，可直接使用这些底层命令：

```bash
docs/scripts/public-gossip-node.sh root-init <dir>
docs/scripts/public-gossip-node.sh config <dir> <peer-id> <listen-addr> <advertise-addr> <root-public-key> [<bootstrap-id> <bootstrap-addr> ...]
docs/scripts/public-gossip-node.sh key-request <dir> <zone> <key.json> <request.b64>
docs/scripts/public-gossip-node.sh delegate-issue <admin-dir> <request.b64> <bundle.b64>
docs/scripts/public-gossip-node.sh join-accept <dir> <bundle.b64> <key.json>
docs/scripts/public-gossip-node.sh run-daemon <dir> [interval-seconds]
docs/scripts/public-gossip-node.sh put-identity <dir> <zone> <value>
docs/scripts/public-gossip-node.sh status <dir>
docs/scripts/public-gossip-node.sh verify <dir> <zone>
```

## 排障 Checklist

- UDP 端口是否在云安全组和本机防火墙都放通。
- `advertise_addr` 是否是其他公网节点能访问的地址，而不是 `0.0.0.0` 或内网地址。
- 每个节点的 `trusted_root_public_key` 是否完全相同。
- `bootstrap.id` 是否等于对端 `peer_id`，通常是 Zone FQDN，如 `catofes.` 或 `node-a.catofes.`；不要把 `zone-catofes-admin` 这类角色名当成公网 gossip `peer_id`。
- TCP object pull 端口是否放通；默认和对端 UDP gossip 使用同一个数字端口。日志里如果同时出现 `exceeds datagram budget`、重复 `fetch_zone` 和 `quota`，先检查 TCP object pull 连通性；对 NAT/outbound-only peer，再检查是否出现 `applied zone ... via UDP chunks` 和 `chunk_fallbacks`。
- 节点时钟是否同步。
- daemon 是否真的在线：`sync status --verbose` 顶部应出现 `daemon: online peer_id=...`。
- 如果公网 IP 会变化，使用 `reflectors: auto`，但要记住远端只信任本节点签名发布后的 endpoint record。
- NAT / CGNAT 节点没有端口映射时，不要把 reflector IP 当成可被主动拨入的 direct endpoint；先看公网 peer 上的 `observed_addr` / `observed_status` 是否 active。
- 公网 gossip 不依赖 IP fragmentation；保持默认 `max_datagram_bytes: 1200`。大 record / snapshot 应通过 object pull 收敛，不要把调大 UDP datagram 当成公网修复方式。
