# Public Internet Daemon Gossip Test

本文档用于在真实公网的若干 Linux 节点之间验证 Phase 3 daemon gossip 收敛。目标不是模拟本机 smoke，而是在真实 UDP 网络、真实公网地址、真实 bootstrap 配置下验证：

- 多节点都运行 `higgs daemon`
- signed endpoint record 能在公网传播
- CLI `record put` 通过 daemon control socket 写入后能触发 outbound sync
- 节点重启后能从 bootstrap / discovered peers 重新收敛
- admin 签发 delegation 后，普通节点不接触 root/admin 私钥

辅助脚本位于：

```bash
docs/scripts/public-gossip-node.sh
```

脚本只是把现有 CLI 命令固定成可重复流程；不会绕过 Higgs 的签名链或信任模型。

## 当前边界

Phase 3 已经让普通 `record put`、endpoint publish、sync apply、timer tick 进入 daemon 单 writer 边界。但 admin 管理写操作仍是后续 Phase 4.0 待办：

- `delegate issue`
- `delegate revoke`
- `join accept`
- `root init`

因此本公网测试中，admin 节点签发 delegation / bundle 仍使用 CLI 直接写 admin DB。生产化前应完成 Phase 4.0，将这些写操作也纳入 daemon control API。

## 测试拓扑

推荐至少 3 个公网节点：

| 角色 | Zone | 示例公网地址 | UDP |
|------|------|--------------|-----|
| node-a | `node-a.catofes.` | `203.0.113.10` | `33434` |
| node-b | `node-b.catofes.` | `203.0.113.11` | `33434` |
| node-c | `node-c.catofes.` | `203.0.113.12` | `33434` |

另有一个 admin 工作目录，可以在你的本机或其中一台服务器上。admin 负责：

- root `.` 初始化
- `catofes.` 管理 Zone 加入
- 为 node-a/node-b/node-c 签发 delegation bundle

## 前置条件

所有公网节点：

```bash
git clone <repo> higgs
cd higgs
make build
chmod +x docs/scripts/public-gossip-node.sh
```

放通 UDP：

```bash
sudo ufw allow 33434/udp
```

或 nftables / 云安全组中放通每个节点的 `listen_addr` UDP 端口。

确认时间同步正常。gossip anti-replay 使用时间戳窗口，机器时钟偏差过大会被拒绝。

## 1. 初始化 root 和管理 Zone

在 admin 机器上：

```bash
cd higgs
chmod +x docs/scripts/public-gossip-node.sh

export HIGGS_BIN="$PWD/build/higgs"
export HIGGS_BASE="$PWD/.public-test"

docs/scripts/public-gossip-node.sh root-init "$HIGGS_BASE/root-admin" \
  | tee "$HIGGS_BASE/root-public-key.txt"

root_key="$(tail -n1 "$HIGGS_BASE/root-public-key.txt")"
```

创建 `catofes.` 管理 Zone：

```bash
docs/scripts/public-gossip-node.sh config \
  "$HIGGS_BASE/catofes-admin" \
  zone-catofes-admin \
  127.0.0.1:33435 \
  127.0.0.1:33435 \
  "$root_key"

docs/scripts/public-gossip-node.sh key-request \
  "$HIGGS_BASE/catofes-admin" \
  catofes. \
  "$HIGGS_BASE/catofes.key.json" \
  "$HIGGS_BASE/catofes.request.json"

docs/scripts/public-gossip-node.sh delegate-issue \
  "$HIGGS_BASE/root-admin" \
  "$HIGGS_BASE/catofes.request.json" \
  "$HIGGS_BASE/catofes.bundle.json"

docs/scripts/public-gossip-node.sh join-accept \
  "$HIGGS_BASE/catofes-admin" \
  "$HIGGS_BASE/catofes.bundle.json" \
  "$HIGGS_BASE/catofes.key.json"
```

## 2. 在公网节点创建配置和 join request

在 node-a 上：

```bash
cd higgs
export HIGGS_BIN="$PWD/build/higgs"
export HIGGS_DIR="$HOME/.higgs-public/node-a"
root_key="<paste root key>"

docs/scripts/public-gossip-node.sh config \
  "$HIGGS_DIR" \
  node-a.catofes. \
  0.0.0.0:33434 \
  203.0.113.10:33434 \
  "$root_key" \
  node-b.catofes. 203.0.113.11:33434 \
  node-c.catofes. 203.0.113.12:33434

docs/scripts/public-gossip-node.sh key-request \
  "$HIGGS_DIR" \
  node-a.catofes. \
  "$HIGGS_DIR/node-a.key.json" \
  "$HIGGS_DIR/node-a.request.json"
```

在 node-b 上：

```bash
cd higgs
export HIGGS_BIN="$PWD/build/higgs"
export HIGGS_DIR="$HOME/.higgs-public/node-b"
root_key="<paste root key>"

docs/scripts/public-gossip-node.sh config \
  "$HIGGS_DIR" \
  node-b.catofes. \
  0.0.0.0:33434 \
  203.0.113.11:33434 \
  "$root_key" \
  node-a.catofes. 203.0.113.10:33434 \
  node-c.catofes. 203.0.113.12:33434

docs/scripts/public-gossip-node.sh key-request \
  "$HIGGS_DIR" \
  node-b.catofes. \
  "$HIGGS_DIR/node-b.key.json" \
  "$HIGGS_DIR/node-b.request.json"
```

在 node-c 上同理，改成 `node-c.catofes.` 和 `203.0.113.12:33434`。

把三个 `*.request.json` 安全传回 admin 机器。只传 request，不传私钥。

## 3. Admin 签发 node delegation bundle

在 admin 机器上：

```bash
for node in node-a node-b node-c; do
  docs/scripts/public-gossip-node.sh delegate-issue \
    "$HIGGS_BASE/catofes-admin" \
    "$HIGGS_BASE/$node.request.json" \
    "$HIGGS_BASE/$node.bundle.json"
done
```

把对应的 `node-a.bundle.json`、`node-b.bundle.json`、`node-c.bundle.json` 发回各节点。

## 4. 节点接受 bundle 并启动 daemon

node-a：

```bash
docs/scripts/public-gossip-node.sh join-accept \
  "$HOME/.higgs-public/node-a" \
  "$HOME/.higgs-public/node-a.bundle.json" \
  "$HOME/.higgs-public/node-a/node-a.key.json"

docs/scripts/public-gossip-node.sh run-daemon "$HOME/.higgs-public/node-a" 5
```

node-b/node-c 同理。

如果你用 systemd，可以先用临时 service：

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

## 5. 写入测试 record 并验证收敛

在 node-a 上：

```bash
docs/scripts/public-gossip-node.sh put-identity \
  "$HOME/.higgs-public/node-a" \
  node-a.catofes. \
  node-a-public
```

在 node-b / node-c 上轮询：

```bash
docs/scripts/public-gossip-node.sh status "$HOME/.higgs-public/node-b"
HIGGS_CONFIG="$HOME/.higgs-public/node-b/config.yaml" build/higgs zone show node-a.catofes.
docs/scripts/public-gossip-node.sh verify "$HOME/.higgs-public/node-b" node-a.catofes.
```

预期：

- `sync status --verbose` 能看到 bootstrap peer 或 discovered peer
- `zone show node-a.catofes.` 能看到 `identity`
- `verify node-a.catofes.` 成功

## 6. NAT / CGNAT 节点 observed path 测试

如果有一台节点在家庭 NAT、CGNAT 或没有端口映射的网络后面，把它作为 `node-b` 测试。这个节点只需要能主动连到公网 `node-a`：

```bash
docs/scripts/public-gossip-node.sh config \
  "$HOME/.higgs-public/node-b" \
  node-b.catofes. \
  0.0.0.0:33434 \
  "" \
  "$root_key" \
  node-a.catofes. 203.0.113.10:33434
```

不要给 NAT 节点配置 `advertise_addr`，也不要把 reflector 结果当成一定可拨入的 direct endpoint。若要强制只测试 outbound/observed path，可在 `node-b/config.yaml` 里加：

```yaml
publish_endpoints: false
```

接受 bundle 后启动 daemon：

```bash
docs/scripts/public-gossip-node.sh run-daemon "$HOME/.higgs-public/node-b" 5
```

在公网 `node-a` 上检查：

```bash
HIGGS_CONFIG="$HOME/.higgs-public/node-a/config.yaml" build/higgs debug peer node-b.catofes.
HIGGS_CONFIG="$HOME/.higgs-public/node-a/config.yaml" build/higgs sync status --verbose
```

预期：

- `observed_addr` 显示 NAT 节点主动发来包时的 UDP 源地址。
- `observed_status` 为 `active`。
- `discovered_addr` 可以为空；这表示当前不是依赖 signed direct endpoint，而是依赖本地短期 observed UDP path。

随后在 `node-a` 写入测试 record，确认 NAT 后的 `node-b` 能收到：

```bash
docs/scripts/public-gossip-node.sh put-identity \
  "$HOME/.higgs-public/node-a" \
  node-a.catofes. \
  node-a-to-nat-b

HIGGS_CONFIG="$HOME/.higgs-public/node-b/config.yaml" build/higgs zone show node-a.catofes.
HIGGS_CONFIG="$HOME/.higgs-public/node-b/config.yaml" build/higgs verify node-a.catofes.
```

如果 `observed_status` 很快过期，说明 NAT 映射生命周期较短；缩短 daemon interval 或后续引入 relay / hole punching。

## 7. 重启和恢复测试

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

## 8. 撤销测试

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

## 排障 checklist

- UDP 端口是否在云安全组和本机防火墙都放通。
- `advertise_addr` 是否是其他公网节点能访问的地址，而不是 `0.0.0.0` 或内网地址。
- 每个节点的 `trusted_root_public_key` 是否完全相同。
- `bootstrap.id` 是否等于对端 `peer_id`，通常是 Zone FQDN，如 `node-a.catofes.`。
- 节点时钟是否同步。
- daemon 是否真的在线：`sync status --verbose` 顶部应出现 `daemon: online peer_id=...`。
- 如果公网 IP 会变化，使用 `reflectors: auto`，但要记住远端只信任本节点签名发布后的 endpoint record。
- NAT / CGNAT 节点没有端口映射时，不要把 reflector IP 当成可被主动拨入的 direct endpoint；先看公网 peer 上的 `observed_addr` / `observed_status` 是否 active。
- 公网 gossip 不依赖 IP fragmentation；保持默认 `max_datagram_bytes: 1200`。大 record / snapshot 应通过 object pull 收敛，不要把调大 UDP datagram 当成公网修复方式。
