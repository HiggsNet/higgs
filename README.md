# Higgs

Higgs 是一个实验性的“信任优先”网络配置系统。当前实现已经覆盖本地 Zone 状态、ED25519 签名、Delegation 信任链、bbolt 持久化、节点准入工具，以及 Phase 2 的多节点 UDP gossip 同步。

详细设计见 [docs/design.md](docs/design.md)。可执行任务路线见 [todo.md](todo.md)。

## 当前设计

Higgs 的状态按 Zone 组织。每个 Zone 包含 `ZoneAuthority`、对子 Zone 的已签名 `Delegation`，以及本 Zone 内的已签名 Records。节点只有在能从本地信任的 root authority 验证到目标 Zone 时，才接受远端状态。

当前信任模型：

- Root Zone `.` 持有根 authority 公钥。
- 父 Zone 通过签名 `Delegation` 委派子 Zone。
- 每个 Zone authority 包含一个或多个 ED25519 公钥。当前实现仍只支持 `threshold=1`。
- Record 必须由该 Zone authority 授权的 key 签名。
- Gossip 收到的数据先视为不可信；信任链和签名验证通过后，才提升到 active state。

当前 gossip 使用 UDP 和 MessagePack wire codec：

- 默认端口：`33434`
- wire version：MessagePack payload 带 `version: 1`，外层 magic 为 `higgs.gossip.m1`；短期兼容读取旧 JSON `higgs.gossip.v1`
- 消息类型：`PING`、`PONG`、`FETCH_ZONE`、`FETCH_RECORD`、`ANNOUNCE`
- 默认限制：单个 UDP datagram 1200 bytes、单次 announce 16 个 Zone snapshot、单 Zone snapshot 1024 条 record
- 防重放：nonce + timestamp window
- peer allowlist：启动时来自 `bootstrap`；运行中会加入已通过信任链验证的 Zone peer，并从 signed endpoint record 更新出站地址
- 同步模型：先交换 Zone digest 与小 metadata；超出 datagram 预算的大 snapshot / record 通过短连接 TCP object pull 拉取，active record 以 Zone authority 签名的最新版本为准，历史只保留有限窗口用于调试和短期补洞

`gossip.proto` 记录了未来协议形状，但当前构建不需要 `protoc`。

## 配置文件

默认读取 `./config.yaml`。如果要在同一个 checkout 下运行多个节点，可以用 `HIGGS_CONFIG=/path/to/config.yaml` 指定配置文件。

示例：

```yaml
data_dir: .higgs
peer_id: node-a
listen_addr: 127.0.0.1:33434
max_datagram_bytes: 1200
max_sync_zones: 16
max_sync_records: 1024
log_level: info

bootstrap:
  - id: node-b
    addr: 127.0.0.1:33435

trusted_root_public_key: <base64-ed25519-public-key>
```

字段说明：

- `data_dir`：本地状态目录。bbolt 数据库位于 `<data_dir>/higgs.db`。
- `peer_id`：gossip peer ID。
- `listen_addr`：UDP gossip 监听地址。也可以用 `listen_port`。
- `max_datagram_bytes` / `target_datagram_bytes`：单个 gossip UDP datagram 的安全预算，默认 `1200`。旧字段 `max_message_bytes` 仍兼容读取，但公网推荐保持 1200；调大只适合实验或已知 MTU 的内网诊断。
- `max_sync_zones`：单次 `ANNOUNCE` 最多携带的 Zone snapshot 数，默认 `16`。
- `max_sync_records`：单个 Zone snapshot 或 record announce 最多携带的 record 数，默认 `1024`。
- `log_level`：日志级别，支持 `debug` / `info` / `warn` / `error`，也可用 `HIGGS_LOG_LEVEL` 覆盖。默认运行日志写入 stderr，格式为 `ts=... level=... component=... event=...`，会标明 `gossip` / `sync` / `transport` / `endpoint` / `object_pull` 等类别。设置为 `debug` 会输出更详细的收发包、relay、backoff、object pull 等诊断字段；周期同步里的重复超时会按 peer 和原因汇总，下一次输出时带 `suppressed=N`。
- `bootstrap`：已知 gossip peer。未知 peer ID 或地址会被拒绝。
- `trusted_root_public_key`：期望的 root authority 公钥。设置后，本地状态必须匹配该公钥。CLI 默认输出 base64 编码的裸 32-byte Ed25519 public key；配置仍兼容读取 hex。

模板见 [config.example.yaml](config.example.yaml)。

## 构建与测试

```bash
make check
```

该命令会执行格式化、`go vet`、测试，以及 `CGO_ENABLED=0` 构建。Makefile 默认使用 `/tmp/higgs-gocache` 和 `/tmp/higgs-gomodcache`，便于在受限环境中运行。

其他常用目标：

```bash
make build
make join-smoke
make phase1-smoke
make phase2-smoke
make phase2-run-smoke
make multi-node-smoke
make chain-relay-smoke
make discovery-smoke
make reflector-smoke
make bootstrap-join-smoke
make delegation-revoke-smoke
make object-pull-smoke
```

`make join-smoke` 和 `make reflector-smoke` 不依赖真实 UDP peer。其他 gossip smoke 会启动本地 UDP peer，因此运行环境需要允许本地 UDP socket。

## 同步诊断

常用状态检查：

```bash
HIGGS_CONFIG=/tmp/higgs-a/config.yaml build/higgs sync status --verbose
HIGGS_CONFIG=/tmp/higgs-a/config.yaml build/higgs debug peer node-b
HIGGS_CONFIG=/tmp/higgs-a/config.yaml build/higgs debug zone node-b.catofes.
```

开启结构化 debug log：

```bash
HIGGS_LOG_LEVEL=debug HIGGS_CONFIG=/tmp/higgs-a/config.yaml build/higgs sync once node-b
```

debug log 输出到 stderr，字段包含消息方向、peer ID、message type、zone/record 数量、字节数、耗时，以及 reject reason（如 `unknown_peer`、`addr_mismatch`、`message_too_large`、`replay`、`quota`、`verify_failed`、`unsupported_wire_version`）。

## 创建独立管理节点

先创建一个独立的 `node-admin`。它只管理根域 `.`，负责签发一级 Zone delegation，不作为普通业务节点参与配置写入，也不持有 `catofes.` 的私钥。

```bash
mkdir -p /tmp/higgs-admin
cat >/tmp/higgs-admin/config.yaml <<'EOF'
data_dir: /tmp/higgs-admin
peer_id: node-admin
listen_addr: 127.0.0.1:33433
EOF

HIGGS_CONFIG=/tmp/higgs-admin/config.yaml build/higgs root init
HIGGS_CONFIG=/tmp/higgs-admin/config.yaml build/higgs root pubkey
```

`root init` 只会创建：

- Root Zone `.` 的 root authority
- 保存在本地 bbolt 状态库中的 root 私钥

`root pubkey` 输出的根公钥应写入普通节点的 `trusted_root_public_key`。

这个节点的状态库里只保存 root 私钥。普通节点和 `catofes.` 管理节点都不应复制这个 DB，也不应接触 root 私钥。

## 委派一级管理 Zone

`catofes.` 也应该作为独立 Zone 加入，而不是由 root admin 直接持有它的私钥。可以创建一个 `zone-catofes-admin`，专门管理 `catofes.` 以及它下面的子 Zone。

```bash
mkdir -p /tmp/higgs-catofes
cat >/tmp/higgs-catofes/config.yaml <<'EOF'
data_dir: /tmp/higgs-catofes
peer_id: zone-catofes-admin
listen_addr: 127.0.0.1:33436
trusted_root_public_key: <root-public-key-from-node-admin>
EOF
```

在 `zone-catofes-admin` 上生成 key 和加入申请：

```bash
HIGGS_CONFIG=/tmp/higgs-catofes/config.yaml build/higgs keygen /tmp/catofes.key.json
HIGGS_CONFIG=/tmp/higgs-catofes/config.yaml build/higgs join request catofes. /tmp/catofes.key.json /tmp/catofes.request.json
```

把 `/tmp/catofes.request.json` 交给 `node-admin`，由根域 `.` 签发 `catofes.` 的 delegation：

```bash
HIGGS_CONFIG=/tmp/higgs-admin/config.yaml build/higgs delegate issue /tmp/catofes.request.json /tmp/catofes.bundle.json
```

把 bundle 交还给 `zone-catofes-admin`：

```bash
HIGGS_CONFIG=/tmp/higgs-catofes/config.yaml build/higgs join accept /tmp/catofes.bundle.json /tmp/catofes.key.json
HIGGS_CONFIG=/tmp/higgs-catofes/config.yaml build/higgs verify catofes.
```

之后：

- `node-admin` 只持有 `.` 的私钥。
- `zone-catofes-admin` 持有 `catofes.` 的私钥。
- `node-a`、`node-b` 等业务节点由 `zone-catofes-admin` 委派。

## 加入普通节点

普通节点都通过 join 流程加入。下面用 `node-a.catofes.` 和 `node-b.catofes.` 举例。它们的 delegation 由 `zone-catofes-admin` 签发，而不是由 root admin 直接签发。

先创建 node A 的配置：

```bash
mkdir -p /tmp/higgs-a
cat >/tmp/higgs-a/config.yaml <<'EOF'
data_dir: /tmp/higgs-a
peer_id: node-a
listen_addr: 127.0.0.1:33434
bootstrap:
  - id: node-b
    addr: 127.0.0.1:33435
trusted_root_public_key: <root-public-key-from-node-admin>
EOF
```

在 node A 上生成 key 和 join request：

```bash
HIGGS_CONFIG=/tmp/higgs-a/config.yaml build/higgs keygen /tmp/node-a.key.json
HIGGS_CONFIG=/tmp/higgs-a/config.yaml build/higgs join request node-a.catofes. /tmp/node-a.key.json /tmp/node-a.request.json
```

把 `/tmp/node-a.request.json` 交给 `zone-catofes-admin`，由 `catofes.` 签发 delegation bundle：

```bash
HIGGS_CONFIG=/tmp/higgs-catofes/config.yaml build/higgs delegate issue /tmp/node-a.request.json /tmp/node-a.bundle.json
```

把 `/tmp/node-a.bundle.json` 交还给 node A，然后导入：

```bash
HIGGS_CONFIG=/tmp/higgs-a/config.yaml build/higgs join accept /tmp/node-a.bundle.json /tmp/node-a.key.json
HIGGS_CONFIG=/tmp/higgs-a/config.yaml build/higgs verify node-a.catofes.
```

node B 的流程相同。创建 B 的配置：

```bash
mkdir -p /tmp/higgs-b
cat >/tmp/higgs-b/config.yaml <<'EOF'
data_dir: /tmp/higgs-b
peer_id: node-b
listen_addr: 127.0.0.1:33435
bootstrap:
  - id: node-a
    addr: 127.0.0.1:33434
trusted_root_public_key: <root-public-key-from-node-admin>
EOF
```

在 node B 上生成 key 和 join request：

```bash
HIGGS_CONFIG=/tmp/higgs-b/config.yaml build/higgs keygen /tmp/node-b.key.json
HIGGS_CONFIG=/tmp/higgs-b/config.yaml build/higgs join request node-b.catofes. /tmp/node-b.key.json /tmp/node-b.request.json
```

把 `/tmp/node-b.request.json` 交给 `zone-catofes-admin`。然后在 `zone-catofes-admin` 上签发 delegation bundle：

```bash
HIGGS_CONFIG=/tmp/higgs-catofes/config.yaml build/higgs delegate issue /tmp/node-b.request.json /tmp/node-b.bundle.json
```

把 `/tmp/node-b.bundle.json` 交还给 node B。然后在 node B 上导入：

```bash
HIGGS_CONFIG=/tmp/higgs-b/config.yaml build/higgs join accept /tmp/node-b.bundle.json /tmp/node-b.key.json
HIGGS_CONFIG=/tmp/higgs-b/config.yaml build/higgs verify node-b.catofes.
```

完成后，node B 拥有：

- 验证 `node-b.catofes.` 所需的 trusted root chain
- 自己的 Zone 私钥
- 本地 active state 中的已委派 Zone

node A 和 node B 都不会接触 root/admin 私钥，也不会接触 `catofes.` 管理私钥。`node-admin` 不需要运行 gossip；它可以作为离线或半离线的根管理节点存在。

## 写入 Records

加入后，普通节点可以在自己的 Zone 下签名写入 records：

```bash
HIGGS_CONFIG=/tmp/higgs-a/config.yaml build/higgs record put node-a.catofes. identity node-a
HIGGS_CONFIG=/tmp/higgs-a/config.yaml build/higgs zone show node-a.catofes.

HIGGS_CONFIG=/tmp/higgs-b/config.yaml build/higgs record put node-b.catofes. identity node-b
HIGGS_CONFIG=/tmp/higgs-b/config.yaml build/higgs zone show node-b.catofes.
```

Record 按 Zone/key 独立版本化。普通同步以签名有效的最高版本为 active state；旧版本只保留有限历史窗口用于审计和排障。

## 数据库调试

bbolt 是二进制文件，不能直接查看。可以用内置的 debug 命令检查本地状态库：

```bash
# 查看所有 bucket 的 key 数量和大小统计
build/higgs db stats

# 打印全部数据库内容（JSON 美化）
build/higgs db dump

# 只打印指定 zone 的内容（会自动带上 _meta bucket）
build/higgs db dump catofes.
```

这些命令都以只读模式打开数据库，不会干扰正在运行的 `sync serve`、`sync run` 或 `daemon` 实例。

## Gossip 同步

同步相关命令分四种运行方式：

- `sync serve`：只监听 UDP，响应其他 peer 发来的 `PING`、`FETCH_ZONE`、`FETCH_RECORD` 和 `ANNOUNCE`。它是被动服务端，适合手动 smoke 或排查。
- `sync once <peer-id>`：主动和一个 peer 做一次同步 round。它会先发 `PING`，根据双方 zone digest 差异拉取缺失 zone/record，然后退出。
- `sync run`：开发/兼容长期运行入口，当前内部委托给 daemon service。它同时执行收包处理、周期性 outbound sync、endpoint publish 和 relay fanout。
- `daemon`：Phase 3 后推荐的本机长期运行入口。daemon 通过 Unix control socket 接收本机 CLI 写命令，把 `record_put`、sync apply、endpoint publish、manual trigger 和 timer tick 收进同一个串行 writer 边界，避免多个进程同时写 state DB。

启动 node B 的 gossip server：

```bash
HIGGS_CONFIG=/tmp/higgs-b/config.yaml build/higgs sync serve
```

在 node A 上写入 record，并触发同步到 node B：

```bash
HIGGS_CONFIG=/tmp/higgs-a/config.yaml build/higgs record put node-a.catofes. identity node-a
HIGGS_CONFIG=/tmp/higgs-a/config.yaml build/higgs sync once node-b
HIGGS_CONFIG=/tmp/higgs-b/config.yaml build/higgs sync status
```

本机双节点测试时，每个节点都需要独立的 `config.yaml` 和 `data_dir`。`bootstrap` 中的 `id` 和 `addr` 必须和对端的 `peer_id`、UDP 监听地址一致。

长期运行两个节点时，推荐让两端都运行 `daemon`：

```bash
HIGGS_CONFIG=/tmp/higgs-a/config.yaml build/higgs daemon --interval 5
HIGGS_CONFIG=/tmp/higgs-b/config.yaml build/higgs daemon --interval 5
```

daemon 会定期比较摘要，也会在收到并应用远端更新后触发 relay fanout。链式拓扑中，节点会优先把新变化同步给除来源 peer 之外的已知 peer，避免完全等待下一轮周期同步。`sync run` 保留为兼容入口，行为尽量复用同一套 daemon service。

daemon 启动后，`record put` 会优先通过本机 control socket 提交给 daemon，由 daemon 签名、落盘并触发 outbound sync：

```bash
HIGGS_CONFIG=/tmp/higgs-a/config.yaml build/higgs record put node-a.catofes. identity node-a
```

如果 daemon 不在，CLI 会明确提示 `daemon control socket unavailable; writing state directly`，并保留直接写 DB 的开发/恢复模式。下次 daemon 启动时会重新加载该状态并继续同步。

### 双节点完整同步脚本

下面的脚本会从空目录创建 root admin、`catofes.` 管理 Zone、`node-a` 和 `node-b`，让 A/B 都通过 delegation bundle 加入，然后做一次双向同步。

```bash
set -eu

make build

tmp="${TMPDIR:-/tmp}/higgs-readme-two-node"
rm -rf "$tmp"
mkdir -p "$tmp/admin" "$tmp/catofes" "$tmp/a" "$tmp/b"

printf '%s\n' \
  "data_dir: $tmp/admin" \
  "peer_id: node-admin" \
  "listen_addr: 127.0.0.1:33443" \
  > "$tmp/admin/config.yaml"

printf '%s\n' \
  "data_dir: $tmp/catofes" \
  "peer_id: zone-catofes-admin" \
  "listen_addr: 127.0.0.1:33446" \
  > "$tmp/catofes/config.yaml"

printf '%s\n' \
  "data_dir: $tmp/a" \
  "peer_id: node-a" \
  "listen_addr: 127.0.0.1:33444" \
  "bootstrap:" \
  "  - id: node-b" \
  "    addr: 127.0.0.1:33445" \
  > "$tmp/a/config.yaml"

printf '%s\n' \
  "data_dir: $tmp/b" \
  "peer_id: node-b" \
  "listen_addr: 127.0.0.1:33445" \
  "bootstrap:" \
  "  - id: node-a" \
  "    addr: 127.0.0.1:33444" \
  > "$tmp/b/config.yaml"

HIGGS_CONFIG="$tmp/admin/config.yaml" build/higgs root init >/dev/null
root_key="$(HIGGS_CONFIG="$tmp/admin/config.yaml" build/higgs root pubkey)"
for node in catofes a b; do
  printf '%s\n' "trusted_root_public_key: $root_key" >> "$tmp/$node/config.yaml"
done

HIGGS_CONFIG="$tmp/catofes/config.yaml" build/higgs keygen "$tmp/catofes.key.json" >/dev/null
HIGGS_CONFIG="$tmp/catofes/config.yaml" build/higgs join request catofes. "$tmp/catofes.key.json" "$tmp/catofes.request.json" >/dev/null
HIGGS_CONFIG="$tmp/admin/config.yaml" build/higgs delegate issue "$tmp/catofes.request.json" "$tmp/catofes.bundle.json" >/dev/null
HIGGS_CONFIG="$tmp/catofes/config.yaml" build/higgs join accept "$tmp/catofes.bundle.json" "$tmp/catofes.key.json" >/dev/null

for node in a b; do
  HIGGS_CONFIG="$tmp/$node/config.yaml" build/higgs keygen "$tmp/node-$node.key.json" >/dev/null
  HIGGS_CONFIG="$tmp/$node/config.yaml" build/higgs join request "node-$node.catofes." "$tmp/node-$node.key.json" "$tmp/node-$node.request.json" >/dev/null
  HIGGS_CONFIG="$tmp/catofes/config.yaml" build/higgs delegate issue "$tmp/node-$node.request.json" "$tmp/node-$node.bundle.json" >/dev/null
  HIGGS_CONFIG="$tmp/$node/config.yaml" build/higgs join accept "$tmp/node-$node.bundle.json" "$tmp/node-$node.key.json" >/dev/null
done

HIGGS_CONFIG="$tmp/a/config.yaml" build/higgs record put node-a.catofes. identity node-a >/dev/null
HIGGS_CONFIG="$tmp/b/config.yaml" build/higgs record put node-b.catofes. identity node-b >/dev/null

HIGGS_CONFIG="$tmp/b/config.yaml" build/higgs sync serve >"$tmp/b.log" 2>&1 &
server_pid="$!"
trap 'kill "$server_pid" >/dev/null 2>&1 || true' EXIT
sleep 1

HIGGS_CONFIG="$tmp/a/config.yaml" build/higgs sync once node-b >/dev/null
kill "$server_pid" >/dev/null 2>&1 || true
wait "$server_pid" >/dev/null 2>&1 || true
trap - EXIT

HIGGS_CONFIG="$tmp/a/config.yaml" build/higgs sync serve >"$tmp/a.log" 2>&1 &
server_pid="$!"
trap 'kill "$server_pid" >/dev/null 2>&1 || true' EXIT
sleep 1

HIGGS_CONFIG="$tmp/b/config.yaml" build/higgs sync once node-a >/dev/null
kill "$server_pid" >/dev/null 2>&1 || true
wait "$server_pid" >/dev/null 2>&1 || true
trap - EXIT

HIGGS_CONFIG="$tmp/a/config.yaml" build/higgs zone show node-b.catofes. | grep -q '"identity"'
HIGGS_CONFIG="$tmp/b/config.yaml" build/higgs zone show node-a.catofes. | grep -q '"identity"'
HIGGS_CONFIG="$tmp/a/config.yaml" build/higgs verify node-b.catofes. >/dev/null
HIGGS_CONFIG="$tmp/b/config.yaml" build/higgs verify node-a.catofes. >/dev/null

echo "two-node sync passed: $tmp"
```

同样的流程也可以直接用 `make phase2-smoke` 跑。脚本失败时先看 `$tmp/a.log` 和 `$tmp/b.log`。

### 三节点传播示例

下面的脚本创建 `node-a`、`node-b`、`node-c`，其中 B 和 C 都只配置 A 为 bootstrap。B 写入自己的 `identity` record 后先同步给 A，C 再从 A 拉取，验证状态可以通过中间节点传播。

```bash
set -eu

make build

tmp="${TMPDIR:-/tmp}/higgs-readme-three-node"
rm -rf "$tmp"
mkdir -p "$tmp/admin" "$tmp/catofes" "$tmp/a" "$tmp/b" "$tmp/c"

printf '%s\n' "data_dir: $tmp/admin" "peer_id: node-admin" "listen_addr: 127.0.0.1:33453" > "$tmp/admin/config.yaml"
printf '%s\n' "data_dir: $tmp/catofes" "peer_id: zone-catofes-admin" "listen_addr: 127.0.0.1:33456" > "$tmp/catofes/config.yaml"
printf '%s\n' "data_dir: $tmp/a" "peer_id: node-a" "listen_addr: 127.0.0.1:33454" "bootstrap:" "  - id: node-b" "    addr: 127.0.0.1:33455" "  - id: node-c" "    addr: 127.0.0.1:33457" > "$tmp/a/config.yaml"
printf '%s\n' "data_dir: $tmp/b" "peer_id: node-b" "listen_addr: 127.0.0.1:33455" "bootstrap:" "  - id: node-a" "    addr: 127.0.0.1:33454" > "$tmp/b/config.yaml"
printf '%s\n' "data_dir: $tmp/c" "peer_id: node-c" "listen_addr: 127.0.0.1:33457" "bootstrap:" "  - id: node-a" "    addr: 127.0.0.1:33454" > "$tmp/c/config.yaml"

HIGGS_CONFIG="$tmp/admin/config.yaml" build/higgs root init >/dev/null
root_key="$(HIGGS_CONFIG="$tmp/admin/config.yaml" build/higgs root pubkey)"
for node in catofes a b c; do
  printf '%s\n' "trusted_root_public_key: $root_key" >> "$tmp/$node/config.yaml"
done

HIGGS_CONFIG="$tmp/catofes/config.yaml" build/higgs keygen "$tmp/catofes.key.json" >/dev/null
HIGGS_CONFIG="$tmp/catofes/config.yaml" build/higgs join request catofes. "$tmp/catofes.key.json" "$tmp/catofes.request.json" >/dev/null
HIGGS_CONFIG="$tmp/admin/config.yaml" build/higgs delegate issue "$tmp/catofes.request.json" "$tmp/catofes.bundle.json" >/dev/null
HIGGS_CONFIG="$tmp/catofes/config.yaml" build/higgs join accept "$tmp/catofes.bundle.json" "$tmp/catofes.key.json" >/dev/null

for node in a b c; do
  HIGGS_CONFIG="$tmp/$node/config.yaml" build/higgs keygen "$tmp/node-$node.key.json" >/dev/null
  HIGGS_CONFIG="$tmp/$node/config.yaml" build/higgs join request "node-$node.catofes." "$tmp/node-$node.key.json" "$tmp/node-$node.request.json" >/dev/null
  HIGGS_CONFIG="$tmp/catofes/config.yaml" build/higgs delegate issue "$tmp/node-$node.request.json" "$tmp/node-$node.bundle.json" >/dev/null
  HIGGS_CONFIG="$tmp/$node/config.yaml" build/higgs join accept "$tmp/node-$node.bundle.json" "$tmp/node-$node.key.json" >/dev/null
done

HIGGS_CONFIG="$tmp/b/config.yaml" build/higgs record put node-b.catofes. identity node-b >/dev/null

HIGGS_CONFIG="$tmp/a/config.yaml" build/higgs sync serve >"$tmp/a.log" 2>&1 &
server_pid="$!"
trap 'kill "$server_pid" >/dev/null 2>&1 || true' EXIT
sleep 1

HIGGS_CONFIG="$tmp/b/config.yaml" build/higgs sync once node-a >/dev/null
HIGGS_CONFIG="$tmp/c/config.yaml" build/higgs sync once node-a >/dev/null
HIGGS_CONFIG="$tmp/c/config.yaml" build/higgs sync once node-a >/dev/null

kill "$server_pid" >/dev/null 2>&1 || true
wait "$server_pid" >/dev/null 2>&1 || true
trap - EXIT

HIGGS_CONFIG="$tmp/c/config.yaml" build/higgs zone show node-b.catofes. | grep -q '"identity"'
HIGGS_CONFIG="$tmp/c/config.yaml" build/higgs verify node-b.catofes. >/dev/null

echo "three-node propagation passed: $tmp"
```

同样的流程也可以直接用 `make multi-node-smoke` 跑。更接近长期运行的自动重连流程见 `make phase2-run-smoke`。

### 链式拓扑传播语义

链式拓扑指节点只知道相邻 peer，例如 `A <-> B <-> C <-> D`。在这种拓扑里有两种收敛路径：

- 周期收敛：每个节点按 `sync run --interval` 周期主动和 bootstrap/已发现 peer 比较摘要。即使没有主动中继，只要图连通，更新也会沿链逐轮传播，但最坏延迟接近链路跳数乘以同步周期。
- 主动 relay fanout：节点应用来自某个 peer 的 `ANNOUNCE` 后，会立即向除来源 peer 外的其他已知 peer 发起轻量同步。这样 A 的更新到达 B 后，B 会马上尝试推给 C，C 再推给 D，不必等待完整周期。

relay fanout 是加速收敛，不是信任捷径。每一跳收到的 snapshot 仍然要通过 root public key、delegation chain 和 record signature 验证；失败的数据不会进入 active state。链式场景可以直接跑：

```bash
make chain-relay-smoke
```

该 smoke 把同步周期设为 60 秒，并验证 D 能在等待完整周期前看到 A 的 record。

### 公网 Endpoint Reflector

节点可以通过公网 reflector 自动发现自己的公网 IP，然后用本 Zone 私钥签名发布到 `sync/endpoint/udp`。Reflector 只是本机自发现输入；其他节点只信任已经进入 verified active state 的 signed endpoint record。

```yaml
reflectors: auto
reflector_interval: 5m
reflector_timeout: 3s
endpoint_ttl: 1h
endpoint_grace: 10m
```

`reflectors: auto` 会展开内置列表：

```text
https://api.ipify.org
https://myip.ipip.net
https://ddns.oray.com/checkip
https://ip.3322.net
https://4.ipw.cn
https://v4.yinghualuo.cn/bejson
https://api64.ipify.org
https://speed.neu6.edu.cn/getIP.php
https://v6.ident.me
https://6.ipw.cn
https://v6.yinghualuo.cn/bejson
```

也可以混合自定义与内置列表：

```yaml
reflectors:
  - https://your-reflector.example/ip
  - auto
```

如果不希望访问公网 reflector，可设置：

```yaml
reflectors: off
```

解析器支持纯文本 IP、HTML/普通文本中嵌入的 IP、JSON、嵌套 JSON 和 JSONP。自动发现会尽量获取一个 IPv4 和一个 IPv6；单个 reflector 请求超过 `reflector_timeout` 或返回不可解析内容时，会继续尝试后续 reflector。若所有 reflector 都失败，节点会保留 `advertise_addrs` 和本机 interface scan 的候选，并在 daemon / `sync run` 日志或 `higgs debug endpoints` 中显示 reflector 错误。

### NAT 后节点与 observed UDP path

signed endpoint record 表示长期、可传播、由 Zone 签名的可达地址；NAT 映射不是这种地址。节点如果在家庭 NAT、CGNAT 或没有端口映射的网络后面，通常只能主动向公网 bootstrap/peer 发起 UDP，同步不能假设其他节点可以主动拨入它的 `listen_addr`。

纯 NAT/outbound-only 节点可以设置 `publish_endpoints: false`，避免把 interface scan 或 reflector 候选发布成 signed direct endpoint。

daemon 收到已准入 peer 的 UDP 包后，会先完成传输层 replay/quota/wire 校验，再由上层按 trust chain 和 record/snapshot 签名验证消息内容。处理成功后，packet 的源地址会被记录为本地短期 `observed_addr`，用于回复、后续 outbound sync 和周期 keepalive/PING。这个地址只保存在本节点 peer state / runtime path table 中，不会写入对外传播的 signed endpoint record。

可以用下面命令排查 NAT path：

```sh
higgs debug peer node-b.catofes.
higgs sync status --verbose
```

输出中的 `observed_addr` / `observed_status` 表示当前维护的短期 UDP 映射。若节点需要被任意 peer 主动拨入，仍需要公网地址、IPv6、端口映射、UDP hole punching，或后续 relay/discovery server 能力。

### 常见错误与排查

| 现象 | 常见原因 | 排查与修复 |
|------|----------|------------|
| `trusted root public key mismatch`、`root public key mismatch` 或 `verify` 失败 | `trusted_root_public_key` 填错，或复用了旧 `data_dir` 中的状态库 | 用 admin 节点重新执行 `root pubkey`，确认所有普通节点配置相同；测试时清空对应 `data_dir` 后重新 join |
| debug log 出现 `unknown_peer` | 对端 `peer_id` 不在本节点 `bootstrap`，也还没有通过已验证 Zone/endpoint record 被发现 | 检查 `bootstrap.id` 是否等于对端配置里的 `peer_id`；首次接入时至少让一侧通过 bootstrap 或已同步 delegation chain 认识对方 |
| `bind: permission denied`、`operation not permitted`、测试提示 UDP socket 不允许 | 当前运行环境禁止创建 UDP socket，或端口被系统策略拦截 | 换本机普通 shell 运行；确认没有容器/sandbox 网络限制；避免使用低端口；先跑不依赖 UDP 的 `make join-smoke` |
| NAT 后节点能主动同步但别人拨不进来 | NAT/CGNAT 没有稳定入站端口映射；reflector 只能发现公网 IP，不能保证该地址可被外部主动访问 | 让 NAT 后节点主动连接公网 bootstrap；用 `debug peer` 查看 `observed_addr` 是否 active；需要任意入站访问时配置端口映射、IPv6 或等待后续 relay 能力 |
| `bind: address already in use` | `listen_addr` 端口被已有 `daemon`、`sync serve`、`sync run` 或其他进程占用 | 停掉旧进程，或给每个节点分配不同端口并同步更新其他节点的 `bootstrap.addr` |
| `record version conflict`、`conflict` 或更新没有覆盖 | 同一 `zone/key` 出现相同 version 的不同内容，或本地正好有直接前驱但新 record 的 `PrevHash` 不匹配 | 用 `debug zone <zone>` 查看 active record 和历史；由该 Zone authority 再写入一个更高版本的合法 record，让网络继续 fast-forward 收敛 |
| `verify_failed` | snapshot 能到达传输层，但 authority、delegation 或 record signature 验证失败 | 确认对端是用正确 bundle `join accept`，没有把 root/admin 私钥数据库复制给普通节点；用 `verify <zone>` 在发送方和接收方分别检查 |
| `message_too_large`、`quota` | 单包超过 datagram 预算，或短时间内同步对象太多 | 公网部署不要依赖调大 UDP 包；确认大 record 能通过 TCP object pull 或 UDP chunk fallback 收敛，必要时降低写入/同步频率或调小单轮对象数量 |

### Latest Record 与历史窗口

Record 按 `zone/key` 独立版本化。普通同步采用 `latest signed state is authoritative` 语义：节点收到更高版本 record 后，先验证 Zone 信任链和 record 签名；验签通过后即可把它作为该 key 的 active record，不要求从 `@1` 依次重放到最新版本。

`PrevHash` 仍会保留在 record 中，但它主要用于审计和调试。如果本地正好持有直接前驱，例如 active 是 `@2` 且收到 `@3`，并且 `@3.PrevHash` 非空，则会检查它是否匹配 `@2` 的 hash；如果不匹配，视为 `conflict`。如果本地只有 `@20`，收到签名有效的 `@100`，节点会直接 fast-forward 到 `@100`。

为了避免数据库无限膨胀，每个 `zone/key` 默认只保留最近 128 条被替换的历史版本。Whole-zone snapshot 只同步 active records，不再把远端完整 `RecordHistory` 作为冷启动依赖。`FETCH_RECORD` 仍保留在协议中用于兼容和手工按需取单条历史 record，但普通同步主路径不会为了补齐历史链主动使用它。

如果同一 version 出现不同内容，或本地正好持有直接前驱但 `PrevHash` 不匹配，节点会把它视为 conflict 并拒绝该条 record；后续更高版本的合法签名 record 仍可让各节点继续收敛。

排查时常用：

```bash
HIGGS_CONFIG=/tmp/higgs-a/config.yaml build/higgs sync status
HIGGS_CONFIG=/tmp/higgs-a/config.yaml build/higgs debug zone node-a.catofes.
```

双节点双向同步可以直接跑：

```bash
make phase2-smoke
```

该流程会创建独立的 `node-admin`、`zone-catofes-admin`、`node-a` 和 `node-b`，两端都通过 delegation bundle 加入；A/B 分别写入自己的 `identity` record 后轮流 `sync serve`/`sync once`，最后检查双方 `zone show`、`sync status` 和 `verify`。

三节点传播可以直接跑：

```bash
make multi-node-smoke
```

该流程使用 A 作为中间 gossip peer：B 写入 `node-b.catofes./identity`，先同步到 A，再由 C 从 A 拉取，验证 C 能看到并验证 B 的 Zone record。随后脚本会停止并重启 A，B 离线期间更新 record，再验证 A 重启后通过摘要比较补齐缺失版本，并继续传播给 C。

链式 relay fanout 可以直接跑：

```bash
make chain-relay-smoke
```

该流程使用 A-B-C-D 链式 bootstrap，所有节点以 60 秒周期运行 `sync run`。A 写入 `node-a.catofes./identity` 后，B/C 在应用远端更新时会立即向非来源邻居触发同步，验证 D 不需要等待完整轮询周期即可收敛。

delegation 撤销传播可以直接跑：

```bash
make delegation-revoke-smoke
```

该流程先让 node-b 的 record 和 endpoint 在 A/C 间传播，再由 `catofes.` 管理节点签发 revocation，最后验证 A/C 不再信任 B 的 record、endpoint 和后续发布内容。

Phase 3 daemon 写入与 fallback 可以直接跑：

```bash
make phase3-daemon-smoke
make phase3-daemon-fallback-smoke
make admin-daemon-smoke
```

前者验证 CLI `record put` 通过 daemon control socket 提交后，由 daemon 串行写入 DB、唤醒 outbound sync，并让远端收敛；后者验证 daemon 停止时 CLI 直接写 DB 的开发/恢复模式仍可用，下一次 daemon 启动后能加载并传播。
`admin-daemon-smoke` 验证 root/catofes 管理端 daemon 运行时，`delegate issue` 和 `delegate revoke` 会经 control socket 串行写入 state，并由 CLI 负责把 daemon 返回的 bundle 写到文件。

Phase 3.6 的大 record / MTU-safe object pull 可以直接跑：

```bash
make object-pull-smoke
```

该 smoke 验证 1200-byte UDP datagram 预算下，大 record 不通过超大 UDP 包传播，而是由 daemon 优先通过 TCP object pull 拉取完整对象后收敛。TCP object pull 默认使用 signed/bootstrap UDP endpoint 的同一个数字端口；如果 TCP 不可达但已准入 peer 的 UDP path 可用，daemon 会用 UDP chunk fallback 补齐完整 Zone snapshot。

排查 MTU / 大包问题时，`higgs sync status --verbose` 和 `higgs debug peer <peer-id>` 会显示当前 datagram 预算、最近 oversized UDP 对象、digest-only announce 次数以及 UDP chunk fallback 计数。大对象优先走未压缩 MessagePack object pull，UDP chunk fallback 只在 object pull 不可达时兜底；通用压缩仅作为后续 object pull 优化候选，不用于默认 UDP 小包。

真实公网多节点 daemon gossip 测试见 [docs/public-internet-test.md](docs/public-internet-test.md)。该文档配套 [docs/scripts/public-gossip-node.sh](docs/scripts/public-gossip-node.sh)，用于在 3+ 台公网 Linux 节点上生成配置、提交 join request、启动 daemon、写入测试 record 并验证收敛。

## 下一步方向

Phase 3 的最小 daemon / 单 writer 边界已经收敛，Phase 4.0 的 admin 写操作 daemon 化也已经落地：`higgs daemon` 常驻负责 gossip 同步、endpoint publish、active state 更新和本机 control socket 写入；CLI 在 daemon 存在时优先作为 client 提交 `record put`、`delegate issue`、`delegate revoke` 和 `join accept`，daemon 不存在时保留直接写 DB 的开发/恢复模式。`root init` 仍是 daemon 启动前的离线初始化；已有 daemon 加载 state 时会拒绝 root 重置。

Phase 4 StrongSwan/IKEv2 + XFRM interface 控制模块正在推进。当前核心链路已经落在 `pkg/transport/ipsec`：planner 从 verified active state + 本地 `LinkGroupSpec` 推导 desired `TransportLinkSpec` 和 skip reason；reconciler 再结合持久化 `LinkInstance`、driver `ListSAs` 快照和 revocation 输入，判定 create/update/adopt/repair/teardown/noop。daemon 已在启动恢复、state change 和 config reload 时接入这条链路，并会合并同一轮内的多次事件，避免重复 `ListSAs` + apply。

`LinkInstance` 记录 desired hash、实际状态、XFRM `if_id`、IKE/CHILD_SA、endpoint、owner、backoff 和最近错误。apply 成功先进入 `connecting`，表示 provider 配置已应用；只有后续 `ListSAs` 观测到匹配 SA 后才进入 `up`。teardown 成功会删除本地实例，避免 link group 删除、record 过期或 peer revocation 后重复清理/重建。`higgs debug links` 会重算 desired links，并与已落盘 instance、最近 SA/CHILD_SA、endpoint、spec hash、backoff 和错误并排显示。显式 `make ipsec-xfrm-smoke` 已作为 root/system integration 入口验证 preflight、真实 XFRM netns/interface/address 生命周期、driver 层真实 StrongSwan/VICI IKE_SA/CHILD_SA bring-up 与 tunnel ping、verified active state 进入 daemon reconcile 后的真实 StrongSwan/XFRM bring-up，以及两个 daemon service `Run` 循环自动发布 `ipsec/*` records、经 UDP gossip 同步后触发真实 VICI/XFRM 建链、`LinkInstance=up` 和 tunnel ping。planner 现在按 peer pair 稳定镜像 tunnel address，避免两端独立规划时拿到同一个 local tunnel IP；外部 CLI `build/higgs daemon` 进程级 smoke、重启恢复和 revocation teardown 仍是后续 hardening；低频生产可用的平滑端口 rotate 已提前到 Phase 4.4 规划，高频/对抗性 port hopping 留到 Phase 7；WireGuard 后移为可选轻量传输驱动。

## CLI 汇总

```bash
build/higgs root init
build/higgs root pubkey
build/higgs keygen <key.json>
build/higgs join request <zone> <key.json> <request.json>
build/higgs delegate issue <request.json> <bundle.json>
build/higgs join accept <bundle.json> <key.json>
build/higgs zone show <zone>
build/higgs record put <zone> <key> <value> [type]
build/higgs verify <zone>
build/higgs daemon [--interval seconds]
build/higgs sync status [--verbose]
build/higgs sync serve
build/higgs sync once <peer-id>
build/higgs sync run [--interval seconds]
build/higgs debug peer <peer-id>
build/higgs debug zone <zone>
build/higgs db dump [zone]
build/higgs db stats
```

## 当前限制

- CLI 目前为了开发便利，把私钥保存在本地 bbolt metadata 中。底层 identity 包已有加密私钥 helper，但 CLI 尚未强制使用加密存储。
- 当前只支持 authority `threshold=1`。
- Delegation scope 只支持 `direct-child`。
- Gossip 当前默认使用 MessagePack framing，并短期兼容读取旧 JSON v1；没有接入 protobuf 生成代码。
- 当前同步保证是连通、可达、至少有 bootstrap 或 signed endpoint 发现路径时的最终一致性；复杂 NAT、无稳定 bootstrap、长期网络分区仍需要后续 discovery/relay 能力补强。
- StrongSwan/IKEv2 + XFRM interface 已有 planner/reconcile/dry-run 基础；真实系统 apply smoke、WireGuard fallback、Babel、route authorization filter、防火墙应用仍在后续阶段。
