# Higgs

Higgs 是一个实验性的“信任优先”网络配置系统。当前实现已经覆盖本地 Zone 状态、ED25519 签名、Delegation 信任链、bbolt 持久化、节点准入工具，以及 Phase 1 的 UDP gossip 同步。

详细设计见 [docs/design.md](docs/design.md)。可执行任务路线见 [todo.md](todo.md)。

## 当前设计

Higgs 的状态按 Zone 组织。每个 Zone 包含 `ZoneAuthority`、对子 Zone 的已签名 `Delegation`，以及本 Zone 内的已签名 Records。节点只有在能从本地信任的 root authority 验证到目标 Zone 时，才接受远端状态。

当前信任模型：

- Root Zone `.` 持有根 authority 公钥。
- 父 Zone 通过签名 `Delegation` 委派子 Zone。
- 每个 Zone authority 包含一个或多个 ED25519 公钥。Phase 1 只支持 `threshold=1`。
- Record 必须由该 Zone authority 授权的 key 签名。
- Gossip 收到的数据先视为不可信；信任链和签名验证通过后，才提升到 active state。

Phase 1 gossip 使用 UDP 和一个轻量 JSON wire codec：

- 默认端口：`33434`
- 消息类型：`PING`、`PONG`、`FETCH_ZONE`、`FETCH_RECORD`、`ANNOUNCE`
- 防重放：nonce + timestamp window
- peer allowlist：只接受 `bootstrap` 中配置的 peer
- 同步模型：Phase 1A 使用 whole-zone sync；缺失前驱的 record 会进入 pending，并可通过 `FETCH_RECORD` 补齐

`gossip.proto` 记录了未来协议形状，但当前构建不需要 `protoc`。

## 配置文件

默认读取 `./config.yaml`。如果要在同一个 checkout 下运行多个节点，可以用 `HIGGS_CONFIG=/path/to/config.yaml` 指定配置文件。

示例：

```yaml
data_dir: .higgs
peer_id: node-a
listen_addr: 127.0.0.1:33434

bootstrap:
  - id: node-b
    addr: 127.0.0.1:33435

trusted_root_public_key: <hex-or-base64-ed25519-public-key>
```

字段说明：

- `data_dir`：本地状态目录。bbolt 数据库位于 `<data_dir>/higgs.db`。
- `peer_id`：gossip peer ID。
- `listen_addr`：UDP gossip 监听地址。也可以用 `listen_port`。
- `bootstrap`：已知 gossip peer。未知 peer ID 或地址会被拒绝。
- `trusted_root_public_key`：期望的 root authority 公钥。设置后，本地状态必须匹配该公钥。

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
```

`make join-smoke` 不依赖 UDP。`make phase1-smoke` 会启动两个本地 UDP gossip peer，因此运行环境需要允许本地 UDP socket。

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

Record 按 Zone/key 独立版本化。如果高版本 record 先于其前驱到达，它会保留在 pending 中，直到前驱被 fetch 或导入。

## Gossip 同步

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

## 下一步方向

当前优先级不是直接进入 WireGuard，而是先把配置同步做稳：

- 双节点端到端流程：`node-admin root init` → `catofes. join` → `node-a/node-b join` → `record put` → `gossip sync` → `verify`
- 三节点传播：A-B-C 拓扑中，B 写入的 Zone/Record 能经由 A 传播到 C
- `sync status` 增强：显示 peer 状态、per-zone root、pending record、最近错误
- pending/`FETCH_RECORD` 闭环：高版本 record 先到时，能补齐前驱并自动提升 active
- 把双节点和三节点流程固化成 Makefile smoke/integration 命令

WireGuard 建链会在配置同步收敛后再做，避免把状态同步问题和系统网络配置问题混在一起。

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
build/higgs sync status
build/higgs sync serve
build/higgs sync once <peer-id>
```

## 当前限制

- CLI 目前为了开发便利，把私钥保存在本地 bbolt metadata 中。底层 identity 包已有加密私钥 helper，但 CLI 尚未强制使用加密存储。
- Phase 1 只支持 authority `threshold=1`。
- Delegation scope 只支持 `direct-child`。
- Gossip 当前使用 JSON framing，还没有接入 protobuf 生成代码。
- 多节点配置同步仍在强化中；WireGuard、Babel、route authorization filter、防火墙应用仍在后续阶段。
