# Higgs

Higgs is an experimental trust-first network configuration system. The current implementation covers local Zone state, ED25519 signing, delegation chains, bbolt persistence, node admission tooling, and Phase 1 UDP gossip sync.

The detailed design lives in [docs/design.md](docs/design.md). The executable roadmap lives in [todo.md](todo.md).

## Current Design

Higgs state is organized as Zones. A Zone has a `ZoneAuthority`, signed delegations to child Zones, and signed records. A node accepts remote state only when it can verify the chain from a locally trusted root authority to the target Zone.

The current trust model is:

- Root Zone `.` has a root authority public key.
- Parent Zones delegate child Zones by signing a `Delegation`.
- Each Zone authority contains one or more ED25519 public keys. Phase 1 supports `threshold=1`.
- Records are signed by a key authorized by that Zone authority.
- Gossip data is treated as untrusted until the chain and signatures verify.

Phase 1 gossip uses UDP with a small JSON wire codec:

- default port: `33434`
- messages: `PING`, `PONG`, `FETCH_ZONE`, `FETCH_RECORD`, `ANNOUNCE`
- anti-replay: nonce plus timestamp window
- peer allowlist: only configured bootstrap peers are accepted
- sync model: Phase 1A whole-zone sync; record predecessor gaps are put into pending and can be fetched with `FETCH_RECORD`

`gossip.proto` documents the intended protocol shape, but the build does not require `protoc` yet.

## Config

By default Higgs reads `./config.yaml`. Use `HIGGS_CONFIG=/path/to/config.yaml` to run multiple nodes from one checkout.

Example:

```yaml
data_dir: .higgs
peer_id: node-a
listen_addr: 127.0.0.1:33434

bootstrap:
  - id: node-b
    addr: 127.0.0.1:33435

trusted_root_public_key: <hex-or-base64-ed25519-public-key>
```

Fields:

- `data_dir`: directory for local state. The bbolt DB is `<data_dir>/higgs.db`.
- `peer_id`: gossip peer ID.
- `listen_addr`: UDP gossip listen address. You can use `listen_port` instead.
- `bootstrap`: known gossip peers. Unknown peer IDs or addresses are rejected.
- `trusted_root_public_key`: expected root authority public key. If set, local state must match it.

See [config.example.yaml](config.example.yaml).

## Build And Test

```bash
make check
```

This runs formatting, vet, tests, and a `CGO_ENABLED=0` build. The Makefile uses `/tmp/higgs-gocache` and `/tmp/higgs-gomodcache` by default so it works in restricted environments.

Other useful targets:

```bash
make build
make join-smoke
make phase1-smoke
```

`make join-smoke` does not require UDP. `make phase1-smoke` starts two local UDP gossip peers, so it requires an environment that permits local UDP sockets.

## Create The First Node

Create an admin/root node that manages `catofes.`:

```bash
mkdir -p /tmp/higgs-a
cat >/tmp/higgs-a/config.yaml <<'EOF'
data_dir: /tmp/higgs-a
peer_id: node-a
listen_addr: 127.0.0.1:33434
EOF

HIGGS_CONFIG=/tmp/higgs-a/config.yaml build/higgs root init catofes.
HIGGS_CONFIG=/tmp/higgs-a/config.yaml build/higgs root pubkey
```

`root init catofes.` creates:

- root authority for `.`
- delegated management Zone `catofes.`
- local private keys in the bbolt state database

The root public key printed by `root pubkey` is what other nodes should place in `trusted_root_public_key`.

## Add A New Node

Assume node A/admin already manages `catofes.` and node B wants to join as `node-b.catofes.`.

Create B config:

```bash
mkdir -p /tmp/higgs-b
cat >/tmp/higgs-b/config.yaml <<'EOF'
data_dir: /tmp/higgs-b
peer_id: node-b
listen_addr: 127.0.0.1:33435
bootstrap:
  - id: node-a
    addr: 127.0.0.1:33434
trusted_root_public_key: <root-public-key-from-node-a>
EOF
```

On node B, generate a key and join request:

```bash
HIGGS_CONFIG=/tmp/higgs-b/config.yaml build/higgs keygen /tmp/node-b.key.json
HIGGS_CONFIG=/tmp/higgs-b/config.yaml build/higgs join request node-b.catofes. /tmp/node-b.key.json /tmp/node-b.request.json
```

Send `/tmp/node-b.request.json` to node A/admin. On node A/admin:

```bash
HIGGS_CONFIG=/tmp/higgs-a/config.yaml build/higgs delegate issue /tmp/node-b.request.json /tmp/node-b.bundle.json
```

Send `/tmp/node-b.bundle.json` back to node B. On node B:

```bash
HIGGS_CONFIG=/tmp/higgs-b/config.yaml build/higgs join accept /tmp/node-b.bundle.json /tmp/node-b.key.json
HIGGS_CONFIG=/tmp/higgs-b/config.yaml build/higgs verify node-b.catofes.
```

Node B now has:

- the trusted root chain needed to verify `node-b.catofes.`
- its own Zone private key
- local active state for its delegated Zone

Node B never receives root/admin private keys.

## Write Records

After joining, node B can sign records in its own Zone:

```bash
HIGGS_CONFIG=/tmp/higgs-b/config.yaml build/higgs record put node-b.catofes. identity node-b
HIGGS_CONFIG=/tmp/higgs-b/config.yaml build/higgs zone show node-b.catofes.
```

Records are versioned per Zone/key. If a higher version arrives before its predecessor, it stays pending until the predecessor is fetched or otherwise imported.

## Gossip Sync

Start node A:

```bash
HIGGS_CONFIG=/tmp/higgs-a/config.yaml build/higgs sync serve
```

Start or trigger node B sync:

```bash
HIGGS_CONFIG=/tmp/higgs-b/config.yaml build/higgs sync once node-a
HIGGS_CONFIG=/tmp/higgs-b/config.yaml build/higgs sync status
```

For local two-node tests, each node needs its own `config.yaml` and `data_dir`. The bootstrap entries must match the other node's `peer_id` and UDP address.

## CLI Summary

```bash
build/higgs root init <zone>
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

## Current Limits

- Private keys are stored in local bbolt metadata for development. The lower-level identity package has encrypted key helpers, but the CLI does not enforce encrypted key storage yet.
- Phase 1 supports authority `threshold=1` only.
- Delegation scope is `direct-child` only.
- Gossip currently uses JSON framing, not generated protobuf code.
- WireGuard, Babel, route authorization filters, and firewall application are planned for later phases.
