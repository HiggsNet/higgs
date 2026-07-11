#!/usr/bin/env bash
# Explicit Phase 7.1.b experiment. It validates one shared WireGuard device
# with multiple transit-only peers and per-peer GRE/Babel links. It is not part
# of smoke-all, bird-babel-smoke, or root-smoke.
set -euo pipefail

go_cmd="${GO:-go}"
go_cache="${GOCACHE:-/tmp/higgs-gocache}"
go_mod_cache="${GOMODCACHE:-/tmp/higgs-gomodcache}"
wg_binary="${WG:-}"
if [ -z "$wg_binary" ]; then
  wg_binary="$(command -v wg || true)"
fi
if [ -z "$wg_binary" ] || [ ! -x "$wg_binary" ]; then
  printf 'wg binary not found; enter the Nix dev shell or set WG=/path/to/wg\n' >&2
  exit 1
fi

docs/scripts/bird-babel-preflight.sh

probe_ns="higgs-wggre-preflight-$$"
cleanup() {
  ip netns delete "$probe_ns" >/dev/null 2>&1 || true
}
trap cleanup EXIT
ip netns add "$probe_ns"
ip netns exec "$probe_ns" ip link add wg-probe type wireguard
ip netns exec "$probe_ns" ip link add gre-probe type gre local 192.0.2.1 remote 192.0.2.2 key 7100
ip netns exec "$probe_ns" "$wg_binary" show wg-probe >/dev/null
cleanup
trap - EXIT

HIGGS_WG_GRE_SMOKE=1 \
  HIGGS_WG_BINARY="$wg_binary" \
  GOCACHE="$go_cache" \
  GOMODCACHE="$go_mod_cache" \
  CGO_ENABLED="${CGO_ENABLED:-0}" \
  "$go_cmd" test ./pkg/transport/wireguard -run '^TestWireGuardGREThreeNodeRootSmoke$' -count=1 -v

printf 'Phase 7.1 WireGuard/GRE experiment passed\n'
