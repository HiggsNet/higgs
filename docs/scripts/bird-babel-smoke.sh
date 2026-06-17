#!/usr/bin/env bash
# BIRD / Babel root smoke: runs real managed-BIRD tests that require root or
# CAP_NET_ADMIN + netns + BIRD 2.x. This is an explicit privileged integration
# target, NOT part of `make smoke-all`.
set -euo pipefail

go_cmd="${GO:-go}"
go_cache="${GOCACHE:-/tmp/higgs-gocache}"
go_mod_cache="${GOMODCACHE:-/tmp/higgs-gomodcache}"

dump_diagnostics() {
  printf '\n[bird-babel-smoke] diagnostics\n' >&2
  ip netns list >&2 || true
  for ns in $(ip netns list 2>/dev/null | awk '{print $1}' | grep '^higgs-bird-' || true); do
    printf '\n--- netns %s ---\n' "$ns" >&2
    ip netns exec "$ns" ip addr 2>&1 || true
    ip netns exec "$ns" ip route 2>&1 || true
    ip netns exec "$ns" birdc show protocols 2>&1 || true
    ip netns exec "$ns" birdc show route 2>&1 || true
  done
}

trap 'rc=$?; if [ "$rc" -ne 0 ]; then dump_diagnostics; fi; exit "$rc"' EXIT

docs/scripts/bird-babel-preflight.sh

# Test 1: Managed BIRD lifecycle in a named netns
HIGGS_BIRD_SMOKE=1 \
  GOCACHE="$go_cache" \
  GOMODCACHE="$go_mod_cache" \
  CGO_ENABLED="${CGO_ENABLED:-0}" \
  "$go_cmd" test ./pkg/routing/bird -run '^TestExecProcessManagerRootSmoke$' -count=1 -v

# Test 2: Two-node BIRD Babel neighbor + route exchange via veth
HIGGS_BIRD_SMOKE=1 \
  GOCACHE="$go_cache" \
  GOMODCACHE="$go_mod_cache" \
  CGO_ENABLED="${CGO_ENABLED:-0}" \
  "$go_cmd" test ./pkg/routing/bird -run '^TestBabelTwoNodeRootSmoke$' -count=1 -v

# Test 2b: veth upstream BIRD Babel neighbor + bidirectional prefix exchange
HIGGS_BIRD_SMOKE=1 \
  GOCACHE="$go_cache" \
  GOMODCACHE="$go_mod_cache" \
  CGO_ENABLED="${CGO_ENABLED:-0}" \
  "$go_cmd" test ./pkg/routing/bird -run '^TestBIRDUpstreamBabelRootSmoke$' -count=1 -v

# Test 3: Daemon routing reconcile with real BIRD in a netns
HIGGS_BIRD_SMOKE=1 \
  GOCACHE="$go_cache" \
  GOMODCACHE="$go_mod_cache" \
  CGO_ENABLED="${CGO_ENABLED:-0}" \
  "$go_cmd" test ./app/higgs -run '^TestDaemonBIRDRoutingRootSmoke$' -count=1 -v

# Test 4: Veth upstream with real BIRD
HIGGS_BIRD_SMOKE=1 \
  GOCACHE="$go_cache" \
  GOMODCACHE="$go_mod_cache" \
  CGO_ENABLED="${CGO_ENABLED:-0}" \
  "$go_cmd" test ./app/higgs -run '^TestDaemonBIRDUpstreamRootSmoke$' -count=1 -v

printf 'bird/babel smoke passed (preflight + managed BIRD lifecycle + two-node Babel exchange + upstream Babel bidirectional prefix exchange + daemon routing reconcile + veth upstream)\n'
