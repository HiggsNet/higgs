#!/usr/bin/env bash
# Explicit Phase 7.1.a experiment. It is kept out of the regular BIRD/root
# smoke because dual-interface Babel convergence, failover, and recovery make
# it materially slower than the production regression lane.
set -euo pipefail

go_cmd="${GO:-go}"
go_cache="${GOCACHE:-/tmp/photon-gocache}"
go_mod_cache="${GOMODCACHE:-/tmp/photon-gomodcache}"

docs/scripts/bird-babel-preflight.sh

PHOTON_BIRD_SMOKE=1 \
  GOCACHE="$go_cache" \
  GOMODCACHE="$go_mod_cache" \
  CGO_ENABLED="${CGO_ENABLED:-0}" \
  "$go_cmd" test ./pkg/routing/bird -run '^TestBabelDualInterfaceCostFailoverRootSmoke$' -count=1 -v

printf 'Phase 7.1 dual-interface BIRD experiment passed\n'
