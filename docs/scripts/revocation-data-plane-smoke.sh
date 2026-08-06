#!/usr/bin/env bash
# Phase 6.5 combined data-plane smoke. This is an explicit privileged lane:
# real netfilter, real BIRD/Babel, real StrongSwan/XFRM, plus the daemon
# revocation cleanup ordering smoke.
set -euo pipefail

go_cmd="${GO:-go}"
go_cache="${GOCACHE:-/tmp/photon-gocache}"
go_mod_cache="${GOMODCACHE:-/tmp/photon-gomodcache}"
skip_shared="${PHOTON_REVOCATION_DATA_PLANE_SKIP_SHARED:-0}"
make_env=(
  "GO=$go_cmd"
  "GOCACHE=$go_cache"
  "GOMODCACHE=$go_mod_cache"
  "CGO_ENABLED=${CGO_ENABLED:-0}"
)

dump_diagnostics() {
  printf '\n[revocation-data-plane-smoke] diagnostics\n' >&2
  ip netns list >&2 || true
  ip link show type xfrm >&2 || true
  ip xfrm state >&2 || true
  ip xfrm policy >&2 || true
  if command -v nft >/dev/null 2>&1; then
    nft list ruleset >&2 || true
  else
    printf '[skip] nft diagnostics: command not found\n' >&2
  fi
  if command -v iptables >/dev/null 2>&1; then
    iptables -S >&2 || true
  else
    printf '[skip] iptables diagnostics: command not found\n' >&2
  fi
  if command -v swanctl >/dev/null 2>&1; then
    swanctl --list-sas >&2 || true
  else
    printf '[skip] swanctl diagnostics: command not found\n' >&2
  fi
}

trap 'rc=$?; if [ "$rc" -ne 0 ]; then dump_diagnostics; fi; exit "$rc"' EXIT

if [[ "$skip_shared" == "1" ]]; then
  printf '[revocation-data-plane-smoke] shared firewall/BIRD/StrongSwan lanes already covered; skipping repeats\n'
else
  printf '[revocation-data-plane-smoke] firewall real backend smoke\n'
  env "${make_env[@]}" make firewall-smoke

  printf '[revocation-data-plane-smoke] BIRD/Babel real routing smoke\n'
  env "${make_env[@]}" make bird-babel-smoke

  printf '[revocation-data-plane-smoke] StrongSwan/XFRM revocation-relevant real smoke\n'
  docs/scripts/ipsec-xfrm-preflight.sh
  PHOTON_IPSEC_XFRM_SMOKE=1 \
    GOCACHE="$go_cache" \
    GOMODCACHE="$go_mod_cache" \
    CGO_ENABLED="${CGO_ENABLED:-0}" \
    "$go_cmd" test ./pkg/transport/ipsec -run '^TestStrongSwanDriverIKEBringupSmoke$' -count=1
  PHOTON_IPSEC_XFRM_SMOKE=1 \
    GOCACHE="$go_cache" \
    GOMODCACHE="$go_mod_cache" \
    CGO_ENABLED="${CGO_ENABLED:-0}" \
    "$go_cmd" test ./app/photon -run '^TestDaemonStrongSwanReconcileBringupSmoke$' -count=1
fi

printf '[revocation-data-plane-smoke] daemon revocation deny-first ordering smoke\n'
env "${make_env[@]}" make revocation-cleanup-smoke

if [[ "$skip_shared" == "1" ]]; then
  printf 'revocation data-plane smoke passed (shared real data-plane lanes skipped + deny-first revocation ordering)\n'
else
  printf 'revocation data-plane smoke passed (real firewall + real BIRD/Babel + revocation-relevant StrongSwan/XFRM + deny-first revocation ordering)\n'
fi
