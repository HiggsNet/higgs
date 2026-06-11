#!/usr/bin/env bash
set -euo pipefail

vici_socket="${HIGGS_VICI_SOCKET:-/run/charon.vici}"
ike_port="${HIGGS_IPSEC_IKE_PORT:-500}"
natt_port="${HIGGS_IPSEC_NATT_PORT:-4500}"
check_udp="${HIGGS_IPSEC_CHECK_UDP:-0}"

failures=0

check() {
  local name="$1"
  shift
  if "$@" >/tmp/higgs-ipsec-preflight.out 2>&1; then
    printf '[ok]   %s\n' "$name"
  else
    printf '[fail] %s: ' "$name"
    tr '\n' ' ' </tmp/higgs-ipsec-preflight.out
    printf '\n'
    failures=$((failures + 1))
  fi
}

note_container_context() {
  if test -f /.dockerenv || test -f /run/.containerenv || grep -qaE '(docker|lxc|containerd|kubepods)' /proc/1/cgroup /proc/self/cgroup 2>/dev/null; then
    printf '[info] container-like environment detected; nested LXC/Docker may still block netns, mount, XFRM, or VICI even with --privileged\n'
  fi
}

note_container_context

check "linux" test "$(uname -s)" = "Linux"
check "root-or-cap-net-admin" bash -c '[ "$(id -u)" = 0 ] || { cap_eff="$(awk "/^CapEff:/ {print \$2}" /proc/self/status)"; cap=$((16#$cap_eff)); [ $((cap & (1 << 12))) -ne 0 ]; }'
check "vici-socket" test -S "$vici_socket"
check "ip command" command -v ip
check "swanctl command" command -v swanctl
check "charon command" command -v charon
check "ping command" command -v ping
check "kernel xfrm" sh -c 'test -e /proc/net/xfrm_stat || test -e /proc/net/xfrm_policy'
check "xfrm interface support" ip link help xfrm
check "named netns create/delete" sh -c 'set -e; ns="higgs-preflight-$$"; trap "ip netns delete \"$ns\" >/dev/null 2>&1 || true" EXIT; ip netns add "$ns"; ip netns exec "$ns" true'

if [ "$check_udp" = "1" ]; then
  check "udp ike port" sh -c "python3 - <<PY
import socket
s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('0.0.0.0', int('$ike_port')))
s.close()
PY"
  check "udp natt port" sh -c "python3 - <<PY
import socket
s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('0.0.0.0', int('$natt_port')))
s.close()
PY"
else
  printf '[skip] udp port bindability (set HIGGS_IPSEC_CHECK_UDP=1)\n'
fi

rm -f /tmp/higgs-ipsec-preflight.out

if [ "$failures" -ne 0 ]; then
  printf 'ipsec/xfrm preflight failed: %s check(s)\n' "$failures" >&2
  exit 1
fi

printf 'ipsec/xfrm preflight passed\n'
