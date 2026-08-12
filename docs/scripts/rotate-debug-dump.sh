#!/usr/bin/env sh
set -u

PHOTON_BIN="${PHOTON_BIN:-build/photon}"
FILTER="${PHOTON_ROTATE_FILTER:-}"
LOG_FILE="${PHOTON_LOG_FILE:-}"
PHOTON_PID="${PHOTON_PID:-}"
CONFIG_FILE="${PHOTON_CONFIG_FILE:-/etc/photon/config.yaml}"
LINES="${PHOTON_DEBUG_LINES:-300}"
NETNS_LIST="${PHOTON_NETNS_LIST:-}"

section() {
  printf '\n===== %s =====\n' "$1"
}

run() {
  printf '+ %s\n' "$*"
  "$@" 2>&1 || true
}

photon_debug() {
  if [ -n "$FILTER" ]; then
    run "$PHOTON_BIN" debug "$1" --filter "$FILTER"
  else
    run "$PHOTON_BIN" debug "$1"
  fi
}

photon_pids() {
  if [ -n "$PHOTON_PID" ]; then
    printf '%s\n' "$PHOTON_PID"
    return
  fi
  ps -eo pid=,args= 2>/dev/null | awk '
    $0 ~ /(^|[[:space:]])([^[:space:]]*\/)?build\/photon([[:space:]]|$)/ {
      print $1
    }
  '
}

netns_names() {
  if [ -n "$NETNS_LIST" ]; then
    printf '%s\n' "$NETNS_LIST" | tr ',' '\n'
    return
  fi
  ip netns list 2>/dev/null | awk '{print $1}'
}

section "time"
run date -Is
run uname -a

section "photon process"
PIDS="$(photon_pids | tr '\n' ' ')"
printf 'matched_build_photon_pids: %s\n' "${PIDS:-none}"

section "photon config"
run sed -n 1,240p "$CONFIG_FILE"

section "photon status"
run "$PHOTON_BIN" debug peers
photon_debug links
run "$PHOTON_BIN" health --verbose
photon_debug rotate

section "photon active ipsec records"
run "$PHOTON_BIN" debug records --prefix ipsec/ --values

section "strongswan status"
run swanctl --stats
run swanctl --list-conns
run swanctl --list-sas
run swanctl --list-pols

section "xfrm links and state"
run ip -d link show type xfrm
run ip xfrm state
run ip xfrm policy
run cat /proc/net/xfrm_stat
run ip route show table all
run ip -6 route show table all
run ip rule show

NETNS_NAMES="$(netns_names | tr '\n' ' ')"
printf 'matched_netns: %s\n' "${NETNS_NAMES:-none}"
for ns in $NETNS_NAMES; do
  section "netns $ns links routes xfrm"
  run ip netns exec "$ns" ip -d link show type xfrm
  run ip netns exec "$ns" ip -s link show
  run ip netns exec "$ns" ip addr show
  run ip netns exec "$ns" ip route show table all
  run ip netns exec "$ns" ip -6 route show table all
  run ip netns exec "$ns" ip neigh show
  run ip netns exec "$ns" ip -6 neigh show
  run ip netns exec "$ns" ip xfrm state
  run ip netns exec "$ns" ip xfrm policy
  run ip netns exec "$ns" cat /proc/net/xfrm_stat
done

section "photon logs"
if [ -n "$LOG_FILE" ]; then
  run tail -n "$LINES" "$LOG_FILE"
else
  if [ -n "$PIDS" ]; then
    for pid in $PIDS; do
      section "photon journal pid $pid"
      run journalctl "_PID=$pid" -n "$LINES" --no-pager
    done
  else
    printf 'no build/photon pid found; set PHOTON_PID=<pid> or PHOTON_LOG_FILE=<path>\n'
  fi
fi

section "strongswan logs"
run journalctl -u strongswan-swanctl.service -u strongswan -u strongswan-starter -u charon -n "$LINES" --no-pager
