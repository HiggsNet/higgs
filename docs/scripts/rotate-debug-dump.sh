#!/usr/bin/env sh
set -u

HIGGS_BIN="${HIGGS_BIN:-build/higgs}"
FILTER="${HIGGS_ROTATE_FILTER:-}"
LOG_FILE="${HIGGS_LOG_FILE:-}"
HIGGS_PID="${HIGGS_PID:-}"
CONFIG_FILE="${HIGGS_CONFIG_FILE:-/etc/higgs/config.yaml}"
LINES="${HIGGS_DEBUG_LINES:-300}"
NETNS_LIST="${HIGGS_NETNS_LIST:-}"

section() {
  printf '\n===== %s =====\n' "$1"
}

run() {
  printf '+ %s\n' "$*"
  "$@" 2>&1 || true
}

higgs_debug() {
  if [ -n "$FILTER" ]; then
    run "$HIGGS_BIN" debug "$1" --filter "$FILTER"
  else
    run "$HIGGS_BIN" debug "$1"
  fi
}

higgs_pids() {
  if [ -n "$HIGGS_PID" ]; then
    printf '%s\n' "$HIGGS_PID"
    return
  fi
  ps -eo pid=,args= 2>/dev/null | awk '
    $0 ~ /(^|[[:space:]])([^[:space:]]*\/)?build\/higgs([[:space:]]|$)/ {
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

section "higgs process"
PIDS="$(higgs_pids | tr '\n' ' ')"
printf 'matched_build_higgs_pids: %s\n' "${PIDS:-none}"

section "higgs config"
run sed -n 1,240p "$CONFIG_FILE"

section "higgs status"
run "$HIGGS_BIN" debug peers
higgs_debug links
run "$HIGGS_BIN" debug health
higgs_debug rotate

section "higgs active ipsec records"
run "$HIGGS_BIN" debug records --prefix ipsec/ --values

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

section "higgs logs"
if [ -n "$LOG_FILE" ]; then
  run tail -n "$LINES" "$LOG_FILE"
else
  if [ -n "$PIDS" ]; then
    for pid in $PIDS; do
      section "higgs journal pid $pid"
      run journalctl "_PID=$pid" -n "$LINES" --no-pager
    done
  else
    printf 'no build/higgs pid found; set HIGGS_PID=<pid> or HIGGS_LOG_FILE=<path>\n'
  fi
fi

section "strongswan logs"
run journalctl -u strongswan-swanctl.service -u strongswan -u strongswan-starter -u charon -n "$LINES" --no-pager
