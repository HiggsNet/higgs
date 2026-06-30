#!/usr/bin/env sh
set -u

HIGGS_BIN="${HIGGS_BIN:-higgs}"
FILTER="${HIGGS_ROTATE_FILTER:-}"
JOURNAL_UNIT="${HIGGS_JOURNAL_UNIT:-higgs}"
LOG_FILE="${HIGGS_LOG_FILE:-}"
LINES="${HIGGS_DEBUG_LINES:-300}"

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

section "time"
run date -Is
run uname -a

section "higgs status"
run "$HIGGS_BIN" debug peers
higgs_debug links
run "$HIGGS_BIN" debug health
higgs_debug rotate

section "higgs db rotate records"
run "$HIGGS_BIN" db dump

section "strongswan status"
run swanctl --stats
run swanctl --list-conns
run swanctl --list-sas
run swanctl --list-pols

section "xfrm links and state"
run ip -d link show type xfrm
run ip xfrm state
run ip xfrm policy
run ip route show table all
run ip rule show

section "higgs logs"
if [ -n "$LOG_FILE" ]; then
  run tail -n "$LINES" "$LOG_FILE"
else
  run journalctl -u "$JOURNAL_UNIT" -n "$LINES" --no-pager
fi

section "strongswan logs"
run journalctl -u strongswan -u strongswan-starter -u charon -n "$LINES" --no-pager
