#!/usr/bin/env bash
set -euo pipefail

bin="${HIGGS_BIN:-build/higgs}"

usage() {
  cat <<'USAGE'
Usage:
  public-gossip-node.sh root-init <dir>
  public-gossip-node.sh config <dir> <peer-id> <listen-addr> <advertise-addr> <root-public-key> [<bootstrap-id> <bootstrap-addr> ...]
  public-gossip-node.sh key-request <dir> <zone> <key.json> <request.json>
  public-gossip-node.sh delegate-issue <admin-dir> <request.json> <bundle.json>
  public-gossip-node.sh join-accept <dir> <bundle.json> <key.json>
  public-gossip-node.sh run-daemon <dir> [interval-seconds]
  public-gossip-node.sh put-identity <dir> <zone> <value>
  public-gossip-node.sh status <dir>
  public-gossip-node.sh verify <dir> <zone>

Environment:
  HIGGS_BIN defaults to build/higgs.
USAGE
}

config_path() {
  printf '%s/config.yaml' "$1"
}

require_bin() {
  if [ ! -x "$bin" ]; then
    printf 'Higgs binary not found or not executable: %s\n' "$bin" >&2
    exit 1
  fi
}

write_config() {
  dir="$1"
  peer_id="$2"
  listen_addr="$3"
  advertise_addr="$4"
  root_key="$5"
  shift 5

  mkdir -p "$dir"
  {
    printf 'data_dir: %s\n' "$dir"
    printf 'peer_id: %s\n' "$peer_id"
    printf 'listen_addr: %s\n' "$listen_addr"
    printf 'advertise_addr: %s\n' "$advertise_addr"
    printf 'trusted_root_public_key: %s\n' "$root_key"
    if [ "$#" -gt 0 ]; then
      printf 'bootstrap:\n'
      while [ "$#" -gt 0 ]; do
        if [ "$#" -lt 2 ]; then
          printf 'bootstrap arguments must be pairs: <id> <addr>\n' >&2
          exit 1
        fi
        printf '  - id: %s\n' "$1"
        printf '    addr: %s\n' "$2"
        shift 2
      done
    fi
  } >"$(config_path "$dir")"
  printf 'wrote %s\n' "$(config_path "$dir")"
}

if [ "$#" -lt 1 ]; then
  usage
  exit 1
fi

cmd="$1"
shift
require_bin

case "$cmd" in
  root-init)
    if [ "$#" -ne 1 ]; then usage; exit 1; fi
    dir="$1"
    mkdir -p "$dir"
    {
      printf 'data_dir: %s\n' "$dir"
      printf 'peer_id: node-admin\n'
      printf 'listen_addr: 127.0.0.1:33433\n'
    } >"$(config_path "$dir")"
    HIGGS_CONFIG="$(config_path "$dir")" "$bin" root init
    HIGGS_CONFIG="$(config_path "$dir")" "$bin" root pubkey
    ;;
  config)
    if [ "$#" -lt 5 ]; then usage; exit 1; fi
    write_config "$@"
    ;;
  key-request)
    if [ "$#" -ne 4 ]; then usage; exit 1; fi
    dir="$1"
    zone="$2"
    key="$3"
    request="$4"
    HIGGS_CONFIG="$(config_path "$dir")" "$bin" keygen "$key"
    HIGGS_CONFIG="$(config_path "$dir")" "$bin" join request "$zone" "$key" "$request"
    ;;
  delegate-issue)
    if [ "$#" -ne 3 ]; then usage; exit 1; fi
    admin_dir="$1"
    request="$2"
    bundle="$3"
    HIGGS_CONFIG="$(config_path "$admin_dir")" "$bin" delegate issue "$request" "$bundle"
    ;;
  join-accept)
    if [ "$#" -ne 3 ]; then usage; exit 1; fi
    dir="$1"
    bundle="$2"
    key="$3"
    HIGGS_CONFIG="$(config_path "$dir")" "$bin" join accept "$bundle" "$key"
    ;;
  run-daemon)
    if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then usage; exit 1; fi
    dir="$1"
    interval="${2:-5}"
    exec env HIGGS_CONFIG="$(config_path "$dir")" "$bin" daemon --interval "$interval"
    ;;
  put-identity)
    if [ "$#" -ne 3 ]; then usage; exit 1; fi
    dir="$1"
    zone="$2"
    value="$3"
    HIGGS_CONFIG="$(config_path "$dir")" "$bin" record put "$zone" identity "$value"
    ;;
  status)
    if [ "$#" -ne 1 ]; then usage; exit 1; fi
    dir="$1"
    HIGGS_CONFIG="$(config_path "$dir")" "$bin" sync status --verbose
    ;;
  verify)
    if [ "$#" -ne 2 ]; then usage; exit 1; fi
    dir="$1"
    zone="$2"
    HIGGS_CONFIG="$(config_path "$dir")" "$bin" verify "$zone"
    ;;
  *)
    usage
    exit 1
    ;;
esac
