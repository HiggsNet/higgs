#!/usr/bin/env bash
set -euo pipefail

bin="${HIGGS_BIN:-build/higgs}"

usage() {
  cat <<'USAGE'
Usage:
  public-gossip-node.sh admin-init <base-dir> [admin-zone] [listen-addr] [advertise-addr]
  public-gossip-node.sh node-init <dir> <zone> <listen-addr> <advertise-addr> <root-public-key> [<bootstrap-id> <bootstrap-addr> ...]
  public-gossip-node.sh issue-nodes <admin-dir> <request.b64>...
  public-gossip-node.sh auto-run <dir> [interval-seconds]
  public-gossip-node.sh accept-run <dir> <zone> <bundle.b64> [interval-seconds]
  public-gossip-node.sh root-init <dir>
  public-gossip-node.sh config <dir> <peer-id> <listen-addr> <advertise-addr> <root-public-key> [<bootstrap-id> <bootstrap-addr> ...]
  public-gossip-node.sh key-request <dir> <zone> <key.json> <request.b64>
  public-gossip-node.sh delegate-issue <admin-dir> <request.b64> <bundle.b64>
  public-gossip-node.sh join-accept <dir> <bundle.b64> <key.json>
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

zone_slug() {
  local zone
  zone="${1%.}"
  printf '%s' "${zone%%.*}"
}

key_path() {
  printf '%s/%s.key.json' "$1" "$(zone_slug "$2")"
}

request_path() {
  printf '%s/%s.request.b64' "$1" "$(zone_slug "$2")"
}

bundle_path_for_request() {
  local request
  request="$1"
  if [ "${request%.request.b64}" != "$request" ]; then
    printf '%s.bundle.b64' "${request%.request.b64}"
  else
    printf '%s.bundle.b64' "$request"
  fi
}

require_bin() {
  if [ ! -x "$bin" ]; then
    printf 'Higgs binary not found or not executable: %s\n' "$bin" >&2
    exit 1
  fi
}

root_init() {
  local dir
  dir="$1"
  mkdir -p "$dir"
  {
    printf 'data_dir: %s\n' "$dir"
    printf 'peer_id: node-admin\n'
    printf 'listen_addr: 127.0.0.1:33433\n'
  } >"$(config_path "$dir")"
  HIGGS_CONFIG="$(config_path "$dir")" "$bin" root init
  HIGGS_CONFIG="$(config_path "$dir")" "$bin" root pubkey
}

write_config() {
  local dir peer_id listen_addr advertise_addr root_key
  dir="$1"
  peer_id="$2"
  listen_addr="$3"
  advertise_addr="$4"
  root_key="$5"
  shift 5

  mkdir -p "$dir"
  {
    printf 'data_dir: %s\n' "$dir"
    if [ "${CONFIG_MANAGED_ZONE:-}" != "" ]; then
      printf 'managed_zone: %s\n' "$CONFIG_MANAGED_ZONE"
    fi
    if [ "${CONFIG_IDENTITY_KEY_PATH:-}" != "" ]; then
      printf 'identity:\n'
      printf '  key_path: %s\n' "$CONFIG_IDENTITY_KEY_PATH"
    fi
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

make_key_request() {
  local dir zone key request
  dir="$1"
  zone="$2"
  key="$3"
  request="$4"
  HIGGS_CONFIG="$(config_path "$dir")" "$bin" keygen "$key"
  HIGGS_CONFIG="$(config_path "$dir")" "$bin" join request "$zone" "$key" "$request"
}

make_configured_request() {
  local dir request
  dir="$1"
  request="$2"
  HIGGS_CONFIG="$(config_path "$dir")" "$bin" join request --from-config "$request"
}

issue_bundle() {
  local admin_dir request bundle
  admin_dir="$1"
  request="$2"
  bundle="$3"
  HIGGS_CONFIG="$(config_path "$admin_dir")" "$bin" delegate issue "$request" "$bundle"
}

accept_bundle() {
  local dir bundle key
  dir="$1"
  bundle="$2"
  key="$3"
  HIGGS_CONFIG="$(config_path "$dir")" "$bin" join accept "$bundle" "$key"
}

if [ "$#" -lt 1 ]; then
  usage
  exit 1
fi

cmd="$1"
shift
require_bin

case "$cmd" in
  admin-init)
    if [ "$#" -lt 1 ] || [ "$#" -gt 4 ]; then usage; exit 1; fi
    base="$1"
    admin_zone="${2:-catofes.}"
    admin_listen_addr="${3:-127.0.0.1:33435}"
    admin_advertise_addr="${4:-127.0.0.1:33435}"
    admin_slug="$(zone_slug "$admin_zone")"
    root_dir="$base/root-admin"
    admin_dir="$base/$admin_slug-admin"
    mkdir -p "$base"
    root_key="$(root_init "$root_dir" | tail -n 1)"
    CONFIG_MANAGED_ZONE="$admin_zone"
    CONFIG_IDENTITY_KEY_PATH="$base/$admin_slug.key.json"
    write_config "$admin_dir" "$admin_zone" "$admin_listen_addr" "$admin_advertise_addr" "$root_key"
    unset CONFIG_MANAGED_ZONE CONFIG_IDENTITY_KEY_PATH
    make_key_request "$admin_dir" "$admin_zone" "$base/$admin_slug.key.json" "$base/$admin_slug.request.b64"
    issue_bundle "$root_dir" "$base/$admin_slug.request.b64" "$base/$admin_slug.bundle.b64"
    accept_bundle "$admin_dir" "$base/$admin_slug.bundle.b64" "$base/$admin_slug.key.json"
    printf 'root_public_key: %s\n' "$root_key"
    printf 'root_admin_dir: %s\n' "$root_dir"
    printf 'admin_zone_dir: %s\n' "$admin_dir"
    ;;
  node-init)
    if [ "$#" -lt 5 ]; then usage; exit 1; fi
    dir="$1"
    zone="$2"
    listen_addr="$3"
    advertise_addr="$4"
    root_key="$5"
    shift 5
    key="$(key_path "$dir" "$zone")"
    request="$(request_path "$dir" "$zone")"
    mkdir -p "$dir"
    HIGGS_CONFIG="$(config_path "$dir")" "$bin" keygen "$key"
    CONFIG_MANAGED_ZONE="$zone"
    CONFIG_IDENTITY_KEY_PATH="$key"
    write_config "$dir" "$zone" "$listen_addr" "$advertise_addr" "$root_key" "$@"
    unset CONFIG_MANAGED_ZONE CONFIG_IDENTITY_KEY_PATH
    make_configured_request "$dir" "$request"
    printf 'request: %s\n' "$request"
    printf 'key: %s\n' "$key"
    ;;
  issue-nodes)
    if [ "$#" -lt 2 ]; then usage; exit 1; fi
    admin_dir="$1"
    shift
    for request in "$@"; do
      bundle="$(bundle_path_for_request "$request")"
      issue_bundle "$admin_dir" "$request" "$bundle"
      printf 'bundle: %s\n' "$bundle"
    done
    ;;
  accept-run)
    if [ "$#" -lt 3 ] || [ "$#" -gt 4 ]; then usage; exit 1; fi
    dir="$1"
    zone="$2"
    bundle="$3"
    interval="${4:-5}"
    accept_bundle "$dir" "$bundle" "$(key_path "$dir" "$zone")"
    exec env HIGGS_CONFIG="$(config_path "$dir")" "$bin" daemon --interval "$interval"
    ;;
  auto-run)
    if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then usage; exit 1; fi
    dir="$1"
    interval="${2:-5}"
    exec env HIGGS_CONFIG="$(config_path "$dir")" "$bin" daemon --interval "$interval"
    ;;
  root-init)
    if [ "$#" -ne 1 ]; then usage; exit 1; fi
    root_init "$1"
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
    make_key_request "$dir" "$zone" "$key" "$request"
    ;;
  delegate-issue)
    if [ "$#" -ne 3 ]; then usage; exit 1; fi
    admin_dir="$1"
    request="$2"
    bundle="$3"
    issue_bundle "$admin_dir" "$request" "$bundle"
    ;;
  join-accept)
    if [ "$#" -ne 3 ]; then usage; exit 1; fi
    dir="$1"
    bundle="$2"
    key="$3"
    accept_bundle "$dir" "$bundle" "$key"
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
