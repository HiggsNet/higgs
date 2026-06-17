#!/usr/bin/env bash
# BIRD / Babel root preflight: verifies that the host or container has
# everything needed to run managed-BIRD root smoke tests.
set -euo pipefail

check() {
  local name="$1"
  shift
  if "$@" >/tmp/higgs-bird-preflight.out 2>&1; then
    printf '[ok]   %s\n' "$name"
  else
    printf '[fail] %s: ' "$name"
    tr '\n' ' ' </tmp/higgs-bird-preflight.out
    printf '\n'
    failures=$((failures + 1))
  fi
}

note_container_context() {
  if test -f /.dockerenv || test -f /run/.containerenv || grep -qaE '(docker|lxc|containerd|kubepods)' /proc/1/cgroup /proc/self/cgroup 2>/dev/null; then
    printf '[info] container-like environment detected; nested LXC/Docker may still block netns even with --privileged\n'
  fi
}

failures=0
note_container_context

check "linux" test "$(uname -s)" = "Linux"
check "root-or-cap-net-admin" bash -c '[ "$(id -u)" = 0 ] || { cap_eff="$(awk "/^CapEff:/ {print \$2}" /proc/self/status)"; cap=$((16#$cap_eff)); [ $((cap & (1 << 12))) -ne 0 ]; }'
check "bird binary" command -v bird
check "birdc binary" command -v birdc
check "ip command" command -v ip
check "ping command" command -v ping
check "named netns create/delete" sh -c 'set -e; ns="higgs-bird-preflight-$$"; trap "ip netns delete \"$ns\" >/dev/null 2>&1 || true" EXIT; ip netns add "$ns"; ip netns exec "$ns" true'

# Check BIRD version >= 2.0
if command -v bird >/dev/null 2>&1; then
  bird_version_raw="$(bird --version 2>&1 | head -1)"
  bird_version="$(printf '%s\n' "$bird_version_raw" | sed -n 's/^.*BIRD version \([0-9][0-9.]*\).*$/\1/p')"
  bird_major="$(printf '%s\n' "$bird_version" | cut -d. -f1)"
  if [ -n "$bird_major" ] && [ "$bird_major" -ge 2 ] 2>/dev/null; then
    printf '[ok]   bird-version %s\n' "$bird_version"
  else
    printf '[fail] bird-version: expected >=2.0, got %q\n' "$bird_version_raw" >&2
    failures=$((failures + 1))
  fi
fi

rm -f /tmp/higgs-bird-preflight.out

if [ "$failures" -ne 0 ]; then
  printf 'bird/babel preflight failed: %s check(s)\n' "$failures" >&2
  exit 1
fi

printf 'bird/babel preflight passed\n'