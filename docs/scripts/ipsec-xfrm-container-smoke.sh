#!/usr/bin/env bash
set -euo pipefail

container_runtime="${HIGGS_CONTAINER_RUNTIME:-docker}"
image="${HIGGS_IPSEC_XFRM_IMAGE:-ubuntu:24.04}"
repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
host_uid="$(id -u)"
host_gid="$(id -g)"

if ! command -v "$container_runtime" >/dev/null 2>&1; then
  printf 'container runtime %q not found; set HIGGS_CONTAINER_RUNTIME=docker or podman\n' "$container_runtime" >&2
  exit 1
fi

printf '[ipsec-xfrm-container] runtime=%s image=%s repo=%s\n' "$container_runtime" "$image" "$repo_root"
printf '[ipsec-xfrm-container] starting disposable privileged container; nested LXC/CI may still block netns/XFRM\n'

"$container_runtime" run --rm -t --privileged \
  -v "$repo_root:/work" \
  -w /work \
  -e DEBIAN_FRONTEND=noninteractive \
  -e HOST_UID="$host_uid" \
  -e HOST_GID="$host_gid" \
  -e GO="${GO:-go}" \
  -e GOCACHE="${GOCACHE:-/tmp/higgs-gocache}" \
  -e GOMODCACHE="${GOMODCACHE:-/tmp/higgs-gomodcache}" \
  -e CGO_ENABLED="${CGO_ENABLED:-0}" \
  "$image" bash -lc '
    set -euo pipefail
    apt-get update
    apt-get install -y --no-install-recommends \
      ca-certificates \
      make \
      golang \
      iproute2 \
      iputils-ping \
      strongswan-swanctl \
      strongswan-charon
    trap '\''if [ -d /work/build ]; then chown -R "$HOST_UID:$HOST_GID" /work/build || true; fi'\'' EXIT
    make ipsec-xfrm-smoke
  '
