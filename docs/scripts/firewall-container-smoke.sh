#!/usr/bin/env bash
set -euo pipefail

container_runtime="${HIGGS_CONTAINER_RUNTIME:-docker}"
base_image="${HIGGS_FIREWALL_IMAGE:-ubuntu:24.04}"
cache_suffix="${base_image//[^A-Za-z0-9_.-]/-}"
cache_image="${HIGGS_FIREWALL_CACHE_IMAGE:-higgs-firewall-smoke:${cache_suffix}}"
rebuild_image="${HIGGS_FIREWALL_REBUILD_IMAGE:-0}"
container_userns="${HIGGS_CONTAINER_USERNS:-host}"
go_cache="${GOCACHE:-/tmp/higgs-gocache}"
go_mod_cache="${GOMODCACHE:-/tmp/higgs-gomodcache}"
cache_prefix="${HIGGS_FIREWALL_CACHE_PREFIX:-higgs-firewall}"
go_cache_volume="${HIGGS_FIREWALL_GO_CACHE_VOLUME:-${cache_prefix}-gocache}"
go_mod_cache_volume="${HIGGS_FIREWALL_GO_MOD_CACHE_VOLUME:-${cache_prefix}-gomodcache}"
repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
host_uid="$(id -u)"
host_gid="$(id -g)"

if ! command -v "$container_runtime" >/dev/null 2>&1; then
  printf 'container runtime %q not found; set HIGGS_CONTAINER_RUNTIME=docker or podman\n' "$container_runtime" >&2
  exit 1
fi

printf '[firewall-container] runtime=%s base_image=%s cache_image=%s repo=%s\n' "$container_runtime" "$base_image" "$cache_image" "$repo_root"
printf '[firewall-container] starting disposable privileged container; nested LXC/CI may still block netfilter/netns\n'

ensure_image() {
  if [ "$rebuild_image" != "1" ] && "$container_runtime" image inspect "$cache_image" >/dev/null 2>&1; then
    printf '[firewall-container] using cached image %s\n' "$cache_image"
    return
  fi

  build_ctx="$(mktemp -d "${TMPDIR:-/tmp}/higgs-firewall-image.XXXXXX")"
  trap 'rm -rf "$build_ctx"' EXIT
  cat > "$build_ctx/Dockerfile" <<'DOCKERFILE'
ARG BASE_IMAGE=ubuntu:24.04
FROM ${BASE_IMAGE}

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    ca-certificates \
    make \
    golang \
    iproute2 \
    iptables \
    nftables \
    util-linux \
  && rm -rf /var/lib/apt/lists/*

RUN if command -v nsenter >/dev/null 2>&1 && [ -x /usr/sbin/ip ] && [ ! -e /usr/sbin/ip.real ]; then \
    mv /usr/sbin/ip /usr/sbin/ip.real; \
    printf '%s\n' \
      '#!/bin/bash' \
      'if [ "$1" = "netns" ] && [ "$2" = "exec" ]; then' \
      '  ns="$3"' \
      '  shift 3' \
      '  exec nsenter --net="/var/run/netns/$ns" "$@"' \
      'fi' \
      'exec /usr/sbin/ip.real "$@"' \
      > /usr/sbin/ip; \
    chmod +x /usr/sbin/ip; \
  fi

WORKDIR /work
DOCKERFILE

  printf '[firewall-container] building cached image %s from %s\n' "$cache_image" "$base_image"
  "$container_runtime" build \
    --build-arg "BASE_IMAGE=$base_image" \
    -t "$cache_image" \
    "$build_ctx"
}

ensure_image

extra_args=()
if [ "$container_runtime" = "docker" ] && [ -n "$container_userns" ]; then
  extra_args+=(--userns="$container_userns")
fi

cache_args=(
  -v "$go_cache_volume:$go_cache"
  -v "$go_mod_cache_volume:$go_mod_cache"
)

"$container_runtime" run --rm -t --privileged \
  "${extra_args[@]}" \
  "${cache_args[@]}" \
  -v "$repo_root:/work" \
  -w /work \
  -e DEBIAN_FRONTEND=noninteractive \
  -e HOST_UID="$host_uid" \
  -e HOST_GID="$host_gid" \
  -e GO="${GO:-go}" \
  -e GOCACHE="$go_cache" \
  -e GOMODCACHE="$go_mod_cache" \
  -e CGO_ENABLED="${CGO_ENABLED:-0}" \
  -e HIGGS_FIREWALL_CONTAINER_SMOKE=1 \
  "$cache_image" bash -lc '
    set -euo pipefail
    trap '\''if [ -d /work/build ]; then chown -R "$HOST_UID:$HOST_GID" /work/build || true; fi'\'' EXIT
    make firewall-smoke
  '
