#!/usr/bin/env bash
# BIRD / Babel container smoke: automatically starts a privileged container,
# mounts the repo, reuses the cached image and Go cache volumes, and runs
# `make bird-babel-smoke`. Mirrors ipsec-xfrm-container-smoke.sh.
set -euo pipefail

container_runtime="${PHOTON_CONTAINER_RUNTIME:-docker}"
base_image="${PHOTON_BIRD_IMAGE:-ubuntu:24.04}"
cache_suffix="${base_image//[^A-Za-z0-9_.-]/-}"
cache_image="${PHOTON_BIRD_CACHE_IMAGE:-photon-bird-babel-smoke:${cache_suffix}}"
rebuild_image="${PHOTON_BIRD_REBUILD_IMAGE:-0}"
container_userns="${PHOTON_CONTAINER_USERNS:-host}"
go_cache="${GOCACHE:-/tmp/photon-gocache}"
go_mod_cache="${GOMODCACHE:-/tmp/photon-gomodcache}"
cache_prefix="${PHOTON_BIRD_CACHE_PREFIX:-photon-bird-babel}"
go_cache_volume="${PHOTON_BIRD_GO_CACHE_VOLUME:-${cache_prefix}-gocache}"
go_mod_cache_volume="${PHOTON_BIRD_GO_MOD_CACHE_VOLUME:-${cache_prefix}-gomodcache}"
repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
host_uid="$(id -u)"
host_gid="$(id -g)"

if ! command -v "$container_runtime" >/dev/null 2>&1; then
  printf 'container runtime %q not found; set PHOTON_CONTAINER_RUNTIME=docker or podman\n' "$container_runtime" >&2
  exit 1
fi

printf '[bird-babel-container] runtime=%s base_image=%s cache_image=%s repo=%s\n' "$container_runtime" "$base_image" "$cache_image" "$repo_root"
printf '[bird-babel-container] starting disposable privileged container; nested LXC/CI may still block netns\n'

ensure_image() {
  if [ "$rebuild_image" != "1" ] && "$container_runtime" image inspect "$cache_image" >/dev/null 2>&1; then
    printf '[bird-babel-container] using cached image %s\n' "$cache_image"
    return
  fi

  build_ctx="$(mktemp -d "${TMPDIR:-/tmp}/photon-bird-image.XXXXXX")"
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
    iputils-ping \
    bird2 \
    bird2-doc \
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

  printf '[bird-babel-container] building cached image %s from %s\n' "$cache_image" "$base_image"
  "$container_runtime" build \
    --build-arg "BASE_IMAGE=$base_image" \
    -t "$cache_image" \
    "$build_ctx"
}

ensure_image

# Docker-in-LXC can lose useful ownership/capability behavior when Docker adds
# another user namespace remap. Keep host userns by default.
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
  -e PHOTON_BIRD_SMOKE_CONTAINER=1 \
  "$cache_image" bash -lc '
    set -euo pipefail
    trap '\''if [ -d /work/build ]; then chown -R "$HOST_UID:$HOST_GID" /work/build || true; fi'\'' EXIT
    make bird-babel-smoke
  '