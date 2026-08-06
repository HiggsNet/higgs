# syntax=docker/dockerfile:1

ARG GO_VERSION=1.25

# The builder distribution does not become part of the final image; both Go
# binaries are built with CGO disabled below.
FROM golang:${GO_VERSION}-bookworm AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

ARG VERSION=container
ARG COMMIT=unknown
ARG DIRTY=false
ARG BUILD_TIME=unknown

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags="-s -w -X main.buildCommit=${COMMIT} -X main.buildDescribe=${VERSION} -X main.buildDirty=${DIRTY} -X main.buildTime=${BUILD_TIME}" \
    -o /out/photon ./app/photon \
    && CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -o /out/photon-services ./app/photon-services

# Match the primary native compatibility baseline and its BIRD 2.14 package.
FROM ubuntu:24.04

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        bird2 \
        ca-certificates \
        iproute2 \
        ipset \
        iptables \
        iputils-ping \
        libstrongswan-extra-plugins \
        libstrongswan-standard-plugins \
        nftables \
        strongswan \
        strongswan-charon \
        strongswan-swanctl \
    && rm -rf /var/lib/apt/lists/* \
    && bird_version="$(bird --version 2>&1 | sed -n 's/^.*BIRD version \([0-9][0-9.]*\).*$/\1/p')" \
    && bird_major="$(printf '%s\n' "$bird_version" | cut -d. -f1)" \
    && bird_minor="$(printf '%s\n' "$bird_version" | cut -d. -f2)" \
    && test -n "$bird_major" \
    && test -n "$bird_minor" \
    && { test "$bird_major" -gt 2 || { test "$bird_major" -eq 2 && test "$bird_minor" -ge 14; }; }

COPY --from=build /out/photon /usr/local/bin/photon
COPY --from=build /out/photon-services /usr/local/bin/photon-services

ENV PHOTON_CONFIG=/etc/photon/config.yaml
ENV PATH="/usr/lib/ipsec:${PATH}"
VOLUME ["/etc/photon", "/var/lib/photon"]
EXPOSE 33434/udp

ENTRYPOINT ["photon"]
CMD ["version"]
