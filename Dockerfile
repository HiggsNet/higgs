# syntax=docker/dockerfile:1

ARG GO_VERSION=1.25

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
    -o /out/higgs ./app/higgs \
    && CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -o /out/higgs-services ./app/higgs-services

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bird2 \
        ca-certificates \
        iproute2 \
        ipset \
        iptables \
        iputils-ping \
        nftables \
        strongswan \
        strongswan-charon \
        strongswan-swanctl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /out/higgs /usr/local/bin/higgs
COPY --from=build /out/higgs-services /usr/local/bin/higgs-services

ENV HIGGS_CONFIG=/etc/higgs/config.yaml
VOLUME ["/etc/higgs", "/var/lib/higgs"]
EXPOSE 33434/udp

ENTRYPOINT ["higgs"]
CMD ["version"]
