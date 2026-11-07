# syntax=docker/dockerfile:1
#
# OpenScale device image (#168, ADR-0091). Built on the owner's own machine
# from the repository root; there is no published image and no registry:
#
#   docker build -f deploy/docker/Dockerfile \
#       --build-arg SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) -t openscale:$(cat VERSION) .
#
# Pin both base images by digest before building a release image
# (docker buildx imagetools inspect <image> prints it), for example
#   --build-arg GO_IMAGE=golang:1.26-alpine@sha256:<digest>
# The build stage downloads Go modules (verified against go.sum) unless a
# vendor/ tree from `scripts/release.sh --vendor` is present.
#
# Running: docs/konteyner.md. In short, the container needs only
# CAP_NET_ADMIN and /dev/net/tun:
#
#   docker run -d --name openscale --cap-drop ALL --cap-add NET_ADMIN \
#       --device /dev/net/tun --security-opt no-new-privileges --read-only \
#       -v openscale-state:/var/lib/openscale \
#       -v ./invite.txt:/run/secrets/openscale-invite:ro \
#       -p 41821:41821/udp -e OPENSCALE_LISTEN_PORT=41821 openscale:0.9.0

ARG GO_IMAGE=golang:1.26-alpine
ARG RUNTIME_IMAGE=alpine:3.22

FROM ${GO_IMAGE} AS build
WORKDIR /src
# Never download a different Go toolchain behind the pinned image's back.
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-buildvcs=false
COPY . .
# Dependency policy (ADR-0002, #214) and module integrity before anything
# is built.
RUN set -eu; \
    if [ ! -d vendor ]; then go mod download && go mod verify; fi; \
    [ ! -d tools/depcheck ] || go run ./tools/depcheck go.mod
ARG SOURCE_DATE_EPOCH=0
# Same flags as scripts/release.sh, so the binary matches the release one
# for the same source, Go version and SOURCE_DATE_EPOCH (panel aside).
RUN set -eu; \
    v=$(tr -d ' \r\n' < VERSION); \
    b=$(date -u -d "@${SOURCE_DATE_EPOCH}" +%Y%m%d.%H%M); \
    mod=''; [ ! -d vendor ] || mod='-mod=vendor'; \
    go build -trimpath $mod \
      -ldflags "-s -w -buildid= -X github.com/openscale/openscale/internal/version.Version=$v -X github.com/openscale/openscale/internal/version.Build=$b" \
      -o /out/openscale ./cmd/openscale; \
    /out/openscale version

FROM ${RUNTIME_IMAGE}
# iproute2 assigns the interface addresses (internal/osnet); nothing else
# is installed. MagicDNS needs systemd-resolved and the exit node role
# needs writable /proc/sys, so neither works in a container
# (docs/konteyner.md).
RUN apk add --no-cache iproute2 \
    && install -d -m 0700 -o root -g root /var/lib/openscale
COPY --from=build /out/openscale /usr/bin/openscale
COPY --chmod=0755 deploy/docker/entrypoint.sh /usr/local/bin/openscale-entrypoint
# A Windows checkout may have CRLF line endings; /bin/sh would then fail.
RUN sed -i 's/\r$//' /usr/local/bin/openscale-entrypoint

# The process runs as root *inside* the container, but with every
# capability dropped except NET_ADMIN (docker run --cap-drop ALL --cap-add
# NET_ADMIN). A non-root USER cannot work: the daemon runs `ip`, and a
# non-root exec drops capabilities unless they are ambient, which neither
# Docker nor Kubernetes can grant; file capabilities are ignored under
# no-new-privileges. Run the container under rootless Podman/Docker or
# userns-remap so that container root is an unprivileged host user
# (ADR-0091).
ENV OPENSCALE_STATE=file \
    OPENSCALE_STATE_DIR=/var/lib/openscale
LABEL org.opencontainers.image.title="OpenScale" \
      org.opencontainers.image.description="OpenScale device: personal WireGuard mesh VPN" \
      org.opencontainers.image.source="local build (deploy/docker/Dockerfile)"
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=30s --timeout=10s --start-period=2m --retries=3 \
    CMD ["/usr/bin/openscale", "health", "--state-dir", "/var/lib/openscale"]
ENTRYPOINT ["/usr/local/bin/openscale-entrypoint"]
