# syntax=docker/dockerfile:1
#
# OpenScale device image for MikroTik RouterOS 7 containers (#889,
# docs/routeros.md). The image contains the signed release program (a
# static Go binary, CGO_ENABLED=0) and is built offline, from the
# repository root, after the program was verified against the signed
# release manifest:
#
#   docker buildx build -f deploy/routeros/Dockerfile --platform linux/arm64 \
#       --build-arg DIST=dist/1.0.0-beta.2 -o type=docker,dest=openscale-routeros-arm64.tar .
#
# RouterOS imports the docker-archive tar (/container/add file=...). Only
# linux/arm64, linux/arm (GOARM=7) and linux/amd64 exist; MIPS RouterBOARDs
# have no container package.
#
# The process needs NET_ADMIN and /dev/net/tun and nothing else; NET_RAW
# only for "openscale ping". It runs as root inside the container because
# it runs `ip` and `nft` (deploy/docker/Dockerfile explains why a non-root
# USER cannot work).

ARG RUNTIME_IMAGE=alpine:3.22

FROM ${RUNTIME_IMAGE}
ARG TARGETARCH
ARG TARGETVARIANT
ARG DIST=dist
# iproute2 assigns addresses and routes; nftables gives forwarding/NAT
# for the subnet router and exit node roles (internal/osnet). Nothing else.
RUN apk add --no-cache iproute2 nftables \
    && install -d -m 0700 -o root -g root /var/lib/openscale
# armv7 binaries are named openscale-linux-armv7 in the release.
COPY ${DIST}/openscale-linux-${TARGETARCH}${TARGETVARIANT} /usr/bin/openscale
COPY --chmod=0755 deploy/docker/entrypoint.sh /usr/local/bin/openscale-entrypoint
COPY --chmod=0755 deploy/routeros/routeros-entrypoint.sh /usr/local/bin/openscale-routeros
# A Windows checkout may have CRLF line endings; /bin/sh would then fail.
RUN sed -i 's/\r$//' /usr/local/bin/openscale-entrypoint /usr/local/bin/openscale-routeros \
    && chmod 0755 /usr/bin/openscale \
    && /usr/bin/openscale version

ENV OPENSCALE_STATE=file \
    OPENSCALE_STATE_DIR=/var/lib/openscale \
    OPENSCALE_LISTEN_PORT=41821 \
    OPENSCALE_MEMORY_PROFILE=low
LABEL org.opencontainers.image.title="OpenScale (RouterOS)" \
      org.opencontainers.image.description="OpenScale device for MikroTik RouterOS 7 containers" \
      org.opencontainers.image.source="local build (deploy/routeros/Dockerfile)"
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/openscale-routeros"]
