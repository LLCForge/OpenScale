# OpenScale add-on image (#890). The Supervisor builds it on the Home
# Assistant machine from this folder; the program is not downloaded but
# copied from bin/, where deploy/homeassistant/prepare.sh put the
# programs verified against the signed release manifest.
ARG BUILD_FROM
FROM ${BUILD_FROM}
ARG BUILD_ARCH
# iproute2 assigns the interface addresses (internal/osnet).
RUN apk add --no-cache iproute2
COPY bin/openscale-${BUILD_ARCH} /usr/bin/openscale
COPY run.sh /run.sh
# A Windows checkout may have CRLF line endings.
RUN sed -i 's/\r$//' /run.sh \
    && chmod 0755 /run.sh /usr/bin/openscale \
    && /usr/bin/openscale version
CMD ["/run.sh"]
