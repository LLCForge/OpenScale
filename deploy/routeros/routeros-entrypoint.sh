#!/bin/sh
# Entry point of the RouterOS image (#889, docs/routeros.md). Checks what
# RouterOS gave the container, prepares the subnet router / exit node
# forwarding inside the container's own network namespace when asked,
# and hands over to the common entry point (deploy/docker/entrypoint.sh:
# joining with the invite file, then "openscale up").
#
# OPENSCALE_ROUTER_ROLE (RouterOS: /container/envs):
#   device  (default) only the tunnel: the router reaches the private
#           network through the container (a route to the overlay range)
#   router  subnet router or exit node: IPv4 forwarding is turned on in
#           the container and traffic from the tunnel is masqueraded to
#           the veth, so RouterOS needs no route back to the overlay range.
#           The role itself still comes from the signed network document.
set -eu

log() { printf 'openscale-routeros: %s\n' "$*" >&2; }

if [ ! -c /dev/net/tun ]; then
	# Some kernels create the node on demand; try once, then explain.
	mkdir -p /dev/net 2>/dev/null || true
	mknod /dev/net/tun c 10 200 2>/dev/null || true
	chmod 0600 /dev/net/tun 2>/dev/null || true
fi
if [ ! -c /dev/net/tun ]; then
	log "/dev/net/tun yok. RouterOS bu konteynere TUN aygıtı vermiyor; docs/routeros.md 'Sınırlar'."
	exit 1
fi

ROLE=${OPENSCALE_ROUTER_ROLE:-device}
IFACE=${OPENSCALE_INTERFACE:-OpenScale}
case "$IFACE" in
'' | *[!A-Za-z0-9_-]*) log "OPENSCALE_INTERFACE geçersiz: $IFACE"; exit 2 ;;
esac
case "$ROLE" in
device) ;;
router)
	if ! sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1; then
		log "IPv4 iletimi açılamadı (/proc/sys salt okunur). Alt ağ yönlendirici ve çıkış düğümü bu RouterOS sürümünde çalışmaz."
		exit 1
	fi
	sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || log "IPv6 iletimi açılamadı; yalnızca IPv4 iletilecek"
	# Own table: replaced as a whole on every start, never touches others.
	nft -f - <<EOF
table ip openscale_routeros
delete table ip openscale_routeros
table ip openscale_routeros {
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		iifname "$IFACE" oifname != "$IFACE" masquerade
	}
}
EOF
	log "yönlendirici kipi: iletim açık, tünelden gelen trafik veth'e maskeleniyor"
	;;
*) log "OPENSCALE_ROUTER_ROLE device veya router olmalı: $ROLE"; exit 2 ;;
esac

exec /usr/local/bin/openscale-entrypoint "$@"
