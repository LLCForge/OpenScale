#!/bin/sh
# Prepares mkosi.extra for the coordinator image (#636, ADR-0184): copies the
# verified static binary, the service unit with its RAM-mode drop-in, the
# service user and the journald/coredump settings. Run from this directory:
#   sh hazirla.sh /yol/openscale-linux-amd64
# The binary must already be verified against the signed release manifest
# (docs/surum-dogrulama.md); this script downloads nothing.
set -eu

BIN=${1:?kullanım: sh hazirla.sh OPENSCALE_IKILISI}
HERE=$(cd "$(dirname "$0")" && pwd)
DEPLOY="$HERE/../../linux"
EXTRA="$HERE/mkosi.extra"

if ! file "$BIN" 2>/dev/null | grep -q 'statically linked'; then
	echo "UYARI: $BIN statik bağlı görünmüyor (CGO_ENABLED=0 ile derleyin)" >&2
fi

install -D -m 0755 "$BIN" "$EXTRA/usr/local/bin/openscale"
install -D -m 0644 "$DEPLOY/openscale-coordinator.service" "$EXTRA/usr/lib/systemd/system/openscale-coordinator.service"
install -D -m 0644 "$DEPLOY/openscale-coordinator-ram.conf" "$EXTRA/usr/lib/systemd/system/openscale-coordinator.service.d/50-openscale-ram.conf"
install -D -m 0644 "$DEPLOY/openscale.sysusers" "$EXTRA/usr/lib/sysusers.d/openscale.conf"
install -D -m 0644 "$DEPLOY/50-openscale-journald.conf" "$EXTRA/usr/lib/systemd/journald.conf.d/50-openscale.conf"
install -D -m 0644 "$DEPLOY/50-openscale-coredump.conf" "$EXTRA/usr/lib/systemd/coredump.conf.d/50-openscale.conf"
install -D -m 0644 "$DEPLOY/nftables.conf" "$EXTRA/etc/nftables.conf"
mkdir -p "$EXTRA/usr/lib/systemd/system/multi-user.target.wants"
ln -sf ../openscale-coordinator.service "$EXTRA/usr/lib/systemd/system/multi-user.target.wants/openscale-coordinator.service"
echo "mkosi.extra hazır. Tohum dosyalarını (/etc/openscale/coordinator-seed) imaja KOYMAYIN; ilk açılışta systemd kimlik bilgisi olarak ekleyin."
