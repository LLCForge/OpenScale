#!/bin/sh
# Installs OpenScale inside the sys-openscale qube (#891, docs/qubes.md).
# Run as root inside the qube, in the directory of an extracted release
# (openscale-<V>-linux-amd64.tar.gz, with deploy/qubes next to it or given
# with --qubes-dir). Nothing is downloaded; the program is checked against
# the signed release manifest first.
#
# Everything goes to the qube's private volume, so the template stays
# untouched:
#   /usr/local/bin/openscale                       program
#   /usr/local/lib/systemd/system/*.service        unit (read by systemd)
#   /rw/config/qubes-bind-dirs.d/50_openscale.conf keeps /var/lib/openscale
#   /rw/config/qubes-firewall-user-script          kill switch
#   /rw/config/rc.local                            starts the device
#
#   sudo sh qube-setup.sh [--qubes-dir DIR] [--manifest FILE] [--verifier FILE] [--no-verify] [BINARY]
set -eu

QDIR='' MANIFEST='' VERIFIER='' NO_VERIFY=0 BIN=''
while [ $# -gt 0 ]; do
	case "$1" in
	--qubes-dir) QDIR=${2:?}; shift 2 ;;
	--manifest) MANIFEST=${2:?}; shift 2 ;;
	--verifier) VERIFIER=${2:?}; shift 2 ;;
	--no-verify) NO_VERIFY=1; shift ;;
	-h | --help) sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
	-*) echo "bilinmeyen seçenek: $1" >&2; exit 2 ;;
	*) BIN=$1; shift ;;
	esac
done

[ "$(id -u)" -eq 0 ] || { echo "root olarak çalıştırın (sudo)" >&2; exit 1; }
[ -d /rw/config ] || { echo "/rw/config yok: bu betik bir Qubes qube'u içinde çalışır" >&2; exit 1; }
[ -n "$QDIR" ] || QDIR=$(cd "$(dirname "$0")" && pwd)
for f in qubes-firewall-user-script rc.local 50_openscale.conf; do
	[ -f "$QDIR/$f" ] || { echo "$QDIR/$f yok" >&2; exit 1; }
done
[ -f openscale-device.service ] || { echo "openscale-device.service bu klasörde yok (sürüm arşivi)" >&2; exit 1; }
BIN=${BIN:-./openscale-linux-amd64}
[ -f "$BIN" ] || { echo "program bulunamadı: $BIN" >&2; exit 1; }
command -v nft >/dev/null 2>&1 || { echo "nft yok: şablona nftables kurun" >&2; exit 1; }

if [ "$NO_VERIFY" -eq 1 ]; then
	echo "UYARI: --no-verify: imza DOĞRULANMADI." >&2
else
	m=$MANIFEST
	[ -n "$m" ] || m=$(ls ./openscale-*.release.json 2>/dev/null | head -n 1)
	[ -n "$m" ] && [ -f "$m" ] || { echo "imzalı sürüm dosyası yok; --manifest ile verin" >&2; exit 1; }
	v=$VERIFIER
	[ -n "$v" ] || { [ ! -x ./openscale-release-verify-linux-amd64 ] || v=./openscale-release-verify-linux-amd64; }
	[ -n "$v" ] || v=$(command -v openscale-release-verify 2>/dev/null || true)
	[ -n "$v" ] || { echo "openscale-release-verify yok; --verifier ile verin" >&2; exit 1; }
	"$v" -manifest "$m" -dir "$(dirname "$BIN")" "$BIN"
fi

# 1. Kill switch first, so it is active before the tunnel ever exists.
install -m 0755 "$QDIR/qubes-firewall-user-script" /rw/config/qubes-firewall-user-script
sh /rw/config/qubes-firewall-user-script

# 2. State kept across restarts.
install -d -m 0755 /rw/config/qubes-bind-dirs.d
install -m 0644 "$QDIR/50_openscale.conf" /rw/config/qubes-bind-dirs.d/50_openscale.conf
install -d -m 0755 /var/lib/openscale
install -d -m 0700 /var/lib/openscale/device
install -d -m 0755 /rw/bind-dirs/var/lib
[ -d /rw/bind-dirs/var/lib/openscale ] || cp -a /var/lib/openscale /rw/bind-dirs/var/lib/

# 3. Program and unit in /usr/local (the private volume).
install -d -m 0755 /usr/local/bin /usr/local/lib/systemd/system
install -m 0755 "$BIN" /usr/local/bin/openscale
install -m 0644 openscale-device.service /usr/local/lib/systemd/system/openscale-device.service

# 4. Start at every qube start (after qubes-firewall).
if [ -s /rw/config/rc.local ] && ! grep -q 'openscale-device' /rw/config/rc.local; then
	echo "UYARI: /rw/config/rc.local zaten var; deploy/qubes/rc.local içeriğini elle ekleyin." >&2
else
	install -m 0755 "$QDIR/rc.local" /rw/config/rc.local
fi
systemctl daemon-reload

if [ -z "$(ls -A /var/lib/openscale/device)" ]; then
	echo "Kuruldu. Ağa katılın, sonra servisi başlatın:"
	echo "  /usr/local/bin/openscale invite-join --state-dir /var/lib/openscale/device --code @davet.txt --name sys-openscale"
	echo "  systemctl start openscale-device"
	echo "Bütün internet trafiği için panelden bir çıkış düğümü seçin: openscale exit-node use <ad>"
else
	systemctl restart openscale-device.service
	echo "Program güncellendi, servis yeniden başlatıldı."
fi
