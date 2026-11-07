#!/bin/sh
# Creates the sys-openscale network qube (#891, docs/qubes.md). Run in
# dom0 as your normal user. Nothing is downloaded and no file is copied
# into dom0: the program goes into the qube later (qube-setup.sh).
#
# Chain:  AppVM(s) -> sys-openscale -> sys-firewall -> sys-net
# sys-openscale forwards the AppVMs' traffic only into the OpenScale
# tunnel; its kill switch (qubes-firewall-user-script) drops everything
# else, also before the tunnel is up.
#
#   sh dom0-create-sys-openscale.sh [--template NAME] [--name sys-openscale]
#       [--netvm sys-firewall] [--label orange]
set -eu

TEMPLATE='' NAME=sys-openscale NETVM=sys-firewall LABEL=orange
while [ $# -gt 0 ]; do
	case "$1" in
	--template) TEMPLATE=${2:?}; shift 2 ;;
	--name) NAME=${2:?}; shift 2 ;;
	--netvm) NETVM=${2:?}; shift 2 ;;
	--label) LABEL=${2:?}; shift 2 ;;
	-h | --help) sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
	*) echo "bilinmeyen seçenek: $1" >&2; exit 2 ;;
	esac
done

command -v qvm-create >/dev/null 2>&1 || { echo "Bu betik dom0'da çalışır (qvm-create yok)." >&2; exit 1; }
for v in "$NAME" "$NETVM" "$LABEL"; do
	case "$v" in
	'' | -* | *[!A-Za-z0-9_.-]*) echo "geçersiz ad: $v" >&2; exit 2 ;;
	esac
done
if [ -z "$TEMPLATE" ]; then
	TEMPLATE=$(qubes-prefs default_template)
fi
case "$TEMPLATE" in
'' | -* | *[!A-Za-z0-9_.-]*) echo "geçersiz şablon: $TEMPLATE" >&2; exit 2 ;;
esac

if qvm-check --quiet "$NAME" 2>/dev/null; then
	echo "$NAME zaten var; yalnızca ayarlar denetleniyor."
else
	qvm-create --class AppVM --template "$TEMPLATE" --label "$LABEL" "$NAME"
fi
qvm-prefs "$NAME" provides_network True
qvm-prefs "$NAME" netvm "$NETVM"
qvm-prefs "$NAME" autostart True
# A network qube needs no more than this; keys stay in its private volume.
qvm-prefs "$NAME" memory 400
qvm-prefs "$NAME" maxmem 800
qvm-prefs "$NAME" vcpus 1
qvm-service --enable "$NAME" qubes-firewall
# The qube may reach only what OpenScale needs upstream (the coordinator
# and peers: any address, UDP and TCP); dom0 rules stay the Qubes default.

echo "$NAME hazır. Sonra:"
echo "  1. Sürüm arşivini $NAME içine kopyalayın: qvm-copy-to-vm $NAME openscale-<V>-linux-amd64.tar.gz"
echo "  2. $NAME içinde: sudo sh qube-setup.sh   (deploy/qubes/qube-setup.sh)"
echo "  3. Bir AppVM'i bağlayın: qvm-prefs <qube> netvm $NAME"
