#!/bin/sh
# Rolls the OpenScale SELinux module back (#886): the coordinator drop-in
# goes first (systemd would otherwise ask for a domain that no longer
# exists), then hand-set permissive marks, the port labels and the module;
# finally the files get their default labels again.
#
#   sh uninstall-selinux.sh [--device-port N] [--coordinator-port N]
set -eu

DEVICE_PORT=41821 COORD_PORT=41820
while [ $# -gt 0 ]; do
	case "$1" in
	--device-port) DEVICE_PORT=${2:?port ister}; shift 2 ;;
	--coordinator-port) COORD_PORT=${2:?port ister}; shift 2 ;;
	*) echo "bilinmeyen seçenek: $1" >&2; exit 2 ;;
	esac
done
for p in "$DEVICE_PORT" "$COORD_PORT"; do
	case "$p" in
	'' | *[!0-9]*) echo "geçersiz port: $p" >&2; exit 2 ;;
	esac
done
[ "$(id -u)" -eq 0 ] || { echo "root olarak çalıştırın" >&2; exit 1; }

rm -f /etc/systemd/system/openscale-coordinator.service.d/60-openscale-selinux.conf
rmdir /etc/systemd/system/openscale-coordinator.service.d 2>/dev/null || true
systemctl daemon-reload

for d in openscale_device_t openscale_coordinator_t; do
	semanage permissive -d "$d" 2>/dev/null || true
done
for p in "$DEVICE_PORT" "$COORD_PORT"; do
	semanage port -d -t openscale_port_t -p udp "$p" 2>/dev/null || true
done
semodule -r openscale 2>/dev/null || true

for p in /usr/bin/openscale /usr/local/bin/openscale /var/lib/openscale/bin/openscale; do
	[ ! -e "$p" ] || restorecon -F "$p"
done
[ ! -d /var/lib/openscale ] || restorecon -RF /var/lib/openscale
[ ! -d /etc/openscale ] || restorecon -RF /etc/openscale
# The immutable layout needs its bin_t rule again; openscale-repair adds it
# at the next boot, or now:
if [ -f /var/lib/openscale/immutable/openscale-repair.sh ]; then
	sh /var/lib/openscale/immutable/openscale-repair.sh --install || true
fi

systemctl try-restart openscale-device.service openscale-coordinator.service 2>/dev/null || true
echo "OpenScale SELinux modülü kaldırıldı."
