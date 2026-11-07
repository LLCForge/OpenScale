#!/bin/sh
# Rolls the OpenScale AppArmor profiles back (#886): the systemd drop-ins
# go first, so a restart never looks for a profile that is gone; then the
# profiles are unloaded and removed. Local additions in
# /etc/apparmor.d/local/openscale-* are kept unless --purge is given.
#
#   sh uninstall-apparmor.sh [--purge]
set -eu

PURGE=0
case "${1:-}" in
'') ;;
--purge) PURGE=1 ;;
*) echo "kullanım: uninstall-apparmor.sh [--purge]" >&2; exit 2 ;;
esac
[ "$(id -u)" -eq 0 ] || { echo "root olarak çalıştırın" >&2; exit 1; }

for p in openscale-device openscale-coordinator; do
	rm -f "/etc/systemd/system/$p.service.d/60-openscale-apparmor.conf"
	rmdir "/etc/systemd/system/$p.service.d" 2>/dev/null || true
done
systemctl daemon-reload

for p in openscale-device openscale-coordinator; do
	if [ -f "/etc/apparmor.d/$p" ]; then
		apparmor_parser -R "/etc/apparmor.d/$p" 2>/dev/null || true
		rm -f "/etc/apparmor.d/$p"
	fi
	[ "$PURGE" -eq 0 ] || rm -f "/etc/apparmor.d/local/$p"
	systemctl try-restart "$p.service" 2>/dev/null || true
done
echo "AppArmor profilleri kaldırıldı; servisler kısıtsız çalışıyor."
