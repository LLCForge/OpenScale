#!/bin/sh
# Loads the OpenScale AppArmor profiles and attaches them to the services
# (#886, docs/apparmor-selinux.md). Run as root from deploy/linux/apparmor.
#
# Default: complain mode (log only). After a quiet trial period:
#   sh install-apparmor.sh --enforce
# Back to complain mode at any time:
#   sh install-apparmor.sh --complain
# Remove everything (services run unconfined again):
#   sh uninstall-apparmor.sh
#
#   sh install-apparmor.sh [--complain|--enforce] [--device-only|--coordinator-only]
set -eu

MODE=complain WHICH='openscale-device openscale-coordinator'
while [ $# -gt 0 ]; do
	case "$1" in
	--complain) MODE=complain; shift ;;
	--enforce) MODE=enforce; shift ;;
	--device-only) WHICH=openscale-device; shift ;;
	--coordinator-only) WHICH=openscale-coordinator; shift ;;
	-h | --help) sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
	*) echo "bilinmeyen seçenek: $1" >&2; exit 2 ;;
	esac
done

[ "$(id -u)" -eq 0 ] || { echo "root olarak çalıştırın" >&2; exit 1; }
command -v apparmor_parser >/dev/null 2>&1 || { echo "apparmor_parser yok (apt install apparmor)" >&2; exit 1; }
[ -d /sys/kernel/security/apparmor ] || { echo "çekirdekte AppArmor etkin değil" >&2; exit 1; }

HERE=$(cd "$(dirname "$0")" && pwd)
PROFILES=/etc/apparmor.d

for p in $WHICH; do
	[ -f "$HERE/$p" ] || { echo "$HERE/$p yok" >&2; exit 1; }
	unit=$p.service
	# Only services that exist on this host.
	if ! systemctl cat "$unit" >/dev/null 2>&1; then
		echo "$unit bu makinede yok; atlandı"
		continue
	fi
	tmp=$(mktemp)
	case "$MODE" in
	complain) cp "$HERE/$p" "$tmp" ;;
	enforce) sed 's/ flags=(complain)//' "$HERE/$p" >"$tmp" ;;
	esac
	# Parse first: a profile with a syntax error never replaces a working one.
	if ! apparmor_parser -Q -K "$tmp"; then
		rm -f "$tmp"
		echo "$p ayrıştırılamadı; hiçbir şey değişmedi" >&2
		exit 1
	fi
	chmod 0644 "$tmp"
	mv -f "$tmp" "$PROFILES/$p"
	install -d -m 0755 "$PROFILES/local"
	[ -f "$PROFILES/local/$p" ] || : >"$PROFILES/local/$p"
	apparmor_parser -r -W "$PROFILES/$p"

	# The profile is loaded before the drop-in exists (AppArmorProfile=
	# fails the start when the profile is missing).
	install -d -m 0755 "/etc/systemd/system/$unit.d"
	install -m 0644 "$HERE/$p-apparmor.conf" "/etc/systemd/system/$unit.d/60-openscale-apparmor.conf"
	echo "$p yüklendi ($MODE)"
done

systemctl daemon-reload
for p in $WHICH; do
	systemctl try-restart "$p.service" 2>/dev/null || true
done
echo "İhlaller: journalctl -k -g 'apparmor=.*openscale'   (complain: \"ALLOWED\", enforce: \"DENIED\")"
