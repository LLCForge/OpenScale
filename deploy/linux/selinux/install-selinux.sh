#!/bin/sh
# Builds and loads the OpenScale SELinux module (#886,
# docs/apparmor-selinux.md). Run as root from deploy/linux/selinux on
# Fedora, RHEL/Alma/Rocky, openSUSE MicroOS or another SELinux system.
# Needs the policy development files (dnf install selinux-policy-devel;
# zypper install selinux-policy-devel).
#
# Default: both domains permissive (denials logged, nothing blocked;
# the permissive statements are compiled into the module),
# while the rest of the system stays enforcing. After a quiet trial:
#   sh install-selinux.sh --enforce
# Back to permissive:   sh install-selinux.sh --permissive
# Remove everything:    sh uninstall-selinux.sh
#
#   sh install-selinux.sh [--permissive|--enforce] [--device-port N] [--coordinator-port N]
set -eu

MODE=permissive DEVICE_PORT=41821 COORD_PORT=41820
port_ok() {
	case "$1" in
	'' | *[!0-9]*) return 1 ;;
	esac
	[ "$1" -ge 1024 ] && [ "$1" -le 65535 ]
}
while [ $# -gt 0 ]; do
	case "$1" in
	--permissive) MODE=permissive; shift ;;
	--enforce) MODE=enforce; shift ;;
	--device-port) DEVICE_PORT=${2:?port ister}; shift 2 ;;
	--coordinator-port) COORD_PORT=${2:?port ister}; shift 2 ;;
	-h | --help) sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
	*) echo "bilinmeyen seçenek: $1" >&2; exit 2 ;;
	esac
done
port_ok "$DEVICE_PORT" || { echo "geçersiz cihaz portu: $DEVICE_PORT (1024-65535)" >&2; exit 2; }
port_ok "$COORD_PORT" || { echo "geçersiz koordinatör portu: $COORD_PORT (1024-65535)" >&2; exit 2; }

[ "$(id -u)" -eq 0 ] || { echo "root olarak çalıştırın" >&2; exit 1; }
command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled || { echo "SELinux etkin değil" >&2; exit 1; }
for t in semodule semanage restorecon make; do
	command -v "$t" >/dev/null 2>&1 || { echo "$t yok (policycoreutils-python-utils, make)" >&2; exit 1; }
done
DEVEL=/usr/share/selinux/devel/Makefile
[ -f "$DEVEL" ] || { echo "$DEVEL yok: selinux-policy-devel kurun" >&2; exit 1; }

HERE=$(cd "$(dirname "$0")" && pwd)
BUILD=$(mktemp -d)
trap 'rm -rf "$BUILD"' EXIT
cp "$HERE/openscale.te" "$HERE/openscale.fc" "$HERE/openscale.if" "$BUILD/"
# Permissive mode is compiled into the module, so the domains are never
# enforcing between loading the module and marking them.
if [ "$MODE" = permissive ]; then
	printf '
permissive openscale_device_t;
permissive openscale_coordinator_t;
' >>"$BUILD/openscale.te"
fi
make -s -C "$BUILD" -f "$DEVEL" openscale.pp
semodule -i "$BUILD/openscale.pp"
# Marks from "semanage permissive -a" (set by hand) would keep a domain
# permissive after --enforce.
if [ "$MODE" = enforce ]; then
	for d in openscale_device_t openscale_coordinator_t; do
		semanage permissive -d "$d" 2>/dev/null || true
	done
fi

# add_port PORT: -a fails when the port is already labeled; -m then
# relabels it (only ports this script chose).
add_port() {
	semanage port -a -t openscale_port_t -p udp "$1" 2>/dev/null ||
		semanage port -m -t openscale_port_t -p udp "$1"
}
add_port "$DEVICE_PORT"
add_port "$COORD_PORT"

# Labels: the program in every layout and the state directories.
for p in /usr/bin/openscale /usr/local/bin/openscale /var/lib/openscale/bin/openscale; do
	[ ! -e "$p" ] || restorecon -F "$p"
done
[ ! -d /var/lib/openscale ] || restorecon -RF /var/lib/openscale
[ ! -d /etc/openscale ] || restorecon -RF /etc/openscale
# The immutable layout's bin_t rule is no longer needed (openscale-repair).
semanage fcontext -d '/var/lib/openscale/bin(/.*)?' 2>/dev/null || true

if systemctl cat openscale-coordinator.service >/dev/null 2>&1; then
	install -d -m 0755 /etc/systemd/system/openscale-coordinator.service.d
	install -m 0644 "$HERE/openscale-coordinator-selinux.conf" \
		/etc/systemd/system/openscale-coordinator.service.d/60-openscale-selinux.conf
fi
systemctl daemon-reload
systemctl try-restart openscale-device.service openscale-coordinator.service 2>/dev/null || true

echo "OpenScale SELinux modülü yüklendi ($MODE)."
echo "Etki alanı: ps -eZ | grep openscale     İhlaller: ausearch -m AVC -c openscale -ts recent"
