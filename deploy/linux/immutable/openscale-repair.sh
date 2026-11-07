#!/bin/sh
# OpenScale self-repair on immutable Linux (#884). Started by
# openscale-repair.service before openscale-device.service on every boot,
# and by install-immutable.sh. After a major image update (a new Fedora
# release, a SteamOS image, a MicroOS snapshot that reset /etc) it puts
# back what the update removed, from the copies in
# /var/lib/openscale/immutable:
#   - the program (var layout) and its SELinux label,
#   - openscale-device.service and the immutable drop-in,
#   - the enable links of both units,
#   - the tun module when /dev/net/tun is missing.
# A file that exists is never overwritten: owner edits stay. Everything is
# logged to the journal; the script never contacts the network.
#
#   sh openscale-repair.sh [--boot|--install|--check]
#     --check  only reports what would be repaired (exit 1 if anything)
set -eu

KEEP=/var/lib/openscale/immutable
UNITS=/etc/systemd/system
MODE=${1:---boot}
case "$MODE" in
--boot | --install | --check) ;;
*) echo "kullanım: openscale-repair.sh [--boot|--install|--check]" >&2; exit 2 ;;
esac

log() { printf 'openscale-repair: %s\n' "$*" >&2; }

[ -f "$KEEP/install.conf" ] || { log "$KEEP/install.conf yok; install-immutable.sh ile kurulmamış"; exit 0; }

# install.conf is matched line by line, never sourced.
LAYOUT=''
while IFS= read -r line; do
	case "$line" in
	LAYOUT=usrlocal) LAYOUT=usrlocal ;;
	LAYOUT=var) LAYOUT=var ;;
	LAYOUT=layer) LAYOUT=layer ;;
	esac
done <"$KEEP/install.conf"
case "$LAYOUT" in
usrlocal) BIN_DIR=/usr/local/bin ;;
var) BIN_DIR=/var/lib/openscale/bin ;;
layer) BIN_DIR=/usr/bin ;;
*) log "install.conf geçersiz LAYOUT; onarım yapılmadı"; exit 1 ;;
esac

NEED=0 CHANGED=0
fix() {
	# fix DESCRIPTION: counts a repair; --check only reports it.
	NEED=1
	if [ "$MODE" = --check ]; then
		log "onarılacak: $1"
		return 1
	fi
	log "onarılıyor: $1"
	CHANGED=1
	return 0
}

# restore SRC DST MODE: copies a saved file when the target is missing or empty.
restore() {
	[ -f "$1" ] || return 0
	[ -s "$2" ] && return 0
	fix "$2" || return 0
	install -d -m 0755 "$(dirname "$2")"
	install -m "$3" -o root -g root "$1" "$2"
}

# 1. The program. In the layer layout it belongs to the RPM.
if [ "$LAYOUT" != layer ]; then
	if [ ! -x "$BIN_DIR/openscale" ]; then
		if [ -f "$KEEP/openscale.bin" ]; then
			restore "$KEEP/openscale.bin" "$BIN_DIR/openscale" 0755
		else
			log "program yok ve yedeği de yok: install-immutable.sh ile yeniden kurun"
			NEED=1
		fi
	elif [ "$MODE" != --check ] && [ -f "$KEEP/openscale.bin" ] && ! cmp -s "$BIN_DIR/openscale" "$KEEP/openscale.bin"; then
		# The automatic updater replaced the program (usrlocal layout): the
		# spare copy follows once the new program runs.
		if "$BIN_DIR/openscale" version >/dev/null 2>&1; then
			install -m 0700 -o root -g root "$BIN_DIR/openscale" "$KEEP/openscale.bin.new"
			mv -f "$KEEP/openscale.bin.new" "$KEEP/openscale.bin"
			log "yedek program güncellendi"
		fi
	fi
fi

# 2. SELinux: systemd (init_t) may not execute a var_lib_t file, so the
# var layout labels its directory bin_t. The label is lost when the file
# is restored or the policy store is reset by an update.
#
# With the OpenScale SELinux module (deploy/linux/selinux) the program is
# openscale_exec_t instead; then only restorecon runs.
HAS_MODULE=0
if command -v semodule >/dev/null 2>&1 && semodule -l 2>/dev/null | awk '{print $1}' | grep -qx openscale; then
	HAS_MODULE=1
fi
if [ "$LAYOUT" = var ] && [ "$HAS_MODULE" -eq 1 ] && command -v restorecon >/dev/null 2>&1; then
	label=$(ls -Z "$BIN_DIR/openscale" 2>/dev/null | awk '{print $1}')
	case "$label" in
	*:openscale_exec_t:*) ;;
	*) if fix "SELinux etiketi ($label)"; then restorecon -R /var/lib/openscale; fi ;;
	esac
elif [ "$LAYOUT" = var ] && command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled; then
	if command -v semanage >/dev/null 2>&1; then
		if ! semanage fcontext -l -C 2>/dev/null | grep -q '^/var/lib/openscale/bin(/\.\*)?'; then
			if fix "SELinux etiket kuralı (/var/lib/openscale/bin bin_t)"; then
				semanage fcontext -a -t bin_t '/var/lib/openscale/bin(/.*)?'
			fi
		fi
	fi
	label=$(ls -Z "$BIN_DIR/openscale" 2>/dev/null | awk '{print $1}')
	case "$label" in
	*:bin_t:*) ;;
	*)
		if fix "SELinux etiketi ($label)"; then
			if command -v restorecon >/dev/null 2>&1 && command -v semanage >/dev/null 2>&1; then
				restorecon -R /var/lib/openscale/bin
			else
				chcon -R -t bin_t /var/lib/openscale/bin
			fi
		fi
		;;
	esac
fi

# 3. Units and the drop-in.
[ "$LAYOUT" = layer ] || restore "$KEEP/openscale-device.service" "$UNITS/openscale-device.service" 0644
[ "$LAYOUT" != var ] || restore "$KEEP/40-openscale-immutable.conf" "$UNITS/openscale-device.service.d/40-openscale-immutable.conf" 0644
restore "$KEEP/openscale-repair.service" "$UNITS/openscale-repair.service" 0644

# 4. The tun device (a new kernel without the module loaded at boot).
if [ ! -c /dev/net/tun ]; then
	if fix "/dev/net/tun"; then
		modprobe tun 2>/dev/null || log "tun modülü yüklenemedi; çekirdek TUN desteği yok mu?"
	fi
fi

if [ "$CHANGED" -eq 1 ] && [ "$MODE" != --check ]; then
	systemctl daemon-reload
fi

# 5. Enable links: only when the owner had enabled the device once
# (install-immutable.sh writes the marker).
if [ -f "$KEEP/enabled" ]; then
	for u in openscale-repair.service openscale-device.service; do
		if ! systemctl is-enabled --quiet "$u" 2>/dev/null; then
			if fix "$u etkin değil"; then
				systemctl enable "$u"
			fi
		fi
	done
	# At boot the device unit was left out of the transaction when its
	# file was missing; start it now (it is ordered after this unit).
	if [ "$CHANGED" -eq 1 ] && [ "$MODE" = --boot ] && [ -n "$(ls -A /var/lib/openscale/device 2>/dev/null)" ]; then
		systemctl --no-block start openscale-device.service
	fi
fi

if [ "$MODE" = --check ]; then
	[ "$NEED" -eq 0 ] && log "her şey yerinde" && exit 0
	exit 1
fi
[ "$CHANGED" -eq 1 ] && log "onarım tamamlandı" || log "onarım gerekmedi"
exit 0
