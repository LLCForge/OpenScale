#!/bin/sh
# Makes /dev/net/tun available on a NAS before the OpenScale container
# starts (#319, docs/nas.md). Synology DSM and some QNAP models ship the
# tun module but neither load it nor create the device node at boot.
#
# Run as root at every boot:
#   Synology: Control Panel > Task Scheduler > Create > Triggered Task >
#             User-defined script, user root, event Boot-up:
#             sh /volume1/docker/openscale/tun-setup.sh
#   QNAP:     autorun.sh (enable "Run user defined processes during
#             startup") calling this script.
#   Unraid:   not needed (tun is built in); the User Scripts plugin can
#             run it "At Startup of Array" if /dev/net/tun is missing.
#
# It only loads the kernel's own tun module and creates the standard
# character device (10:200, mode 0600); it changes nothing else.
set -eu

[ "$(id -u)" -eq 0 ] || { echo "root olarak çalıştırın" >&2; exit 1; }

if [ -c /dev/net/tun ]; then
	echo "/dev/net/tun hazır."
	exit 0
fi

if ! grep -qw tun /proc/modules 2>/dev/null && ! [ -d /sys/module/tun ]; then
	loaded=0
	if command -v modprobe >/dev/null 2>&1 && modprobe tun 2>/dev/null; then
		loaded=1
	else
		for ko in /lib/modules/tun.ko "/lib/modules/$(uname -r)/kernel/drivers/net/tun.ko"; do
			if [ -f "$ko" ] && insmod "$ko" 2>/dev/null; then
				loaded=1
				break
			fi
		done
	fi
	[ "$loaded" -eq 1 ] || { echo "tun çekirdek modülü yüklenemedi; bu NAS TUN desteklemiyor olabilir." >&2; exit 1; }
fi

mkdir -p /dev/net
[ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200
chmod 0600 /dev/net/tun
echo "/dev/net/tun oluşturuldu."
