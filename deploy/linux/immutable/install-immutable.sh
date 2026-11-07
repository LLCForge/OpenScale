#!/bin/sh
# Installs or updates an OpenScale device on an immutable (image based)
# Linux distribution (#884): Fedora Silverblue/Kinoite (rpm-ostree),
# SteamOS 3 (Steam Deck) and openSUSE MicroOS. Run as root from the
# directory of an extracted release (openscale-<V>-linux-<arch>.tar.gz)
# that also holds the deploy/linux/immutable files. Nothing is downloaded.
#
# The read-only /usr is never modified. Two layouts:
#   usrlocal  /usr/local/bin/openscale; used where /usr/local is writable
#             and survives image updates (Silverblue/Kinoite: a link to
#             /var/usrlocal; MicroOS: its own subvolume). Automatic
#             updates (ADR-0225) keep working.
#   var       /var/lib/openscale/bin/openscale and a drop-in that points
#             the unit there; used on SteamOS, whose /usr/local belongs to
#             the read-only image. Automatic updates are turned off; run
#             this script again with the new release.
# --layer RPM instead layers the signed RPM with rpm-ostree (Silverblue/
# Kinoite only; takes effect after a reboot, updates come with the RPM).
#
# Units go to /etc/systemd/system. A copy of every installed file is kept
# in /var/lib/openscale/immutable, and openscale-repair.service puts them
# back at boot when a major image update reset /etc (docs/degismez-linux.md).
#
#   sh install-immutable.sh [--layout usrlocal|var] [--layer RPM]
#       [--manifest FILE] [--verifier FILE] [--root-fingerprint FP]
#       [--no-verify] [BINARY]
#   sh install-immutable.sh --uninstall
set -eu

usage() {
	sed -n '2,27p' "$0" | sed 's/^# \{0,1\}//'
}

LAYOUT='' LAYER_RPM='' MANIFEST='' VERIFIER='' ROOT_FP='' NO_VERIFY=0 BIN='' UNINSTALL=0
while [ $# -gt 0 ]; do
	case "$1" in
	--layout) LAYOUT=${2:?--layout usrlocal veya var ister}; shift 2 ;;
	--layer) LAYER_RPM=${2:?--layer RPM dosyası ister}; shift 2 ;;
	--manifest) MANIFEST=${2:?--manifest dosya ister}; shift 2 ;;
	--verifier) VERIFIER=${2:?--verifier dosya ister}; shift 2 ;;
	--root-fingerprint) ROOT_FP=${2:?--root-fingerprint değer ister}; shift 2 ;;
	--no-verify) NO_VERIFY=1; shift ;;
	--uninstall) UNINSTALL=1; shift ;;
	-h | --help) usage; exit 0 ;;
	-*) echo "bilinmeyen seçenek: $1" >&2; exit 2 ;;
	*) BIN=$1; shift ;;
	esac
done

[ "$(id -u)" -eq 0 ] || { echo "root olarak çalıştırın (sudo)" >&2; exit 1; }

HERE=$(cd "$(dirname "$0")" && pwd)
KEEP=/var/lib/openscale/immutable
UNITS=/etc/systemd/system
DROPIN_DIR=$UNITS/openscale-device.service.d
DROPIN=$DROPIN_DIR/40-openscale-immutable.conf

# os_id prints ID from os-release (never sourced: it is only read).
os_id() {
	f=/etc/os-release
	[ -f "$f" ] || f=/usr/lib/os-release
	sed -n 's/^ID=//p' "$f" 2>/dev/null | tr -d '"' | head -n 1
}

# flavor prints silverblue, steamos, microos or unknown.
flavor() {
	id=$(os_id)
	case "$id" in
	steamos) echo steamos; return ;;
	opensuse-microos | opensuse-aeon | opensuse-kalpa | sl-micro) echo microos; return ;;
	esac
	if [ -e /run/ostree-booted ] && command -v rpm-ostree >/dev/null 2>&1; then
		echo silverblue
		return
	fi
	if command -v transactional-update >/dev/null 2>&1; then
		echo microos
		return
	fi
	echo unknown
}

if [ "$UNINSTALL" -eq 1 ]; then
	systemctl disable --now openscale-device.service openscale-repair.service 2>/dev/null || true
	rm -f "$DROPIN" "$UNITS/openscale-repair.service" /etc/atomic-update.conf.d/openscale.conf
	if [ -f "$KEEP/install.conf" ] && grep -qx 'LAYOUT=var' "$KEEP/install.conf"; then
		rm -f /var/lib/openscale/bin/openscale
		rmdir /var/lib/openscale/bin 2>/dev/null || true
		if command -v semanage >/dev/null 2>&1; then
			semanage fcontext -d '/var/lib/openscale/bin(/.*)?' 2>/dev/null || true
		fi
	fi
	rm -f "$UNITS/openscale-device.service"
	rm -rf "$KEEP"
	systemctl daemon-reload
	echo "Kaldırıldı. Cihaz kimliği /var/lib/openscale/device içinde kaldı; iz bırakmamak için"
	echo "cihazı panelden iptal edip klasörü silin. rpm-ostree katmanı: rpm-ostree uninstall openscale"
	exit 0
fi

FLAVOR=$(flavor)
[ "$FLAVOR" != unknown ] || echo "UYARI: değişmez dağıtım tanınmadı; yine de /etc ve /var kullanılarak kurulacak." >&2

detect_arch() {
	case "$(uname -m)" in
	x86_64 | amd64) echo amd64 ;;
	aarch64 | arm64) echo arm64 ;;
	*) echo "desteklenmeyen mimari: $(uname -m)" >&2; return 1 ;;
	esac
}
ARCH=$(detect_arch)

for f in openscale-device.service; do
	[ -f "$f" ] || { echo "$f bu klasörde yok; sürüm arşivinin klasöründen çalıştırın" >&2; exit 1; }
done
for f in openscale-repair.sh openscale-repair.service; do
	[ -f "$HERE/$f" ] || { echo "$HERE/$f yok" >&2; exit 1; }
done

if [ -n "$LAYER_RPM" ]; then
	[ "$FLAVOR" = silverblue ] || { echo "--layer yalnızca rpm-ostree kullanan sistemlerde (Silverblue/Kinoite)" >&2; exit 1; }
	[ -f "$LAYER_RPM" ] || { echo "RPM bulunamadı: $LAYER_RPM" >&2; exit 1; }
	case "$LAYER_RPM" in
	*.rpm) ;;
	*) echo "--layer bir .rpm dosyası ister" >&2; exit 1 ;;
	esac
fi

if [ -z "$LAYOUT" ]; then
	case "$FLAVOR" in
	steamos) LAYOUT=var ;;
	*)
		# usrlocal only when the directory is writable now; on these systems
		# it lives outside the image and survives updates.
		if mkdir -p /usr/local/bin 2>/dev/null && [ -w /usr/local/bin ]; then
			LAYOUT=usrlocal
		else
			LAYOUT=var
		fi
		;;
	esac
fi
case "$LAYOUT" in
usrlocal) BIN_DIR=/usr/local/bin ;;
var) BIN_DIR=/var/lib/openscale/bin ;;
*) echo "--layout usrlocal veya var olmalı: $LAYOUT" >&2; exit 2 ;;
esac

# verify FILE...: checks the files against the signed release manifest
# (ADR-0022), as deploy/linux/install-device.sh does.
verify() {
	if [ "$NO_VERIFY" -eq 1 ]; then
		echo "UYARI: --no-verify: imza DOĞRULANMADI." >&2
		return 0
	fi
	m=$MANIFEST
	if [ -z "$m" ]; then
		found=''
		for f in ./openscale-*.release.json; do
			[ -f "$f" ] || continue
			[ -z "$found" ] || { echo "birden fazla imzalı sürüm dosyası var; --manifest ile seçin" >&2; return 1; }
			found=$f
		done
		[ -n "$found" ] || { echo "imzalı sürüm dosyası (openscale-*.release.json) yok; --manifest ile verin" >&2; return 1; }
		m=$found
	fi
	v=$VERIFIER
	if [ -z "$v" ]; then
		if [ -x "./openscale-release-verify-linux-$ARCH" ]; then
			v=./openscale-release-verify-linux-$ARCH
		else
			v=$(command -v openscale-release-verify 2>/dev/null || true)
		fi
		[ -n "$v" ] || { echo "openscale-release-verify bulunamadı; --verifier ile verin (docs/surum-dogrulama.md)" >&2; return 1; }
	fi
	set -- -manifest "$m" -dir "$(dirname "$1")" "$@"
	[ ! -f /etc/openscale/release-root.pub ] || set -- -root-key /etc/openscale/release-root.pub "$@"
	[ -z "$ROOT_FP" ] || set -- -root-fingerprint "$ROOT_FP" "$@"
	"$v" "$@"
}

install -d -m 0755 -o root -g root /var/lib/openscale
install -d -m 0700 -o root -g root /var/lib/openscale/device
install -d -m 0700 -o root -g root "$KEEP"

if [ -n "$LAYER_RPM" ]; then
	verify "$LAYER_RPM"
	rpm-ostree install --idempotent "$LAYER_RPM"
	LAYOUT=layer
	BIN_DIR=/usr/bin
else
	BIN=${BIN:-./openscale-linux-$ARCH}
	[ -f "$BIN" ] || { echo "program bulunamadı: $BIN" >&2; exit 1; }
	verify "$BIN"
	install -d -m 0755 -o root -g root "$BIN_DIR"
	install -m 0755 -o root -g root "$BIN" "$BIN_DIR/openscale.new"
	mv -f "$BIN_DIR/openscale.new" "$BIN_DIR/openscale"
	# Spare copy for openscale-repair (kept in /var, outside the image).
	install -m 0700 -o root -g root "$BIN" "$KEEP/openscale.bin"
fi

# Saved copies the repair script restores. install.conf holds only
# KEY=value lines that the repair script matches literally (never sourced).
install -m 0644 openscale-device.service "$KEEP/openscale-device.service"
install -m 0644 "$HERE/openscale-repair.service" "$KEEP/openscale-repair.service"
install -m 0700 "$HERE/openscale-repair.sh" "$KEEP/openscale-repair.sh"
{
	echo "LAYOUT=$LAYOUT"
	echo "FLAVOR=$FLAVOR"
} >"$KEEP/install.conf.new"
chmod 0600 "$KEEP/install.conf.new"
mv -f "$KEEP/install.conf.new" "$KEEP/install.conf"

if [ "$LAYOUT" != layer ]; then
	install -m 0644 openscale-device.service "$UNITS/openscale-device.service"
fi
if [ "$LAYOUT" = var ]; then
	install -d -m 0755 "$DROPIN_DIR"
	cat >"$KEEP/40-openscale-immutable.conf" <<'EOF'
# Written by deploy/linux/immutable/install-immutable.sh (#884): the
# program lives in /var because /usr is read-only on this system.
[Service]
ExecStart=
ExecStart=/var/lib/openscale/bin/openscale up --state-dir /var/lib/openscale/device --listen-port 41821 --interface OpenScale
EOF
	install -m 0644 "$KEEP/40-openscale-immutable.conf" "$DROPIN"
fi
install -m 0644 "$HERE/openscale-repair.service" "$UNITS/openscale-repair.service"

# SteamOS keeps /etc files listed under /etc/atomic-update.conf.d across
# image updates; elsewhere the repair unit covers a reset /etc.
if [ "$FLAVOR" = steamos ] && [ -d /etc/atomic-update.conf.d ]; then
	cat >/etc/atomic-update.conf.d/openscale.conf <<'EOF'
/etc/systemd/system/openscale-device.service
/etc/systemd/system/openscale-device.service.d/40-openscale-immutable.conf
/etc/systemd/system/openscale-repair.service
/etc/systemd/system/multi-user.target.wants/openscale-device.service
/etc/systemd/system/multi-user.target.wants/openscale-repair.service
EOF
fi

# The repair script also applies the SELinux label and loads the tun module.
sh "$KEEP/openscale-repair.sh" --install
systemctl daemon-reload
systemctl enable openscale-repair.service

if [ "$LAYOUT" = var ] && [ -x "$BIN_DIR/openscale" ]; then
	# The updater writes /usr/local/bin, which is read-only here.
	"$BIN_DIR/openscale" update auto off >/dev/null 2>&1 || true
	echo "Not: otomatik güncelleme kapatıldı; yeni sürümde bu betiği yeniden çalıştırın."
fi

if [ "$LAYOUT" = layer ]; then
	echo "RPM katman olarak eklendi; yeniden başlattıktan sonra:"
	echo "  openscale join --state-dir /var/lib/openscale/device --bundle @paket.txt --root-fingerprint <panelde yazan>"
	echo "  systemctl enable --now openscale-device"
	echo "  touch $KEEP/enabled"
elif [ -z "$(ls -A /var/lib/openscale/device)" ]; then
	echo "Cihaz henüz ağa katılmadı; servis başlatılmadı:"
	echo "  $BIN_DIR/openscale join --state-dir /var/lib/openscale/device --bundle @paket.txt --root-fingerprint <panelde yazan>"
	echo "  systemctl enable --now openscale-device && touch $KEEP/enabled"
else
	systemctl enable openscale-device.service
	touch "$KEEP/enabled"
	systemctl try-restart openscale-device.service || systemctl start openscale-device.service
	echo "Program güncellendi ve servis yeniden başlatıldı ($LAYOUT)."
fi
