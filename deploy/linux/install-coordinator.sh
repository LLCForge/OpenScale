#!/bin/sh
# Installs or updates the OpenScale coordinator on Debian. Run as root from
# the directory of an extracted release (openscale-<V>-linux-<arch>.tar.gz),
# which holds openscale-linux-<arch>, the signed release manifest
# (openscale-<V>.release.json) and the deploy/linux files.
#
# The program is verified against the signed release manifest before
# anything is installed (ADR-0022, docs/surum-dogrulama.md); a release older
# than the installed one is refused. There is no download and no `curl | sh`.
# It never starts an unjoined coordinator; see docs/sunucu-kurulumu.md.
#
#   sh install-coordinator.sh [--manifest FILE] [--verifier FILE]
#       [--root-fingerprint FP] [--allow-downgrade] [--no-verify] [BINARY]
set -eu

usage() {
	sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'
}

MANIFEST='' VERIFIER='' ROOT_FP='' NO_VERIFY=0 ALLOW_DOWNGRADE=0 BIN=''
while [ $# -gt 0 ]; do
	case "$1" in
	--manifest) MANIFEST=${2:?--manifest dosya ister}; shift 2 ;;
	--verifier) VERIFIER=${2:?--verifier dosya ister}; shift 2 ;;
	--root-fingerprint) ROOT_FP=${2:?--root-fingerprint değer ister}; shift 2 ;;
	--allow-downgrade) ALLOW_DOWNGRADE=1; shift ;;
	--no-verify) NO_VERIFY=1; shift ;;
	-h | --help) usage; exit 0 ;;
	-*) echo "bilinmeyen seçenek: $1" >&2; exit 2 ;;
	*) BIN=$1; shift ;;
	esac
done

[ "$(id -u)" -eq 0 ] || { echo "root olarak çalıştırın" >&2; exit 1; }

detect_arch() {
	case "$(uname -m)" in
	x86_64 | amd64) echo amd64 ;;
	aarch64 | arm64) echo arm64 ;;
	armv7l | armv7*) echo armv7 ;;
	*) echo "desteklenmeyen mimari: $(uname -m)" >&2; return 1 ;;
	esac
}
ARCH=$(detect_arch)
BIN=${BIN:-./openscale-linux-$ARCH}
[ -f "$BIN" ] || { echo "program bulunamadı: $BIN" >&2; exit 1; }
[ -f openscale-coordinator.service ] || { echo "openscale-coordinator.service bu klasörde yok" >&2; exit 1; }

if dpkg-query -W -f='${Status}' openscale 2>/dev/null | grep -q 'install ok installed'; then
	echo "openscale Debian paketi kurulu; güncellemeyi paketle yapın (apt install ./openscale_*.deb)." >&2
	exit 1
fi
if command -v rpm >/dev/null 2>&1 && rpm -q openscale >/dev/null 2>&1; then
	echo "openscale RPM paketi kurulu; güncellemeyi paketle yapın (dnf install ./openscale-*.rpm)." >&2
	exit 1
fi

installed_version() {
	for p in /usr/local/bin/openscale /usr/bin/openscale; do
		if [ -x "$p" ]; then
			"$p" version 2>/dev/null | awk 'NR == 1 { print $2 }'
			return 0
		fi
	done
}

# verify FILE...: checks the files against the signed release manifest.
verify() {
	if [ "$NO_VERIFY" -eq 1 ]; then
		echo "UYARI: --no-verify: program imzası DOĞRULANMADI." >&2
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
		v=$(command -v openscale-release-verify 2>/dev/null || true)
		[ -n "$v" ] || {
			echo "openscale-release-verify bulunamadı. Güvenilir bir kopyasını PATH'e koyun" >&2
			echo "veya --verifier ile verin (docs/surum-dogrulama.md, 'İlk kurulum')." >&2
			return 1
		}
	fi
	set -- -manifest "$m" -dir "$(dirname "$1")" "$@"
	[ ! -f /etc/openscale/release-root.pub ] || set -- -root-key /etc/openscale/release-root.pub "$@"
	[ -z "$ROOT_FP" ] || set -- -root-fingerprint "$ROOT_FP" "$@"
	[ "$ALLOW_DOWNGRADE" -eq 0 ] || set -- -allow-downgrade "$@"
	iv=$(installed_version)
	[ -z "$iv" ] || set -- -installed "$iv" "$@"
	"$v" "$@"
}

VERIFY_BIN=./openscale-release-verify-linux-$ARCH
if [ -f "$VERIFY_BIN" ] && [ "$(dirname "$BIN")" = "." ]; then
	verify "$BIN" "$VERIFY_BIN"
else
	verify "$BIN"
fi

id openscale >/dev/null 2>&1 || useradd --system --home-dir /var/lib/openscale --no-create-home --shell /usr/sbin/nologin openscale
# The parent stays root-owned: the device service on the same host (root
# without CAP_DAC_OVERRIDE) must be able to reach /var/lib/openscale/device.
install -d -m 0755 -o root -g root /var/lib/openscale
install -d -m 0700 -o openscale -g openscale /var/lib/openscale/coordinator
install -m 0755 -o root -g root "$BIN" /usr/local/bin/openscale
if [ -f "$VERIFY_BIN" ] && [ "$NO_VERIFY" -eq 0 ]; then
	# Verified above against the same manifest; later updates use it.
	install -m 0755 -o root -g root "$VERIFY_BIN" /usr/local/bin/openscale-release-verify
fi
install -m 0644 -o root -g root openscale-coordinator.service /etc/systemd/system/openscale-coordinator.service
# ADR-0225: optional release source sync (does nothing until the owner runs
# 'openscale update source set'; then: systemctl enable --now openscale-release-sync.timer).
for u in openscale-release-sync.service openscale-release-sync.timer; do
	[ ! -f "$u" ] || install -m 0644 -o root -g root "$u" "/etc/systemd/system/$u"
done
systemctl daemon-reload

if [ ! -f /var/lib/openscale/coordinator/coordinator.key ]; then
	runuser -u openscale -- /usr/local/bin/openscale coordinator keygen --state-dir /var/lib/openscale/coordinator
else
	echo "Koordinatör anahtarı zaten var; yalnızca program güncellendi."
	systemctl try-restart openscale-coordinator
fi
