#!/bin/sh
# Prepares the Home Assistant add-on repository (#890): copies the Linux
# programs of a release, after checking them against the signed release
# manifest, into openscale/bin/ under the architecture names the
# Supervisor uses (aarch64, amd64, armv7). Nothing is downloaded.
#
#   sh deploy/homeassistant/prepare.sh --dist dist/1.0.0-beta.2 \
#       [--verifier PATH] [--manifest FILE] [--out DIR] [--no-verify]
#
# The result (DIR, default ./openscale-ha-repo) is the repository to
# publish; the add-on version follows VERSION.
set -eu

DIST='' VERIFIER='' MANIFEST='' OUT=./openscale-ha-repo NO_VERIFY=0
while [ $# -gt 0 ]; do
	case "$1" in
	--dist) DIST=${2:?}; shift 2 ;;
	--verifier) VERIFIER=${2:?}; shift 2 ;;
	--manifest) MANIFEST=${2:?}; shift 2 ;;
	--out) OUT=${2:?}; shift 2 ;;
	--no-verify) NO_VERIFY=1; shift ;;
	-h | --help) sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
	*) echo "bilinmeyen seçenek: $1" >&2; exit 2 ;;
	esac
done

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
[ -n "$DIST" ] && [ -d "$DIST" ] || { echo "--dist ile sürüm klasörünü verin" >&2; exit 1; }
VERSION=$(tr -d ' \r\n' <"$ROOT/VERSION")

set -- amd64:amd64 arm64:aarch64 armv7:armv7
for pair in "$@"; do
	src=$DIST/openscale-linux-${pair%%:*}
	[ -f "$src" ] || { echo "$src yok" >&2; exit 1; }
done

if [ "$NO_VERIFY" -eq 0 ]; then
	m=$MANIFEST
	[ -n "$m" ] || m=$(ls "$DIST"/openscale-*.release.json 2>/dev/null | head -n 1)
	[ -n "$m" ] && [ -f "$m" ] || { echo "imzalı sürüm dosyası yok; --manifest ile verin" >&2; exit 1; }
	v=$VERIFIER
	[ -n "$v" ] || v=$(command -v openscale-release-verify 2>/dev/null || true)
	[ -n "$v" ] || { echo "openscale-release-verify yok; --verifier ile verin" >&2; exit 1; }
	"$v" -manifest "$m" -dir "$DIST" "$DIST/openscale-linux-amd64" "$DIST/openscale-linux-arm64" "$DIST/openscale-linux-armv7"
else
	echo "UYARI: --no-verify: programlar DOĞRULANMADI." >&2
fi

rm -rf "$OUT"
install -d "$OUT/openscale/bin" "$OUT/openscale/translations"
for f in repository.yaml; do
	sed 's/\r$//' "$HERE/$f" >"$OUT/$f"
done
for f in build.yaml Dockerfile run.sh translations/en.yaml translations/tr.yaml; do
	sed 's/\r$//' "$HERE/openscale/$f" >"$OUT/openscale/$f"
done
sed -e 's/\r$//' -e "s/^version: .*/version: \"$VERSION\"/" "$HERE/openscale/config.yaml" >"$OUT/openscale/config.yaml"
chmod 0755 "$OUT/openscale/run.sh"
for pair in "$@"; do
	install -m 0755 "$DIST/openscale-linux-${pair%%:*}" "$OUT/openscale/bin/openscale-${pair#*:}"
done
echo "Eklenti deposu hazır: $OUT (sürüm $VERSION). Git deposu olarak yayımlayın."
