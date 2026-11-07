#!/bin/sh
# Builds the FreeBSD package of the OpenScale device (#885) for FreeBSD,
# pfSense and OPNsense. Runs on FreeBSD (needs pkg(8)); nothing is
# downloaded. Verify the program against the signed release manifest
# first (openscale-release-verify, docs/surum-dogrulama.md).
#
#   sh deploy/pfsense/build-pkg.sh --binary dist/<V>/openscale-freebsd-amd64 \
#       [--version 1.0.0-beta.2] [--abi FreeBSD:14:amd64] [--out DIR]
#       [--source-date-epoch N]
#
# The program is built with: GOOS=freebsd GOARCH=amd64 (or arm64)
# CGO_ENABLED=0, the flags of scripts/release.sh.
set -eu

BINARY='' VERSION='' ABI='' OUT=. SDE=''
while [ $# -gt 0 ]; do
	case "$1" in
	--binary) BINARY=${2:?}; shift 2 ;;
	--version) VERSION=${2:?}; shift 2 ;;
	--abi) ABI=${2:?}; shift 2 ;;
	--out) OUT=${2:?}; shift 2 ;;
	--source-date-epoch) SDE=${2:?}; shift 2 ;;
	-h | --help) sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
	*) echo "bilinmeyen seçenek: $1" >&2; exit 2 ;;
	esac
done

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
[ -n "$BINARY" ] && [ -f "$BINARY" ] || { echo "--binary ile FreeBSD programını verin" >&2; exit 1; }
command -v pkg >/dev/null 2>&1 || { echo "pkg(8) yok: bu betik FreeBSD'de çalışır" >&2; exit 1; }
[ -n "$VERSION" ] || VERSION=$(tr -d ' \r\n' <"$ROOT/VERSION")
[ -n "$ABI" ] || ABI=$(pkg config abi)

# pkg versions have no '-': 1.0.0-beta.2 -> 1.0.0.b2 (sorts before 1.0.0).
PKGVER=$(printf '%s' "$VERSION" | sed -e 's/-beta\./.b/' -e 's/-rc\./.rc/' -e 's/-alpha\./.a/')
case "$PKGVER" in
*[!0-9A-Za-z.]*) echo "sürüm çevrilemedi: $VERSION" >&2; exit 1 ;;
esac
case "$ABI" in
FreeBSD:[0-9]*:amd64) ARCH=$(printf '%s' "$ABI" | sed 's/^FreeBSD:\([0-9]*\):amd64$/freebsd:\1:x86:64/') ;;
FreeBSD:[0-9]*:aarch64) ARCH=$(printf '%s' "$ABI" | sed 's/^FreeBSD:\([0-9]*\):aarch64$/freebsd:\1:aarch64:64/') ;;
*) echo "desteklenmeyen ABI: $ABI (FreeBSD:<sürüm>:amd64 veya aarch64)" >&2; exit 1 ;;
esac

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
STAGE=$WORK/stage
install -d "$STAGE/usr/local/bin" "$STAGE/usr/local/etc/rc.d"
install -m 0755 "$BINARY" "$STAGE/usr/local/bin/openscale"
# A Windows checkout may have CRLF line endings.
sed 's/\r$//' "$HERE/openscale.rc" >"$STAGE/usr/local/etc/rc.d/openscale"
chmod 0755 "$STAGE/usr/local/etc/rc.d/openscale"
sed -e "s/@VERSION@/$PKGVER/" -e "s/@ABI@/$ABI/" -e "s/@ARCH@/$ARCH/" "$HERE/+MANIFEST" >"$WORK/+MANIFEST"
grep -q '@[A-Z]*@' "$WORK/+MANIFEST" && { echo "manifesto doldurulamadı" >&2; exit 1; }

[ -z "$SDE" ] || export SOURCE_DATE_EPOCH="$SDE"
install -d "$OUT"
pkg create -M "$WORK/+MANIFEST" -p "$HERE/pkg-plist" -r "$STAGE" -o "$OUT"
echo "paket: $OUT/openscale-$PKGVER.pkg"
