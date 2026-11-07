#!/bin/sh
# Builds the OPNsense plugin package (os-openscale) without the OPNsense
# plugins tree (#885). Runs on OPNsense or FreeBSD (needs pkg(8)).
# Install the "openscale" package first (deploy/pfsense/build-pkg.sh).
#
#   sh deploy/opnsense/build-plugin.sh [--version 1.0.0-beta.2] [--abi FreeBSD:14:amd64] [--out DIR]
set -eu

VERSION='' ABI='' OUT=.
while [ $# -gt 0 ]; do
	case "$1" in
	--version) VERSION=${2:?}; shift 2 ;;
	--abi) ABI=${2:?}; shift 2 ;;
	--out) OUT=${2:?}; shift 2 ;;
	-h | --help) sed -n '2,7p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
	*) echo "bilinmeyen seçenek: $1" >&2; exit 2 ;;
	esac
done

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
command -v pkg >/dev/null 2>&1 || { echo "pkg(8) yok" >&2; exit 1; }
[ -n "$VERSION" ] || VERSION=$(tr -d ' \r\n' <"$ROOT/VERSION")
[ -n "$ABI" ] || ABI=$(pkg config abi)
PKGVER=$(printf '%s' "$VERSION" | sed -e 's/-beta\./.b/' -e 's/-rc\./.rc/' -e 's/-alpha\./.a/')
case "$PKGVER" in
*[!0-9A-Za-z.]*) echo "sürüm çevrilemedi: $VERSION" >&2; exit 1 ;;
esac
case "$ABI" in
FreeBSD:[0-9]*:amd64) ARCH=$(printf '%s' "$ABI" | sed 's/^FreeBSD:\([0-9]*\):amd64$/freebsd:\1:x86:64/') ;;
FreeBSD:[0-9]*:aarch64) ARCH=$(printf '%s' "$ABI" | sed 's/^FreeBSD:\([0-9]*\):aarch64$/freebsd:\1:aarch64:64/') ;;
*) echo "desteklenmeyen ABI: $ABI" >&2; exit 1 ;;
esac

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
STAGE=$WORK/stage
install -d "$STAGE/usr/local"
cp -R "$HERE/src/opnsense" "$STAGE/usr/local/"
# CRLF from a Windows checkout would break configd and the templates.
find "$STAGE" -type f -exec sed -i '' 's/\r$//' {} +
(cd "$STAGE" && find usr -type f | sed 's|^usr/local/||' | sort) >"$WORK/plist"
sed -e "s/@VERSION@/$PKGVER/g" -e "s/@ABI@/$ABI/" -e "s/@ARCH@/$ARCH/" "$HERE/+MANIFEST" >"$WORK/+MANIFEST"
grep -q '@[A-Z]*@' "$WORK/+MANIFEST" && { echo "manifesto doldurulamadı" >&2; exit 1; }
install -d "$OUT"
pkg create -M "$WORK/+MANIFEST" -p "$WORK/plist" -r "$STAGE" -o "$OUT"
echo "paket: $OUT/os-openscale-$PKGVER.pkg   kurulum: pkg add ./os-openscale-$PKGVER.pkg"
