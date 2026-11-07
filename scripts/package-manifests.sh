#!/usr/bin/env bash
# Fills the winget and Scoop manifest templates (#887) from a built release:
# the version, the download mirror the owner chose and the SHA-256 of the
# Windows archive from dist/<sürüm>/SHA256SUMS. It is separate from
# scripts/release.sh and only reads the release; nothing is uploaded.
#
#   scripts/package-manifests.sh --mirror https://indir.ornek.net/openscale [--version 1.0.0-beta.2] [--out KLASÖR]
#
# The mirror (also OPENSCALE_MIRROR) must serve the release files laid out
# like dist/: <mirror>/<sürüm>/openscale-<sürüm>-windows-amd64.zip. Output:
# <out>/winget/<sürüm>/*.yaml and <out>/scoop/openscale.json (default out:
# dist/<sürüm>/manifests).
set -euo pipefail

cd "$(dirname "$0")/.."

VERSION=""
MIRROR="${OPENSCALE_MIRROR:-}"
OUT=""

die() {
	echo "package-manifests: $*" >&2
	exit 1
}

while [ "$#" -gt 0 ]; do
	case "$1" in
	--version) VERSION="${2:-}"; shift 2 ;;
	--mirror) MIRROR="${2:-}"; shift 2 ;;
	--out) OUT="${2:-}"; shift 2 ;;
	-h | --help)
		sed -n '2,13p' "$0"
		exit 0
		;;
	*) die "bilinmeyen argüman: $1" ;;
	esac
done

[ -n "$VERSION" ] || VERSION=$(tr -d ' \r\n' <VERSION)
# Versions as scripts/bump-version writes them (ADR-0193).
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-(alpha|beta|rc)\.[0-9]+)?$ ]] || die "geçersiz sürüm: $VERSION"

[ -n "$MIRROR" ] || die "--mirror (veya OPENSCALE_MIRROR) gerekli: sürüm dosyalarının indirileceği https adresi"
MIRROR="${MIRROR%/}"
# https only, and only characters that are safe in YAML, JSON and sed.
[[ "$MIRROR" =~ ^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~%/-]*)?$ ]] || die "geçersiz yansı adresi: $MIRROR (yalnızca https, boşluk/tırnak/sorgu yok)"

DIST="dist/$VERSION"
SUMS="$DIST/SHA256SUMS"
[ -f "$SUMS" ] || die "$SUMS bulunamadı; önce scripts/release.sh çalıştırın"

ZIP="openscale-$VERSION-windows-amd64.zip"
HASH=$(awk -v f="$ZIP" '$2 == f || $2 == "*" f { print $1 }' "$SUMS")
[ -n "$HASH" ] || die "$SUMS içinde $ZIP yok"
[ "$(printf '%s\n' "$HASH" | wc -l)" -eq 1 ] || die "$SUMS içinde $ZIP birden çok kez geçiyor"
[[ "$HASH" =~ ^[0-9a-f]{64}$ ]] || die "$ZIP için geçersiz SHA-256: $HASH"

# When the archive is here, it must match the list.
if [ -f "$DIST/$ZIP" ]; then
	if command -v sha256sum >/dev/null; then
		ACTUAL=$(sha256sum "$DIST/$ZIP" | awk '{print $1}')
	else
		ACTUAL=$(shasum -a 256 "$DIST/$ZIP" | awk '{print $1}')
	fi
	[ "$ACTUAL" = "$HASH" ] || die "$ZIP özeti SHA256SUMS ile uyuşmuyor"
fi

[ -n "$OUT" ] || OUT="$DIST/manifests"
mkdir -p "$OUT/winget/$VERSION" "$OUT/scoop"

fill() {
	sed -e "s|@VERSION@|$VERSION|g" -e "s|@MIRROR@|$MIRROR|g" -e "s|@SHA256_WINDOWS_ZIP@|$HASH|g" "$1" >"$2"
	if grep -q '@[A-Z0-9_]*@' "$2"; then
		die "$2 içinde doldurulmamış değişken kaldı"
	fi
}

for f in deploy/windows/winget/*.yaml; do
	fill "$f" "$OUT/winget/$VERSION/$(basename "$f")"
done
fill deploy/windows/scoop/openscale.json "$OUT/scoop/openscale.json"

echo "Yazıldı: $OUT/winget/$VERSION/ ve $OUT/scoop/openscale.json"
echo "İndirme adresi: $MIRROR/$VERSION/$ZIP"
echo "SHA-256: $HASH"
