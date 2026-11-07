#!/usr/bin/env bash
# Builds the OpenScale AppImage (#502, ADR-0162) from a release binary.
# Run from the repository root on Linux. appimagetool is an outside tool
# and is not downloaded here: put it on PATH yourself (verify its
# signature first), or pass --appdir-only to get the AppDir and pack it
# elsewhere.
#
#   deploy/appimage/build-appimage.sh --binary dist/0.9.1/openscale-linux-amd64 \
#       [--arch x86_64|aarch64|armhf] [--out DIR] [--appdir-only]
#
# The image is not signed with appimagetool's GPG option; like every other
# release file it is listed in the signed release manifest (ADR-0022) and
# checked with openscale-release-verify.
set -euo pipefail
cd "$(dirname "$0")/../.."

BIN='' ARCH=x86_64 OUT=dist/appimage APPDIR_ONLY=0
while [ $# -gt 0 ]; do
	case "$1" in
	--binary) BIN=${2:?--binary dosya ister}; shift 2 ;;
	--arch) ARCH=${2:?--arch değer ister}; shift 2 ;;
	--out) OUT=${2:?--out klasör ister}; shift 2 ;;
	--appdir-only) APPDIR_ONLY=1; shift ;;
	-h | --help) sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
	*) echo "bilinmeyen seçenek: $1" >&2; exit 2 ;;
	esac
done
[ -n "$BIN" ] && [ -f "$BIN" ] || { echo "--binary ile bir openscale-linux-* programı verin" >&2; exit 2; }
case "$ARCH" in x86_64 | aarch64 | armhf) ;; *) echo "--arch x86_64, aarch64 veya armhf olmalı" >&2; exit 2 ;; esac
V=$(tr -d ' \r\n' < VERSION)

APPDIR=build/appimage-work/OpenScale.AppDir
rm -rf build/appimage-work
mkdir -p "$APPDIR/usr/bin" "$APPDIR/usr/share/applications" "$APPDIR/usr/share/icons/hicolor/512x512/apps" "$OUT"
install -m 0755 "$BIN" "$APPDIR/usr/bin/openscale"
install -m 0755 deploy/appimage/AppRun "$APPDIR/AppRun"
install -m 0644 deploy/appimage/openscale.desktop "$APPDIR/openscale.desktop"
install -m 0644 deploy/appimage/openscale.desktop "$APPDIR/usr/share/applications/openscale.desktop"
install -m 0644 logos/android-chrome-512x512.png "$APPDIR/openscale.png"
install -m 0644 logos/android-chrome-512x512.png "$APPDIR/usr/share/icons/hicolor/512x512/apps/openscale.png"
ln -s openscale.png "$APPDIR/.DirIcon"

if [ "$APPDIR_ONLY" -eq 1 ]; then
	echo "AppDir hazır: $APPDIR"
	exit 0
fi
TOOL=$(command -v appimagetool || command -v appimagetool-"$ARCH".AppImage || true)
[ -n "$TOOL" ] || { echo "appimagetool bulunamadı; AppDir hazır: $APPDIR (--appdir-only ile yalnızca bu adım)" >&2; exit 1; }
# SOURCE_DATE_EPOCH keeps the squashfs timestamps fixed where the tool
# supports it; the image is not guaranteed to be byte-for-byte reproducible.
ARCH=$ARCH "$TOOL" --no-appstream "$APPDIR" "$OUT/OpenScale-$V-$ARCH.AppImage"
rm -rf build/appimage-work
echo "paketlendi: $OUT/OpenScale-$V-$ARCH.AppImage"
