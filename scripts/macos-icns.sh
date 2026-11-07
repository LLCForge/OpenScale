#!/usr/bin/env bash
# Builds the macOS app icon (.icns) from one 1024x1024 PNG with the system
# tools sips and iconutil. macOS only.
#
#   scripts/macos-icns.sh [source.png] [out.icns]
#
# The default source, build/macos/AppIcon-1024.png, is
# logos/app-icon-dark-rounded-1024.png scaled to 824x824 and centred on a
# transparent 1024x1024 canvas: the size of Apple's macOS icon grid, so the
# icon lines up with the others in the Dock and Finder.
set -euo pipefail
cd "$(dirname "$0")/.."

SRC=${1:-build/macos/AppIcon-1024.png}
OUT=${2:-build/macos/OpenScale.icns}

[ "$(uname -s)" = Darwin ] || { echo "bu betik yalnızca macOS'ta çalışır (sips, iconutil)" >&2; exit 1; }
for t in sips iconutil; do
	command -v "$t" >/dev/null 2>&1 || { echo "$t bulunamadı" >&2; exit 1; }
done
[ -f "$SRC" ] || { echo "kaynak PNG yok: $SRC" >&2; exit 1; }

w=$(sips -g pixelWidth "$SRC" | awk '/pixelWidth/ {print $2}')
h=$(sips -g pixelHeight "$SRC" | awk '/pixelHeight/ {print $2}')
if [ "$w" != 1024 ] || [ "$h" != 1024 ]; then
	echo "kaynak 1024x1024 olmalı, $SRC ${w}x${h}" >&2
	exit 1
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
SET="$TMP/OpenScale.iconset"
mkdir "$SET"
# iconutil needs exactly these names: 16, 32, 128, 256 and 512 points at
# 1x and 2x.
for s in 16 32 128 256 512; do
	sips -s format png -z "$s" "$s" "$SRC" --out "$SET/icon_${s}x${s}.png" >/dev/null
	d=$((s * 2))
	sips -s format png -z "$d" "$d" "$SRC" --out "$SET/icon_${s}x${s}@2x.png" >/dev/null
done
mkdir -p "$(dirname "$OUT")"
iconutil -c icns "$SET" -o "$OUT"
echo "simge: $OUT"
