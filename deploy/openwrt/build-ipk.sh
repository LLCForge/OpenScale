#!/usr/bin/env bash
# Builds the OpenWrt package of OpenScale (#446, ADR-0162) from a release
# binary, without the OpenWrt SDK: cmd/distpack writes a reproducible
# .ipk (opkg, OpenWrt 23.05 and 24.10). Run from the repository root.
#
#   deploy/openwrt/build-ipk.sh --binary dist/0.9.1/openscale-linux-arm64 \
#       --opkg-arch aarch64_cortex-a53 [--version 0.9.1-1] [--out DIR] \
#       [--source-date-epoch N]
#
# --opkg-arch must be the router's package architecture ("opkg print-
# architecture" on the router); a wrong one would install a program the
# CPU cannot run, so there is no default. The Go target must match:
#   aarch64_*            GOARCH=arm64
#   arm_cortex-a7_*      GOARCH=arm GOARM=7  (also a9, a15)
#   x86_64               GOARCH=amd64
#   i386_pentium4        GOARCH=386
#   mipsel_24kc          GOARCH=mipsle GOMIPS=softfloat (see docs/openwrt.md)
# The package goes into the signed release manifest like every other file;
# opkg's own feed signatures (usign) are not used.
set -euo pipefail
cd "$(dirname "$0")/../.."

BIN='' ARCH='' VER='' OUT='' SDE=${SOURCE_DATE_EPOCH:-}
while [ $# -gt 0 ]; do
	case "$1" in
	--binary) BIN=${2:?--binary dosya ister}; shift 2 ;;
	--opkg-arch) ARCH=${2:?--opkg-arch değer ister}; shift 2 ;;
	--version) VER=${2:?--version değer ister}; shift 2 ;;
	--out) OUT=${2:?--out klasör ister}; shift 2 ;;
	--source-date-epoch) SDE=${2:?--source-date-epoch sayı ister}; shift 2 ;;
	-h | --help) sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
	*) echo "bilinmeyen seçenek: $1" >&2; exit 2 ;;
	esac
done
[ -n "$BIN" ] && [ -f "$BIN" ] || { echo "--binary ile bir openscale-linux-* programı verin" >&2; exit 2; }
[[ "$ARCH" =~ ^[a-z0-9_]+(-[a-z0-9_.-]+)?$ ]] || { echo "--opkg-arch geçersiz veya eksik (ör. aarch64_cortex-a53)" >&2; exit 2; }
[ -n "$VER" ] || VER="$(tr -d ' \r\n' < VERSION)-1"
[[ "$VER" =~ ^[0-9]+\.[0-9]+\.[0-9]+-[0-9]+$ ]] || { echo "--version 1.2.3-1 biçiminde olmalı" >&2; exit 2; }
[ -n "$SDE" ] || SDE=$(stat -c %Y VERSION 2>/dev/null || stat -f %m VERSION)
[ -n "$OUT" ] || OUT=dist/openwrt

WORK=build/openwrt-work
rm -rf "$WORK"
mkdir -p "$WORK" "$OUT"
trap 'rm -rf "$WORK"' EXIT
cat >"$WORK/control" <<CONTROL
Package: openscale
Version: $VER
Depends: libc, kmod-tun, ip-full, nftables
SourceName: openscale
Section: net
Architecture: $ARCH
Installed-Size: $(( ($(wc -c <"$BIN") + 1023) / 1024 ))
Maintainer: ${DEB_MAINTAINER:-OpenScale <root@localhost>}
Description: OpenScale kişisel mesh VPN (WireGuard); alt ağ yönlendirici ve
 çıkış düğümü olarak çalışabilir. Yapılandırma: /etc/config/openscale (UCI).
CONTROL

go run ./cmd/distpack -out "$OUT/openscale_${VER}_${ARCH}.ipk" -source-date-epoch "$SDE" \
	-control "$WORK/control" -conffiles deploy/openwrt/conffiles \
	-postinst deploy/openwrt/postinst -prerm deploy/openwrt/prerm \
	-x usr/bin/openscale -x etc/init.d/openscale -x etc/uci-defaults/90-openscale \
	"$BIN=usr/bin/openscale" \
	deploy/openwrt/openscale.init=etc/init.d/openscale \
	deploy/openwrt/openscale.config=etc/config/openscale \
	deploy/openwrt/openscale.uci-defaults=etc/uci-defaults/90-openscale
echo "paketlendi: $OUT/openscale_${VER}_${ARCH}.ipk"
