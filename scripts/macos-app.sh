#!/usr/bin/env bash
# Builds the macOS app OpenScale.app (ADR-0227) with the version from
# VERSION into dist/<V>/macos/: a universal (arm64 + x86_64) cgo build of
# cmd/openscale with the menu bar and the native panel window, the app
# bundle, openscale-<V>-macos.zip, openscale-<V>-macos.dmg and their
# SHA-256 sums. macOS only (cgo with AppKit and WebKit, sips, iconutil,
# lipo, codesign, hdiutil, ditto).
#
#   scripts/macos-app.sh [--skip-panel-check]
#
# The panel must already be built into internal/panel/web/dist
# (pnpm --dir panel build, or the artifact of the release job).
#
# Environment (all optional):
#   SOURCE_DATE_EPOCH       build time stamp (git commit time by default)
#   RELEASE_ROOT_PUB        release root public key file (build/release/root.pub);
#                           embedded as in scripts/release.sh
#   RELEASE_REVOCATIONS     signed revocation list (build/release/revocations.json)
#   APPLE_SIGN_IDENTITY     "Developer ID Application: ..." identity in a
#                           keychain; without it the app is ad-hoc signed and
#                           Gatekeeper warns on first open
#   APPLE_ID, APPLE_TEAM_ID, APPLE_APP_PASSWORD
#                           notarize and staple with notarytool (needs the
#                           identity above)
#   MACOSX_DEPLOYMENT_TARGET  oldest macOS (12.0; Go 1.26 needs Monterey)
set -euo pipefail
cd "$(dirname "$0")/.."

PANEL_CHECK=1
for arg in "$@"; do
	case "$arg" in
	--skip-panel-check) PANEL_CHECK=0 ;;
	-h | --help) sed -n '2,28p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
	*) echo "bilinmeyen seçenek: $arg" >&2; exit 2 ;;
	esac
done

warn() { echo "UYARI: $*" >&2; }

[ "$(uname -s)" = Darwin ] || { echo "bu betik yalnızca macOS'ta çalışır" >&2; exit 1; }
for t in go clang lipo sips iconutil codesign hdiutil ditto plutil shasum; do
	command -v "$t" >/dev/null 2>&1 || { echo "$t bulunamadı (Xcode komut satırı araçları: xcode-select --install)" >&2; exit 1; }
done

V=$(tr -d ' \r\n' < VERSION)
if ! [[ "$V" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)(-beta\.([0-9]+))?$ ]]; then
	echo "VERSION 1.2.3 veya 1.2.3-beta.N biçiminde olmalı: '$V'" >&2
	exit 1
fi
MA=${BASH_REMATCH[1]} MI=${BASH_REMATCH[2]} PA=${BASH_REMATCH[3]}

SDE=${SOURCE_DATE_EPOCH:-}
if [ -z "$SDE" ] && git rev-parse --git-dir >/dev/null 2>&1; then
	SDE=$(git log -1 --format=%ct 2>/dev/null || true)
fi
[ -n "$SDE" ] || SDE=$(stat -f %m VERSION)
[[ "$SDE" =~ ^[0-9]+$ ]] || { echo "SOURCE_DATE_EPOCH sayı olmalı: '$SDE'" >&2; exit 1; }
export SOURCE_DATE_EPOCH=$SDE
B=$(date -u -r "$SDE" +%Y%m%d.%H%M)
echo "OpenScale.app $V ($B)"

if [ "$PANEL_CHECK" -eq 1 ] && ! [ -f internal/panel/web/dist/index.html ]; then
	echo "panel derlenmemiş (internal/panel/web/dist/index.html yok): pnpm --dir panel build" >&2
	exit 1
fi

export MACOSX_DEPLOYMENT_TARGET=${MACOSX_DEPLOYMENT_TARGET:-12.0}
OUT=dist/$V/macos
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
rm -rf "$OUT"
mkdir -p "$OUT"

# Link flags as in scripts/release.sh.
LD="-s -w -buildid= -X github.com/openscale/openscale/internal/version.Version=$V -X github.com/openscale/openscale/internal/version.Build=$B"
ROOT_PUB=${RELEASE_ROOT_PUB:-build/release/root.pub}
if [ -f "$ROOT_PUB" ]; then
	ROOT_KEY=$(tr -d ' \r\n' < "$ROOT_PUB")
	[[ "$ROOT_KEY" == osrelkey1:* ]] || { echo "$ROOT_PUB geçerli bir sürüm kök açık anahtarı değil" >&2; exit 1; }
	LD="$LD -X github.com/openscale/openscale/internal/updater.EmbeddedRootKey=$ROOT_KEY"
	REVOCATIONS=${RELEASE_REVOCATIONS:-build/release/revocations.json}
	if [ -f "$REVOCATIONS" ]; then
		REVOCATIONS_B64=$(base64 < "$REVOCATIONS" | tr -d '\n')
		[ "${#REVOCATIONS_B64}" -gt 16384 ] ||
			LD="$LD -X github.com/openscale/openscale/internal/updater.EmbeddedRevocations=$REVOCATIONS_B64"
	fi
else
	warn "$ROOT_PUB yok: program gömülü sürüm kök anahtarı olmadan derleniyor."
fi

# Universal program: one cgo build per architecture, joined with lipo.
for arch in arm64 amd64; do
	carch=$arch
	[ "$arch" = amd64 ] && carch=x86_64
	echo "derleniyor: darwin/$arch (cgo)"
	env CGO_ENABLED=1 GOOS=darwin GOARCH="$arch" \
		CC="clang -arch $carch" \
		CGO_CFLAGS="-O2 -mmacosx-version-min=$MACOSX_DEPLOYMENT_TARGET" \
		CGO_LDFLAGS="-mmacosx-version-min=$MACOSX_DEPLOYMENT_TARGET" \
		go build -trimpath -buildvcs=false -ldflags "$LD" -o "$WORK/openscale-$arch" ./cmd/openscale
done
lipo -create -output "$WORK/openscale" "$WORK/openscale-arm64" "$WORK/openscale-amd64"
lipo -verify_arch "$WORK/openscale" arm64 x86_64

# Bundle.
APP=$OUT/OpenScale.app
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$WORK/openscale" "$APP/Contents/MacOS/openscale"
chmod 0755 "$APP/Contents/MacOS/openscale"
bash scripts/macos-icns.sh build/macos/AppIcon-1024.png "$APP/Contents/Resources/OpenScale.icns"
printf 'APPL????' > "$APP/Contents/PkgInfo"

# CFBundleVersion must be up to three integers and grow with every build:
# the build stamp (YYYYMMDD.HHMM) does both. The full version, beta label
# included, is in CFBundleShortVersionString's companion OpenScaleVersion.
cat > "$APP/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleDevelopmentRegion</key>
	<string>tr</string>
	<key>CFBundleExecutable</key>
	<string>openscale</string>
	<key>CFBundleIconFile</key>
	<string>OpenScale</string>
	<key>CFBundleIdentifier</key>
	<string>com.openscale.app</string>
	<key>CFBundleInfoDictionaryVersion</key>
	<string>6.0</string>
	<key>CFBundleName</key>
	<string>OpenScale</string>
	<key>CFBundleDisplayName</key>
	<string>OpenScale</string>
	<key>CFBundlePackageType</key>
	<string>APPL</string>
	<key>CFBundleShortVersionString</key>
	<string>$MA.$MI.$PA</string>
	<key>CFBundleVersion</key>
	<string>$B</string>
	<key>OpenScaleVersion</key>
	<string>$V</string>
	<key>LSMinimumSystemVersion</key>
	<string>$MACOSX_DEPLOYMENT_TARGET</string>
	<key>LSUIElement</key>
	<true/>
	<key>LSApplicationCategoryType</key>
	<string>public.app-category.utilities</string>
	<key>LSArchitecturePriority</key>
	<array>
		<string>arm64</string>
		<string>x86_64</string>
	</array>
	<key>NSHighResolutionCapable</key>
	<true/>
	<key>NSAppTransportSecurity</key>
	<dict>
		<!-- The panel is plain HTTP on 127.0.0.1 only; every other
		     connection keeps the default HTTPS rules. -->
		<key>NSAllowsLocalNetworking</key>
		<true/>
	</dict>
	<key>NSSupportsAutomaticGraphicsSwitching</key>
	<true/>
	<key>NSHumanReadableCopyright</key>
	<string>OpenScale. Kişisel, bağımsız mesh VPN.</string>
</dict>
</plist>
EOF
plutil -lint "$APP/Contents/Info.plist"

# Code signature. With a Developer ID: hardened runtime (no DYLD_*
# injection, ADR-0227) and a secure timestamp. Without: an ad-hoc
# signature, which Apple silicon needs to run the program at all.
SIGNED=0
if [ -n "${APPLE_SIGN_IDENTITY:-}" ]; then
	# Signing the bundle signs its main program (each architecture).
	codesign --force --options runtime --timestamp --sign "$APPLE_SIGN_IDENTITY" "$APP"
	SIGNED=1
else
	warn "APPLE_SIGN_IDENTITY yok: uygulama ad-hoc imzalanıyor; Gatekeeper ilk açılışta uyarır."
	codesign --force --sign - "$APP"
fi
codesign --verify --deep --strict --verbose=2 "$APP"

# Disk image: the app and a link to /Applications for drag and drop.
DMG=$OUT/openscale-$V-macos.dmg
STAGE=$WORK/dmg
mkdir -p "$STAGE"
ditto "$APP" "$STAGE/OpenScale.app"
ln -s /Applications "$STAGE/Applications"
hdiutil create -volname "OpenScale $V" -srcfolder "$STAGE" -fs HFS+ -format UDZO -ov "$DMG" >/dev/null
[ "$SIGNED" -eq 0 ] || codesign --force --timestamp --sign "$APPLE_SIGN_IDENTITY" "$DMG"

# Notarization (optional): the disk image and the app inside it get one
# ticket; both are stapled so the first open works offline.
if [ "$SIGNED" -eq 1 ] && [ -n "${APPLE_ID:-}" ] && [ -n "${APPLE_TEAM_ID:-}" ] && [ -n "${APPLE_APP_PASSWORD:-}" ]; then
	echo "noter onayı isteniyor (notarytool)..."
	xcrun notarytool submit "$DMG" --apple-id "$APPLE_ID" --team-id "$APPLE_TEAM_ID" \
		--password "$APPLE_APP_PASSWORD" --wait --timeout 30m
	xcrun stapler staple "$DMG"
	xcrun stapler staple "$APP"
	spctl --assess --type execute --verbose "$APP"
else
	[ "$SIGNED" -eq 0 ] || warn "APPLE_ID/APPLE_TEAM_ID/APPLE_APP_PASSWORD yok: imzalı ama noter onaysız."
fi

ZIP=$OUT/openscale-$V-macos.zip
ditto -c -k --sequesterRsrc --keepParent "$APP" "$ZIP"

(cd "$OUT" && shasum -a 256 "$(basename "$ZIP")" "$(basename "$DMG")" > "openscale-$V-macos.sha256")
cat "$OUT/openscale-$V-macos.sha256"
echo "macOS uygulaması: $OUT (imzalı: $SIGNED)"
echo "signed=$SIGNED" > "$OUT/.signed"
