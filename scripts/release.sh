#!/usr/bin/env bash
# Builds an OpenScale release with the version from VERSION into dist/<V>/:
# the Windows exe (with icon and file version), Linux binaries for amd64,
# arm64 and armv7, macOS binaries for amd64 and arm64, the embedded panel, release verifiers, Debian and RPM packages,
# archives, an SPDX SBOM, SHA256SUMS and the signed release manifest
# (ADR-0022). bin/openscale.exe and bin/openscale-linux-amd64 are still
# written for the existing workflow. Bump VERSION before every build that
# goes to a computer.
#
# Builds are reproducible (#209): -trimpath -buildvcs=false, empty build ID,
# CGO_ENABLED=0 and the Build stamp taken from SOURCE_DATE_EPOCH (git commit
# time by default). See docs/surum-dogrulama.md.
#
#   scripts/release.sh [--vendor] [--unsigned] [--skip-panel]
#
#   --vendor      run `go mod vendor` and build with -mod=vendor (#212); the
#                 vendor/ tree is left in place for review
#   --unsigned    do not sign even if a signing key is present
#   --skip-panel  reuse the already built panel (faster, not for releases)
#
# Environment (all optional):
#   SOURCE_DATE_EPOCH         fixed build time (seconds since 1970, UTC)
#   RELEASE_ROOT_PUB          release root public key   (build/release/root.pub)
#   RELEASE_SIGNING_KEY       sealed signing key        ($HOME/.openscale-release/signing.key)
#   RELEASE_SIGNING_CERT      signing key certificate   ($HOME/.openscale-release/signing.cert)
#   RELEASE_PASSPHRASE_FILE   private file holding the signing key passphrase
#   DEB_MAINTAINER            Maintainer field of the .deb ("Name <address>")
#   RPM_PACKAGER              Packager field of the .rpm ("Name <address>")
#   SIGNTOOL_CERT_SHA1        thumbprint of an Authenticode certificate in the
#                             Windows certificate store; signs the .exe files
#   SIGNTOOL_TIMESTAMP_URL    RFC 3161 timestamp server for signtool and
#                             osslsigncode (contacts that server; leave empty
#                             to skip timestamping)
#   OSSLSIGNCODE_PFX          Authenticode certificate and key (.pfx/.p12) for
#                             osslsigncode, the Linux signer used by release.yml
#                             (#217); ignored when SIGNTOOL_CERT_SHA1 is set
#   OSSLSIGNCODE_PASSWORD_FILE private file holding the .pfx password
#   ANDROID_APK               signed release APK of the same VERSION (built with
#                             Gradle, see docs/android-dagitim.md); copied as
#                             openscale-<V>-android.apk and listed in the
#                             signed manifest (#183, P27)
#   ANDROID_CERT_SHA256       expected SHA-256 of the APK signing certificate;
#                             with apksigner on PATH the APK must match it
set -euo pipefail
cd "$(dirname "$0")/.."

VENDOR=0 UNSIGNED=0 SKIP_PANEL=0
for arg in "$@"; do
	case "$arg" in
	--vendor) VENDOR=1 ;;
	--unsigned) UNSIGNED=1 ;;
	--skip-panel) SKIP_PANEL=1 ;;
	-h | --help) sed -n '2,38p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
	*) echo "bilinmeyen seçenek: $arg" >&2; exit 2 ;;
	esac
done

warn() { echo "UYARI: $*" >&2; }

V=$(tr -d ' \r\n' < VERSION)
# A beta (1.2.3-beta.N, internal/version/scheme.go) builds like 1.2.3.
if ! [[ "$V" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)(-beta\.[0-9]+)?$ ]]; then
	echo "VERSION must look like 1.2.3 or 1.2.3-beta.N, got '$V'" >&2
	exit 1
fi
MA=${BASH_REMATCH[1]} MI=${BASH_REMATCH[2]} PA=${BASH_REMATCH[3]}

# Reproducible build time: SOURCE_DATE_EPOCH, else the last commit time, else
# the modification time of VERSION (reproducible only on the same checkout).
SDE=${SOURCE_DATE_EPOCH:-}
if [ -z "$SDE" ] && git rev-parse --git-dir >/dev/null 2>&1; then
	SDE=$(git log -1 --format=%ct 2>/dev/null || true)
fi
if [ -z "$SDE" ]; then
	SDE=$(stat -c %Y VERSION 2>/dev/null || stat -f %m VERSION)
	warn "SOURCE_DATE_EPOCH yok ve git geçmişi okunamadı; VERSION dosyasının zamanı ($SDE) kullanıldı."
fi
if ! [[ "$SDE" =~ ^[0-9]+$ ]]; then
	echo "SOURCE_DATE_EPOCH must be a number of seconds, got '$SDE'" >&2
	exit 1
fi
export SOURCE_DATE_EPOCH=$SDE
B=$(date -u -d "@$SDE" +%Y%m%d.%H%M 2>/dev/null || date -u -r "$SDE" +%Y%m%d.%H%M)
echo "OpenScale $V ($B, SOURCE_DATE_EPOCH=$SDE)"

OUT=dist/$V
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
EXE=$(go env GOEXE)

# Dependency policy (ADR-0002, #214) and module integrity against go.sum.
[ ! -d tools/depcheck ] || go run ./tools/depcheck go.mod
go mod verify

MODFLAG=()
if [ "$VENDOR" -eq 1 ]; then
	go mod vendor
	MODFLAG=(-mod=vendor)
	echo "vendor/ güncellendi; derleme -mod=vendor ile yapılıyor (vendor/ gözden geçirme için yerinde bırakıldı)."
fi
GOBUILD=(go build -trimpath -buildvcs=false "${MODFLAG[@]}")

# Windows resources: version info and manifest.
RC=build/windows/openscale.rc
sed -i -E "s/^(FILEVERSION|PRODUCTVERSION) .*/\1 $MA,$MI,$PA,0/" "$RC"
sed -i -E "s/(VALUE \"(FileVersion|ProductVersion)\", )\"[^\"]*\"/\1\"$V\"/" "$RC"
sed -i -E "s/(assemblyIdentity type=\"win32\" name=\"OpenScale\" version=)\"[^\"]*\"/\1\"$MA.$MI.$PA.0\"/" build/windows/openscale.manifest
WINDRES=${WINDRES:-$(command -v x86_64-w64-mingw32-windres || command -v windres)}
[ -n "$WINDRES" ] || { echo "windres bulunamadı (Linux: binutils-mingw-w64-x86-64 ve mingw-w64-x86-64-dev)" >&2; exit 1; }
(cd build/windows && "$WINDRES" --target=pe-x86-64 -O coff -i openscale.rc -o ../../cmd/openscale/rsrc_windows_amd64.syso)

# Panel.
sed -i -E "s/^  \"version\": \"[^\"]*\"/  \"version\": \"$V\"/" panel/package.json
if [ "$SKIP_PANEL" -eq 0 ]; then
	pnpm --dir panel build
else
	warn "--skip-panel: panel yeniden derlenmedi."
fi

# Host tools used by this script (never shipped).
for t in distpack pkgdeb pkgrpm sbom releasesign releaseverify; do
	"${GOBUILD[@]}" -o "$WORK/$t$EXE" "./cmd/$t"
done

rm -rf "$OUT"
mkdir -p "$OUT" bin

ROOT_PUB=${RELEASE_ROOT_PUB:-build/release/root.pub}
ROOT_KEY=''
if [ -f "$ROOT_PUB" ]; then
	ROOT_KEY=$(tr -d ' \r\n' < "$ROOT_PUB")
	[[ "$ROOT_KEY" == osrelkey1:* ]] || { echo "$ROOT_PUB geçerli bir sürüm kök açık anahtarı değil" >&2; exit 1; }
	"$WORK/releasesign$EXE" pubkey "$ROOT_KEY"
else
	warn "$ROOT_PUB yok: doğrulayıcılar gömülü kök anahtarsız derleniyor (-root-key gerekir)."
fi

LD="-s -w -buildid= -X github.com/openscale/openscale/internal/version.Version=$V -X github.com/openscale/openscale/internal/version.Build=$B"
# "openscale update apply" verifies with the same root key (ADR-0095).
[ -z "$ROOT_KEY" ] || LD="$LD -X github.com/openscale/openscale/internal/updater.EmbeddedRootKey=$ROOT_KEY"
VLD="-s -w -buildid= -X main.embeddedRootKey=$ROOT_KEY"
# The current signed revocation list goes into the program and next to the
# manifest, so a device that has never seen a list still enforces it (ADR-0195).
# 'releasesign revoke' writes it; reproducing this build needs the same file.
REVOCATIONS=${RELEASE_REVOCATIONS:-build/release/revocations.json}
if [ -n "$ROOT_KEY" ] && [ -f "$REVOCATIONS" ]; then
	REVOCATIONS_B64=$(base64 -w0 < "$REVOCATIONS")
	if [ "${#REVOCATIONS_B64}" -le 16384 ]; then
		LD="$LD -X github.com/openscale/openscale/internal/updater.EmbeddedRevocations=$REVOCATIONS_B64"
	else
		warn "$REVOCATIONS programa gömülemeyecek kadar büyük; yalnızca manifestonun yanında yayımlanıyor."
	fi
else
	warn "$REVOCATIONS yok: bu sürüm imzalı iptal listesi taşımıyor; hiç liste görmemiş cihaz iptal edilmiş anahtarı tanıyamaz."
fi

# name GOOS GOARCH GOARM debarch
TARGETS=(
	"windows-amd64 windows amd64 - -"
	"linux-amd64 linux amd64 - amd64"
	"linux-arm64 linux arm64 - arm64"
	"linux-armv7 linux arm 7 armhf"
	"darwin-amd64 darwin amd64 - -"
	"darwin-arm64 darwin arm64 - -"
	"freebsd-amd64 freebsd amd64 - -"
	"freebsd-arm64 freebsd arm64 - -"
)
for t in "${TARGETS[@]}"; do
	read -r name goos goarch goarm _ <<<"$t"
	suffix=''
	[ "$goos" = windows ] && suffix=.exe
	arm=()
	[ "$goarm" = - ] || arm=(GOARM="$goarm")
	echo "derleniyor: $name"
	env CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" "${arm[@]}" \
		"${GOBUILD[@]}" -ldflags "$LD" -o "$OUT/openscale-$name$suffix" ./cmd/openscale
	env CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" "${arm[@]}" \
		"${GOBUILD[@]}" -ldflags "$VLD" -o "$OUT/openscale-release-verify-$name$suffix" ./cmd/releaseverify
	go version -m "$OUT/openscale-$name$suffix" >"$WORK/openscale-$name.modinfo"
done

# Optional Authenticode signature (F-170). The signature is appended to the
# exe, so the unsigned digests are kept for reproducibility checks.
if [ -n "${SIGNTOOL_CERT_SHA1:-}" ]; then
	SIGNTOOL=$(command -v signtool.exe || command -v signtool || ls -1 "/c/Program Files (x86)/Windows Kits/10/bin/"*/x64/signtool.exe 2>/dev/null | sort -V | tail -n 1 || true)
	[ -n "$SIGNTOOL" ] || { echo "SIGNTOOL_CERT_SHA1 verildi ama signtool bulunamadı (Windows SDK)" >&2; exit 1; }
	: >"$OUT/openscale-$V-unsigned.sha256"
	for exe in "$OUT"/*.exe; do
		echo "$(sha256sum "$exe" | cut -d' ' -f1)  $(basename "$exe")" >>"$OUT/openscale-$V-unsigned.sha256"
		ts=()
		[ -z "${SIGNTOOL_TIMESTAMP_URL:-}" ] || ts=(/tr "$SIGNTOOL_TIMESTAMP_URL" /td SHA256)
		MSYS_NO_PATHCONV=1 "$SIGNTOOL" sign /fd SHA256 /sha1 "$SIGNTOOL_CERT_SHA1" "${ts[@]}" "$(cygpath -w "$exe" 2>/dev/null || echo "$exe")"
	done
elif [ -n "${OSSLSIGNCODE_PFX:-}" ]; then
	# Linux runners have no signtool (#217): osslsigncode writes the same
	# Authenticode signature (SHA-256, optional RFC 3161 timestamp).
	command -v osslsigncode >/dev/null 2>&1 || { echo "OSSLSIGNCODE_PFX verildi ama osslsigncode yok (apt-get install osslsigncode)" >&2; exit 1; }
	[ -f "$OSSLSIGNCODE_PFX" ] || { echo "OSSLSIGNCODE_PFX bulunamadı: $OSSLSIGNCODE_PFX" >&2; exit 1; }
	pass=()
	[ -z "${OSSLSIGNCODE_PASSWORD_FILE:-}" ] || pass=(-readpass "$OSSLSIGNCODE_PASSWORD_FILE")
	: >"$OUT/openscale-$V-unsigned.sha256"
	for exe in "$OUT"/*.exe; do
		echo "$(sha256sum "$exe" | cut -d' ' -f1)  $(basename "$exe")" >>"$OUT/openscale-$V-unsigned.sha256"
		ts=()
		[ -z "${SIGNTOOL_TIMESTAMP_URL:-}" ] || ts=(-ts "$SIGNTOOL_TIMESTAMP_URL")
		osslsigncode sign -pkcs12 "$OSSLSIGNCODE_PFX" "${pass[@]}" -h sha256 -n "OpenScale" "${ts[@]}" -in "$exe" -out "$exe.signed"
		mv -f "$exe.signed" "$exe"
		# The certificate chain may not be in the runner's store; a failed
		# verification is reported, the signature itself is in place.
		osslsigncode verify -in "$exe" >/dev/null 2>&1 || warn "$(basename "$exe"): osslsigncode verify imza zincirini doğrulayamadı (kök sertifika bu makinede yok olabilir)"
	done
	echo "Authenticode imzası (osslsigncode): $(ls "$OUT"/*.exe | wc -l) program."
else
	echo "Authenticode imzası atlandı (SIGNTOOL_CERT_SHA1 ve OSSLSIGNCODE_PFX yok)."
fi

cp "$OUT/openscale-windows-amd64.exe" bin/openscale.exe
cp "$OUT/openscale-linux-amd64" bin/openscale-linux-amd64

# Windows installer scripts and archive.
cp scripts/install-windows.ps1 scripts/uninstall-windows.ps1 "$OUT/"
"$WORK/distpack$EXE" -out "$OUT/openscale-$V-windows-amd64.zip" -prefix "openscale-$V-windows-amd64" -source-date-epoch "$SDE" \
	"$OUT/openscale-windows-amd64.exe" "$OUT/openscale-release-verify-windows-amd64.exe" \
	scripts/install-windows.ps1 scripts/uninstall-windows.ps1

# macOS archives: the tunnel, CLI and panel (opened in the browser; the
# menu bar app and native window need a cgo build on a Mac: OpenScale.app
# from scripts/macos-app.sh, the macos job of release.yml, ADR-0227)
# with the launchd property lists.
for arch in amd64 arm64; do
	"$WORK/distpack$EXE" -out "$OUT/openscale-$V-darwin-$arch.tar.gz" -prefix "openscale-$V-darwin-$arch" -source-date-epoch "$SDE" \
		-x "openscale-darwin-$arch" -x "openscale-release-verify-darwin-$arch" \
		"$OUT/openscale-darwin-$arch" "$OUT/openscale-release-verify-darwin-$arch" \
		deploy/macos/com.openscale.device.plist deploy/macos/com.openscale.killswitch.plist \
		deploy/macos/newsyslog-openscale.conf
done

# FreeBSD archives (tunnel only, docs/bsd.md); the pfSense package and the
# OPNsense plugin are built on FreeBSD from these (docs/pfsense-opnsense.md).
BSD_EXTRA=()
for d in pfsense opnsense; do
	while IFS= read -r f; do BSD_EXTRA+=("$f=${f#deploy/}"); done < <(find "deploy/$d" -type f | sort)
done
for arch in amd64 arm64; do
	"$WORK/distpack$EXE" -out "$OUT/openscale-$V-freebsd-$arch.tar.gz" -prefix "openscale-$V-freebsd-$arch" -source-date-epoch "$SDE" \
		-x "openscale-freebsd-$arch" -x "openscale-release-verify-freebsd-$arch" \
		"$OUT/openscale-freebsd-$arch" "$OUT/openscale-release-verify-freebsd-$arch" "${BSD_EXTRA[@]}"
done

# Linux archives, Debian and RPM packages (ADR-0091).
# Hardening profiles and immutable-distribution scripts keep their folder.
LINUX_EXTRA=()
for d in immutable apparmor selinux; do
	for f in deploy/linux/$d/*; do
		[ -f "$f" ] && LINUX_EXTRA+=("$f=$d/$(basename "$f")")
	done
done
DEB_ROOT=()
[ -z "$ROOT_KEY" ] || DEB_ROOT=(-root-pub "$ROOT_PUB")
for t in "${TARGETS[@]}"; do
	read -r name goos _ _ debarch <<<"$t"
	[ "$goos" = linux ] || continue
	arch=${name#linux-}
	"$WORK/distpack$EXE" -out "$OUT/openscale-$V-$name.tar.gz" -prefix "openscale-$V-$name" -source-date-epoch "$SDE" \
		-x "openscale-$name" -x "openscale-release-verify-$name" \
		"$OUT/openscale-$name" "$OUT/openscale-release-verify-$name" \
		deploy/linux/install-coordinator.sh deploy/linux/install-device.sh \
		deploy/linux/openscale-coordinator.service deploy/linux/openscale-device.service \
		deploy/linux/openscale-autoupdate.service deploy/linux/openscale-autoupdate.path \
		deploy/linux/openscale-release-sync.service deploy/linux/openscale-release-sync.timer \
		deploy/linux/nftables.conf deploy/linux/sshd-openscale.conf deploy/linux/50-openscale-upgrades.conf \
		"${LINUX_EXTRA[@]}"
	# dpkg reads 1.2.3-beta.1 as revision "beta.1" (newer than 1.2.3);
	# "~" sorts the pre-release before the release.
	"$WORK/pkgdeb$EXE" -version "${V//-/\~}" -arch "$debarch" -binary "$OUT/openscale-$name" \
		-verifier "$OUT/openscale-release-verify-$name" -deploy deploy/linux "${DEB_ROOT[@]}" \
		-maintainer "${DEB_MAINTAINER:-OpenScale <root@localhost>}" \
		-source-date-epoch "$SDE" -out "$OUT/openscale_${V}_$debarch.deb"
	# RPM forbids '-' in Version; '~' keeps pre-releases sorting first.
	RPMV=${V//-/\~}
	case "$debarch" in
	amd64) rpmarch=x86_64 ;;
	arm64) rpmarch=aarch64 ;;
	armhf) rpmarch=armv7hl ;;
	*) echo "RPM mimarisi bilinmiyor: $debarch" >&2; exit 1 ;;
	esac
	"$WORK/pkgrpm$EXE" -version "$RPMV" -arch "$debarch" -binary "$OUT/openscale-$name" \
		-verifier "$OUT/openscale-release-verify-$name" -deploy deploy/linux "${DEB_ROOT[@]}" \
		-packager "${RPM_PACKAGER:-${DEB_MAINTAINER:-OpenScale <root@localhost>}}" \
		-source-date-epoch "$SDE" -out "$OUT/openscale-$RPMV-1.$rpmarch.rpm"
	echo "paketlendi: $name ($arch)"
done

# SBOM (#211).
"$WORK/sbom$EXE" -version "$V" -source-date-epoch "$SDE" -panel-lock panel/pnpm-lock.yaml \
	-out "$OUT/openscale-$V.spdx.json" "$WORK"/openscale-*.modinfo

# Android APK (#183, P27): Google Play'siz dağıtım. APK Gradle ile ayrı
# derlenir ve sahibin Android anahtarıyla imzalanır; burada yalnızca imzası
# denetlenip aynı sürüm manifestosuna eklenir, böylece sahibin sunucusundan
# indirilen APK da releaseverify ile doğrulanır.
if [ -n "${ANDROID_APK:-}" ]; then
	[ -f "$ANDROID_APK" ] || { echo "ANDROID_APK bulunamadı: $ANDROID_APK" >&2; exit 1; }
	if command -v apksigner >/dev/null 2>&1; then
		CERTS=$(apksigner verify --print-certs "$ANDROID_APK") || { echo "APK imzası geçersiz: $ANDROID_APK" >&2; exit 1; }
		if [ -n "${ANDROID_CERT_SHA256:-}" ]; then
			want=$(echo "$ANDROID_CERT_SHA256" | tr -d ': ' | tr 'A-F' 'a-f')
			echo "$CERTS" | grep -i 'certificate SHA-256 digest' | tr -d ': ' | tr 'A-F' 'a-f' | grep -q "$want" ||
				{ echo "APK imza sertifikası ANDROID_CERT_SHA256 ile eşleşmiyor" >&2; exit 1; }
		fi
	else
		warn "apksigner yok: APK imzası denetlenmedi (Android SDK build-tools)."
	fi
	cp "$ANDROID_APK" "$OUT/openscale-$V-android.apk"
	echo "eklendi: openscale-$V-android.apk"
fi

# SHA256SUMS and the signed manifest (ADR-0022).
mapfile -t ARTIFACTS < <(find "$OUT" -maxdepth 1 -type f ! -name SHA256SUMS ! -name '*.release.json' ! -name revocations.json | sort)
# The list is signed by itself and may be replaced on a mirror later, so it is
# not an artifact of the manifest; the self-check below enforces it.
if [ -n "$ROOT_KEY" ] && [ -f "$REVOCATIONS" ]; then
	cp "$REVOCATIONS" "$OUT/revocations.json"
fi
SIGN_KEY=${RELEASE_SIGNING_KEY:-$HOME/.openscale-release/signing.key}
SIGN_CERT=${RELEASE_SIGNING_CERT:-$HOME/.openscale-release/signing.cert}
MANIFEST=$OUT/openscale-$V.release.json
if [ "$UNSIGNED" -eq 0 ] && [ -n "$ROOT_KEY" ] && [ -f "$SIGN_KEY" ] && [ -f "$SIGN_CERT" ]; then
	PASS=()
	[ -z "${RELEASE_PASSPHRASE_FILE:-}" ] || PASS=(-passphrase-file "$RELEASE_PASSPHRASE_FILE")
	RUN=()
	# mintty (Git Bash) has no console for the passphrase prompt.
	if [ ${#PASS[@]} -eq 0 ] && [[ "$(uname -s)" == MINGW* || "$(uname -s)" == MSYS* ]] && command -v winpty >/dev/null 2>&1; then
		RUN=(winpty)
	fi
	"${RUN[@]}" "$WORK/releasesign$EXE" sign -key "$SIGN_KEY" -cert "$SIGN_CERT" -root-pub "$ROOT_PUB" "${PASS[@]}" \
		-version "$V" -build "$B" -source-date-epoch "$SDE" -out "$MANIFEST" -sums "$OUT/SHA256SUMS" "${ARTIFACTS[@]}"
	# Self-check exactly as a user will verify.
	"$WORK/releaseverify$EXE" -root-key "$ROOT_PUB" -manifest "$MANIFEST" >/dev/null
	echo "İmzalı sürüm: $MANIFEST"
else
	warn "İMZASIZ sürüm: imzalama anahtarı, sertifika veya kök açık anahtar yok (ya da --unsigned)."
	warn "Yalnızca SHA256SUMS üretildi; bu tek başına özgünlük kanıtı değildir (docs/surum-dogrulama.md)."
	: >"$OUT/SHA256SUMS"
	for f in "${ARTIFACTS[@]}"; do
		echo "$(sha256sum "$f" | cut -d' ' -f1)  $(basename "$f")" >>"$OUT/SHA256SUMS"
	done
fi

cat "$OUT/SHA256SUMS"
echo "Sürüm dosyaları: $OUT"
