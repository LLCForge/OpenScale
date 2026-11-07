#!/usr/bin/env bash
# Rebuilds the Linux programs of an OpenScale release from this checkout
# and compares them byte for byte with the published ones (#219,
# docs/kaynaktan-derleme.md). One command, no network apart from the Go
# modules pinned in go.sum (none with a vendor/ tree):
#
#   scripts/reproduce.sh --manifest openscale-0.9.0.release.json [--root-fingerprint "e982 ..."]
#   scripts/reproduce.sh --sums SHA256SUMS --source-date-epoch 1793361600
#   scripts/reproduce.sh --manifest M --witness-key witness.key --builder "ad" [--witness-out F]
#     (#581, ADR-0148: bu makine bağımsız tanıksa aynı çıkan dosyaları imzalar)
#
# With --manifest the expected digests and the build stamp come from the
# signed manifest, whose signature is checked by a verifier built from this
# same source with the root key in build/release/root.pub (or --root-key).
# --sums alone only compares digests: it proves nothing about who published
# them, and the build time must be given.
#
# The checkout must be the release's source (same VERSION) and the Go
# version must match the release's (`go version -m` on a published binary
# prints it). The openscale binaries embed the panel; they only match when
# internal/panel/web/dist holds the same panel build (Next.js build IDs are
# random today; see docs/kaynaktan-derleme.md). The verifiers embed no
# panel and must always match.
set -euo pipefail
cd "$(dirname "$0")/.."

usage() { sed -n '2,23p' "$0" | sed 's/^# \{0,1\}//'; }

MANIFEST='' SUMS='' SDE=${SOURCE_DATE_EPOCH:-} ROOT_KEY_FILE=build/release/root.pub ROOT_FP=''
WITNESS_KEY='' WITNESS_OUT='' BUILDER=''
while [ $# -gt 0 ]; do
	case "$1" in
	--manifest) MANIFEST=${2:?--manifest dosya ister}; shift 2 ;;
	--sums) SUMS=${2:?--sums dosya ister}; shift 2 ;;
	--source-date-epoch) SDE=${2:?--source-date-epoch sayı ister}; shift 2 ;;
	--root-key) ROOT_KEY_FILE=${2:?--root-key dosya ister}; shift 2 ;;
	--root-fingerprint) ROOT_FP=${2:?--root-fingerprint değer ister}; shift 2 ;;
	--witness-key) WITNESS_KEY=${2:?--witness-key dosya ister}; shift 2 ;;
	--witness-out) WITNESS_OUT=${2:?--witness-out dosya ister}; shift 2 ;;
	--builder) BUILDER=${2:?--builder ad ister}; shift 2 ;;
	-h | --help) usage; exit 0 ;;
	*) echo "bilinmeyen seçenek: $1" >&2; exit 2 ;;
	esac
done
[ -n "$MANIFEST" ] || [ -n "$SUMS" ] || { echo "--manifest veya --sums gerekli" >&2; exit 2; }
if [ -n "$WITNESS_KEY" ]; then
	[ -n "$MANIFEST" ] && [ -n "$BUILDER" ] || { echo "--witness-key için --manifest ve --builder gerekli" >&2; exit 2; }
	[ -n "$WITNESS_OUT" ] || WITNESS_OUT=${MANIFEST%.release.json}.witness.json
fi

V=$(tr -d ' \r\n' < VERSION)
# GOTOOLCHAIN is left alone: like release.sh, go.mod selects the exact
# toolchain (go 1.26.0), which is what makes the result comparable.
export CGO_ENABLED=0
go mod verify >/dev/null
MODFLAG=()
[ ! -d vendor ] || MODFLAG=(-mod=vendor)
GOBUILD=(go build -trimpath -buildvcs=false "${MODFLAG[@]}")

ROOT_KEY=''
[ ! -f "$ROOT_KEY_FILE" ] || ROOT_KEY=$(tr -d ' \r\n' < "$ROOT_KEY_FILE")
VLD="-s -w -buildid= -X main.embeddedRootKey=$ROOT_KEY"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
OUT=$WORK/out
mkdir -p "$OUT" "$WORK/none"

# Expected digests and the build stamp.
EXPECTED=$WORK/expected.sha256
if [ -n "$MANIFEST" ]; then
	[ -n "$ROOT_KEY" ] || { echo "$ROOT_KEY_FILE yok: imzalı manifesto doğrulanamaz (--root-key verin)" >&2; exit 1; }
	EXE=$(go env GOEXE)
	"${GOBUILD[@]}" -ldflags "$VLD" -o "$WORK/releaseverify$EXE" ./cmd/releaseverify
	args=(-manifest "$MANIFEST" -dir "$WORK/none" -present-only -print-sums -root-key "$ROOT_KEY_FILE")
	[ -z "$ROOT_FP" ] || args+=(-root-fingerprint "$ROOT_FP")
	"$WORK/releaseverify$EXE" "${args[@]}" >"$WORK/verify.txt"
	sed -n '1,3p' "$WORK/verify.txt"
	grep -E '^[0-9a-f]{64}  ' "$WORK/verify.txt" >"$EXPECTED"
	# "Sürüm: openscale 0.9.0 (derleme 20261030.1200, imza ...)"
	read -r MV B < <(sed -n '1s/^[^ ]* [^ ]* \([^ ]*\) (derleme \([^,]*\),.*/\1 \2/p' "$WORK/verify.txt")
	[ -n "${B:-}" ] || { echo "manifestodan derleme damgası okunamadı" >&2; exit 1; }
	[ "$MV" = "$V" ] || { echo "VERSION ($V) manifestodaki sürümle ($MV) aynı değil: doğru commit'i alın" >&2; exit 1; }
else
	[[ "$SDE" =~ ^[0-9]+$ ]] || { echo "--sums ile --source-date-epoch gerekli" >&2; exit 2; }
	echo "UYARI: --sums imzasız; yalnızca özetler karşılaştırılır, yayımlayan kanıtlanmaz." >&2
	B=$(date -u -d "@$SDE" +%Y%m%d.%H%M 2>/dev/null || date -u -r "$SDE" +%Y%m%d.%H%M)
	tr -d '\r' <"$SUMS" >"$EXPECTED"
fi
echo "OpenScale $V yeniden derleniyor (derleme $B, $(go env GOVERSION))"

LD="-s -w -buildid= -X github.com/openscale/openscale/internal/version.Version=$V -X github.com/openscale/openscale/internal/version.Build=$B"
# Same targets and flags as scripts/release.sh.
for t in "linux-amd64 amd64 -" "linux-arm64 arm64 -" "linux-armv7 arm 7"; do
	read -r name goarch goarm <<<"$t"
	arm=()
	[ "$goarm" = - ] || arm=(GOARM="$goarm")
	env GOOS=linux GOARCH="$goarch" "${arm[@]}" "${GOBUILD[@]}" -ldflags "$LD" -o "$OUT/openscale-$name" ./cmd/openscale
	env GOOS=linux GOARCH="$goarch" "${arm[@]}" "${GOBUILD[@]}" -ldflags "$VLD" -o "$OUT/openscale-release-verify-$name" ./cmd/releaseverify
done

fail=0 panel_only=1 same=()
for f in "$OUT"/*; do
	n=$(basename "$f")
	want=$(awk -v n="$n" '$2 == n || $2 == "*" n { print $1; exit }' "$EXPECTED")
	got=$(sha256sum "$f" | cut -d' ' -f1)
	if [ -z "$want" ]; then
		echo "YOK     $n (yayında listelenmemiş)"
	elif [ "$want" = "$got" ]; then
		echo "AYNI    $n"
		same+=("$f")
	else
		echo "FARKLI  $n"
		fail=1
		case "$n" in openscale-release-verify-*) panel_only=0 ;; esac
	fi
done

if [ "$fail" -eq 0 ]; then
	echo "Karşılaştırılan bütün ikililer yayımlananlarla bayt bayt aynı."
	if [ -n "$WITNESS_KEY" ] && [ "${#same[@]}" -gt 0 ]; then
		# Independent reproduction witness (#581, ADR-0148).
		"${GOBUILD[@]}" -o "$WORK/releasesign$(go env GOEXE)" ./cmd/releasesign
		"$WORK/releasesign$(go env GOEXE)" witness -key "$WITNESS_KEY" -root-pub "$ROOT_KEY_FILE" -release "$MANIFEST" 			-builder "$BUILDER" -out "$WITNESS_OUT" "${same[@]}"
	fi
	exit 0
fi
if [ "$panel_only" -eq 1 ]; then
	echo "Doğrulayıcılar aynı, openscale ikilileri farklı: büyük olasılıkla gömülü panel farklı" >&2
	echo "(internal/panel/web/dist). docs/kaynaktan-derleme.md, 'Panel' bölümüne bakın." >&2
else
	echo "Doğrulayıcı da farklı: kaynak, Go sürümü veya kök açık anahtar yayınla aynı değil." >&2
fi
exit 1
