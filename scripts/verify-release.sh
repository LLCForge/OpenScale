#!/usr/bin/env bash
# Verifies a downloaded OpenScale release directory (ADR-0022): the signed
# manifest's chain from the release root key, then the size and SHA-256 of
# every file, then that SHA256SUMS agrees with the signed manifest. Nothing
# is downloaded. See docs/surum-dogrulama.md.
#
#   scripts/verify-release.sh [--verifier FILE] [--root-key KEY|FILE]
#       [--root-fingerprint FP] [--revocations FILE] [--installed VERSION]
#       [--allow-downgrade] [--present-only] DIR|MANIFEST [FILE...]
#
# The verifier is, in order: --verifier, openscale-release-verify on PATH, or
# one built from this source tree with Go (cmd/releaseverify, root key from
# build/release/root.pub). A verifier taken from the release being checked
# proves nothing on its own; the script warns when --verifier points into it.
set -euo pipefail

usage() { sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'; }

VERIFIER='' ARGS=() TARGET=''
while [ $# -gt 0 ]; do
	case "$1" in
	--verifier) VERIFIER=${2:?}; shift 2 ;;
	--root-key) ARGS+=(-root-key "${2:?}"); shift 2 ;;
	--root-fingerprint) ARGS+=(-root-fingerprint "${2:?}"); shift 2 ;;
	--revocations) ARGS+=(-revocations "${2:?}"); shift 2 ;;
	--installed) ARGS+=(-installed "${2:?}"); shift 2 ;;
	--allow-downgrade) ARGS+=(-allow-downgrade); shift ;;
	--present-only) ARGS+=(-present-only); shift ;;
	-h | --help) usage; exit 0 ;;
	-*) echo "bilinmeyen seçenek: $1" >&2; exit 2 ;;
	*) TARGET=$1; shift; break ;;
	esac
done
[ -n "$TARGET" ] || { usage >&2; exit 2; }
FILES=("$@")

if [ -d "$TARGET" ]; then
	DIR=$TARGET
	mapfile -t found < <(find "$DIR" -maxdepth 1 -type f -name 'openscale-*.release.json')
	case ${#found[@]} in
	0) echo "$DIR içinde imzalı sürüm dosyası (openscale-*.release.json) yok. İmzasız bir sürüm doğrulanamaz." >&2; exit 1 ;;
	1) MANIFEST=${found[0]} ;;
	*) echo "$DIR içinde birden fazla imzalı sürüm dosyası var; dosyayı açıkça verin." >&2; exit 1 ;;
	esac
else
	MANIFEST=$TARGET
	DIR=$(dirname "$MANIFEST")
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
if [ -z "$VERIFIER" ]; then
	VERIFIER=$(command -v openscale-release-verify 2>/dev/null || true)
fi
if [ -z "$VERIFIER" ]; then
	SRC=$(cd "$(dirname "$0")/.." && pwd)
	if command -v go >/dev/null 2>&1 && [ -f "$SRC/cmd/releaseverify/main.go" ]; then
		KEY=''
		[ ! -f "$SRC/build/release/root.pub" ] || KEY=$(tr -d ' \r\n' <"$SRC/build/release/root.pub")
		echo "Doğrulayıcı kaynaktan derleniyor ($SRC)..." >&2
		(cd "$SRC" && CGO_ENABLED=0 go build -trimpath -ldflags "-X main.embeddedRootKey=$KEY" -o "$WORK/openscale-release-verify$(go env GOEXE)" ./cmd/releaseverify)
		VERIFIER=$WORK/openscale-release-verify$(go env GOEXE)
	else
		echo "openscale-release-verify yok ve Go ile kaynaktan derlenemiyor; --verifier verin." >&2
		exit 1
	fi
fi
case "$(cd "$(dirname "$VERIFIER")" && pwd)" in
"$(cd "$DIR" && pwd)")
	echo "UYARI: doğrulayıcı, doğrulanan sürümle aynı klasörde. Bu yalnızca tutarlılığı gösterir;" >&2
	echo "       SHA-256 değerini ayrı bir kanaldan karşılaştırdıysanız devam edin." >&2
	;;
esac

"$VERIFIER" "${ARGS[@]}" -manifest "$MANIFEST" -dir "$DIR" -print-sums "${FILES[@]}" >"$WORK/out"
grep -v -E '^[0-9a-f]{64}  ' "$WORK/out" || true
grep -E '^[0-9a-f]{64}  ' "$WORK/out" | sort -k2 >"$WORK/signed-sums"

if [ -f "$DIR/SHA256SUMS" ]; then
	tr -d '\r' <"$DIR/SHA256SUMS" | sort -k2 >"$WORK/sums"
	if ! cmp -s "$WORK/sums" "$WORK/signed-sums"; then
		echo "UYARI: SHA256SUMS imzalı manifestoyla aynı değil; yalnızca imzalı manifestoya güvenin." >&2
		diff "$WORK/signed-sums" "$WORK/sums" >&2 || true
		exit 1
	fi
	echo "SHA256SUMS imzalı manifestoyla tutarlı."
fi
echo "Sürüm doğrulandı: $MANIFEST"
