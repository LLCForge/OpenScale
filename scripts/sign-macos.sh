#!/bin/sh
# macOS ikilisini hardened runtime ile imzalar, isteğe bağlı olarak
# notarize eder ve imzayı doğrular (#643, ADR-0195 bölüm 10).
#
#   scripts/sign-macos.sh --identity "Developer ID Application: Ad (TEAMID)" \
#       [--notary-profile profil] dist/openscale-darwin-arm64
#
# Kimlik ve notarizasyon profili anahtar zincirinde durur; bu betik parola
# veya belirteç almaz, günlüğe yazmaz. Ağ yalnızca --notary-profile
# verildiğinde Apple'ın notarizasyon servisine gider (xcrun notarytool).
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
entitlements="$root/scripts/macos/openscale.entitlements"
identity=""
profile=""

usage() {
  echo "kullanım: scripts/sign-macos.sh --identity \"Developer ID Application: ...\" [--notary-profile profil] <ikili>..." >&2
  exit 2
}

while [ $# -gt 0 ]; do
  case "$1" in
    --identity) [ $# -ge 2 ] || usage; identity=$2; shift 2 ;;
    --notary-profile) [ $# -ge 2 ] || usage; profile=$2; shift 2 ;;
    --) shift; break ;;
    -*) usage ;;
    *) break ;;
  esac
done
[ -n "$identity" ] || usage
[ $# -ge 1 ] || usage

if [ "$(uname -s)" != "Darwin" ]; then
  echo "hata: imzalama yalnızca macOS'ta yapılır" >&2
  exit 1
fi
[ -f "$entitlements" ] || { echo "hata: $entitlements yok" >&2; exit 1; }
/usr/bin/plutil -lint "$entitlements" >/dev/null

for bin in "$@"; do
  [ -f "$bin" ] || { echo "hata: $bin yok" >&2; exit 1; }
  # --options runtime: hardened runtime. --timestamp: notarizasyon için
  # güvenli zaman damgası. Var olan imza değiştirilir.
  /usr/bin/codesign --force --options runtime --timestamp \
    --entitlements "$entitlements" --sign "$identity" "$bin"
  /usr/bin/codesign --verify --strict --verbose=2 "$bin"
  # Hardened runtime bayrağı imzada görünmeli.
  if ! /usr/bin/codesign --display --verbose=4 "$bin" 2>&1 | grep -q 'flags=.*runtime'; then
    echo "hata: $bin imzasında hardened runtime yok" >&2
    exit 1
  fi
  echo "imzalandı: $bin"
done

if [ -n "$profile" ]; then
  work=$(mktemp -d "$root/dist/.notary.XXXXXX")
  trap 'rm -rf "$work"' EXIT
  zip="$work/openscale-notary.zip"
  /usr/bin/ditto -c -k --keepParent "$@" "$zip"
  /usr/bin/xcrun notarytool submit "$zip" --keychain-profile "$profile" --wait
  # Çıplak ikiliye zımba (staple) eklenemez; .pkg veya .dmg dağıtılırsa
  # o paket ayrıca imzalanıp zımbalanır. Gatekeeper değerlendirmesi:
  for bin in "$@"; do
    /usr/sbin/spctl --assess --type execute --verbose=2 "$bin" || true
  done
fi
