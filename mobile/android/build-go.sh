#!/bin/sh
# Go çekirdeğini (mobile/openscale) gomobile ile app/libs/openscale.aar
# olarak derler (ADR-0101). golang.org/x/mobile ADR-0002'nin golang.org/x/*
# iznine girer ama go.mod'a sahip onayıyla eklenir; bu betik go.mod'u
# değiştirmez, eksikse durur.
#
# Gerekenler: Go (go.mod sürümü), Android SDK (ANDROID_HOME) ve NDK
# (ANDROID_NDK_HOME). gomobile cgo ile derler; Go'nun ad çözücüsü böylece
# Android'in kendi çözücüsünü kullanır.
#
# Tekrarlanabilir derleme (#183, docs/android-dagitim.md): -trimpath ve boş
# derleme kimliği; Go, NDK ve gomobile sürümleri sabit tutulmalıdır.
set -eu

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$ROOT"

if ! grep -q '^[[:space:]]*golang.org/x/mobile ' go.mod; then
	echo "golang.org/x/mobile go.mod içinde yok." >&2
	echo "ADR-0101: sahip onayıyla 'go get golang.org/x/mobile@<sabit sürüm>' çalıştırıp go.sum ile birlikte işleyin." >&2
	exit 1
fi
: "${ANDROID_HOME:?ANDROID_HOME ayarlı değil}"
: "${ANDROID_NDK_HOME:?ANDROID_NDK_HOME ayarlı değil}"

mkdir -p mobile/android/app/libs
go run golang.org/x/mobile/cmd/gomobile init
go run golang.org/x/mobile/cmd/gomobile bind \
	-target=android/arm64,android/arm,android/amd64 \
	-androidapi 29 \
	-javapkg org.openscale.go \
	-trimpath \
	-ldflags="-s -w -buildid=" \
	-o mobile/android/app/libs/openscale.aar \
	./mobile/openscale
echo "Oluşturuldu: mobile/android/app/libs/openscale.aar"
