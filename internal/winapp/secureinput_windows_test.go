//go:build windows

package winapp

import (
	"testing"
	"unicode/utf8"
)

func TestEncodeRune(t *testing.T) {
	for _, r := range []rune{'a', 'ş', 'İ', '€', 0x1F600, 0x10FFFF} {
		var p [4]byte
		n := encodeRune(p[:], r)
		want := utf8.AppendRune(nil, r)
		if string(p[:n]) != string(want) {
			t.Fatalf("%U: % x, want % x", r, p[:n], want)
		}
	}
}
