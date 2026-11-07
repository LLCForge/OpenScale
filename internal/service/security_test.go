package service

import (
	"net/netip"
	"testing"
)

func TestClassifyListener(t *testing.T) {
	overlay := []netip.Prefix{netip.MustParsePrefix("100.80.0.0/16"), netip.MustParsePrefix("fde6:1f40:8c2::/48")}
	cases := map[string]string{
		"0.0.0.0":          exposureAll,
		"::":               exposureAll,
		"127.0.0.1":        exposureLocal,
		"::1":              exposureLocal,
		"100.80.0.2":       exposureOpenScale,
		"fde6:1f40:8c2::2": exposureOpenScale,
		"192.168.1.20":     exposureLAN,
		"fe80::1":          exposureLAN,
		"bozuk":            exposureLAN,
	}
	for addr, want := range cases {
		if got := classify(addr, overlay); got != want {
			t.Errorf("classify(%s) = %s, want %s", addr, got, want)
		}
	}
}
