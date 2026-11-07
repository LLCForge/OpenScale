package geoip

import (
	"net/netip"
	"testing"
)

func TestCountry(t *testing.T) {
	cases := map[string]string{
		"8.8.8.8":              "US", // Google DNS, ARIN
		"195.175.39.39":        "TR", // Türk Telekom DNS, RIPE NCC
		"2001:4860:4860::8888": "US",
		"192.168.1.10":         "",
		"100.80.0.2":           "",
		"127.0.0.1":            "",
		"::ffff:8.8.8.8":       "US",
	}
	for ip, want := range cases {
		if got := Country(netip.MustParseAddr(ip)); got != want {
			t.Errorf("Country(%s) = %q, want %q", ip, got, want)
		}
	}
	if DataDate() == "" {
		t.Error("missing data date")
	}
}

func TestDecodeRejectsGarbage(t *testing.T) {
	if _, err := decode([]byte("nope")); err == nil {
		t.Fatal("garbage accepted")
	}
	if _, err := decode([]byte("OSGEO1" + "20260101" + "\xff\xff\xff\xff")); err == nil {
		t.Fatal("truncated table accepted")
	}
}
