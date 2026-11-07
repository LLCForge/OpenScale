package osnet

import (
	"net/netip"
	"testing"
)

func TestDNSConfigValidation(t *testing.T) {
	ok := DNSConfig{Interface: "OpenScale", Server: netip.MustParseAddr("100.80.255.254"), Domain: "openscale.internal"}
	if err := ok.validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	bad := []DNSConfig{
		{Interface: "OpenScale", Server: ok.Server, Domain: "a'; Remove-Item C:\\ -Recurse; '"},
		{Interface: "OpenScale", Server: ok.Server, Domain: "Upper.Case"},
		{Interface: "OpenScale", Server: ok.Server, Domain: "-bad.internal"},
		{Interface: "x'y", Server: ok.Server, Domain: ok.Domain},
		{Interface: "OpenScale", Server: netip.MustParseAddr("fd00::1"), Domain: ok.Domain},
		{Interface: "OpenScale", Domain: ok.Domain},
	}
	for _, c := range bad {
		if err := c.validate(); err == nil {
			t.Errorf("accepted %+v", c)
		}
	}
}
