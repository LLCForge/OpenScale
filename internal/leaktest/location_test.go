package leaktest

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/openscale/openscale/internal/geoip"
)

func TestRegionOf(t *testing.T) {
	for in, want := range map[string]string{
		"tr_TR.UTF-8": "TR", "en-GB": "GB", "de_DE@euro": "DE", "C": "", "POSIX": "", "": "", "en_US1": "", "sr_RS@latin": "RS",
	} {
		if got := regionOf(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

func TestLocationCheck(t *testing.T) {
	seen := "8.8.8.8"
	exit := geoip.Country(netip.MustParseAddr(seen))
	if exit == "" {
		t.Skip("bundled table has no country for the test address")
	}
	zone := ""
	for z, c := range ianaZones {
		if c == exit {
			zone = z
			break
		}
	}
	if zone == "" {
		t.Skipf("no test zone for %s", exit)
	}
	rep := Report{SeenIPv4: seen}
	AddLocation(&rep, Locale{TimeZone: zone, Region: exit})
	if len(rep.Checks) != 1 || rep.Checks[0].Level != LevelOK || rep.Leak {
		t.Fatalf("matching locale: %+v", rep)
	}

	other := "TR"
	if exit == "TR" {
		other = "DE"
	}
	rep = Report{SeenIPv4: seen}
	AddLocation(&rep, Locale{TimeZone: "Europe/Istanbul", Region: other})
	c := rep.Checks[0]
	if c.Level != LevelInfo || rep.Leak || !strings.Contains(c.Detail, "dil bölgesi") {
		t.Fatalf("mismatch: %+v", rep)
	}

	// Unknown locale or country: no line at all.
	rep = Report{SeenIPv4: seen}
	AddLocation(&rep, Locale{TimeZone: "Etc/UTC"})
	rep2 := Report{SeenIPv4: "10.0.0.1"}
	AddLocation(&rep2, Locale{TimeZone: zone})
	if len(rep.Checks) != 0 || len(rep2.Checks) != 0 {
		t.Fatalf("check without data: %+v %+v", rep, rep2)
	}
}
