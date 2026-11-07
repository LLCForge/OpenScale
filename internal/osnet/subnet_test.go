package osnet

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// Route conflicts (#165), network identity (#80) and the shared route
// config checks (ADR-0133).

func TestRouteConflicts(t *testing.T) {
	overlay := []netip.Prefix{netip.MustParsePrefix("100.80.0.0/16")}
	routes := map[netip.Prefix]string{
		netip.MustParsePrefix("192.168.1.0/24"): "ev",
		netip.MustParsePrefix("10.9.0.0/16"):    "ofis",
	}
	locals := []LocalNet{
		{Interface: "wlan0", Prefix: netip.MustParsePrefix("192.168.1.0/24")},
		{Interface: "tun0", Prefix: netip.MustParsePrefix("100.80.5.0/24"), VPN: true},
	}
	cs := RouteConflicts(overlay, routes, locals)
	if len(cs) != 2 {
		t.Fatalf("conflicts: %+v", cs)
	}
	var route, ov bool
	for _, c := range cs {
		switch c.Kind {
		case "route":
			route = c.Skipped && c.RouteFrom == "ev" && strings.Contains(c.Message, "wlan0")
		case "overlay":
			ov = strings.Contains(c.Message, "başka bir VPN")
		}
	}
	if !route || !ov {
		t.Fatalf("conflicts: %+v", cs)
	}
	kept := SkipConflicting([]netip.Prefix{netip.MustParsePrefix("192.168.1.0/24"), netip.MustParsePrefix("10.9.0.0/16")}, locals)
	if len(kept) != 1 || kept[0] != netip.MustParsePrefix("10.9.0.0/16") {
		t.Fatalf("kept %v", kept)
	}
	if !looksLikeVPN("wg0") || !looksLikeVPN("OpenVPN TAP-Windows6") || looksLikeVPN("eth0") {
		t.Fatal("VPN name detection")
	}
}

func TestRouteConfigValidate(t *testing.T) {
	if err := (RouteConfig{}).validate(); err != nil {
		t.Fatalf("empty config: %v", err)
	}
	bad := []RouteConfig{
		{Interface: "x;y", Client: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}},
		{Interface: "x", Client: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}},
		{Interface: "x", Own: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}},
	}
	for _, c := range bad {
		if err := c.validate(); err == nil {
			t.Errorf("accepted %+v", c)
		}
	}
}

func TestParseNmcliDevices(t *testing.T) {
	out := "wifi:connected:Ev Ağı\nethernet:connected:Kablolu bağlantı 1\nwifi:disconnected:\nloopback:connected (externally):lo\n" +
		"wifi:connected:Kafe\\:Misafir\nbridge:connected:docker0\n"
	nets := parseNmcliDevices(out)
	want := []CurrentNetwork{{NetworkWiFi, "Ev Ağı"}, {NetworkWired, "Kablolu bağlantı 1"}, {NetworkWiFi, "Kafe:Misafir"}}
	if len(nets) != len(want) {
		t.Fatalf("nets %+v", nets)
	}
	for i := range want {
		if nets[i] != want[i] {
			t.Fatalf("net %d: %+v", i, nets[i])
		}
	}
	if got := cleanNetworkName("a\x1bb\x00c" + strings.Repeat("x", 300)); strings.ContainsAny(got, "\x1b\x00") || len(got) > maxNetworkName {
		t.Fatalf("clean: %q", got)
	}
}

func TestNetworkTrust(t *testing.T) {
	tr := NetworkTrust{Trusted: []string{"Ev"}}
	home := []CurrentNetwork{{NetworkWiFi, "Ev"}}
	if !tr.IsTrusted(home, nil) {
		t.Fatal("home Wi-Fi must be trusted")
	}
	if tr.IsTrusted([]CurrentNetwork{{NetworkWiFi, "Kafe"}}, nil) {
		t.Fatal("unknown Wi-Fi must be untrusted")
	}
	if tr.IsTrusted(append(home, CurrentNetwork{NetworkWired, "eth0"}), nil) {
		t.Fatal("wired is untrusted unless allowed")
	}
	tr.TrustWired = true
	if !tr.IsTrusted(append(home, CurrentNetwork{NetworkWired, "eth0"}), nil) {
		t.Fatal("wired allowed")
	}
	if tr.IsTrusted(nil, nil) || tr.IsTrusted(home, errors.New("x")) {
		t.Fatal("no network or an error must count as untrusted")
	}
	if tr.IsTrusted([]CurrentNetwork{{NetworkWiFi, ""}}, nil) {
		t.Fatal("unknown SSID must be untrusted")
	}
}

func FuzzParseNmcliDevices(f *testing.F) {
	f.Add("wifi:connected:Ev\nethernet:connected:x\n")
	f.Add("wifi:connected:a\\:b\\\\c")
	f.Add("\\")
	f.Fuzz(func(t *testing.T, s string) {
		for _, n := range parseNmcliDevices(s) {
			if n.Kind != NetworkWiFi && n.Kind != NetworkWired {
				t.Fatalf("kind %q", n.Kind)
			}
			if len(n.Name) > maxNetworkName || strings.ContainsAny(n.Name, "\x00\n\r") {
				t.Fatalf("name %q", n.Name)
			}
		}
	})
}
