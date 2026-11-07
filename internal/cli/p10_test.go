package cli

import (
	"flag"
	"io"
	"testing"
)

// Routing commands (ADR-0133).
func TestP10RouteCommands(t *testing.T) {
	h := newHarness(t)
	pass := policyNetwork(t, h)
	dir := []string{"--dir", h.netDir, pass}

	out := h.run(exitOK, append([]string{"route", "set", "--device", "masaustu", "--routes", "192.168.1.0/24"}, dir...)...)
	mustContain(t, out, "+ alt ağ rotası 192.168.1.0/24 (yönlendirici masaustu)", "Rota tek başına erişim açmaz")
	h.run(exitUsage, append([]string{"route", "set", "--device", "masaustu", "--routes", "192.168.1.1/24"}, dir...)...)
	h.run(exitError, append([]string{"route", "set", "--device", "masaustu", "--routes", "8.8.8.0/24"}, dir...)...)

	// A rule and a named address inside the approved route.
	h.run(exitOK, append([]string{"host", "set", "--name", "nas", "--prefix", "192.168.1.10/32"}, dir...)...)
	h.run(exitOK, append([]string{"rule", "add", "--from", "laptop", "--to", "192.168.1.0/24", "--ports", "445"}, dir...)...)
	h.run(exitError, append([]string{"route", "rm", "--device", "masaustu", "--route", "192.168.1.0/24"}, dir...)...)

	out = h.run(exitOK, "route", "list", "--dir", h.netDir)
	mustContain(t, out, "192.168.1.0/24", "yönlendirici masaustu")

	// Plain WireGuard exit node.
	key := "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="
	out = h.run(exitOK, append([]string{"exit-node", "external", "set", "--name", "evwg", "--key", key, "--endpoint", "198.51.100.7:51820", "--dns", "10.66.0.1"}, dir...)...)
	mustContain(t, out, "+ düz WireGuard çıkış düğümü evwg")
	h.run(exitUsage, append([]string{"exit-node", "external", "set", "--name", "x", "--key", key, "--endpoint", "198.51.100.7:51820"}, dir...)...)
	out = h.run(exitOK, "exit-node", "external", "config", "--dir", h.netDir)
	mustContain(t, out, "[Peer]", "AllowedIPs = 100.80.")

	// Address strategy.
	out = h.run(exitOK, append([]string{"address", "strategy", "--strategy", "sequential", "--reserve", "100.80.200.0/24"}, dir...)...)
	mustContain(t, out, "Adres atama: ilk boş adres -> sıralı, ayrılmış 100.80.200.0/24")
	h.run(exitUsage, append([]string{"address", "strategy", "--strategy", "weird"}, dir...)...)
}

func TestP10ParseRate(t *testing.T) {
	cases := map[string]uint64{"": 0, "20mbit": 2500000, "5MB": 5 << 20, "800kb": 800 << 10, "1048576": 1 << 20}
	for in, want := range cases {
		got, err := parseRate(in)
		if err != nil || got != want {
			t.Errorf("parseRate(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, bad := range []string{"fast", "-1mbit", "mbit"} {
		if _, err := parseRate(bad); err == nil {
			t.Errorf("parseRate(%q) accepted", bad)
		}
	}
}

func TestP10UpFlags(t *testing.T) {
	parse := func(args ...string) (upP10Options, error) {
		fs := flag.NewFlagSet("up", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		f := addUpP10Flags(fs)
		if err := fs.Parse(args); err != nil {
			return upP10Options{}, err
		}
		return f.resolve()
	}
	o, err := parse("--exit-untrusted", "--trusted-wifi", "Ev Ağı,Ofis", "--exit-candidates", "vps,vps2", "--exit-except", "203.0.113.0/24")
	if err != nil || o.auto != "failover" || o.untrusted == nil || len(o.untrusted.Trusted) != 2 || o.untrusted.Trusted[0] != "Ev Ağı" || len(o.except) != 1 {
		t.Fatalf("options %+v %v", o, err)
	}
	for _, bad := range [][]string{
		{"--exit-auto", "random"},
		{"--trusted-wifi", "Ev"},
		{"--exit-candidates", "vps"},
		{"--exit-except", "0.0.0.0/0"},
		{"--exit-rate-limit", "1kbit"},
	} {
		if _, err := parse(bad...); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
	if o, err := parse("--no-subnet-routes"); err != nil || o.routeApplier() != nil {
		t.Fatal("--no-subnet-routes must disable the OS router")
	}
}
