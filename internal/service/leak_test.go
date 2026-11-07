package service

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/osnet"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/trust"
)

func TestLeakInput(t *testing.T) {
	doc := &trust.Document{
		IPv4Prefix:  netip.MustParsePrefix("100.80.0.0/16"),
		IPv6Prefix:  netip.MustParsePrefix("fd7a:1:2::/48"),
		Coordinator: &trust.Coordinator{Endpoint: "coord.example.org:41820"},
	}
	st := panel.DiagStatus{ExitNode: "vps", Interface: "OpenScale", Peers: []panel.DiagPeer{
		{Name: "nas", IPv4: "100.80.0.9", Endpoint: "192.168.1.5:41641", Path: panel.PathDirect},
		{Name: "vps", IPv4: "100.80.0.7", Endpoint: "203.0.113.50:41641", Path: panel.PathDirect, ActiveExit: true},
	}}
	in, err := LeakInput(st, "192.0.2.77:41641", doc)
	if err != nil {
		t.Fatal(err)
	}
	if in.ExitNode != "vps" || in.ExitDNS != netip.MustParseAddr("100.80.0.7") || in.ExitPublic != netip.MustParseAddr("203.0.113.50") ||
		in.OwnPublic != netip.MustParseAddr("192.0.2.77") || in.CoordinatorEndpoint != "coord.example.org:41820" || in.TunnelLink != "OpenScale" {
		t.Fatalf("input %+v", in)
	}
	// A relayed exit node's endpoint is the coordinator, not the exit.
	st.Peers[1].Path = panel.PathRelay
	if in, _ := LeakInput(st, "", doc); in.ExitPublic.IsValid() || in.OwnPublic.IsValid() {
		t.Fatalf("relayed or unknown addresses used: %+v", in)
	}
	if _, err := LeakInput(st, "", &trust.Document{}); err == nil {
		t.Fatal("document without coordinator accepted")
	}
}

func TestCaptiveLocationAddr(t *testing.T) {
	for loc, want := range map[string]string{
		"http://192.168.1.1/login":     "192.168.1.1",
		"https://10.0.0.2:8443/portal": "10.0.0.2",
		"http://portal.hotel.example/": "",
		"http://203.0.113.9/":          "",
		"ftp://192.168.1.1/":           "",
		"http://[fe80::1]/":            "",
		"":                             "",
	} {
		a, ok := captiveLocationAddr(loc)
		if (want == "") == ok || (ok && a.String() != want) {
			t.Fatalf("%q: %v %v", loc, a, ok)
		}
	}
}

func TestRuntimeCaptivePortal(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := newRuntime(t, ctx, t.TempDir(), "dizustu")
	var got []netip.Addr
	var dur time.Duration
	revoked := 0
	saved := captiveOps
	captiveOps.allow = func(a []netip.Addr, d time.Duration) error { got, dur = a, d; return nil }
	captiveOps.revoke = func() error { revoked++; return nil }
	captiveOps.gateways = func() ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("192.168.1.1")}, nil
	}
	t.Cleanup(func() { captiveOps = saved })

	if _, err := r.AllowCaptivePortal(5 * time.Minute); !errors.Is(err, osnet.ErrKillSwitchNotInstalled) {
		t.Fatalf("exception without kill switch: %v", err)
	}
	r.ksStateMu.Lock()
	r.ks.installed = true
	r.ksStateMu.Unlock()
	g, err := r.AllowCaptivePortal(5 * time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != netip.MustParseAddr("192.168.1.1") || dur != 5*time.Minute || len(g.Addrs) != 1 {
		t.Fatalf("allowed %v for %s (grant %+v)", got, dur, g)
	}
	if err := r.RevokeCaptivePortal(); err != nil || revoked != 1 {
		t.Fatalf("revoke: %v %d", err, revoked)
	}
	if _, err := r.ExitLeakTest(ctx); err == nil {
		t.Fatal("leak test without an exit node succeeded")
	}
}
