package node

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/osnet"
	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/internal/wgconf"
)

// Engine side of subnet routing, plain WireGuard exits and the automatic
// exit node choice (ADR-0133).

type fakeRoutes struct {
	mu     sync.Mutex
	last   osnet.RouteConfig
	calls  int
	closed bool
}

func (f *fakeRoutes) Apply(c osnet.RouteConfig) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.last, f.calls = c, f.calls+1
	return nil
}

func (f *fakeRoutes) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

func p10Doc(now time.Time) *trust.Document {
	end := now.Add(time.Hour)
	return &trust.Document{
		IPv4Prefix: netip.MustParsePrefix("100.80.0.0/16"),
		IPv6Prefix: netip.MustParsePrefix("fd00:1::/48"),
		ExpiresAt:  end,
		Devices: []trust.Device{
			{Name: "laptop", IPv4: netip.MustParseAddr("100.80.0.1"), ExpiresAt: end},
			{Name: "ev", IPv4: netip.MustParseAddr("100.80.0.2"), ExpiresAt: end,
				Routes: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24"), netip.MustParsePrefix("10.5.0.0/16")}},
			{Name: "vps", IPv4: netip.MustParseAddr("100.80.0.3"), ExpiresAt: end, Roles: []trust.Role{trust.RoleExitNode}},
			{Name: "vps2", IPv4: netip.MustParseAddr("100.80.0.4"), ExpiresAt: end, Roles: []trust.Role{trust.RoleExitNode}},
		},
		Rules: []trust.Rule{{From: []string{"laptop"}, To: []string{"192.168.1.0/24"}, Protocol: trust.ProtocolTCP, Ports: []string{"445"}}},
	}
}

func p10Engine(now time.Time, routes RouteApplier) *Engine {
	return &Engine{cfg: Config{Now: func() time.Time { return now }, Routes: routes},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)), reapply: make(chan struct{}, 1)}
}

func TestApplyRoutesClientAndRouter(t *testing.T) {
	now := time.Now()
	doc := p10Doc(now)
	old := localNetworks
	defer func() { localNetworks = old }()
	localNetworks = func(string) ([]osnet.LocalNet, error) {
		return []osnet.LocalNet{{Interface: "eth0", Prefix: netip.MustParsePrefix("10.5.3.0/24")}}, nil
	}
	f := &fakeRoutes{}
	e := p10Engine(now, f)
	laptop, _ := doc.DeviceByName("laptop")
	e.applyRoutes(doc, laptop, false)
	// Both routes of "ev" are configured (the rule makes ev a router
	// peer), but 10.5.0.0/16 overlaps the local 10.5.3.0/24 and is skipped.
	if !slices.Equal(f.last.Client, []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}) || len(f.last.Own) != 0 {
		t.Fatalf("laptop routes: %+v", f.last)
	}
	localNetworks = func(string) ([]osnet.LocalNet, error) {
		return []osnet.LocalNet{{Interface: "wlan0", Prefix: netip.MustParsePrefix("192.168.1.0/24")}}, nil
	}
	e.applyRoutes(doc, laptop, false)
	if slices.Contains(f.last.Client, netip.MustParsePrefix("192.168.1.0/24")) {
		t.Fatal("a subnet overlapping the local LAN must not be routed into the tunnel")
	}
	st := e.Routing()
	if len(st.Conflicts) != 1 || st.Conflicts[0].Kind != "route" || !st.Conflicts[0].Skipped {
		t.Fatalf("conflicts: %+v", st.Conflicts)
	}
	ev, _ := doc.DeviceByName("ev")
	e2 := p10Engine(now, &fakeRoutes{})
	e2.applyRoutes(doc, ev, false)
	if got := e2.cfg.Routes.(*fakeRoutes).last; len(got.Own) != 2 || got.Overlay4 != doc.IPv4Prefix {
		t.Fatalf("router config: %+v", got)
	}
	// Expired: everything withdrawn.
	e2.applyRoutes(doc, ev, true)
	if got := e2.cfg.Routes.(*fakeRoutes).last; !got.Empty() {
		t.Fatalf("expired device keeps routes: %+v", got)
	}
	e2.stopRoutes()
	// Telefon-like device without a rule gets nothing and the OS is never
	// touched.
	vps, _ := doc.DeviceByName("vps")
	f3 := &fakeRoutes{}
	p10Engine(now, f3).applyRoutes(doc, vps, false)
	if f3.calls != 0 {
		t.Fatal("no routes: the OS must not be touched")
	}
}

func TestExitExceptionsValidation(t *testing.T) {
	e := p10Engine(time.Now(), nil)
	if err := e.SetExitExceptions([]netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}); err == nil {
		t.Fatal("/0 must be refused")
	}
	if err := e.SetExitExceptions([]netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}); err != nil {
		t.Fatal(err)
	}
	if got := e.Routing().ExitExceptions; len(got) != 1 {
		t.Fatalf("exceptions: %v", got)
	}
}

func TestExternalExitPeer(t *testing.T) {
	now := time.Now()
	doc := p10Doc(now)
	key := trust.Key{1, 2, 3}
	doc.ExternalExits = []trust.ExternalExit{{Name: "evwg", WireGuardKey: key, Endpoint: "198.51.100.7:51820", DNS: netip.MustParseAddr("10.66.0.1")}}
	laptop, _ := doc.DeviceByName("laptop")
	exit := externalExitFor(doc, laptop, "evwg")
	if exit == nil || exit.ID != "" || exit.IPv4 != netip.MustParseAddr("10.66.0.1") {
		t.Fatalf("pseudo device: %+v", exit)
	}
	e := p10Engine(now, nil)
	want := map[trust.Key]wgconf.Peer{}
	if got := e.addExternalExitPeer(context.Background(), doc, exit, want); got == nil {
		t.Fatal("external exit must be configured")
	}
	p := want[key]
	if p.Endpoint.String() != "198.51.100.7:51820" || len(p.AllowedIPs) != 2 || p.AllowedIPs[0].Bits() != 0 {
		t.Fatalf("peer: %+v", p)
	}
	// exit_users limits plain exits too.
	users := []string{"vps"}
	doc.ExitUsers = &users
	if externalExitFor(doc, laptop, "evwg") != nil {
		t.Fatal("a device not in exit_users must not use a plain exit")
	}
}

func TestExitChooserFailover(t *testing.T) {
	c := newExitChooser(ExitModeFailover)
	t0 := time.Now()
	order := []string{"a", "b"}
	up := func(names ...string) map[string]ExitHealth {
		m := map[string]ExitHealth{"a": {Name: "a"}, "b": {Name: "b"}}
		for _, n := range names {
			m[n] = ExitHealth{Name: n, Online: true}
		}
		return m
	}
	if got, _ := c.choose(t0, "", order, up("a", "b")); got != "a" {
		t.Fatalf("first choice %q", got)
	}
	// a fails: the first failed check (after the start grace) waits, the
	// second switches.
	t1 := t0.Add(time.Minute)
	if got, _ := c.choose(t1, "a", order, up("b")); got != "a" {
		t.Fatalf("one failed check must not switch, got %q", got)
	}
	if got, _ := c.choose(t1.Add(10*time.Second), "a", order, up("b")); got != "b" {
		t.Fatalf("failover to b expected, got %q", got)
	}
	// a back: only after it has been healthy for exitStableFor.
	t2 := t1.Add(time.Minute)
	if got, _ := c.choose(t2, "b", order, up("a", "b")); got != "b" {
		t.Fatal("must not flap back at once")
	}
	if got, _ := c.choose(t2.Add(exitStableFor), "b", order, up("a", "b")); got != "a" {
		t.Fatal("must return to the preferred exit once it is stable")
	}
	// Nothing works: keep the current choice (no leak).
	t3 := t2.Add(10 * time.Minute)
	c.choose(t3, "a", order, up())
	if got, _ := c.choose(t3.Add(time.Minute), "a", order, up()); got != "a" {
		t.Fatalf("all down must keep the choice, got %q", got)
	}
}

func TestExitChooserFastest(t *testing.T) {
	c := newExitChooser(ExitModeFastest)
	t0 := time.Now()
	order := []string{"a", "b"}
	h := map[string]ExitHealth{"a": {Name: "a", Online: true, RTT: 80 * time.Millisecond}, "b": {Name: "b", Online: true, RTT: 20 * time.Millisecond}}
	if got, _ := c.choose(t0, "", order, h); got != "b" {
		t.Fatalf("fastest expected b, got %q", got)
	}
	// Slightly faster a does not cause a switch.
	h["a"] = ExitHealth{Name: "a", Online: true, RTT: 18 * time.Millisecond}
	if got, _ := c.choose(t0.Add(time.Hour), "b", order, h); got != "b" {
		t.Fatalf("hysteresis: got %q", got)
	}
	h["a"] = ExitHealth{Name: "a", Online: true, RTT: 5 * time.Millisecond}
	if got, _ := c.choose(t0.Add(2*time.Hour), "b", order, h); got != "a" {
		t.Fatalf("clearly faster a expected, got %q", got)
	}
}

func TestExitCandidates(t *testing.T) {
	doc := p10Doc(time.Now())
	self, _ := doc.DeviceByName("laptop")
	if got := exitCandidates(doc, self, nil); !slices.Equal(got, []string{"vps", "vps2"}) {
		t.Fatalf("default candidates %v", got)
	}
	if got := exitCandidates(doc, self, []string{"vps2", "ev", "yok", "vps2"}); !slices.Equal(got, []string{"vps2"}) {
		t.Fatalf("filtered candidates %v", got)
	}
}
