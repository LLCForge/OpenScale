package upstream

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/openscale/openscale/internal/osnet"
	"github.com/openscale/openscale/internal/testnet"
)

// fakeTor records the Tor exit filter and answers the probe.
type fakeTor struct {
	mu      sync.Mutex
	applied []osnet.TorRoute
	removed int
	fail    bool
	health  osnet.TorHealth
}

func (f *fakeTor) Apply(_ context.Context, r osnet.TorRoute) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return errors.New("nft failed")
	}
	f.applied = append(f.applied, r)
	return nil
}

func (f *fakeTor) Remove(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removed++
	return nil
}

func (f *fakeTor) Probe(osnet.TorRoute) osnet.TorHealth {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.health
}

func (f *fakeTor) set(h osnet.TorHealth) {
	f.mu.Lock()
	f.health = h
	f.mu.Unlock()
}

func newTorManager(t *testing.T) (*Manager, *Store, *fakeTor, *fakeRouter) {
	t.Helper()
	st, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ft, fr := &fakeTor{}, &fakeRouter{}
	m, err := NewManager(ManagerConfig{
		Store: st,
		Deps: Deps{
			NewTUN:  func(string, int) (tun.Device, error) { return nil, errors.New("no tun in this test") },
			NewBind: func() conn.Bind { return testnet.NewLoopbackBind() },
			Router:  fr,
			Tor:     ft,
			Now:     time.Now,
		},
		Overlay: func() (Overlay, error) {
			return Overlay{Interface: "OpenScale", V4: netip.MustParsePrefix("100.80.0.0/16"),
				V6: netip.MustParsePrefix("fd7a:1:2::/48"), Self4: netip.MustParseAddr("100.80.0.1")}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return m, st, ft, fr
}

// TestTorExit: the filter goes in before forwarding may start; members'
// DNS reaches Tor's DNSPort only while it listens; a stopped Tor drops
// traffic (never this host's address); turning it off removes the filter.
func TestTorExit(t *testing.T) {
	m, st, ft, fr := newTorManager(t)
	if _, err := st.EnableTor(9040, 5353); err != nil {
		t.Fatal(err)
	}

	// Tor not running yet.
	m.SetRole(true)
	if err := m.Ready(); err != nil {
		t.Fatalf("filter installed but not ready: %v", err)
	}
	if len(ft.applied) != 1 {
		t.Fatalf("filter applied %d times", len(ft.applied))
	}
	r := ft.applied[0]
	if r.Overlay != "OpenScale" || r.TransPort != 9040 || r.DNSPort != 5353 || r.Self4 != netip.MustParseAddr("100.80.0.1") {
		t.Fatalf("route %+v", r)
	}
	if apps, _, _ := fr.snapshot(); len(apps) != 0 {
		t.Fatal("WireGuard upstream routing installed for the Tor exit")
	}
	server, _, ok := m.DNS()
	if !ok || server.IsValid() {
		t.Fatalf("DNS while Tor is down: %v %v (want dropped)", server, ok)
	}
	s := m.Status()
	if s.Kind != KindTor || s.Mode != ModeBlocked || s.Tor == nil || s.Tor.TransUp || s.Error == "" || s.Tor.Listen != "100.80.0.1" {
		t.Fatalf("status %+v %+v", s, s.Tor)
	}

	// TransPort only on loopback: a torrc mistake, still dropped.
	ft.set(osnet.TorHealth{TransLoopbackOnly: true, DNS: true})
	m.Tick()
	if s := m.Status(); s.Mode != ModeBlocked || !s.Tor.TransLoopbackOnly {
		t.Fatalf("loopback-only status %+v", s)
	}

	// Tor listens.
	ft.set(osnet.TorHealth{Trans: true, DNS: true})
	m.Tick()
	server, source, ok := m.DNS()
	if !ok || server != netip.MustParseAddrPort("127.0.0.1:5353") || source != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("DNS via %v from %v (%v)", server, source, ok)
	}
	if s := m.Status(); s.Mode != ModeTunnel || !s.Connected || s.Error != "" || s.OnDown != OnDownDrop {
		t.Fatalf("status %+v", s)
	}
	if len(ft.applied) != 1 {
		t.Fatal("unchanged filter applied again")
	}
	// The status file carries the Tor part.
	if got, ok, err := st.ReadStatus(); err != nil || !ok || got.Kind != KindTor || got.Tor == nil || !got.Tor.DNSUp {
		t.Fatalf("status file %+v %v %v", got, ok, err)
	}

	// Tor stops: DNS is dropped, the filter stays.
	ft.set(osnet.TorHealth{})
	m.Tick()
	if server, _, ok := m.DNS(); !ok || server.IsValid() {
		t.Fatal("DNS not dropped after Tor stopped")
	}
	if ft.removed != 0 {
		t.Fatal("filter removed while Tor is down")
	}

	// New ports: the filter is replaced.
	if _, err := st.EnableTor(9041, 5354); err != nil {
		t.Fatal(err)
	}
	m.Tick()
	if len(ft.applied) != 2 || ft.applied[1].TransPort != 9041 {
		t.Fatalf("filter not updated: %+v", ft.applied)
	}

	// Off: the filter goes, members exit normally.
	if _, err := st.DisableTor(); err != nil {
		t.Fatal(err)
	}
	m.Tick()
	if ft.removed != 1 {
		t.Fatalf("filter removed %d times", ft.removed)
	}
	if _, _, ok := m.DNS(); ok {
		t.Fatal("DNS still overridden after Tor was turned off")
	}
	if s := m.Status(); s.Mode != ModeOff || s.Kind != "" {
		t.Fatalf("status after off %+v", s)
	}
}

// TestTorExitFilterFails: without the filter the exit node must stay off
// and members' DNS is dropped.
func TestTorExitFilterFails(t *testing.T) {
	m, st, ft, _ := newTorManager(t)
	ft.fail = true
	if _, err := st.EnableTor(0, 0); err != nil {
		t.Fatal(err)
	}
	m.SetRole(true)
	if err := m.Ready(); err == nil {
		t.Fatal("ready without the Tor filter")
	}
	if server, _, ok := m.DNS(); !ok || server.IsValid() {
		t.Fatal("DNS not dropped without the filter")
	}
	if s := m.Status(); s.Mode != ModeOff || s.Error == "" {
		t.Fatalf("status %+v", s)
	}
	// A later success is picked up by the next tick.
	ft.mu.Lock()
	ft.fail = false
	ft.mu.Unlock()
	m.Tick()
	if err := m.Ready(); err != nil {
		t.Fatal(err)
	}
	m.Close()
	if ft.removed != 1 {
		t.Fatal("Close left the filter")
	}
}

// TestTorExitWithoutRouter: a system without a Tor router never forwards.
func TestTorExitWithoutRouter(t *testing.T) {
	m, st, _, _ := newTorManager(t)
	m.cfg.Deps.Tor = nil
	if _, err := st.EnableTor(0, 0); err != nil {
		t.Fatal(err)
	}
	m.SetRole(true)
	if err := m.Ready(); err == nil {
		t.Fatal("ready without Tor support")
	}
}

func TestStatusEqual(t *testing.T) {
	a := Status{Mode: ModeTunnel, Tor: &TorStatus{TransPort: 1}}
	b := Status{Mode: ModeTunnel, Tor: &TorStatus{TransPort: 1}}
	if !statusEqual(a, b) {
		t.Fatal("equal statuses differ")
	}
	b.Tor.DNSUp = true
	if statusEqual(a, b) || statusEqual(a, Status{Mode: ModeTunnel}) {
		t.Fatal("different statuses equal")
	}
}
