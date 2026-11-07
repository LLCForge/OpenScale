package filter

import (
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/packet"
)

type eventSink struct {
	mu  sync.Mutex
	evs []ThreatEvent
	got chan struct{}
}

func newSink() *eventSink { return &eventSink{got: make(chan struct{}, 64)} }

func (s *eventSink) add(ev ThreatEvent) {
	s.mu.Lock()
	s.evs = append(s.evs, ev)
	s.mu.Unlock()
	s.got <- struct{}{}
}

func (s *eventSink) wait(t *testing.T, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		select {
		case <-s.got:
		case <-time.After(5 * time.Second):
			t.Fatalf("waited for %d events", n)
		}
	}
}

func threatFilter(t *testing.T, self string, c ThreatConfig) (*Filter, *clock, *eventSink) {
	t.Helper()
	clk := &clock{now: time.Date(2026, 10, 30, 3, 0, 0, 0, time.UTC)}
	d := doc()
	f := New(clk.Now)
	dev, _ := d.DeviceByName(self)
	f.Update(d, dev)
	s := newSink()
	if err := f.SetThreats(c, s.add); err != nil {
		t.Fatal(err)
	}
	return f, clk, s
}

func TestInboundPortScanBlocksPeer(t *testing.T) {
	f, clk, sink := threatFilter(t, "masaustu", ThreatConfig{ScanPorts: 10})
	// An allowed connection opened before the scan keeps working.
	if !f.Inbound(tcp(laptopIP, masaustuIP, 40000, 3389, packet.TCPSyn)) {
		t.Fatal("allowed connection refused")
	}
	for p := uint16(1); p <= 9; p++ {
		f.Inbound(tcp(laptopIP, masaustuIP, 40001, p, packet.TCPSyn))
	}
	if len(f.ThreatEvents()) != 0 {
		t.Fatal("event below the threshold")
	}
	// Repeated ports and non-SYN packets do not count.
	f.Inbound(tcp(laptopIP, masaustuIP, 40001, 1, packet.TCPSyn))
	f.Inbound(tcp(laptopIP, masaustuIP, 40001, 99, packet.TCPAck))
	if len(f.ThreatEvents()) != 0 {
		t.Fatal("repeat counted")
	}
	f.Inbound(tcp(laptopIP, masaustuIP, 40001, 10, packet.TCPSyn))
	sink.wait(t, 1)
	evs := f.ThreatEvents()
	if len(evs) != 1 || evs[0].Kind != ThreatInboundScan || evs[0].Peer != "laptop" || evs[0].Count != 10 || evs[0].BlockedUntil.IsZero() {
		t.Fatalf("%+v", evs)
	}
	if evs[0].At.Second() != 0 {
		t.Fatal("time not rounded")
	}
	// Blocked: a new, otherwise allowed connection is refused...
	if f.Inbound(tcp(laptopIP, masaustuIP, 40002, 3389, packet.TCPSyn)) {
		t.Fatal("blocked peer opened a connection")
	}
	// ...the tracked one still passes, other peers are not affected.
	if !f.Inbound(tcp(laptopIP, masaustuIP, 40000, 3389, packet.TCPAck)) {
		t.Fatal("tracked connection cut")
	}
	if _, ok := f.BlockedPeers()["laptop"]; !ok {
		t.Fatal("not listed as blocked")
	}
	// More scanning in the same period: no second event.
	for p := uint16(100); p < 130; p++ {
		f.Inbound(tcp(laptopIP, masaustuIP, 40003, p, packet.TCPSyn))
	}
	if len(f.ThreatEvents()) != 1 {
		t.Fatal("duplicate event")
	}
	// The block ends.
	clk.now = clk.now.Add(DefaultBlockFor + time.Second)
	if !f.Inbound(tcp(laptopIP, masaustuIP, 40004, 3389, packet.TCPSyn)) {
		t.Fatal("block did not end")
	}
}

func TestScanReportOnlyAndUnblock(t *testing.T) {
	f, _, sink := threatFilter(t, "masaustu", ThreatConfig{ScanPorts: 5, DisableBlock: true})
	for p := uint16(1); p <= 5; p++ {
		f.Inbound(udp(laptopIP, masaustuIP, 5000, p))
	}
	sink.wait(t, 1)
	if !f.ThreatEvents()[0].BlockedUntil.IsZero() || len(f.BlockedPeers()) != 0 {
		t.Fatal("report-only mode blocked")
	}
	if !f.Inbound(tcp(laptopIP, masaustuIP, 40002, 3389, packet.TCPSyn)) {
		t.Fatal("allowed connection refused in report-only mode")
	}

	g, _, sink2 := threatFilter(t, "masaustu", ThreatConfig{ScanPorts: 5})
	for p := uint16(1); p <= 5; p++ {
		g.Inbound(tcp(laptopIP, masaustuIP, 40001, p, packet.TCPSyn))
	}
	sink2.wait(t, 1)
	g.Unblock("laptop")
	if !g.Inbound(tcp(laptopIP, masaustuIP, 40002, 3389, packet.TCPSyn)) {
		t.Fatal("unblock did not lift the block")
	}
}

func TestShieldsAndWindowDoNotCount(t *testing.T) {
	f, clk, _ := threatFilter(t, "masaustu", ThreatConfig{ScanPorts: 5})
	// Spread over windows: never five ports within one minute.
	for p := uint16(1); p <= 12; p++ {
		f.Inbound(tcp(laptopIP, masaustuIP, 40001, p, packet.TCPSyn))
		clk.now = clk.now.Add(20 * time.Second)
	}
	if len(f.ThreatEvents()) != 0 {
		t.Fatalf("slow probing reported: %+v", f.ThreatEvents())
	}
	f.SetShields(true)
	for p := uint16(200); p < 260; p++ {
		f.Inbound(tcp(laptopIP, masaustuIP, 40001, p, packet.TCPSyn))
	}
	if len(f.ThreatEvents()) != 0 {
		t.Fatal("shield refusals counted as a scan")
	}
}

func TestOutboundSweepAndCanaries(t *testing.T) {
	canary := netip.MustParseAddr("100.80.0.99")
	f, _, sink := threatFilter(t, "telefon", ThreatConfig{ScanPorts: 5, ScanPeers: 3, CanaryAddrs: []netip.Addr{canary}, CanaryPorts: []uint16{2323}})
	// A program on this device contacts the canary address.
	if f.Outbound(tcp(telefonIP, canary, 40000, 445, packet.TCPSyn)) {
		t.Fatal("canary reachable")
	}
	sink.wait(t, 1)
	// A local program scanning a peer's ports.
	for p := uint16(1); p <= 5; p++ {
		f.Outbound(tcp(telefonIP, laptopIP, 40000, p, packet.TCPSyn))
	}
	sink.wait(t, 1)
	// ...and sweeping peers (laptop, masaustu, plus the pass above).
	f.Outbound(echo(telefonIP, masaustuIP, packet.ICMPv4EchoRequest, 1))
	f.Outbound(tcp(telefonIP, netip.MustParseAddr("100.80.0.1"), 40000, 7, packet.TCPSyn))
	evs := f.ThreatEvents()
	kinds := map[ThreatKind]ThreatEvent{}
	for _, e := range evs {
		kinds[e.Kind] = e
	}
	if e := kinds[ThreatCanaryAddress]; e.Peer != "" || e.Canary != canary.String() || !e.BlockedUntil.IsZero() {
		t.Fatalf("canary event %+v", e)
	}
	if e := kinds[ThreatOutboundScan]; e.Kind == "" {
		t.Fatalf("no outbound scan: %+v", evs)
	}
	// A peer reaching a canary port of this device is reported and blocked.
	g, _, sink2 := threatFilter(t, "masaustu", ThreatConfig{CanaryPorts: []uint16{2323}})
	g.Inbound(tcp(telefonIP, masaustuIP, 40000, 2323, packet.TCPSyn))
	sink2.wait(t, 1)
	e := g.ThreatEvents()[0]
	if e.Kind != ThreatCanaryPort || e.Peer != "telefon" || e.Port != 2323 || e.BlockedUntil.IsZero() {
		t.Fatalf("%+v", e)
	}
	// A canary that became a device's address is no canary any more.
	h, _, _ := threatFilter(t, "telefon", ThreatConfig{CanaryAddrs: []netip.Addr{masaustuIP}})
	h.Outbound(tcp(telefonIP, masaustuIP, 40000, 22, packet.TCPSyn))
	for _, e := range h.ThreatEvents() {
		if e.Kind == ThreatCanaryAddress {
			t.Fatal("device address treated as canary")
		}
	}
}

func TestThreatConfigValidation(t *testing.T) {
	bad := []ThreatConfig{
		{ScanPorts: 1}, {ScanPeers: 2000}, {ScanWindow: time.Second}, {BlockFor: 48 * time.Hour},
		{CanaryAddrs: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}, {CanaryPorts: []uint16{0}},
	}
	for _, c := range bad {
		if _, err := c.WithDefaults(); !errors.Is(err, ErrThreatConfig) {
			t.Errorf("%+v accepted", c)
		}
	}
	c, err := ThreatConfig{}.WithDefaults()
	if err != nil || c.ScanPorts != DefaultScanPorts || c.BlockFor != DefaultBlockFor {
		t.Fatalf("%v %+v", err, c)
	}
	// Off: no detection state, nothing reported.
	f := filterFor("masaustu")
	for p := uint16(1); p < 100; p++ {
		f.Inbound(tcp(laptopIP, masaustuIP, 40001, p, packet.TCPSyn))
	}
	if f.ThreatEvents() != nil || len(f.BlockedPeers()) != 0 {
		t.Fatal("detection without SetThreats")
	}
}
