package healthmon

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/notify"
	"github.com/openscale/openscale/internal/speedtest"
	"github.com/openscale/openscale/internal/sysinfo"
	"github.com/openscale/openscale/internal/trust"
)

var tunnelScope = Scope{Prefixes: []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")}}

func loopbackProber() *Prober {
	return &Prober{Scope: tunnelScope, dialAllowLoopback: true}
}

func loopbackHTTP(t *testing.T, h http.Handler) netip.AddrPort {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewUnstartedServer(h)
	_ = s.Listener.Close()
	s.Listener = ln
	s.Start()
	t.Cleanup(s.Close)
	return netip.MustParseAddrPort(ln.Addr().String())
}

func TestTargetValidateScope(t *testing.T) {
	ok := Target{Name: "nas", Kind: ProbeTCP, Addr: netip.MustParseAddrPort("100.64.0.5:445")}
	if err := ok.Validate(tunnelScope); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []Target{
		{Name: "dış", Kind: ProbeTCP, Addr: netip.MustParseAddrPort("192.0.2.1:80")},
		{Name: "meta", Kind: ProbeHTTP, Addr: netip.MustParseAddrPort("169.254.169.254:80")},
		{Name: "", Kind: ProbeTCP, Addr: netip.MustParseAddrPort("100.64.0.5:1")},
		{Name: "x", Kind: "icmp", Addr: netip.MustParseAddrPort("100.64.0.5:1")},
		{Name: "x", Kind: ProbeHTTP, Addr: netip.MustParseAddrPort("100.64.0.5:80"), Path: "yol"},
		{Name: "x", Kind: ProbeTCP, Addr: netip.MustParseAddrPort("100.64.0.5:80"), Interval: time.Second},
	} {
		if err := bad.Validate(tunnelScope); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

func TestProberRefusesOutOfScope(t *testing.T) {
	p := &Prober{Scope: tunnelScope}
	r := p.Probe(context.Background(), Target{Name: "x", Kind: ProbeTCP, Addr: netip.MustParseAddrPort("127.0.0.1:1")})
	if r.OK || !strings.Contains(r.Error, "tünel") {
		t.Fatalf("%+v", r)
	}
}

func TestMonitorHTTPDownAndUp(t *testing.T) {
	var fail atomic.Bool
	ap := loopbackHTTP(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if r.Host != "ha.ev.test" || r.URL.Path != "/saglik" {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	m, err := NewMonitor(loopbackProber(), []Target{{Name: "Home Assistant", Kind: ProbeHTTP, Addr: ap, Host: "ha.ev.test", Path: "/saglik", Interval: MinInterval, Fall: 2, Rise: 2}})
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	step := func(i int) []Event { return m.Tick(context.Background(), t0.Add(time.Duration(i)*MinInterval)) }
	if ev := step(0); len(ev) != 0 || m.Status()[0].State != StateUp {
		t.Fatalf("first probe: %+v %+v", ev, m.Status())
	}
	fail.Store(true)
	if ev := step(1); len(ev) != 0 {
		t.Fatalf("down after one failure: %+v", ev)
	}
	ev := step(2)
	if len(ev) != 1 || ev[0].Kind != KindServiceDown || !strings.Contains(ev[0].Detail, "503") {
		t.Fatalf("down: %+v", ev)
	}
	if msg := ev[0].Message(); msg.Priority != notify.PriorityHigh || msg.Kind != KindServiceDown {
		t.Fatalf("message %+v", msg)
	}
	fail.Store(false)
	if ev := step(3); len(ev) != 0 {
		t.Fatalf("up after one success: %+v", ev)
	}
	if ev := step(4); len(ev) != 1 || ev[0].Kind != KindServiceUp {
		t.Fatalf("up: %+v", ev)
	}
	if d := m.Downtime(true); d["Home Assistant"] != 2*MinInterval {
		t.Fatalf("downtime %v", d)
	}
	if ev := m.Tick(context.Background(), t0.Add(4*MinInterval+time.Second)); ev != nil {
		t.Fatal("probed before the interval elapsed")
	}
}

func TestMonitorTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ap := netip.MustParseAddrPort(ln.Addr().String())
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	m, _ := NewMonitor(loopbackProber(), []Target{{Name: "smb", Kind: ProbeTCP, Addr: ap, Interval: MinInterval, Fall: 1}})
	now := time.Now()
	m.Tick(context.Background(), now)
	if m.Status()[0].State != StateUp {
		t.Fatalf("%+v", m.Status())
	}
	_ = ln.Close()
	ev := m.Tick(context.Background(), now.Add(MinInterval))
	if len(ev) != 1 || ev[0].Kind != KindServiceDown {
		t.Fatalf("%+v", ev)
	}
}

func TestNewMonitorDuplicate(t *testing.T) {
	tg := Target{Name: "a", Kind: ProbeTCP, Addr: netip.MustParseAddrPort("100.64.0.5:1")}
	if _, err := NewMonitor(&Prober{Scope: tunnelScope}, []Target{tg, tg}); err == nil {
		t.Fatal("duplicate accepted")
	}
}

func TestPresence(t *testing.T) {
	p := NewPresence([]string{"nas", "sunucu"}, 5*time.Minute)
	t0 := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	if ev := p.Observe(map[string]time.Time{"nas": t0, "sunucu": t0, "laptop": time.Time{}}, t0); len(ev) != 0 {
		t.Fatalf("%+v", ev)
	}
	ev := p.Observe(map[string]time.Time{"nas": t0, "sunucu": t0.Add(5 * time.Minute)}, t0.Add(6*time.Minute))
	if len(ev) != 1 || ev[0].Kind != KindDeviceOffline || ev[0].Subject != "nas" {
		t.Fatalf("%+v", ev)
	}
	if ev := p.Observe(map[string]time.Time{"nas": t0}, t0.Add(8*time.Minute)); len(ev) != 0 {
		t.Fatal("offline repeated")
	}
	if off := p.Offline(t0.Add(8 * time.Minute)); off["nas"] != 2*time.Minute {
		t.Fatalf("%v", off)
	}
	ev = p.Observe(map[string]time.Time{"nas": t0.Add(9 * time.Minute)}, t0.Add(9*time.Minute))
	if len(ev) != 1 || ev[0].Kind != KindDeviceOnline {
		t.Fatalf("%+v", ev)
	}
	if p.Watched("laptop") {
		t.Fatal("unwatched device watched")
	}
}

func testDoc() *trust.Document {
	return &trust.Document{
		Version:    7,
		IPv4Prefix: netip.MustParsePrefix("100.64.0.0/24"),
		Devices: []trust.Device{
			{ID: "d1", Name: "laptop", IPv4: netip.MustParseAddr("100.64.0.1")},
			{ID: "d2", Name: "nas", IPv4: netip.MustParseAddr("100.64.0.2")},
		},
		Rules: []trust.Rule{{From: []string{"laptop"}, To: []string{"nas"}, Service: trust.ServiceSpeedtest}},
	}
}

func TestMemberChanges(t *testing.T) {
	prev := testDoc()
	next := testDoc()
	next.Version = 8
	next.Devices = []trust.Device{
		{ID: "d1", Name: "dizustu"},
		{ID: "d3", Name: "misafir", Ephemeral: true},
	}
	ev := MemberChanges(prev, next, time.Now())
	kinds := map[string]Event{}
	for _, e := range ev {
		kinds[e.Kind] = e
	}
	if len(ev) != 3 || kinds[KindDeviceJoined].Subject != "misafir" || kinds[KindDeviceJoined].Severity != SeverityInfo ||
		kinds[KindDeviceLeft].Subject != "nas" || kinds[KindDeviceRenamed].Subject != "dizustu" {
		t.Fatalf("%+v", ev)
	}
	if ev := MemberChanges(nil, next, time.Now()); len(ev) != 0 {
		t.Fatal("first document reported as joins")
	}
}

func TestScopeFromDocument(t *testing.T) {
	s, err := ScopeFromDocument(testDoc(), []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")})
	if err != nil || !s.Allows(netip.MustParseAddr("100.64.0.9")) || !s.Allows(netip.MustParseAddr("192.168.1.20")) || s.Allows(netip.MustParseAddr("192.0.2.1")) {
		t.Fatalf("%v %+v", err, s)
	}
	if _, err := ScopeFromDocument(testDoc(), []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}); err == nil {
		t.Fatal("public extra prefix accepted")
	}
}

func TestResources(t *testing.T) {
	w, err := NewResourceWatcher(DefaultThresholds)
	if err != nil {
		t.Fatal(err)
	}
	d := &sysinfo.Detail{
		Volumes: []sysinfo.Volume{
			{Mount: "C:", Size: 500 << 30, Free: 20 << 30},
			{Mount: "/home/ayse", Size: 100 << 30, Free: 50 << 30},
			{Mount: "E:", Size: 64 << 30, Free: 1 << 20, Removable: true},
		},
		Battery: &sysinfo.Battery{Percent: 8, State: "discharging", Health: 61, Cycles: 900},
	}
	now := time.Now()
	ev := w.Update("laptop", d, now)
	kinds := map[string]bool{}
	for _, e := range ev {
		kinds[e.Kind] = true
	}
	if len(ev) != 3 || !kinds[KindDiskLow] || !kinds[KindBatteryWorn] || !kinds[KindBatteryLow] {
		t.Fatalf("%+v", ev)
	}
	if ev := w.Update("laptop", d, now); len(ev) != 0 {
		t.Fatalf("repeated: %+v", ev)
	}
	d.Volumes[0].Free = 200 << 30
	d.Battery = nil
	ev = w.Update("laptop", d, now)
	if len(ev) != 1 || ev[0].Kind != KindDiskOK {
		t.Fatalf("%+v", ev)
	}
	masked := CheckResources("pc", &sysinfo.Detail{Volumes: []sysinfo.Volume{{Mount: "/home/ayse", Size: 100, Free: 1}}}, DefaultThresholds)
	if len(masked) != 1 || strings.Contains(masked[0].Title, "ayse") {
		t.Fatalf("mount not masked: %+v", masked)
	}
	if _, err := NewResourceWatcher(Thresholds{DiskFreePercent: 99}); err == nil {
		t.Fatal("bad thresholds accepted")
	}
}

func TestQualityRingsAndEncode(t *testing.T) {
	q := NewQuality()
	t0 := time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)
	for i := range 12 { // one hour, every five minutes
		at := t0.Add(time.Duration(i) * FineStep)
		q.Add("nas", at, 20*time.Millisecond, false)
		q.Add("nas", at.Add(time.Second), 40*time.Millisecond, false)
		q.Add("nas", at.Add(2*time.Second), 0, true)
	}
	now := t0.Add(time.Hour)
	fine, err := q.Series("nas", Fine, now)
	if err != nil || len(fine) != 12 {
		t.Fatalf("fine %d %v", len(fine), err)
	}
	p := fine[0]
	if p.Samples != 3 || p.AvgRTT != 30*time.Millisecond || p.MaxRTT != 40*time.Millisecond || p.MinRTT != 20*time.Millisecond || int(p.LossPct) != 33 {
		t.Fatalf("%+v", p)
	}
	coarse, _ := q.Series("nas", Coarse, now)
	if len(coarse) != 1 || coarse[0].Samples != 36 {
		t.Fatalf("coarse %+v", coarse)
	}
	// After two days the fine ring forgets, the coarse ring remembers.
	later := now.Add(48 * time.Hour)
	if f, _ := q.Series("nas", Fine, later); len(f) != 0 {
		t.Fatal("fine ring kept old buckets")
	}
	if c, _ := q.Series("nas", Coarse, later); len(c) != 1 {
		t.Fatal("coarse ring lost the bucket")
	}
	if c, _ := q.Series("nas", Coarse, now.Add(8*24*time.Hour)); len(c) != 0 {
		t.Fatal("coarse ring kept a bucket older than seven days")
	}
	data, err := q.Encode()
	if err != nil {
		t.Fatal(err)
	}
	q2, err := DecodeQuality(data)
	if err != nil {
		t.Fatal(err)
	}
	f2, _ := q2.Series("nas", Fine, now)
	if len(f2) != 12 || f2[0] != fine[0] {
		t.Fatal("round trip changed the series")
	}
	if _, err := q.Series("nas", "1d", now); err == nil {
		t.Fatal("bad resolution accepted")
	}
}

func TestQualityEviction(t *testing.T) {
	q := NewQuality()
	t0 := time.Now()
	for i := range MaxDevices + 1 {
		q.Add(strings.Repeat("a", 1)+string(rune('A'+i%26))+time.Duration(i).String(), t0.Add(time.Duration(i)*time.Second), time.Millisecond, false)
	}
	if n := len(q.Devices()); n != MaxDevices {
		t.Fatalf("devices %d", n)
	}
}

func TestSpeedButton(t *testing.T) {
	var calls []speedtest.Direction
	var gotAddr netip.AddrPort
	b := &SpeedButton{Duration: time.Second, Run: func(_ context.Context, ap netip.AddrPort, dir speedtest.Direction, d time.Duration) (speedtest.Result, error) {
		calls = append(calls, dir)
		gotAddr = ap
		return speedtest.Result{Direction: dir, Bytes: 12_500_000, Elapsed: time.Second}, nil
	}}
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	b.Now = func() time.Time { return now }
	doc := testDoc()
	r, err := b.Measure(context.Background(), doc, "laptop", "nas")
	if err != nil {
		t.Fatal(err)
	}
	if r.DownloadMbps != 100 || r.UploadMbps != 100 || len(calls) != 2 || gotAddr != netip.MustParseAddrPort("100.64.0.2:4045") {
		t.Fatalf("%+v %v %v", r, calls, gotAddr)
	}
	if _, err := b.Measure(context.Background(), doc, "laptop", "nas"); !errors.Is(err, ErrSpeedCooldown) {
		t.Fatalf("cooldown: %v", err)
	}
	if _, err := b.Measure(context.Background(), doc, "nas", "laptop"); !errors.Is(err, ErrSpeedDenied) {
		t.Fatalf("denied: %v", err)
	}
	if _, err := b.Measure(context.Background(), doc, "laptop", "yok"); !errors.Is(err, ErrSpeedNoDevice) {
		t.Fatalf("no device: %v", err)
	}
	now = now.Add(SpeedCooldown)
	b.Run = func(context.Context, netip.AddrPort, speedtest.Direction, time.Duration) (speedtest.Result, error) {
		return speedtest.Result{}, speedtest.ErrBusy
	}
	if _, err := b.Measure(context.Background(), doc, "laptop", "nas"); !errors.Is(err, speedtest.ErrBusy) {
		t.Fatalf("runner error lost: %v", err)
	}
	if h := b.History(); len(h) != 2 || h[1].Error == "" {
		t.Fatalf("history %+v", h)
	}
}
