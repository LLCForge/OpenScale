package service

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/healthmon"
	"github.com/openscale/openscale/internal/magicdns"
	"github.com/openscale/openscale/internal/netdrive"
	"github.com/openscale/openscale/internal/netwatch"
	"github.com/openscale/openscale/internal/notify"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/sysinfo"
	"github.com/openscale/openscale/internal/trust"
)

func w4Doc(version uint64, devices ...string) *trust.Document {
	doc := &trust.Document{Version: version, DNSDomain: "ev.ag", IPv4Prefix: netip.MustParsePrefix("100.64.0.0/24")}
	for i, n := range devices {
		doc.Devices = append(doc.Devices, trust.Device{ID: "id-" + n, Name: n, IPv4: netip.AddrFrom4([4]byte{100, 64, 0, byte(i + 1)})})
	}
	return doc
}

type w4Sink struct {
	mu     sync.Mutex
	events []panel.DiagEvent
	shown  []notify.Message
}

func (s *w4Sink) kinds() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]int{}
	for _, e := range s.events {
		out[e.Kind]++
	}
	return out
}

// TestW4MonitorWiring runs the service's monitoring loop without a
// tunnel: service probe on 127.0.0.1, watched device going offline,
// joined device, low disk, quality history, desktop notification
// channel, weekly report, drives, wake, LAN alarm and port audit.
func TestW4MonitorWiring(t *testing.T) {
	dir := t.TempDir()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	svcAddr := netip.MustParseAddrPort(ln.Addr().String())

	cfg := MonitorConfig{
		Services:      []healthmon.Target{{Name: "nas-web", Kind: "tcp", Addr: svcAddr, Fall: 1, Rise: 1}},
		ExtraPrefixes: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
		Watched:       []string{"nas"},
		Drives:        []netdrive.Mount{{Name: "arsiv", Device: "nas", Share: "arsiv", Letter: "Z:"}},
		LANWatch:      true,
		AuditPorts:    []uint16{445},
	}
	if err := SaveMonitorConfig(dir, cfg); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 25, 9, 0, 0, 0, time.UTC) // Sunday
	clock := func() time.Time { return now }
	m := newW4Monitor(dir, clock)
	sink := &w4Sink{}
	m.event = func(ev panel.DiagEvent) { sink.mu.Lock(); sink.events = append(sink.events, ev); sink.mu.Unlock() }
	m.deliver = func(_ context.Context, device string, msg notify.Message) error {
		sink.mu.Lock()
		defer sink.mu.Unlock()
		if device != "laptop" {
			return errors.New("yanlış cihaz")
		}
		sink.shown = append(sink.shown, msg)
		return nil
	}
	doc := w4Doc(1, "laptop", "nas")
	self := doc.Devices[0]
	self.Roles = []trust.Role{trust.RoleExitNode}
	seen := map[string]time.Time{"nas": now}
	m.snapshot = func() (monitorSnapshot, bool) {
		ls := map[string]time.Time{}
		for k, v := range seen {
			ls[k] = v
		}
		return monitorSnapshot{doc: doc, self: self, lastSeen: ls, rtt: map[string]time.Duration{"nas": 12 * time.Millisecond}}, true
	}
	m.inventory = func() map[string]sysinfo.Info {
		return map[string]sysinfo.Info{
			"nas": {Version: "0.9.0", PublicIP: "9.9.9.7", Detail: &sysinfo.Detail{Volumes: []sysinfo.Volume{{Mount: "/", Size: 100 << 30, Free: 1 << 30}}}},
		}
	}
	var woke []string
	m.wake = func(_ context.Context, d string) error { woke = append(woke, d); return nil }
	var mapped []string
	m.mapDrive = func(_ context.Context, _ *trust.Document, d netdrive.Mount) error {
		mapped = append(mapped, "map:"+d.Name)
		return nil
	}
	m.unmapDrive = func(_ context.Context, _ *trust.Document, d netdrive.Mount) error {
		mapped = append(mapped, "unmap:"+d.Name)
		return nil
	}
	neigh := []netwatch.Neighbor{}
	m.neighbors = func() []netwatch.Neighbor { return neigh }
	var auditRuns int
	m.audit = func(_ context.Context, c netwatch.AuditConfig, targets []netwatch.AuditTarget) ([]netwatch.AuditFinding, error) {
		auditRuns++
		if len(c.Ports) != 1 || len(targets) != 1 || targets[0].Device != "nas" {
			t.Errorf("audit targets %+v ports %v", targets, c.Ports)
		}
		return []netwatch.AuditFinding{{Device: "nas", Addr: targets[0].Addr, Port: 445}}, nil
	}

	// Notification channel through the panel interface.
	var app panel.MonitorApp = m
	if err := app.SetNotifyConfig(notify.Config{Schema: 1, WeeklyReport: true, ReportDay: 0, ReportHour: 8, TimeZone: "UTC",
		Channels: []notify.ChannelConfig{{Kind: notify.KindDesktop, Label: "masa", Devices: []string{"laptop"}}}}); err != nil {
		t.Fatal(err)
	}
	if err := app.NotifyTest("masa"); err != nil {
		t.Fatal(err)
	}
	if err := app.NotifyTest("yok"); err == nil {
		t.Fatal("unknown channel tested")
	}

	t.Cleanup(func() { magicdns.SetShortNames(nil) })
	if err := netdrive.SaveShortNames(filepath.Join(dir, netdrive.ShortNamesFile), doc, netdrive.ShortNames{Entries: []netdrive.ShortName{{Name: "medya", Device: "nas"}}}); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	m.tick(ctx)
	if got := magicdns.ShortNames(); got["medya"] != "nas" {
		t.Fatalf("short names not given to MagicDNS: %v", got)
	}
	k := sink.kinds()
	if k[healthmon.KindServiceUp] != 1 && len(app.MonitorServices()) != 1 {
		t.Fatalf("service probe not wired: %v %+v", k, app.MonitorServices())
	}
	if st := app.MonitorServices(); len(st) != 1 || st[0].State != healthmon.StateUp {
		t.Fatalf("services %+v", st)
	}
	if k[healthmon.KindDiskLow] != 1 {
		t.Fatalf("disk event missing: %v", k)
	}
	if k[EventPortOpen] != 1 || auditRuns != 1 {
		t.Fatalf("port audit not wired: %v runs %d", k, auditRuns)
	}

	// Watched device goes silent; a device joins; the service stops.
	now = now.Add(10 * time.Minute)
	doc = w4Doc(2, "laptop", "nas", "yazici")
	_ = ln.Close()
	neigh = []netwatch.Neighbor{{Addr: netip.MustParseAddr("192.168.1.40"), MAC: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}}}
	m.tick(ctx)
	k = sink.kinds()
	if k[healthmon.KindDeviceOffline] != 1 || k[healthmon.KindDeviceJoined] != 1 || k[healthmon.KindServiceDown] != 1 {
		t.Fatalf("presence/member/service events: %v", k)
	}
	if k[EventLANDevice] != 0 {
		t.Fatalf("first LAN read must only learn: %v", k)
	}
	// Second LAN read after the interval with a new MAC alarms.
	now = now.Add(6 * time.Minute)
	neigh = append(neigh, netwatch.Neighbor{Addr: netip.MustParseAddr("192.168.1.41"), MAC: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x66}})
	m.tick(ctx)
	if sink.kinds()[EventLANDevice] != 1 {
		t.Fatalf("LAN alarm not wired: %v", sink.kinds())
	}

	devs := app.MonitorDevices()
	if len(devs) != 3 || !devs[1].Watched || devs[1].Online || len(devs[1].Warnings) == 0 {
		t.Fatalf("devices %+v", devs)
	}
	if pts, err := app.MonitorQuality("nas", false); err != nil || len(pts) == 0 {
		t.Fatalf("quality %v %v", pts, err)
	}

	// Weekly report: due on Sunday after 08:00, sent once.
	sink.mu.Lock()
	var weekly int
	for _, msg := range sink.shown {
		if msg.Kind == "weekly_report" {
			weekly++
		}
	}
	sink.mu.Unlock()
	if weekly != 1 {
		t.Fatalf("weekly report sent %d times", weekly)
	}
	if subj, text, err := app.WeeklyPreview(); err != nil || subj == "" || !strings.Contains(text, "nas") {
		t.Fatalf("preview %q %q %v", subj, text, err)
	}
	if c, err := app.NotifyConfig(); err != nil || len(c.Channels) != 1 {
		t.Fatalf("notify config %+v %v", c, err)
	}

	// Panel actions.
	if err := app.Wake("nas"); err != nil || len(woke) != 1 {
		t.Fatalf("wake %v %v", err, woke)
	}
	if err := app.MapDrive("arsiv"); err != nil {
		t.Fatal(err)
	}
	if err := app.UnmapDrive("arsiv"); err != nil {
		t.Fatal(err)
	}
	if err := app.MapDrive("yok"); err == nil {
		t.Fatal("unknown drive mapped")
	}
	if strings.Join(mapped, ",") != "map:arsiv,unmap:arsiv" {
		t.Fatalf("drives %v", mapped)
	}
	if _, err := app.SpeedTest("nas"); !errors.Is(err, healthmon.ErrSpeedDenied) {
		t.Fatalf("speed test without a rule: %v", err)
	}

	// Quality history survives a restart.
	m.saveQuality(now, true)
	m2 := newW4Monitor(dir, clock)
	if pts, _ := m2.quality.Series("nas", healthmon.Fine, now); len(pts) == 0 {
		t.Fatal("quality history not persisted")
	}
	if !m2.lastReport.Equal(m.lastReport) || m2.lastReport.IsZero() {
		t.Fatal("weekly stamp not persisted")
	}

	// Intrusion detector: a port scan from inside the tunnel.
	src := doc.Devices[1].IPv4
	for p := uint16(1); p <= 200; p++ {
		m.ObserveFlow(ctx, netwatch.Flow{At: now, Src: src, Dst: doc.Devices[0].IPv4, Proto: 6, Port: p})
	}
	if sink.kinds()[EventIDSAlert] == 0 {
		t.Fatal("IDS alert not recorded")
	}
	for _, e := range sink.events {
		if strings.Contains(e.Message, "100.64.") || strings.Contains(e.Message, "192.168.") {
			t.Fatalf("address leaked into event: %+v", e)
		}
	}
}

func TestW4MonitorConfigValidate(t *testing.T) {
	bad := []MonitorConfig{
		{Drives: []netdrive.Mount{{Name: "a"}, {Name: "a"}}},
		{AuditPorts: []uint16{0}},
	}
	for i, c := range bad {
		if c.Validate() == nil {
			t.Fatalf("%d accepted", i)
		}
	}
	if c, err := LoadMonitorConfig(t.TempDir()); err != nil || len(c.Services) != 0 {
		t.Fatalf("missing file: %+v %v", c, err)
	}
}
