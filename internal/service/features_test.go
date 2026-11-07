package service

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/trust"
)

// --- coordinator name lookups (kill switch lockout) ---

func stubLookups(t *testing.T, system, gores lookupFunc) {
	t.Helper()
	oldSys, oldGo := systemLookup, goLookup
	systemLookup, goLookup = system, gores
	t.Cleanup(func() { systemLookup, goLookup = oldSys, oldGo })
}

func addrs(s ...string) []netip.Addr {
	out := make([]netip.Addr, len(s))
	for i, a := range s {
		out[i] = netip.MustParseAddr(a)
	}
	return out
}

func TestResolveCoordinatorFallsBack(t *testing.T) {
	r, _, _ := ksRuntime(t, settings{})
	var systemCalls, goCalls atomic.Int32
	failing := errors.New("çözülemedi")
	system := func(context.Context, string) ([]netip.Addr, error) {
		systemCalls.Add(1)
		return addrs("203.0.113.7", "2001:db8::7"), nil
	}
	gores := func(context.Context, string) ([]netip.Addr, error) {
		goCalls.Add(1)
		return nil, failing
	}
	stubLookups(t, system, gores)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got, err := r.resolveCoordinator(ctx, "vpn.example.com")
	if err != nil || len(got) != 2 || got[0] != netip.MustParseAddr("203.0.113.7") {
		t.Fatalf("system lookup: %v %v", got, err)
	}
	if st, _ := loadSettings(r.cfg.DataDir); st.CoordinatorAddrs == nil || st.CoordinatorAddrs.Host != "vpn.example.com" || len(st.CoordinatorAddrs.Addrs) != 2 {
		t.Fatalf("addresses not remembered: %+v", st.CoordinatorAddrs)
	}

	// With the kill switch in place the system resolver is skipped (it is
	// blocked), Go's resolver fails too, and the saved addresses are used.
	if err := r.saveExitChoice("vps"); err != nil {
		t.Fatal(err)
	}
	if !r.killSwitchSnapshot().installed {
		t.Fatal("kill switch not installed for the test")
	}
	systemCalls.Store(0)
	got, err = r.resolveCoordinator(ctx, "vpn.example.com")
	if err != nil || len(got) != 2 {
		t.Fatalf("cache fallback: %v %v", got, err)
	}
	if systemCalls.Load() != 0 || goCalls.Load() == 0 {
		t.Fatalf("system %d, go %d: the blocked system resolver must be skipped", systemCalls.Load(), goCalls.Load())
	}

	// Go's resolver answers through the kill switch and refreshes the cache.
	stubLookups(t, system, func(context.Context, string) ([]netip.Addr, error) { return addrs("198.51.100.9"), nil })
	got, err = r.resolveCoordinator(ctx, "vpn.example.com")
	if err != nil || len(got) != 1 || got[0] != netip.MustParseAddr("198.51.100.9") {
		t.Fatalf("go resolver: %v %v", got, err)
	}
	if st, _ := loadSettings(r.cfg.DataDir); st.CoordinatorAddrs.Addrs[0] != "198.51.100.9" {
		t.Fatalf("cache not refreshed: %+v", st.CoordinatorAddrs)
	}

	// A cache for another name is never used.
	stubLookups(t, func(context.Context, string) ([]netip.Addr, error) { return nil, failing }, func(context.Context, string) ([]netip.Addr, error) { return nil, failing })
	if _, err := r.resolveCoordinator(ctx, "other.example.com"); !errors.Is(err, errNoAddress) {
		t.Fatalf("other host: %v", err)
	}
}

func TestUsableAddrs(t *testing.T) {
	got := usableAddrs(addrs("::1", "0.0.0.0", "2001:db8::1", "224.0.0.1", "::ffff:203.0.113.5", "203.0.113.5"))
	if len(got) != 2 || got[0] != netip.MustParseAddr("203.0.113.5") || got[1] != netip.MustParseAddr("2001:db8::1") {
		t.Fatalf("usable addresses %v", got)
	}
}

// --- timed disconnect (F-121) ---

func TestDisconnectDeadline(t *testing.T) {
	loc := time.Local
	at := func(h, m int) time.Time { return time.Date(2026, 10, 30, h, m, 0, 0, loc) }
	cases := []struct {
		choice string
		now    time.Time
		want   time.Time
	}{
		{panel.Disconnect5Min, at(14, 0), at(14, 5)},
		{panel.Disconnect1Hour, at(23, 30), at(23, 30).Add(time.Hour)},
		{panel.DisconnectMorning, at(22, 0), time.Date(2026, 10, 31, morningHour, 0, 0, 0, loc)},
		{panel.DisconnectMorning, at(7, 30), time.Date(2026, 10, 31, morningHour, 0, 0, 0, loc)},
		{panel.DisconnectMorning, at(2, 0), at(morningHour, 0)},
	}
	for _, tc := range cases {
		got, err := disconnectDeadline(tc.choice, tc.now)
		if err != nil || !got.Equal(tc.want) {
			t.Errorf("%s at %s: %s %v, want %s", tc.choice, tc.now.Format("15:04"), got, err, tc.want)
		}
	}
	if _, err := disconnectDeadline("2d", at(1, 0)); err == nil {
		t.Fatal("unknown choice accepted")
	}
}

func TestTimedDisconnectSurvivesRestart(t *testing.T) {
	if testing.Short() {
		t.Skip("uses real UDP sockets")
	}
	dir := filepath.Join(t.TempDir(), "owner")
	var now atomic.Int64
	now.Store(time.Now().UnixNano())
	clock := func() time.Time { return time.Unix(0, now.Load()) }

	ctx, cancel := context.WithCancel(context.Background())
	withClock := func(c *Config) { c.Now = clock }
	owner := newRuntime(t, ctx, dir, "Masaustu", withClock)
	if _, err := owner.CreateNetwork(ctx, panel.CreateNetworkInput{Passphrase: testPass, EndpointHost: "127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "tunnel", 10*time.Second, func() bool { st := owner.Status(); return st.Device != nil && st.Device.Running })

	if err := owner.DisconnectFor(panel.Disconnect5Min); err != nil {
		t.Fatal(err)
	}
	st := owner.Status()
	if st.Device.Connected || st.Device.DisconnectedUntil == nil {
		t.Fatalf("timed disconnect not shown: %+v", st.Device)
	}
	if !hasAlert(st.Health, panel.HealthTunnelPaused) {
		t.Fatalf("paused tunnel not in the health alerts: %+v", st.Health)
	}
	// Restart the service before the deadline: it stays off.
	cancel()
	time.Sleep(300 * time.Millisecond)
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	owner2 := newRuntime(t, ctx2, dir, "Masaustu", withClock)
	if st := owner2.Status(); st.Device == nil || st.Device.Connected || st.Device.DisconnectedUntil == nil {
		t.Fatalf("the deadline did not survive the restart: %+v", st.Device)
	}
	// After the deadline the service reconnects by itself.
	now.Add(int64(6 * time.Minute))
	waitFor(t, "automatic reconnect", 10*time.Second, func() bool {
		st := owner2.Status()
		return st.Device.Connected && st.Device.DisconnectedUntil == nil && st.Device.Running
	})
	if s, _ := loadSettings(dir); s.Disconnected || s.DisconnectedUntil != nil {
		t.Fatalf("settings still disconnected: %+v", s)
	}

	// Pinning: the own name exists in the document; unknown names do not.
	if err := owner2.SetPinned("masaustu", true); err != nil {
		t.Fatal(err)
	}
	if err := owner2.SetPinned("yok-boyle-bir-cihaz", true); err == nil {
		t.Fatal("unknown device pinned")
	}
	if st := owner2.Status(); len(st.Device.Pinned) != 1 || st.Device.Pinned[0] != "masaustu" {
		t.Fatalf("pins %v", st.Device.Pinned)
	}
	if err := owner2.SetPinned("masaustu", false); err != nil {
		t.Fatal(err)
	}
	if st := owner2.Status(); len(st.Device.Pinned) != 0 {
		t.Fatalf("unpin kept %v", st.Device.Pinned)
	}
}

func TestPrepareDeviceStartEndsPassedDisconnect(t *testing.T) {
	r, ks, _ := ksRuntime(t, settings{})
	past := time.Now().Add(-time.Minute)
	if err := saveSettings(r.cfg.DataDir, settings{Disconnected: true, DisconnectedUntil: &past}); err != nil {
		t.Fatal(err)
	}
	ks.installed = true // left behind, but there is no membership
	r.prepareDeviceStart()
	st, _ := loadSettings(r.cfg.DataDir)
	if st.Disconnected || st.DisconnectedUntil != nil {
		t.Fatalf("passed deadline kept: %+v", st)
	}
	if installed, _, _ := ks.state(); installed {
		t.Fatal("filters without a membership must be removed at start")
	}
	// An open-ended disconnect stays.
	if err := saveSettings(r.cfg.DataDir, settings{Disconnected: true}); err != nil {
		t.Fatal(err)
	}
	r.prepareDeviceStart()
	if st, _ := loadSettings(r.cfg.DataDir); !st.Disconnected {
		t.Fatal("an open-ended disconnect was ended")
	}
}

func TestSortPinned(t *testing.T) {
	peers := []panel.PeerInfo{{Name: "a"}, {Name: "b"}, {Name: "c"}, {Name: "d"}}
	sortPinned(peers, []string{"c", "a"})
	got := []string{}
	for _, p := range peers {
		got = append(got, p.Name)
	}
	if strings.Join(got, ",") != "a,c,b,d" || !peers[0].Pinned || !peers[1].Pinned || peers[2].Pinned {
		t.Fatalf("order %v %+v", got, peers)
	}
}

func TestSettingsListsAreCapped(t *testing.T) {
	dir := t.TempDir()
	st := settings{CoordinatorAddrs: &addrCache{Host: "x"}}
	for i := 0; i < maxPinned+10; i++ {
		st.Pinned = append(st.Pinned, "d")
	}
	for i := 0; i < maxCachedAddrs+3; i++ {
		st.CoordinatorAddrs.Addrs = append(st.CoordinatorAddrs.Addrs, "203.0.113.1")
	}
	if err := saveSettings(dir, st); err != nil {
		t.Fatal(err)
	}
	got, err := loadSettings(dir)
	if err != nil || len(got.Pinned) != maxPinned || len(got.CoordinatorAddrs.Addrs) != maxCachedAddrs {
		t.Fatalf("caps not applied: %d %d %v", len(got.Pinned), len(got.CoordinatorAddrs.Addrs), err)
	}
}

// --- health alerts (F-193) ---

func hasAlert(alerts []panel.HealthAlert, code string) bool {
	for _, a := range alerts {
		if a.Code == code {
			return true
		}
	}
	return false
}

func TestHealthAlerts(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	r := &Runtime{cfg: Config{Now: func() time.Time { return now }}, engineSince: now.Add(-time.Hour)}
	synced := now.Add(-time.Minute)
	soon := now.Add(2 * 24 * time.Hour)
	doc := &trust.Document{IssuedAt: now.Add(time.Hour), ExpiresAt: now.Add(5 * 24 * time.Hour)}
	r.dnsErr = "NRPT kuralı yazılamadı"
	st := &panel.AppStatus{Mode: panel.ModeMember, Device: &panel.DeviceStatus{
		Name: "laptop", Connected: true, Running: true, LastSync: &synced, LastSyncError: "zaman aşımı",
		ExitNodeWanted: "vps", ExitNode: "", KillSwitchActive: true, KillSwitchError: "Kill switch kurulamadı: BFE",
		ExitNodes:           []panel.PeerInfo{{Name: "vps"}},
		MembershipExpiresAt: &soon,
	}}
	got := r.healthLocked(st, doc)
	for _, code := range []string{panel.HealthCoordinatorUnreachable, panel.HealthDNSNotApplied, panel.HealthExitUnreachable,
		panel.HealthKillSwitchFailed, panel.HealthMembershipExpiring, panel.HealthDocumentExpiring, panel.HealthClockSkew} {
		if !hasAlert(got, code) {
			t.Errorf("missing %s in %+v", code, got)
		}
	}
	for i := 1; i < len(got); i++ {
		if got[i-1].Level == panel.LevelInfo && got[i].Level != panel.LevelInfo || got[i-1].Level == panel.LevelWarning && got[i].Level == panel.LevelDanger {
			t.Fatalf("alerts not sorted by severity: %+v", got)
		}
	}
	for _, a := range got {
		if a.Code == panel.HealthExitUnreachable && a.Level != panel.LevelDanger {
			t.Fatalf("an exit node down behind the kill switch blocks the internet: %+v", a)
		}
	}

	// A healthy device has no alerts; the owner's overview covers expiry.
	r.dnsErr = ""
	ok := &panel.AppStatus{Mode: panel.ModeAdmin, Device: &panel.DeviceStatus{Name: "pc", Connected: true, Running: true, LastSync: &synced, MembershipExpiresAt: &soon}}
	if got := r.healthLocked(ok, &trust.Document{IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour)}); len(got) != 0 {
		t.Fatalf("healthy admin device: %+v", got)
	}
	// A fresh tunnel gets a grace period before "no sync yet" counts.
	r.engineSince = now.Add(-10 * time.Second)
	fresh := &panel.AppStatus{Mode: panel.ModeMember, Device: &panel.DeviceStatus{Name: "pc", Connected: true, Running: true, ExitNodeWanted: "vps", ExitNodes: []panel.PeerInfo{{Name: "vps"}}}}
	if got := r.healthLocked(fresh, nil); len(got) != 0 {
		t.Fatalf("fresh tunnel: %+v", got)
	}
	if got := r.healthLocked(&panel.AppStatus{}, nil); got == nil {
		t.Fatal("health must be an empty list, not nil")
	}
}

// --- read-only panel (F-180) ---

func TestPanelReadOnlySwitch(t *testing.T) {
	dir := t.TempDir()
	if PanelReadOnly(dir) {
		t.Fatal("read-only without the marker")
	}
	if err := SetPanelReadOnly(dir, true); err != nil {
		t.Fatal(err)
	}
	if !PanelReadOnly(dir) {
		t.Fatal("marker not seen")
	}
	if err := SetPanelReadOnly(dir, false); err != nil {
		t.Fatal(err)
	}
	if PanelReadOnly(dir) || SetPanelReadOnly(dir, false) != nil {
		t.Fatal("turning off must be idempotent")
	}
	if PanelReadOnly("") || SetPanelReadOnly("", true) == nil {
		t.Fatal("an unknown data directory is never read-only and cannot be switched")
	}
}
