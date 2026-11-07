package service

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/edgenet"
	"github.com/openscale/openscale/internal/osnet"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/surface"
)

// edgeMember starts a service that owns a network, so every preference
// can be set.
func edgeMember(t *testing.T) *Runtime {
	t.Helper()
	if testing.Short() {
		t.Skip("uses real UDP sockets")
	}
	ctx, cancel := context.WithCancel(context.Background())
	base := t.TempDir()
	// Runs after the service stopped, just before the temporary directory
	// is removed: background writers of the stopped tunnel get a moment
	// to finish (Windows refuses to remove a directory still in use).
	t.Cleanup(func() {
		for range 30 {
			if os.RemoveAll(base) == nil {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	})
	r := newRuntime(t, ctx, filepath.Join(base, "owner"), "Edge-PC")
	// Registered after newRuntime's wait, so it runs first.
	t.Cleanup(cancel)
	// Runs before cancel: let a tunnel restart caused by the test settle,
	// so nothing writes into the temporary directory after the stop.
	t.Cleanup(func() {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if d := r.Status().Device; d != nil && d.Running {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		time.Sleep(200 * time.Millisecond)
	})
	if _, err := r.CreateNetwork(ctx, panel.CreateNetworkInput{Passphrase: testPass, EndpointHost: "127.0.0.1"}); err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}
	return r
}

func prefValue(t *testing.T, r *Runtime, key string) string {
	t.Helper()
	p, err := r.DiagPrefs()
	if err != nil {
		t.Fatal(err)
	}
	return prefMap(p)[key]
}

func TestEdgeGameModeRestoresAndKeepsOwnerChanges(t *testing.T) {
	r := edgeMember(t)
	if _, err := r.DiagSetPrefs(map[string]string{"padding": "buckets", "cover-traffic": "512"}); err != nil {
		t.Fatal(err)
	}
	st, err := r.EdgeSetMode(panel.EdgeModeRequest{Mode: "game"})
	if err != nil {
		t.Fatalf("game on: %v", err)
	}
	if st.Mode != panel.EdgeModeGame || len(st.Changes) != 3 {
		t.Fatalf("status %+v", st)
	}
	if prefValue(t, r, "padding") != "off" || prefValue(t, r, "cover-traffic") != "0" || prefValue(t, r, "interactive-priority") != "true" {
		t.Fatal("game mode not applied")
	}
	if _, err := r.EdgeSetMode(panel.EdgeModeRequest{Mode: "metered"}); err == nil {
		t.Fatal("second mode accepted")
	}
	if _, err := r.EdgeSetMode(panel.EdgeModeRequest{Mode: "game", ExitNode: "x"}); err == nil {
		t.Fatal("exit node outside travel accepted")
	}
	// The owner changes one of the mode's settings meanwhile.
	if _, err := r.DiagSetPrefs(map[string]string{"cover-traffic": "1024"}); err != nil {
		t.Fatal(err)
	}
	st, err = r.EdgeSetMode(panel.EdgeModeRequest{Mode: "off"})
	if err != nil {
		t.Fatalf("game off: %v", err)
	}
	if st.Mode != "" || len(st.Notes) != 1 || !strings.Contains(st.Notes[0], "cover-traffic") {
		t.Fatalf("status %+v", st)
	}
	if prefValue(t, r, "padding") != "buckets" || prefValue(t, r, "interactive-priority") != "false" || prefValue(t, r, "cover-traffic") != "1024" {
		t.Fatal("restore wrong")
	}
	if st, err := r.EdgeSetMode(panel.EdgeModeRequest{Mode: "off"}); err != nil || len(st.Notes) != 1 {
		t.Fatalf("off twice: %+v %v", st, err)
	}
	if _, err := r.EdgeSetMode(panel.EdgeModeRequest{Mode: "uçak"}); err == nil {
		t.Fatal("unknown mode accepted")
	}
}

func TestEdgeTravelModeWithoutExitWarns(t *testing.T) {
	r := edgeMember(t)
	st, err := r.EdgeSetMode(panel.EdgeModeRequest{Mode: "travel"})
	if err != nil {
		t.Fatalf("travel: %v", err)
	}
	if len(st.Notes) == 0 || !strings.Contains(st.Notes[0], "Çıkış düğümü") {
		t.Fatalf("notes %+v", st.Notes)
	}
	if prefValue(t, r, "shields") != "true" || prefValue(t, r, "hide-local-candidates") != "true" {
		t.Fatal("travel not applied")
	}
	// The lock shield does not turn off a shield the travel mode wants.
	if _, err := r.EdgeSetOptions(panel.EdgeOptionsChange{LockShield: ptr(true)}); err != nil {
		t.Fatal(err)
	}
	if st, err := r.EdgeSessionLock(true); err != nil || st.LockShield {
		t.Fatalf("lock while shielded: %+v %v", st, err)
	}
	if _, err := r.EdgeSetMode(panel.EdgeModeRequest{Mode: "off"}); err != nil {
		t.Fatal(err)
	}
	if prefValue(t, r, "shields") != "false" || prefValue(t, r, "hide-local-candidates") != "false" {
		t.Fatal("travel not restored")
	}
}

func ptr[T any](v T) *T { return &v }

func saveEdgeRaw(dir string, data []byte) error {
	return os.WriteFile(filepath.Join(dir, edgeFile), data, 0o600)
}

func TestEdgeLockShield(t *testing.T) {
	r := edgeMember(t)
	// Off by default: a lock changes nothing.
	if st, err := r.EdgeSessionLock(true); err != nil || st.LockShield {
		t.Fatalf("lock without option: %+v %v", st, err)
	}
	if _, err := r.EdgeSessionLock(false); err != nil {
		t.Fatal(err)
	}
	if _, err := r.EdgeSetOptions(panel.EdgeOptionsChange{LockShield: ptr(true)}); err != nil {
		t.Fatal(err)
	}
	st, err := r.EdgeSessionLock(true)
	if err != nil || !st.LockShield || prefValue(t, r, "shields") != "true" {
		t.Fatalf("lock: %+v %v", st, err)
	}
	st, err = r.EdgeSessionLock(false)
	if err != nil || st.LockShield || prefValue(t, r, "shields") != "false" {
		t.Fatalf("unlock: %+v %v", st, err)
	}
	// A shield the owner turned on stays on after unlock.
	if err := r.SetShields(true); err != nil {
		t.Fatal(err)
	}
	if st, _ := r.EdgeSessionLock(true); st.LockShield {
		t.Fatal("lock took over the owner's shield")
	}
	if _, err := r.EdgeSessionLock(false); err != nil || prefValue(t, r, "shields") != "true" {
		t.Fatal("owner's shield was turned off")
	}
}

func TestEdgeOptionsValidation(t *testing.T) {
	r, err := New(Config{DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.EdgeSetOptions(panel.EdgeOptionsChange{LANGuardTravel: ptr(true)}); err == nil {
		t.Fatal("travel reaction without exit accepted")
	}
	// No signed manifest here, so integrity cannot be required.
	if _, err := r.EdgeSetOptions(panel.EdgeOptionsChange{RequireIntegrity: ptr(true)}); err == nil {
		t.Fatal("integrity required without a manifest")
	}
	st, err := r.EdgeSetOptions(panel.EdgeOptionsChange{LANGuard: ptr(false), AutoMetered: ptr(true), TravelExit: ptr(" exit-1 ")})
	if err != nil || !st.Options.LANGuardOff || !st.Options.AutoMetered || st.Options.TravelExit != "exit-1" {
		t.Fatalf("options %+v %v", st, err)
	}
	again, err := r.EdgeStatus()
	if err != nil || again.Options != st.Options {
		t.Fatalf("not saved: %+v %v", again, err)
	}
}

func TestEdgeIntegrityGate(t *testing.T) {
	dir := t.TempDir()
	r, err := New(Config{DataDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.edgeIntegrityGate(); err != nil {
		t.Fatalf("gate without option: %v", err)
	}
	if err := saveEdge(dir, edgeFileState{Options: panel.EdgeOptions{RequireIntegrity: true}}); err != nil {
		t.Fatal(err)
	}
	if err := r.edgeIntegrityGate(); err == nil || !strings.Contains(err.Error(), "tünel açılmadı") {
		t.Fatalf("gate: %v", err)
	}
	// An unreadable file keeps the gate closed.
	if err := saveEdgeRaw(dir, []byte("{bozuk")); err != nil {
		t.Fatal(err)
	}
	if err := r.edgeIntegrityGate(); err == nil {
		t.Fatal("corrupt edge.json lifted the gate")
	}
}

func TestEdgeTickGatewayAlertAndAutoMetered(t *testing.T) {
	dir := t.TempDir()
	r, err := New(Config{DataDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	gw := netip.MustParseAddr("192.168.1.1")
	mac := "aa:aa:aa:aa:aa:01"
	metered := true
	e := r.edge()
	e.mu.Lock()
	e.gateways = func() ([]netip.Addr, error) { return []netip.Addr{gw}, nil }
	e.neighbors = func() []edgenet.Neighbor { return []edgenet.Neighbor{{Addr: gw, MAC: mac}} }
	e.network = func() string { return "wifi:Kafe" }
	e.hint = func() (bool, bool) { return metered, true }
	e.mu.Unlock()
	r.edgeTick()
	mac = "bb:bb:bb:bb:bb:02"
	r.edgeTick()
	st, err := r.EdgeStatus()
	if err != nil {
		t.Fatal(err)
	}
	if len(st.LANAlerts) != 1 || st.LANAlerts[0].Kind != edgenet.AlertGatewayMAC || st.Metered == nil || !*st.Metered {
		t.Fatalf("status %+v", st)
	}
	events := r.eventLog().List()
	found := false
	for _, ev := range events {
		found = found || ev.Kind == "lan-guard"
	}
	if !found {
		t.Fatalf("no lan-guard event in %+v", events)
	}
	// Auto metered without membership: the mode cannot start (the
	// preferences need a network) and nothing is saved.
	if _, err := r.EdgeSetOptions(panel.EdgeOptionsChange{AutoMetered: ptr(true)}); err != nil {
		t.Fatal(err)
	}
	r.edgeTick()
	if st, _ := r.EdgeStatus(); st.Mode != "" {
		t.Fatalf("mode started without a network: %+v", st)
	}
}

func TestEdgeAutoMeteredStartsAndEnds(t *testing.T) {
	r := edgeMember(t)
	metered := true
	var mu sync.Mutex
	e := r.edge()
	e.mu.Lock()
	e.gateways = func() ([]netip.Addr, error) { return nil, osnet.ErrNoGateway }
	e.hint = func() (bool, bool) { mu.Lock(); defer mu.Unlock(); return metered, true }
	e.mu.Unlock()
	if _, err := r.EdgeSetOptions(panel.EdgeOptionsChange{AutoMetered: ptr(true)}); err != nil {
		t.Fatal(err)
	}
	r.edgeTick()
	st, _ := r.EdgeStatus()
	if st.Mode != panel.EdgeModeMetered || st.ModeAuto != "metered" || prefValue(t, r, "psk-rotation") != "1h0m0s" {
		t.Fatalf("auto metered: %+v", st)
	}
	mu.Lock()
	metered = false
	mu.Unlock()
	r.edgeTick()
	if st, _ := r.EdgeStatus(); st.Mode != "" || prefValue(t, r, "psk-rotation") != "0" {
		t.Fatalf("auto metered not ended: %+v", st)
	}
}

func TestEdgeSurfaceDescribes(t *testing.T) {
	saved := ownSockets
	t.Cleanup(func() { ownSockets = saved })
	ownSockets = func() ([]surface.Socket, bool) {
		return []surface.Socket{
			{Proto: "tcp", Addr: netip.MustParseAddr("127.0.0.1"), Port: 41641},
			{Proto: "udp", Addr: netip.IPv4Unspecified(), Port: 51820},
			{Proto: "udp", Addr: netip.MustParseAddr("100.80.0.1"), Port: 53},
		}, true
	}
	r, err := New(Config{DataDir: t.TempDir(), PanelPort: 41641})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := r.EdgeSurface()
	if err != nil || len(rep.Entries) != 3 {
		t.Fatalf("surface %+v %v", rep, err)
	}
	if !strings.Contains(rep.Entries[0].Purpose, "panel") || rep.Entries[0].Reach != "yalnızca bu bilgisayar" {
		t.Fatalf("panel entry %+v", rep.Entries[0])
	}
	if !strings.Contains(rep.Entries[1].Purpose, "WireGuard") || rep.Entries[1].Reach != "bütün arayüzler" {
		t.Fatalf("udp entry %+v", rep.Entries[1])
	}
	if !strings.Contains(rep.Entries[2].Purpose, "DNS") {
		t.Fatalf("dns entry %+v", rep.Entries[2])
	}
	e := describeSocket("tcp", netip.MustParseAddr("100.80.0.1"), 22, 1, 0, 0, []netip.Addr{netip.MustParseAddr("100.80.0.1")})
	if !strings.Contains(e.Reach, "tünel") || !strings.Contains(e.Rule, "ağ belgesi") {
		t.Fatalf("tunnel entry %+v", e)
	}
	ownSockets = func() ([]surface.Socket, bool) { return nil, false }
	if _, err := r.EdgeSurface(); err == nil {
		t.Fatal("unreadable tables accepted")
	}
}
