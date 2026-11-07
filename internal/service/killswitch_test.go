package service

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/openscale/openscale/internal/osnet"
	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/internal/winapp"
)

// fakeKillSwitch records what the service asks of the operating system.
type fakeKillSwitch struct {
	mu         sync.Mutex
	log        []string
	installed  bool
	cfg        osnet.KillSwitchConfig
	failAdd    error
	failRemove error
}

func (f *fakeKillSwitch) install(c osnet.KillSwitchConfig) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.log = append(f.log, "install:"+c.Interface)
	if f.failAdd != nil {
		return f.failAdd
	}
	f.installed, f.cfg = true, c
	return nil
}

func (f *fakeKillSwitch) remove() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.log = append(f.log, "remove")
	if f.failRemove != nil {
		return f.failRemove
	}
	f.installed = false
	return nil
}

func (f *fakeKillSwitch) state() (bool, osnet.KillSwitchConfig, []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.installed, f.cfg, append([]string(nil), f.log...)
}

// fakeRouter shares the log so the order of filters and routes shows.
type fakeRouter struct {
	ks      *fakeKillSwitch
	failErr error
}

func (r *fakeRouter) Enable(trust.Device, *trust.Document, string, conn.Bind) error {
	r.ks.mu.Lock()
	defer r.ks.mu.Unlock()
	r.ks.log = append(r.ks.log, "routes")
	return r.failErr
}

func (r *fakeRouter) Disable() error {
	r.ks.mu.Lock()
	defer r.ks.mu.Unlock()
	r.ks.log = append(r.ks.log, "unroute")
	return nil
}

func ksRuntime(t *testing.T, st settings) (*Runtime, *fakeKillSwitch, *fakeRouter) {
	t.Helper()
	ks := &fakeKillSwitch{}
	router := &fakeRouter{ks: ks}
	dir := t.TempDir()
	r, err := New(Config{DataDir: dir, Hooks: Hooks{
		ExitRouter:        router,
		InstallKillSwitch: ks.install,
		RemoveKillSwitch:  ks.remove,
	}})
	if err != nil {
		t.Fatal(err)
	}
	r.ctx = context.Background()
	if err := saveSettings(dir, st); err != nil {
		t.Fatal(err)
	}
	return r, ks, router
}

func TestKillSwitchSettingDefaultsOn(t *testing.T) {
	dir := t.TempDir()
	// A settings file written before the field existed.
	if err := os.WriteFile(filepath.Join(dir, settingsFile), []byte(`{"coordinator_port":41820,"exit_node":"vps"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := loadSettings(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !st.killSwitchOn() || st.ExitAllowLAN {
		t.Fatalf("old settings: kill switch %v, LAN %v; want on, off", st.killSwitchOn(), st.ExitAllowLAN)
	}
	if !(settings{}).killSwitchOn() {
		t.Fatal("missing settings must mean kill switch on")
	}
	off := false
	st.KillSwitch = &off
	if err := saveSettings(dir, st); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, settingsFile))
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if raw["kill_switch"] != false {
		t.Fatalf("explicit off must be stored: %s", data)
	}
	if st, _ := loadSettings(dir); st.killSwitchOn() {
		t.Fatal("explicit off read back as on")
	}
}

func TestExitGuardInstallsBeforeRoutes(t *testing.T) {
	r, ks, _ := ksRuntime(t, settings{ExitNode: "vps", ExitAllowLAN: true})
	if err := r.exitRouter.Enable(trust.Device{}, nil, "OpenScale", nil); err != nil {
		t.Fatal(err)
	}
	installed, cfg, log := ks.state()
	if !installed || cfg.Interface != "OpenScale" || !cfg.AllowLAN {
		t.Fatalf("installed %v cfg %+v", installed, cfg)
	}
	if len(log) != 2 || log[0] != "install:OpenScale" || log[1] != "routes" {
		t.Fatalf("filters must come before routes: %v", log)
	}
	if st := r.killSwitchSnapshot(); !st.installed || st.err != "" {
		t.Fatalf("state %+v", st)
	}
	if err := r.exitRouter.Disable(); err != nil {
		t.Fatal(err)
	}
	installed, _, log = ks.state()
	if installed || log[len(log)-2] != "unroute" || log[len(log)-1] != "remove" {
		t.Fatalf("routes then filters must go: %v", log)
	}
}

func TestExitGuardFailsClosedWithoutFilters(t *testing.T) {
	r, ks, _ := ksRuntime(t, settings{ExitNode: "vps"})
	ks.failAdd = errors.New("BFE kapalı")
	err := r.exitRouter.Enable(trust.Device{}, nil, "OpenScale", nil)
	if err == nil {
		t.Fatal("exit node enabled without the kill switch")
	}
	if _, _, log := ks.state(); len(log) != 1 || log[0] != "install:OpenScale" {
		t.Fatalf("routes must not be set after a failed install: %v", log)
	}
	if st := r.killSwitchSnapshot(); st.installed || st.err == "" {
		t.Fatalf("the failure must be shown: %+v", st)
	}
}

func TestExitGuardWithoutKillSwitch(t *testing.T) {
	off := false
	r, ks, _ := ksRuntime(t, settings{ExitNode: "vps", KillSwitch: &off})
	if err := r.exitRouter.Enable(trust.Device{}, nil, "OpenScale", nil); err != nil {
		t.Fatal(err)
	}
	installed, _, log := ks.state()
	if installed || len(log) != 2 || log[0] != "remove" || log[1] != "routes" {
		t.Fatalf("kill switch off must only clean up: %v", log)
	}
}

// Any stop of the service (restart, update, shutdown) keeps the filters,
// so the computer stays protected until the service runs again; only the
// owner's full exit releases them (ADR-0023).
func TestKillSwitchKeptOnEveryStop(t *testing.T) {
	for _, cause := range []error{nil, winapp.ErrSystemShutdown} {
		r, ks, _ := ksRuntime(t, settings{ExitNode: "vps"})
		if err := r.exitRouter.Enable(trust.Device{}, nil, "OpenScale", nil); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancelCause(context.Background())
		r.ctx = ctx
		cancel(cause)
		if err := r.exitRouter.Disable(); err != nil {
			t.Fatal(err)
		}
		r.releaseKillSwitchOnStop()
		if installed, _, _ := ks.state(); !installed {
			t.Fatalf("stop (cause %v) removed the kill switch", cause)
		}
	}
}

func TestFullExitReleasesKillSwitch(t *testing.T) {
	r, ks, _ := ksRuntime(t, settings{ExitNode: "vps"})
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	r.cfg.Now = func() time.Time { return now }
	if err := r.exitRouter.Enable(trust.Device{}, nil, "OpenScale", nil); err != nil {
		t.Fatal(err)
	}
	r.ReleaseKillSwitchOnStop()
	if installed, _, _ := ks.state(); !installed {
		t.Fatal("the request alone must not remove the filters before the stop")
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	r.ctx = ctx
	cancel(nil)
	if err := r.exitRouter.Disable(); err != nil {
		t.Fatal(err)
	}
	if installed, _, log := ks.state(); installed || log[len(log)-1] != "remove" {
		t.Fatalf("a full exit must remove the filters with the routes: %v", log)
	}

	// Also when no exit node was active to take them down.
	r2, ks2, _ := ksRuntime(t, settings{ExitNode: "vps"})
	r2.cfg.Now = func() time.Time { return now }
	ks2.installed = true
	r2.ReleaseKillSwitchOnStop()
	ctx2, cancel2 := context.WithCancelCause(context.Background())
	r2.ctx = ctx2
	cancel2(nil)
	r2.releaseKillSwitchOnStop()
	if installed, _, _ := ks2.state(); installed {
		t.Fatal("the stop after a full exit must remove the filters")
	}

	// A request that is not followed by a stop expires.
	r3, ks3, _ := ksRuntime(t, settings{ExitNode: "vps"})
	r3.cfg.Now = func() time.Time { return now }
	ks3.installed = true
	r3.ReleaseKillSwitchOnStop()
	now = now.Add(releaseWindow + time.Second)
	ctx3, cancel3 := context.WithCancelCause(context.Background())
	r3.ctx = ctx3
	cancel3(nil)
	r3.releaseKillSwitchOnStop()
	if installed, _, _ := ks3.state(); !installed {
		t.Fatal("an expired release request removed the filters")
	}
}

func TestStoppingServiceNeverInstalls(t *testing.T) {
	r, ks, _ := ksRuntime(t, settings{ExitNode: "vps"})
	ctx, cancel := context.WithCancelCause(context.Background())
	r.ctx = ctx
	cancel(nil)
	if err := r.exitRouter.Enable(trust.Device{}, nil, "OpenScale", nil); !errors.Is(err, errServiceStopping) {
		t.Fatalf("enable while stopping: %v", err)
	}
	installed, _, log := ks.state()
	if installed || len(log) != 0 {
		t.Fatalf("a stopping service must neither install nor route: %v", log)
	}
}

// The explicit owner actions still remove the filters at once.
func TestOwnerActionsRemoveKillSwitch(t *testing.T) {
	r, ks, _ := ksRuntime(t, settings{ExitNode: "vps"})
	ks.installed = true
	if err := r.applyExitOptions(false, false); err != nil {
		t.Fatal(err)
	}
	if installed, _, _ := ks.state(); installed {
		t.Fatal("turning the kill switch off must remove it")
	}
	r2, ks2, _ := ksRuntime(t, settings{ExitNode: "vps"})
	ks2.installed = true
	if err := r2.ResetDevice(); err != nil {
		t.Fatal(err)
	}
	if installed, _, _ := ks2.state(); installed {
		t.Fatal("a reset must remove the kill switch")
	}
}

func TestSyncKillSwitchFollowsSettings(t *testing.T) {
	off := false
	cases := []struct {
		name string
		st   settings
		want bool
	}{
		{"exit chosen", settings{ExitNode: "vps"}, true},
		{"no exit", settings{}, false},
		{"tunnel off", settings{ExitNode: "vps", Disconnected: true}, false},
		{"switch off", settings{ExitNode: "vps", KillSwitch: &off}, false},
	}
	for _, tc := range cases {
		r, ks, _ := ksRuntime(t, tc.st)
		ks.installed = true // left over from a crash
		if err := r.syncKillSwitch(""); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		installed, cfg, _ := ks.state()
		if installed != tc.want {
			t.Fatalf("%s: installed %v, want %v", tc.name, installed, tc.want)
		}
		if tc.want && cfg.Interface != "" {
			t.Fatalf("%s: before the tunnel there is no interface permit", tc.name)
		}
	}
}

func TestExitOptionsApplyOnlyWhenUsed(t *testing.T) {
	r, ks, _ := ksRuntime(t, settings{ExitNode: "vps"})
	r.setTunnelInterface("OpenScale")
	if err := r.applyExitOptions(true, true); err != nil {
		t.Fatal(err)
	}
	installed, cfg, _ := ks.state()
	if !installed || !cfg.AllowLAN || cfg.Interface != "OpenScale" {
		t.Fatalf("LAN option not applied: %v %+v", installed, cfg)
	}
	if st, _ := loadSettings(r.cfg.DataDir); !st.killSwitchOn() || !st.ExitAllowLAN {
		t.Fatalf("options not saved: %+v", st)
	}
	if err := r.applyExitOptions(false, true); err != nil {
		t.Fatal(err)
	}
	if installed, _, _ := ks.state(); installed {
		t.Fatal("turning the kill switch off must remove it")
	}
	if st, _ := loadSettings(r.cfg.DataDir); st.killSwitchOn() || !st.ExitAllowLAN {
		t.Fatalf("options not saved: %+v", st)
	}

	// A failed install keeps the old setting.
	ks.failAdd = errors.New("erişim engellendi")
	if err := r.applyExitOptions(true, false); err == nil {
		t.Fatal("failed install accepted")
	}
	if st, _ := loadSettings(r.cfg.DataDir); st.killSwitchOn() {
		t.Fatal("setting changed although the kill switch could not be installed")
	}

	// Without an exit node nothing is installed, only saved.
	r2, ks2, _ := ksRuntime(t, settings{})
	if err := r2.applyExitOptions(true, false); err != nil {
		t.Fatal(err)
	}
	if _, _, log := ks2.state(); len(log) != 0 {
		t.Fatalf("no exit node: nothing to apply, got %v", log)
	}
}

func TestSaveExitChoiceInstallsFirst(t *testing.T) {
	r, ks, _ := ksRuntime(t, settings{})
	ks.failAdd = errors.New("BFE kapalı")
	if err := r.saveExitChoice("vps"); err == nil {
		t.Fatal("exit node saved without the kill switch")
	}
	if st, _ := loadSettings(r.cfg.DataDir); st.ExitNode != "" {
		t.Fatal("choice saved although the kill switch failed")
	}
	ks.failAdd = nil
	if err := r.saveExitChoice("vps"); err != nil {
		t.Fatal(err)
	}
	if installed, _, _ := ks.state(); !installed {
		t.Fatal("kill switch not installed for the new exit node")
	}
	if st, _ := loadSettings(r.cfg.DataDir); st.ExitNode != "vps" {
		t.Fatal("choice not saved")
	}
}

func TestNoKillSwitchHooks(t *testing.T) {
	dir := t.TempDir()
	r, err := New(Config{DataDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if r.exitRouter != nil {
		t.Fatal("no exit router hook must leave exit nodes unavailable")
	}
	if err := r.syncKillSwitch("x"); err != nil || r.removeKillSwitch() != nil {
		t.Fatal("missing hooks must be a no-op")
	}
	if err := r.applyExitOptions(true, false); err == nil {
		t.Fatal("turning on a kill switch that does not exist must fail")
	}
	if err := r.applyExitOptions(false, true); err != nil {
		t.Fatalf("turning it off must still be saved: %v", err)
	}
}
