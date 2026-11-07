package service

import (
	"context"
	"crypto/rand"
	"errors"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/osnet"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/internal/wintunembed"
)

// withPlatformProbes replaces the system queries for one test.
func withPlatformProbes(t *testing.T, p platformProbes) {
	t.Helper()
	platformState.mu.Lock()
	old := platformState.probes
	platformState.probes = &p
	platformState.mu.Unlock()
	oldWait, oldPoll := platformTunnelWait, platformTunnelPoll
	platformTunnelWait, platformTunnelPoll = 50*time.Millisecond, 10*time.Millisecond
	t.Cleanup(func() {
		platformState.mu.Lock()
		platformState.probes = old
		platformState.mu.Unlock()
		platformTunnelWait, platformTunnelPoll = oldWait, oldPoll
	})
}

func platformRuntime(t *testing.T, dir string) *Runtime {
	t.Helper()
	r, err := New(Config{DataDir: dir, Random: rand.Reader, Argon2: trust.Argon2Params{Time: 1, MemoryKiB: 64 * 1024, Threads: 1}})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRepairAfterMajorOSUpdate(t *testing.T) {
	build := osnet.OSBuild{Family: "windows", Version: "10.0", Build: "22631", Patch: "4000"}
	ensured := 0
	withPlatformProbes(t, platformProbes{
		build:               func() osnet.OSBuild { return build },
		killSwitchInstalled: func() (bool, error) { return false, nil },
		firewallPresent:     func() (bool, error) { return false, nil },
		firewallEnsure:      func(netip.Prefix) error { ensured++; return nil },
		wintunVersion:       func() (string, error) { return "", wintunembed.ErrDriverNotLoaded },
		wfpRisks:            func() (int, error) { return 2, nil },
		tunDevice:           func() error { return errors.New("yok") },
		serverCore:          func() bool { return true },
		wsl:                 func() osnet.WSLInfo { return osnet.WSLInfo{Installed: true, Notes: []string{"not"}} },
	})
	dir := filepath.Join(t.TempDir(), "veri")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// First start: the build is remembered, nothing is repaired.
	r := platformRuntime(t, dir)
	r.platformStartup(ctx)
	st, err := r.PlatformStatus()
	if err != nil || st.OSUpdate != nil || st.LastRepair != nil || st.OS.Build != "22631" || !st.OS.ServerCore || st.WSL == nil {
		t.Fatalf("first start: %+v %v", st, err)
	}

	// A monthly update (patch only) is not a feature update.
	build.Patch = "4100"
	r = platformRuntime(t, dir)
	r.platformStartup(ctx)
	if st, _ := r.PlatformStatus(); st.OSUpdate != nil {
		t.Fatalf("monthly update reported: %+v", st.OSUpdate)
	}

	// A feature update: recorded at once, repaired after the start.
	build.Build, build.Patch = "26100", "1"
	r = platformRuntime(t, dir)
	r.platformStartup(ctx)
	if st, _ := r.PlatformStatus(); st.OSUpdate == nil || !strings.Contains(st.OSUpdate.To, "26100") {
		t.Fatalf("update not recorded: %+v", st.OSUpdate)
	}
	close(r.ready)
	var rep *panel.PlatformRepair
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if st, _ := r.PlatformStatus(); st.LastRepair != nil {
			rep = st.LastRepair
			if st.OSUpdate != nil {
				t.Fatal("handled update still shown")
			}
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if rep == nil {
		t.Fatal("repair did not run")
	}
	if rep.Reason != "os-update" || !strings.Contains(rep.From, "22631") || !strings.Contains(rep.To, "26100") {
		t.Fatalf("repair %+v", rep)
	}
	levels := map[string]string{}
	for _, c := range rep.Checks {
		levels[c.Area] = c.Level
	}
	// Not joined: the firewall rules wait for the tunnel; no ensure call.
	want := map[string]string{"güvenlik duvarı": panel.PlatformWarn, "Wintun": panel.PlatformOK, "WFP": panel.PlatformWarn, "TUN": panel.PlatformError}
	for area, level := range want {
		if levels[area] != level {
			t.Errorf("%s: %q, want %q (%+v)", area, levels[area], level, rep.Checks)
		}
	}
	if ensured != 0 {
		t.Fatal("firewall rules created without a network")
	}
	if _, ok := levels["kill switch"]; ok {
		t.Fatal("kill switch checked without kill switch hooks")
	}
	// A manual repair is recorded as such.
	st, err = r.PlatformRepair(ctx)
	if err != nil || st.LastRepair == nil || st.LastRepair.Reason != "manual" {
		t.Fatalf("manual: %+v %v", st.LastRepair, err)
	}
}

func TestPlatformStatusMemory(t *testing.T) {
	withPlatformProbes(t, platformProbes{
		build:      func() osnet.OSBuild { return osnet.OSBuild{Family: "linux", Version: "debian 12", Build: "6.1.0"} },
		serverCore: func() bool { return false },
		wsl:        func() osnet.WSLInfo { return osnet.WSLInfo{} },
	})
	r := platformRuntime(t, filepath.Join(t.TempDir(), "veri"))
	st, err := r.PlatformStatus()
	if err != nil || st.Memory.Profile == "" || st.Memory.Live == 0 || st.WSL != nil {
		t.Fatalf("%+v %v", st, err)
	}
}
