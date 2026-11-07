package autoupdate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/control"
	"github.com/openscale/openscale/internal/coordinator"
	"github.com/openscale/openscale/internal/release"
	"github.com/openscale/openscale/internal/rollout"
	"github.com/openscale/openscale/internal/trust"
)

// ringClock is the shared fake time of the coordinator and the devices.
type ringClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *ringClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *ringClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// ringCoordinator serves the mirror with update rings, per device.
type ringCoordinator struct {
	handle func(string, control.Message) control.Message
	reload func()
	// tamper rewrites the reply (a lying coordinator); nil passes it on.
	tamper func(control.Message) control.Message
}

type ringFetcher struct {
	c  *ringCoordinator
	id string
}

func (f ringFetcher) ReleaseCall(_ context.Context, req control.Message) (control.Message, error) {
	data, err := control.Encode(req)
	if err != nil {
		return control.Message{}, err
	}
	if req, err = control.Decode(data); err != nil {
		return control.Message{}, err
	}
	resp := f.c.handle(f.id, req)
	if f.c.tamper != nil && resp.T == control.TypeRelease {
		resp = f.c.tamper(resp)
	}
	resp.ID = req.ID
	out, err := control.Encode(resp)
	if err != nil {
		return control.Message{}, err
	}
	if resp, err = control.Decode(out); err != nil {
		return control.Message{}, err
	}
	if resp.T == control.TypeError {
		return resp, errors.New("coordinator: " + resp.Error)
	}
	return resp, nil
}

type ringWorld struct {
	*world
	clock *ringClock
	doc   *trust.Document
	rc    *ringCoordinator
	base  string
}

func newRingWorld(t *testing.T) *ringWorld {
	w := newWorld(t, "1.0.0")
	rw := &ringWorld{world: w, clock: &ringClock{t: time.Now().UTC()}, base: t.TempDir()}
	rw.doc = &trust.Document{Devices: []trust.Device{
		{ID: "c1", Name: "kanarya", Tags: []string{rollout.TagCanary}},
		{ID: "e1", Name: "erken", Tags: []string{rollout.TagEarly, "ofis"}},
		{ID: "m1", Name: "ana"},
	}}
	h, reload := coordinator.ReleaseRingsHandler(w.mirror, func() *trust.Document { return rw.doc }, rw.clock.now, nil)
	rw.rc = &ringCoordinator{handle: h, reload: reload}
	w.coord.reload = reload
	return rw
}

// device returns the runner of device id running installed, with its own
// work folder.
func (rw *ringWorld) device(id, installed string) *Runner {
	upd := filepath.Join(rw.base, id)
	p := rw.paths
	p.UpdaterState, p.Settings, p.Work = upd, filepath.Join(upd, SettingsFile), filepath.Join(upd, "auto")
	return New(Config{
		Paths: p, Fetcher: ringFetcher{c: rw.rc, id: id}, Installed: installed, GOOS: "windows", GOARCH: "amd64",
		LoadRoot: func() (release.PublicKey, error) { return rw.keys.root, nil },
		Trigger:  func(context.Context) error { return nil },
		Jitter:   func(time.Duration) time.Duration { return 0 },
		Rate:     -1,
		Now:      rw.clock.now,
		Rings:    func() RingInfo { return RingInfoOf(rw.doc, id) },
	})
}

func (rw *ringWorld) check(id, installed, want string) Status {
	rw.t.Helper()
	st, _ := rw.device(id, installed).Check(context.Background())
	if st.State != want {
		rw.t.Fatalf("%s (%s): state %s, want %s: %s", id, installed, st.State, want, st.Message)
	}
	return st
}

// TestRingsOpenOneAfterAnother: canary first, early after the canary
// soak, main after the early soak; the device's ring comes from its tags.
func TestRingsOpenOneAfterAnother(t *testing.T) {
	rw := newRingWorld(t)
	rw.publish("1.0.1")
	st := rw.check("c1", "1.0.0", StateInstalling)
	if st.Ring != rollout.RingCanary || st.Rollout == nil || !st.Rollout.Announced || st.Rollout.Open != rollout.RingCanary {
		t.Fatalf("canary status %+v %+v", st, st.Rollout)
	}
	st = rw.check("e1", "1.0.0", StateRingWait)
	if st.Ring != rollout.RingEarly || st.Rollout.Rings[0].Members != 1 {
		t.Fatalf("early status %+v %+v", st, st.Rollout)
	}
	rw.check("m1", "1.0.0", StateRingWait)
	// The canary device runs the new version and reports in; it sees the
	// progress too.
	if st := rw.check("c1", "1.0.1", StateUpToDate); st.Rollout == nil || st.Rollout.Rings[0].Updated != 1 {
		t.Fatalf("up-to-date canary without progress: %+v", st.Rollout)
	}
	rw.clock.add(5 * time.Hour)
	rw.check("c1", "1.0.1", StateUpToDate)
	rw.check("e1", "1.0.0", StateRingWait)
	rw.clock.add(time.Hour)
	rw.check("c1", "1.0.1", StateUpToDate)
	rw.check("e1", "1.0.0", StateInstalling)
	rw.check("m1", "1.0.0", StateRingWait)
	rw.check("e1", "1.0.1", StateUpToDate)
	rw.clock.add(24 * time.Hour)
	rw.check("e1", "1.0.1", StateUpToDate)
	st = rw.check("m1", "1.0.0", StateInstalling)
	if st.Rollout.Open != rollout.RingMain || st.Rollout.MainAt.IsZero() {
		t.Fatalf("main status %+v", st.Rollout)
	}
	// Canary and early devices check every hour.
	if r := rw.device("c1", "1.0.1"); r.ringInfo().Ring != rollout.RingCanary {
		t.Fatal("ring")
	}
	if st := rw.check("c1", "1.0.1", StateUpToDate); st.NextCheck.Sub(st.LastCheck) > time.Hour {
		t.Fatalf("canary next check in %s", st.NextCheck.Sub(st.LastCheck))
	}
}

// TestCanaryRollbackHalts: the installer's rollback on a canary device is
// reported and stops the release everywhere; the panel sees "halted".
func TestCanaryRollbackHalts(t *testing.T) {
	rw := newRingWorld(t)
	rw.publish("1.0.1")
	rw.check("c1", "1.0.0", StateInstalling)
	// The installer rolled back: it leaves its result for the device.
	work := filepath.Join(rw.base, "c1", "auto")
	if err := writeJSON(filepath.Join(work, ResultFile), Result{Format: resultFormat, Version: "1.0.1", Digest: annDigest(t, rw), RolledBack: true, Message: "sağlıksız", At: rw.clock.now()}); err != nil {
		t.Fatal(err)
	}
	st := rw.check("c1", "1.0.0", StateRejected) // its own rejection of the release
	if st.LastAttempt == nil || !st.LastAttempt.RolledBack {
		t.Fatalf("attempt %+v", st.LastAttempt)
	}
	rw.clock.add(48 * time.Hour)
	st = rw.check("e1", "1.0.0", StateHalted)
	if !st.Rollout.Halted || st.Rollout.HaltRing != rollout.RingCanary || !strings.Contains(st.Message, "resume") {
		t.Fatalf("halted status %+v %+v", st, st.Rollout)
	}
	rw.check("m1", "1.0.0", StateHalted)
	if saved, err := ReadStatus(filepath.Join(rw.base, "m1", "auto")); err != nil || saved.State != StateHalted || saved.Rollout == nil || !saved.Rollout.Halted {
		t.Fatalf("saved %+v %v", saved, err)
	}
	// The owner resumes after looking into it.
	if err := rollout.WriteSettings(rw.coordDir, rollout.Settings{CanarySoak: rollout.Duration(rollout.DefaultCanarySoak), EarlySoak: rollout.Duration(rollout.DefaultEarlySoak), ResumeDigest: annDigest(t, rw), ResumedAt: rw.clock.now()}); err != nil {
		t.Fatal(err)
	}
	rw.clock.add(2 * time.Minute)
	rw.check("e1", "1.0.0", StateRingWait)
}

func annDigest(t *testing.T, rw *ringWorld) string {
	t.Helper()
	resp := rw.rc.handle("", control.Message{T: control.TypeRelease})
	if len(resp.Digest) != 64 {
		t.Fatalf("no announcement %+v", resp)
	}
	return resp.Digest
}

// TestLyingCoordinatorOnlyInstallsEarly: a coordinator announcing every
// ring open with tiny soaks gets main devices to install after the
// device's own floor (MinSoak per earlier ring), not at once. The release
// signature is verified as always.
func TestLyingCoordinatorOnlyInstallsEarly(t *testing.T) {
	rw := newRingWorld(t)
	rw.publish("1.0.1")
	lie, err := rollout.Announcement{Open: rollout.RingMain, CanarySoak: time.Second, EarlySoak: time.Second, Since: rw.clock.now()}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	rw.rc.tamper = func(m control.Message) control.Message { m.Data = lie; return m }
	rw.check("m1", "1.0.0", StateRingWait)
	rw.clock.add(time.Hour + 59*time.Minute)
	rw.check("m1", "1.0.0", StateRingWait)
	rw.clock.add(time.Minute)
	rw.check("m1", "1.0.0", StateInstalling)
	// A forged halt only delays.
	rw2 := newRingWorld(t)
	rw2.publish("1.0.1")
	halt, _ := rollout.Announcement{Open: rollout.RingMain, Halted: true, HaltRing: rollout.RingCanary, CanarySoak: time.Hour, EarlySoak: time.Hour}.Encode()
	rw2.rc.tamper = func(m control.Message) control.Message { m.Data = halt; return m }
	rw2.check("c1", "1.0.0", StateHalted)
	// Garbage progress counts as none: the defaults since first sight.
	rw2.rc.tamper = func(m control.Message) control.Message { m.Data = []byte("{bozuk"); return m }
	rw2.check("c1", "1.0.0", StateInstalling)
	rw2.check("m1", "1.0.0", StateRingWait)
}

// TestOldCoordinatorKeepsWorking: without progress in the reply (an older
// coordinator) the devices fall back to their floor; a network without
// ring tags installs at once as before.
func TestOldCoordinatorKeepsWorking(t *testing.T) {
	rw := newRingWorld(t)
	rw.publish("1.0.1")
	rw.rc.tamper = func(m control.Message) control.Message { m.Data = nil; return m }
	rw.check("c1", "1.0.0", StateInstalling)
	rw.check("e1", "1.0.0", StateRingWait)
	rw.clock.add(rollout.DefaultCanarySoak)
	rw.check("e1", "1.0.0", StateInstalling)
	rw.doc = &trust.Document{Devices: []trust.Device{{ID: "m1"}}}
	rw.check("m1", "1.0.0", StateInstalling)
	// The first sight is remembered across restarts of the service.
	seen := filepath.Join(rw.base, "e1", "auto", SeenFile)
	if _, err := os.Stat(seen); err != nil {
		t.Fatal(err)
	}
}
