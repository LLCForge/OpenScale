package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/rollout"
)

// TestUpdateRingsCommands: the owner sets the soak times, sees the
// coordinator's progress and resumes a halted release.
func TestUpdateRingsCommands(t *testing.T) {
	env, dir, out := g5Env(t)
	state := dir + "/coordinator"
	if code := Run([]string{"update", "rings", "set", "--state-dir", state, "--canary", "10m"}, env); code == exitOK {
		t.Fatal("a soak below the minimum was accepted")
	}
	out.Reset()
	if code := Run([]string{"update", "rings", "set", "--state-dir", state, "--canary", "2h", "--early", "12h"}, env); code != exitOK {
		t.Fatalf("set: %s", out)
	}
	if s, err := rollout.ReadSettings(state); err != nil || time.Duration(s.CanarySoak) != 2*time.Hour || time.Duration(s.EarlySoak) != 12*time.Hour {
		t.Fatalf("settings %+v %v", s, err)
	}
	// The coordinator saw a rollback on a canary device.
	tr := rollout.NewTracker(state, time.Now)
	members := []rollout.Member{{ID: "c1", Ring: rollout.RingCanary}, {ID: "m1", Ring: rollout.RingMain}}
	digest := strings.Repeat("ab", 32)
	tr.Observe(digest, "1.0.1", members, "c1", &rollout.Report{V: 1, Run: "1.0.0", OK: true, RolledBack: "1.0.1"})
	out.Reset()
	if code := Run([]string{"update", "rings", "status", "--state-dir", state}, env); code != exitOK {
		t.Fatalf("status: %s", out)
	}
	for _, want := range []string{"1.0.1", "DURDURULDU", "canary", "2 sa", "12 sa", "update rings resume"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("status lacks %q:\n%s", want, out)
		}
	}
	out.Reset()
	if code := Run([]string{"update", "rings", "resume", "--state-dir", state}, env); code != exitOK {
		t.Fatalf("resume: %s", out)
	}
	if s, err := rollout.ReadSettings(state); err != nil || s.ResumeDigest != digest || s.ResumedAt.IsZero() {
		t.Fatalf("resume settings %+v %v", s, err)
	}
	out.Reset()
	if code := Run([]string{"update", "rings", "status", "--state-dir", state, "--json"}, env); code != exitOK || !strings.Contains(out.String(), `"halted": true`) {
		t.Fatalf("json: %s", out)
	}
}
