package memprofile

import (
	"math"
	"runtime/debug"
	"testing"

	"github.com/openscale/openscale/internal/filter"
)

func TestLookup(t *testing.T) {
	for _, n := range []string{"", "default", " DEFAULT "} {
		if p, err := Lookup(n); err != nil || p.Name != NameDefault {
			t.Fatalf("%q: %+v %v", n, p, err)
		}
	}
	low, err := Lookup("low")
	if err != nil || low.MemoryLimit <= 0 || low.MemoryLimit >= LowBudget {
		t.Fatalf("low: %+v %v", low, err)
	}
	// The low conntrack limits must pass the filter's own validation.
	if _, err := low.ConnTrack.WithDefaults(); err != nil {
		t.Fatalf("low conntrack invalid: %v", err)
	}
	if _, err := Lookup("tiny"); err == nil {
		t.Fatal("unknown profile accepted")
	}
}

func TestApplyRespectsEnvironmentAndFills(t *testing.T) {
	oldLimit := debug.SetMemoryLimit(-1)
	oldGC := debug.SetGCPercent(-1)
	debug.SetGCPercent(oldGC)
	t.Cleanup(func() {
		debug.SetMemoryLimit(oldLimit)
		debug.SetGCPercent(oldGC)
		Apply(Profile{Name: NameDefault}, func(string) string { return "" })
	})
	env := map[string]string{EnvProfile: "low", "GOGC": "200"}
	a, err := ApplyFromEnv(func(k string) string { return env[k] })
	if err != nil || !a.MemoryLimitSet || a.GCSet {
		t.Fatalf("applied %+v %v", a, err)
	}
	if got := debug.SetMemoryLimit(-1); got != 24<<20 {
		t.Fatalf("memory limit %d", got)
	}
	l := FillConnTrack(filter.Limits{MaxFlows: 2048})
	if l.MaxFlows != 2048 || l.MaxFragments != 256 || l.UDPTimeout == 0 {
		t.Fatalf("fill %+v", l)
	}
	if _, err := ApplyFromEnv(func(k string) string { return map[string]string{EnvProfile: "x"}[k] }); err == nil {
		t.Fatal("bad name accepted")
	}
	Apply(Profile{Name: NameDefault}, func(string) string { return "" })
	if l := FillConnTrack(filter.Limits{}); l != (filter.Limits{}) {
		t.Fatalf("default profile filled %+v", l)
	}
	debug.SetMemoryLimit(math.MaxInt64)
}
