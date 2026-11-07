package panel

import (
	"testing"
	"time"

	"github.com/openscale/openscale/internal/sysinfo"
)

func TestOlderRelease(t *testing.T) {
	for _, c := range []struct {
		device, ref string
		want        bool
	}{
		{"0.8.0", "0.9.0", true},
		{"0.9.0", "0.9.0", false},
		{"0.10.0", "0.9.5", false},
		{"v0.9.1", "0.9.2", true},
		{"0.9.2-rc1", "0.9.2", false},
		{"1.0.0", "0.9.9", false},
		{"0.0.0-dev", "0.9.0", false},
		{"0.8.0", "0.0.0-dev", false},
		{"bozuk", "0.9.0", false},
	} {
		if got := olderRelease(c.device, c.ref); got != c.want {
			t.Errorf("olderRelease(%q, %q) = %t", c.device, c.ref, got)
		}
	}
}

func TestSystemViewMarksOutdated(t *testing.T) {
	old := referenceVersion
	referenceVersion = func() string { return "0.9.0" }
	defer func() { referenceVersion = old }()
	now := time.Now()
	v := system(&Report{Info: sysinfo.Info{OS: "linux", Version: "0.8.3"}, At: now}, now)
	if v == nil || !v.Outdated || v.Latest != "0.9.0" {
		t.Fatalf("view = %+v", v)
	}
	v = system(&Report{Info: sysinfo.Info{OS: "linux", Version: "0.9.0"}, At: now}, now)
	if v.Outdated || v.Latest != "" {
		t.Fatalf("current version marked: %+v", v)
	}
}
