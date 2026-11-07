package service

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/updater"
	"github.com/openscale/openscale/internal/version"
)

func p14Finding(fs []Finding, level, area, text string) bool {
	for _, f := range fs {
		if f.Level == level && f.Area == area && strings.Contains(f.Message, text) {
			return true
		}
	}
	return false
}

func TestSelfCheckFindings(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "OpenScale")
	if err := os.MkdirAll(filepath.Join(dir, UpdateDir), 0o700); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	fs := SelfCheck(dir, now, "", true, DefaultPanelPort)
	if !p14Finding(fs, FindingOK, "disk", "boş alan") && !p14Finding(fs, FindingWarn, "disk", "boş") {
		t.Fatalf("no disk finding: %+v", fs)
	}
	if runtime.GOOS != "windows" && !p14Finding(fs, FindingOK, "veri klasörü", "yalnızca") {
		t.Fatalf("no permission finding: %+v", fs)
	}
	// An interrupted update is reported.
	j := []byte(`{"format":"openscale-update-journal-v1","state":"swapped","exe":"x","from":"0.8.0","to":"0.9.0","started":"2026-10-30T10:00:00Z"}`)
	if err := os.WriteFile(filepath.Join(dir, UpdateDir, updater.JournalFile), j, 0o600); err != nil {
		t.Fatal(err)
	}
	fs = SelfCheck(dir, now, "", true, DefaultPanelPort)
	if !p14Finding(fs, FindingWarn, "güncelleme", "yarım kalmış") {
		t.Fatalf("pending update not reported: %+v", fs)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if fs := SelfCheck(dir, now, "", true, DefaultPanelPort); !p14Finding(fs, FindingError, "veri klasörü", "başka kullanıcılara açık") {
			t.Fatalf("open data directory not reported: %+v", fs)
		}
	}
}

func TestSelfCheckBuildClock(t *testing.T) {
	old := version.Build
	defer func() { version.Build = old }()
	version.Build = "20261030.0412"
	c := &checker{now: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)}
	c.checkBuildClock()
	if len(c.out) != 1 || c.out[0].Level != FindingWarn {
		t.Fatalf("clock behind the build not reported: %+v", c.out)
	}
	c = &checker{now: time.Date(2026, 10, 31, 0, 0, 0, 0, time.UTC)}
	c.checkBuildClock()
	if len(c.out) != 0 {
		t.Fatalf("correct clock reported: %+v", c.out)
	}
}

func TestSelfCheckReportRoundTrip(t *testing.T) {
	dir := t.TempDir()
	r := SelfCheckReport{At: time.Now().UTC().Truncate(time.Second), Version: "0.9.0", Findings: []Finding{{Level: FindingWarn, Area: "disk", Message: "az yer"}}}
	if err := saveSelfCheck(dir, r); err != nil {
		t.Fatal(err)
	}
	got, err := LastSelfCheck(dir)
	if err != nil || got.Version != "0.9.0" || len(got.Findings) != 1 {
		t.Fatalf("%+v %v", got, err)
	}
}
