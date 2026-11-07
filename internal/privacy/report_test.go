package privacy

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/trust"
)

func hasFinding(fs []Finding, code string) bool {
	for _, f := range fs {
		if f.Code == code {
			return true
		}
	}
	return false
}

func TestReportListsStoredDataWithoutSecrets(t *testing.T) {
	dir, _ := fakeDataDir(t)
	const secret = "SUPER-SECRET-KEY-MATERIAL"
	writeFile(t, filepath.Join(dir, "device", "device.key"), []byte(secret))
	writeFile(t, filepath.Join(dir, "settings.json"), []byte(`{
		"exit_node": "ev-sunucu", "kill_switch": false, "exit_allow_lan": true,
		"tunnel": {"log_level": "debug", "hide_local_candidates": false},
		"unknown_future_field": 1
	}`))
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	r := BuildReport(ReportOptions{
		Dirs:       []DataDir{{Path: dir, Kind: "servis"}, {Path: filepath.Join(t.TempDir(), "missing"), Kind: "cli"}},
		Now:        now,
		OSHostname: "masaustu",
		Hardening:  HardeningStatus{CoreDumpsDisabled: true, Measures: []string{"test"}},
	})
	if len(r.Stores) != 2 || !r.Stores[0].Exists || r.Stores[1].Exists {
		t.Fatalf("stores = %+v", r.Stores)
	}
	var keyClass string
	for _, f := range r.Stores[0].Files {
		if filepath.Base(f.Path) == "device.key" {
			keyClass = f.Class
		}
	}
	if keyClass != ClassSecret {
		t.Fatalf("device.key class = %q, want %q", keyClass, ClassSecret)
	}
	for _, code := range []string{"debug_log", "exit_without_killswitch", "exit_allow_lan", "local_candidates"} {
		if !hasFinding(r.Findings, code) {
			t.Errorf("missing finding %s in %+v", code, r.Findings)
		}
	}
	var text, js bytes.Buffer
	if err := r.WriteText(&text); err != nil {
		t.Fatal(err)
	}
	if err := r.WriteJSON(&js); err != nil {
		t.Fatal(err)
	}
	for name, out := range map[string]string{"text": text.String(), "json": js.String()} {
		if strings.Contains(out, secret) {
			t.Fatalf("%s report contains key material", name)
		}
	}
	if !strings.Contains(text.String(), "Koordinatörün göremedikleri") {
		t.Fatalf("text report lacks the coordinator section:\n%s", text.String())
	}
	if !json.Valid(js.Bytes()) {
		t.Fatal("JSON report is not valid JSON")
	}
}

func TestReportPermissionFinding(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions only")
	}
	dir, _ := fakeDataDir(t)
	key := filepath.Join(dir, "device", "device.key")
	if err := chmod(key, 0o644); err != nil {
		t.Fatal(err)
	}
	r := BuildReport(ReportOptions{Dirs: []DataDir{{Path: dir, Kind: "cli"}}, Now: time.Now()})
	if !hasFinding(r.Findings, "file_permissions") {
		t.Fatalf("no permission finding: %+v", r.Findings)
	}
}

func TestHostnameFindings(t *testing.T) {
	doc := &trust.Document{Devices: []trust.Device{{ID: "a", Name: "laptop"}, {ID: "b", Name: "sunucu"}}}
	if f := hostnameFindings("LAPTOP.lan", []*trust.Document{doc}); len(f) != 1 || f[0].Code != "device_name_is_hostname" {
		t.Fatalf("findings = %+v", f)
	}
	if f := hostnameFindings("baska", []*trust.Document{doc}); len(f) != 0 {
		t.Fatalf("unexpected findings %+v", f)
	}
}

func TestRecentPeers(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	writeFile(t, filepath.Join(dir, "endpoints.json"), []byte(`{"version":1,"network_id":"n",
		"coordinator":{"endpoint":"203.0.113.1:41820","seen":"2026-10-30T11:00:00Z"},
		"peers":{"dev-a":{"endpoint":"198.51.100.2:41821","seen":"2026-10-30T11:30:00Z"},
		         "0123456789abcdef":{"endpoint":"198.51.100.3:41821","seen":"2026-10-29T10:00:00Z"},
		         "future":{"endpoint":"198.51.100.4:1","seen":"2030-01-01T00:00:00Z"}}}`))
	doc := &trust.Document{Devices: []trust.Device{{ID: "dev-a", Name: "telefon"}}}
	got := recentPeers(dir, doc, now)
	names := map[string]bool{}
	for _, p := range got {
		names[p.Name] = true
	}
	if len(got) != 3 || !names["telefon"] || !names["(koordinatör)"] || !names["01234567…"] {
		t.Fatalf("recent = %+v", got)
	}
}

func TestCoordinatorViewFollowsSettings(t *testing.T) {
	var st settingsView
	sees, never := coordinatorView(st)
	if len(never) == 0 || !strings.Contains(strings.Join(sees, "\n"), "hide-local-candidates") {
		t.Fatalf("default view: %v", sees)
	}
	st.ForceRelay = true
	sees, _ = coordinatorView(st)
	if !strings.Contains(strings.Join(sees, "\n"), "bütün eş trafiği") {
		t.Fatalf("force relay not reflected: %v", sees)
	}
}
