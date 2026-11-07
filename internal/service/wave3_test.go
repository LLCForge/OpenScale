package service

import (
	"testing"

	"github.com/openscale/openscale/internal/panel"
)

func TestNormalizeExitAuto(t *testing.T) {
	got, err := NormalizeExitAuto(panel.ExitAutoSettings{Mode: "fastest", Candidates: []string{" a ", "a", "b"}, Untrusted: true,
		TrustedWiFi: []string{"Ev", "Ev"}, Except: []string{"203.0.113.7/24"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Candidates) != 2 || len(got.TrustedWiFi) != 1 || got.Except[0] != "203.0.113.0/24" {
		t.Fatalf("normalized = %+v", got)
	}
	bad := []panel.ExitAutoSettings{
		{Mode: "random"},
		{Except: []string{"0.0.0.0/0"}},
		{Except: []string{"2001:db8::/32"}},
		{TrustedWiFi: []string{"Ev"}},
		{Candidates: []string{"a"}},
		{Mode: "failover", TrustedWiFi: []string{"a\nb"}, Untrusted: true},
	}
	for _, b := range bad {
		if _, err := NormalizeExitAuto(b); err == nil {
			t.Fatalf("accepted %+v", b)
		}
	}
}

func TestExitAutoFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if s, err := loadExitAuto(dir); err != nil || s.Enabled() {
		t.Fatalf("missing file = %+v, %v", s, err)
	}
	want := panel.ExitAutoSettings{Mode: "failover", Except: []string{"198.51.100.0/24"}}
	if err := saveExitAuto(dir, want); err != nil {
		t.Fatal(err)
	}
	got, err := loadExitAuto(dir)
	if err != nil || got.Mode != "failover" || len(got.Except) != 1 {
		t.Fatalf("loaded = %+v, %v", got, err)
	}
}
