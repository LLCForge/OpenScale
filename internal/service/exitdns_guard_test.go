package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/node"
)

func TestExitDNSGuardPrefs(t *testing.T) {
	list := filepath.Join(t.TempDir(), "cocuk.txt")
	if err := os.WriteFile(list, []byte("oyun.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var w wave2Options
	set := func(key, v string) error {
		t.Helper()
		ok, err := applyWave2Pref(&w, key, v)
		if !ok {
			t.Fatalf("%s not handled", key)
		}
		return err
	}
	for key, v := range map[string]string{
		"exit-dns-rebind-protect": "false",
		"exit-dns-rebind-allow":   "Ev.Example.com, nas.example.org",
		"exit-dns-serve-stale":    "true",
		"exit-dns-rate-limit":     "-1",
		"exit-dns-tunnel-detect":  "false",
		"exit-dns-tunnel-block":   "true",
		"exit-dns-aaaa":           "filter",
		"exit-dns-profile-lists":  "cocuk=" + list,
	} {
		if err := set(key, v); err != nil {
			t.Fatalf("%s=%s: %v", key, v, err)
		}
	}
	g := w.ExitDNSGuard
	if !g.RebindOff || len(g.RebindAllow) != 2 || g.RebindAllow[0] != "ev.example.com" || !g.ServeStale || g.RateLimit != -1 ||
		!g.TunnelDetectOff || !g.TunnelBlock || g.AAAA != "filter" || g.ProfileLists["cocuk"] != list {
		t.Fatalf("settings %+v", g)
	}
	if err := w.validate(transportOptions{}); err != nil {
		t.Fatal(err)
	}
	for key, v := range map[string]string{
		"exit-dns-rate-limit":    "-5",
		"exit-dns-aaaa":          "belki",
		"exit-dns-rebind-allow":  "com",
		"exit-dns-profile-lists": "cocuk=" + filepath.Join(t.TempDir(), "yok.txt"),
	} {
		before := wave2Options{ExitDNSGuard: w.ExitDNSGuard}.clone()
		if err := set(key, v); err == nil {
			t.Fatalf("%s=%s must be refused", key, v)
		}
		if !w.equal(before) {
			t.Fatalf("%s: a refused value was stored", key)
		}
	}
	if err := set("exit-dns-aaaa", "auto"); err != nil || w.ExitDNSGuard.AAAA != "" {
		t.Fatal("auto is stored as the zero value")
	}
	// Clone is deep and empty values compare equal.
	c := w.clone()
	c.ExitDNSGuard.ProfileLists["baska"] = "/x"
	if _, ok := w.ExitDNSGuard.ProfileLists["baska"]; ok {
		t.Fatal("clone shares the profile map")
	}
	if !(wave2Options{ExitDNSGuard: node.ExitDNSGuardConfig{RebindAllow: []string{}}}).equal(wave2Options{}) {
		t.Fatal("empty list must equal nil")
	}
	if ok, _ := applyWave2Pref(&w, "baska-bir-ayar", "1"); ok {
		t.Fatal("unknown key handled")
	}
}

func TestExitDNSThreatText(t *testing.T) {
	if s, ok := exitDNSThreatText(string(node.ThreatDNSTunnel), "tablet", 42); !ok || !strings.Contains(s, "tablet") || !strings.Contains(s, "42") {
		t.Fatalf("%q", s)
	}
	if _, ok := exitDNSThreatText("inbound_scan", "x", 1); ok {
		t.Fatal("other kinds are not ours")
	}
}

func TestEngineDiagExitDNS(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	d := &EngineDiag{Now: func() time.Time { return now }}
	if _, err := d.DiagExitDNSAllow("reklam.example", 15*time.Minute); err == nil {
		t.Fatal("an exception needs a running tunnel")
	}
	if _, err := d.DiagExitDNSSetLog(time.Minute); err == nil {
		t.Fatal("the log needs a running tunnel")
	}
	if _, err := d.DiagExitDNSSetLog(0); err != nil {
		t.Fatal("turning the log off always works")
	}
	rep, err := d.DiagExitDNS()
	if err != nil || rep.LogUntil != nil || rep.Exceptions == nil {
		t.Fatalf("%+v %v", rep, err)
	}
}
