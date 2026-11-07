package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestG7BlockingAndPluginCommands(t *testing.T) {
	h := newHarness(t)
	pass := "--passphrase-file=" + h.passFile
	h.run(exitOK, "network", "init", "--dir", h.netDir, pass)
	dir := t.TempDir()

	list := filepath.Join(dir, "reklam.txt")
	if err := os.WriteFile(list, []byte("ads.example\n0.0.0.0 tracker.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := h.run(exitOK, "blocking", "digest", list, "--category", "ads")
	if !strings.Contains(out, "sha256 ") || !strings.Contains(out, "2 ad") {
		t.Fatalf("digest: %s", out)
	}
	h.run(exitError, "blocking", "digest", list, "--category", "bilinmeyen")

	settings := filepath.Join(dir, "ayar.json")
	if err := os.WriteFile(settings, []byte(`{"policy":{"default":["ads"]},"block_doh":["doh.example.net"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	out = h.run(exitOK, "blocking", "set", "--dir", h.netDir, "--file", settings, "--dry-run")
	if !strings.Contains(out, "imzalanmadı") {
		t.Fatalf("dry run: %s", out)
	}
	h.run(exitOK, "blocking", "set", "--dir", h.netDir, "--file", settings, pass)
	out = h.run(exitOK, "blocking", "show", "--dir", h.netDir)
	if !strings.Contains(out, "ads") || !strings.Contains(out, "DoH engeli: 1") {
		t.Fatalf("show: %s", out)
	}
	// Unknown keys and telemetry without keep are refused.
	if err := os.WriteFile(settings, []byte(`{"policy":{"default":["os-telemetry"]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	h.run(exitError, "blocking", "set", "--dir", h.netDir, "--file", settings, pass)
	if err := os.WriteFile(settings, []byte(`{"bilinmeyen":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	h.run(exitError, "blocking", "set", "--dir", h.netDir, "--file", settings, pass)

	// Pin the sample plugin from the plugin package's test data.
	src := filepath.Join("..", "plugin", "testdata", "plugins")
	out = h.run(exitOK, "plugin", "pin", "ornek-engel", "--dir", h.netDir, "--plugins", src, pass)
	if !strings.Contains(out, "DNS sorgu adı") {
		t.Fatalf("pin: %s", out)
	}
	out = h.run(exitOK, "blocking", "show", "--dir", h.netDir, "--json")
	if !strings.Contains(out, `"name": "ornek-engel"`) {
		t.Fatalf("show json: %s", out)
	}
	h.run(exitError, "plugin", "unpin", "yok", "--dir", h.netDir, pass)
	h.run(exitOK, "plugin", "unpin", "ornek-engel", "--dir", h.netDir, pass)
	out = h.run(exitOK, "plugin", "list", "--state-dir", dir)
	if !strings.Contains(out, "Eklenti yok") {
		t.Fatalf("list: %s", out)
	}
}
