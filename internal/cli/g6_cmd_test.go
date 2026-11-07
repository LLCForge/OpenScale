package cli

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/posture"
)

func TestG6ParseBootRequirement(t *testing.T) {
	q, err := parseBootRequirement("secure-boot,tpm,screen-lock")
	if err != nil || !q.SecureBoot || !q.TPM || !q.ScreenLock {
		t.Fatalf("%+v %v", q, err)
	}
	if _, err := parseBootRequirement("disk"); err == nil {
		t.Fatal("unknown condition accepted")
	}
}

func TestG6Commands(t *testing.T) {
	h := newHarness(t)
	// Registered commands are reachable and do not hide the static ones.
	out := h.run(exitOK, "screen-share")
	if !strings.Contains(out, "Tarayıcı") {
		t.Fatalf("screen-share output: %s", out)
	}
	dir := t.TempDir()
	victim := filepath.Join(dir, "sil.txt")
	if err := os.WriteFile(victim, []byte("gizli"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.run(exitUsage, "secure-delete", victim)
	if _, err := os.Stat(victim); err != nil {
		t.Fatal("deleted without --yes")
	}
	h.run(exitOK, "secure-delete", victim, "--yes")
	if _, err := os.Stat(victim); !os.IsNotExist(err) {
		t.Fatal("file survived")
	}

	// e2e strip writes a cleaned copy and never overwrites.
	pdf := filepath.Join(dir, "a.pdf")
	if err := os.WriteFile(pdf, []byte("%PDF-1.4 /Author (Ayse) %%EOF"), 0o600); err != nil {
		t.Fatal(err)
	}
	clean := filepath.Join(dir, "b.pdf")
	h.run(exitOK, "e2e", "strip", pdf, clean)
	b, _ := os.ReadFile(clean)
	if strings.Contains(string(b), "Ayse") {
		t.Fatal("author survived")
	}
	h.run(exitError, "e2e", "strip", pdf, clean)

	// tamper verify accepts a real log and refuses a wrong key.
	pub, priv, _ := ed25519.GenerateKey(nil)
	state := filepath.Join(dir, "state")
	watched := filepath.Join(dir, "bin")
	if err := os.WriteFile(watched, []byte("v1"), 0o600); err != nil {
		t.Fatal(err)
	}
	w, err := posture.OpenTamperWatcher(posture.TamperConfig{Device: "pc", Paths: []string{watched}, StateDir: state, Key: priv, Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(watched, []byte("v2"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Check(); err != nil {
		t.Fatal(err)
	}
	logFile := filepath.Join(state, "tamper.log")
	out = h.run(exitOK, "tamper", "verify", logFile, "--key", base64.StdEncoding.EncodeToString(pub))
	if !strings.Contains(out, "1 olay doğrulandı") {
		t.Fatalf("verify output: %s", out)
	}
	other, _, _ := ed25519.GenerateKey(nil)
	h.run(exitError, "tamper", "verify", logFile, "--key", base64.StdEncoding.EncodeToString(other))
	h.run(exitUsage, "posture-ext", "--require", "disk")
}
