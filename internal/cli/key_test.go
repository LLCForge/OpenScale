package cli

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/openscale/openscale/internal/logcrypt"
	"github.com/openscale/openscale/internal/securefile"
)

var sasPattern = regexp.MustCompile(`\d{4}-\d{4}-\d{4}-\d{4}-\d{4}`)

func TestKeyRequestAndSAS(t *testing.T) {
	h := newHarness(t)
	state := filepath.Join(t.TempDir(), "cihaz")
	png := filepath.Join(t.TempDir(), "istek.png")
	out := h.run(exitOK, "key", "request", "--state-dir", state, "--png", png)
	line := requestLine.FindString(out)
	code := sasPattern.FindString(out)
	if line == "" || code == "" || !strings.Contains(out, "█") {
		t.Fatalf("request output:\n%s", out)
	}
	if data, err := os.ReadFile(png); err != nil || !bytes.HasPrefix(data, []byte("\x89PNG")) {
		t.Fatalf("png: %v", err)
	}
	// The owner and the device see the same code.
	if got := sasPattern.FindString(h.run(exitOK, "key", "sas", "--request", line)); got != code {
		t.Fatalf("owner code %q, device %q", got, code)
	}
	if got := sasPattern.FindString(h.run(exitOK, "key", "sas", "--state-dir", state)); got != code {
		t.Fatalf("self code %q, request %q", got, code)
	}
	h.run(exitOK, "network", "init", "--dir", h.netDir, "--passphrase-file="+h.passFile)
	if root := sasPattern.FindString(h.run(exitOK, "key", "sas", "--dir", h.netDir)); root == "" || root == code {
		t.Fatalf("root code %q", root)
	}
	h.run(exitUsage, "key", "nope")
	h.run(exitUsage, "key")
}

func TestKeyPaperBackupRestore(t *testing.T) {
	h := newHarness(t)
	h.run(exitOK, "network", "init", "--dir", h.netDir, "--passphrase-file="+h.passFile)
	backupPass := filepath.Join(t.TempDir(), "yedek.txt")
	if err := securefile.WriteNew(backupPass, []byte("kâğıttaki yedek parolası 9\n")); err != nil {
		t.Fatal(err)
	}
	out := h.run(exitOK, "key", "paper-backup", "--dir", h.netDir, "--passphrase-file="+h.passFile, "--backup-passphrase-file="+backupPass, "--no-qr")
	var lines []string
	for _, l := range strings.Split(out, "\n") {
		if regexp.MustCompile(`^  \d\d [A-Z2-7]{4} `).MatchString(l) {
			lines = append(lines, strings.TrimSpace(l))
		}
	}
	if len(lines) != 13 {
		t.Fatalf("paper lines:\n%s", out)
	}
	paper := filepath.Join(t.TempDir(), "kagit.txt")
	if err := securefile.WriteNew(paper, []byte(strings.Join(lines, "\n"))); err != nil {
		t.Fatal(err)
	}
	h.run(exitOK, "key", "paper-restore", "--dir", h.netDir, "--from", paper, "--passphrase-file="+backupPass)
	h.run(exitOK, "network", "show", "--dir", h.netDir)
	// The root key now opens with the backup passphrase.
	h.run(exitOK, "network", "renew", "--dir", h.netDir, "--passphrase-file="+backupPass)
}

func TestKeyKDFUpgradeAndStrength(t *testing.T) {
	h := newHarness(t)
	h.run(exitOK, "network", "init", "--dir", h.netDir, "--passphrase-file="+h.passFile)
	out := h.run(exitOK, "key", "kdf-upgrade", "--dir", h.netDir, "--passphrase-file="+h.passFile, "--target", "100ms")
	if !strings.Contains(out, "yeniden şifrelendi") {
		t.Fatalf("upgrade output:\n%s", out)
	}
	h.run(exitOK, "network", "renew", "--dir", h.netDir, "--passphrase-file="+h.passFile)

	weak := filepath.Join(t.TempDir(), "zayif.txt")
	if err := securefile.WriteNew(weak, []byte("Galatasaray1905\n")); err != nil {
		t.Fatal(err)
	}
	if out := h.run(exitOK, "key", "strength", "--passphrase-file="+weak); !strings.Contains(out, "Kabul edilmez") {
		t.Fatalf("strength output:\n%s", out)
	}
	if out := h.run(exitOK, "key", "strength", "--passphrase-file="+h.passFile); !strings.Contains(out, "Kabul edilir") {
		t.Fatalf("strength output:\n%s", out)
	}
	h.run(exitError, "network", "init", "--dir", filepath.Join(t.TempDir(), "ag2"), "--passphrase-file="+weak)
}

func TestKeyStatusAndLogDecrypt(t *testing.T) {
	h := newHarness(t)
	state := filepath.Join(t.TempDir(), "cihaz")
	h.keygen(state, "pc")
	out := h.run(exitOK, "key", "status", "--state-dir", state)
	if !strings.Contains(out, "device.key") || !strings.Contains(out, "Rastgelelik sağlık denetimi: geçti") {
		t.Fatalf("status:\n%s", out)
	}
	h.run(exitOK, "key", "selftest")

	secrets, err := readSecrets(filepath.Join(state, deviceKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	var enc bytes.Buffer
	lw, err := logcrypt.NewWriter(&enc, secrets.SigningSeed, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = lw.Write([]byte("level=DEBUG msg=gizli-ayrinti\n"))
	logPath := filepath.Join(t.TempDir(), "debug.log.enc")
	if err := securefile.WriteNew(logPath, enc.Bytes()); err != nil {
		t.Fatal(err)
	}
	if out := h.run(exitOK, "key", "log-decrypt", "--in", logPath, "--state-dir", state); !strings.Contains(out, "gizli-ayrinti") {
		t.Fatalf("decrypt:\n%s", out)
	}
	other := filepath.Join(t.TempDir(), "baska")
	h.keygen(other, "pc2")
	h.run(exitError, "key", "log-decrypt", "--in", logPath, "--state-dir", other)

	if !securefile.ProtectionAvailable() {
		h.run(exitError, "key", "protect", "--state-dir", state)
	}
	// Unprotect on a plain folder only writes the opt-out marker.
	h.run(exitOK, "key", "unprotect", "--state-dir", state)
	if _, err := os.Stat(filepath.Join(state, securefile.OptOutFile)); err != nil {
		t.Fatal("opt-out marker missing")
	}
}
