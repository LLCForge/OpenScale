package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/securefile"
)

func (h *harness) backupPassFile(text string) string {
	h.t.Helper()
	p := filepath.Join(h.t.TempDir(), "yedek-parola.txt")
	if err := securefile.WriteNew(p, []byte(text+"\n")); err != nil {
		h.t.Fatal(err)
	}
	return p
}

func TestInitRequiresBackupForCompleteSetup(t *testing.T) {
	h := newHarness(t)
	pass := "--passphrase-file=" + h.passFile
	out := h.run(exitOK, "network", "init", "--dir", h.netDir, pass)
	if !strings.Contains(out, "KURULUM TAMAMLANMADI") {
		t.Fatalf("init without a backup claims a complete setup:\n%s", out)
	}

	h2 := newHarness(t)
	backup := filepath.Join(t.TempDir(), "usb", "yedek.key")
	if err := os.MkdirAll(filepath.Dir(backup), 0o700); err != nil {
		t.Fatal(err)
	}
	out = h2.run(exitOK, "network", "init", "--dir", h2.netDir, "--passphrase-file="+h2.passFile,
		"--backup-out", backup, "--backup-passphrase-file", h2.backupPassFile("ayrı yedek parolası 9"))
	if !strings.Contains(out, "Kurulum tamamlandı") || strings.Contains(out, "TAMAMLANMADI") {
		t.Fatalf("init with a backup:\n%s", out)
	}
	if out := h2.run(exitOK, "network", "show", "--dir", h2.netDir); !strings.Contains(out, "Yedek sayısı:            1") {
		t.Fatalf("backup not recorded:\n%s", out)
	}
	// The same passphrase for the backup is refused, and the setup is
	// reported as incomplete.
	h3 := newHarness(t)
	out = h3.run(exitError, "network", "init", "--dir", h3.netDir, "--passphrase-file="+h3.passFile,
		"--backup-out", filepath.Join(t.TempDir(), "y.key"), "--backup-passphrase-file", h3.passFile)
	if !strings.Contains(out, "KURULUM TAMAMLANMADI") {
		t.Fatalf("failed backup step:\n%s", out)
	}
}

func TestBackupDrillAndRecover(t *testing.T) {
	h := newHarness(t)
	pass := "--passphrase-file=" + h.passFile
	h.run(exitOK, "network", "init", "--dir", h.netDir, pass, "--skip-backup")
	req, fp := h.keygen(filepath.Join(t.TempDir(), "laptop"), "laptop")
	h.run(exitOK, "device", "add", "--dir", h.netDir, "--request", req, "--fingerprint", fp, pass)
	backupPass := h.backupPassFile("ayrı yedek parolası 9")
	backup := filepath.Join(t.TempDir(), "yedek.key")
	h.run(exitOK, "network", "backup", "--dir", h.netDir, "--out", backup, pass, "--backup-passphrase-file="+backupPass)

	rootBefore, err := os.ReadFile(filepath.Join(h.netDir, "root.key"))
	if err != nil {
		t.Fatal(err)
	}
	docBefore, err := os.ReadFile(filepath.Join(h.netDir, "network.json"))
	if err != nil {
		t.Fatal(err)
	}
	out := h.run(exitOK, "backup", "drill", "--dir", h.netDir, "--from", backup, "--passphrase-file", backupPass)
	if !strings.Contains(out, "Tatbikat başarılı") {
		t.Fatalf("drill:\n%s", out)
	}
	out = h.run(exitError, "drill", "--dir", h.netDir, "--from", backup, "--passphrase-file", h.passFile)
	if !strings.Contains(out, "HATA") {
		t.Fatalf("drill with the wrong passphrase:\n%s", out)
	}
	rootAfter, _ := os.ReadFile(filepath.Join(h.netDir, "root.key"))
	docAfter, _ := os.ReadFile(filepath.Join(h.netDir, "network.json"))
	if !bytes.Equal(rootBefore, rootAfter) || !bytes.Equal(docBefore, docAfter) {
		t.Fatal("the drill changed the real network directory")
	}

	// The admin computer is lost: recover on another one from the backup
	// and a document copy, and revoke the lost device.
	other := filepath.Join(t.TempDir(), "yeni-ag")
	out = h.run(exitOK, "network", "recover", "--dir", other, "--from", backup, "--document", filepath.Join(h.netDir, "network.json"),
		"--passphrase-file", backupPass, "--revoke", "laptop", "--confirm", "laptop")
	if !strings.Contains(out, "laptop iptal edildi") {
		t.Fatalf("recover:\n%s", out)
	}
	out = h.run(exitOK, "network", "show", "--dir", other)
	if !strings.Contains(out, "İptal edilmiş cihaz sayısı: 1") {
		t.Fatalf("revocation missing:\n%s", out)
	}
	// A second recover into the same folder is refused.
	h.run(exitError, "network", "recover", "--dir", other, "--from", backup, "--document", filepath.Join(h.netDir, "network.json"), "--passphrase-file", backupPass)
	// A document signed by another root is skipped.
	h2 := newHarness(t)
	h2.run(exitOK, "network", "init", "--dir", h2.netDir, "--passphrase-file="+h2.passFile)
	h.run(exitError, "network", "recover", "--dir", filepath.Join(t.TempDir(), "x"), "--from", backup, "--document", filepath.Join(h2.netDir, "network.json"), "--passphrase-file", backupPass)
}

func TestStateRepairCommand(t *testing.T) {
	h := newHarness(t)
	h.run(exitOK, "network", "init", "--dir", h.netDir, "--passphrase-file="+h.passFile, "--skip-backup")
	n, err := admin.Load(h.netDir, h.env.adminOptions())
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := n.JoinBundle()
	if err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(t.TempDir(), "uye")
	if _, err := member.Join(stateDir, bundle, n.RootFingerprint(), time.Now()); err != nil {
		t.Fatal(err)
	}
	out := h.run(exitOK, "state", "repair", "--state-dir", stateDir, "--document", filepath.Join(h.netDir, "network.json"))
	if !strings.Contains(out, "sağlam") {
		t.Fatalf("healthy state:\n%s", out)
	}
	for _, f := range []string{"network.json", "network.json.bak"} {
		if err := os.WriteFile(filepath.Join(stateDir, f), []byte("bozuk"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	out = h.run(exitOK, "state", "repair", "--state-dir", stateDir, "--document", filepath.Join(h.netDir, "network.json"))
	if !strings.Contains(out, "yeniden kuruldu") {
		t.Fatalf("repair:\n%s", out)
	}
	if _, err := member.Open(stateDir); err != nil {
		t.Fatalf("open after repair: %v", err)
	}
}
