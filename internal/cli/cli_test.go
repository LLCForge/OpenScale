package cli

import (
	"bytes"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
)

type harness struct {
	t        *testing.T
	env      *Env
	stdout   *bytes.Buffer
	stderr   *bytes.Buffer
	netDir   string
	passFile string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	base := t.TempDir()
	h := &harness{
		t:        t,
		stdout:   &bytes.Buffer{},
		stderr:   &bytes.Buffer{},
		netDir:   filepath.Join(base, "ag"),
		passFile: filepath.Join(base, "parola.txt"),
	}
	if err := securefile.WriteNew(h.passFile, []byte("çok gizli parola 42\n")); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	h.env = &Env{
		Stdin:           strings.NewReader(""),
		Stdout:          h.stdout,
		Stderr:          h.stderr,
		Now:             func() time.Time { return now },
		Random:          rand.Reader,
		ReadSecret:      func(string) ([]byte, error) { return nil, errors.New("no terminal in tests") },
		ReadLine:        func(string) (string, error) { return "", errors.New("no terminal in tests") },
		IsTerminal:      func() bool { return false },
		Hostname:        func() (string, error) { return "Test-PC", nil },
		DefaultStateDir: func() (string, error) { return filepath.Join(base, "state"), nil },
		Argon2:          trust.Argon2Params{Time: 1, MemoryKiB: 64 * 1024, Threads: 1},
	}
	return h
}

func (h *harness) run(want int, args ...string) string {
	h.t.Helper()
	h.stdout.Reset()
	h.stderr.Reset()
	if got := Run(args, h.env); got != want {
		h.t.Fatalf("openscale %s: exit %d, want %d\nstdout:\n%s\nstderr:\n%s", strings.Join(args, " "), got, want, h.stdout, h.stderr)
	}
	return h.stdout.String() + h.stderr.String()
}

var (
	requestLine = regexp.MustCompile(`osreq1\.[A-Za-z0-9_-]+`)
	fingerprint = regexp.MustCompile(`Parmak izi: ([A-Z2-7]{4}-[A-Z2-7]{4}-[A-Z2-7]{4}-[A-Z2-7]{4})`)
)

func (h *harness) keygen(stateDir, hostname string) (string, string) {
	h.t.Helper()
	out := h.run(exitOK, "keygen", "--state-dir", stateDir, "--hostname", hostname)
	req := requestLine.FindString(out)
	fp := fingerprint.FindStringSubmatch(out)
	if req == "" || len(fp) != 2 {
		h.t.Fatalf("keygen output missing request or fingerprint:\n%s", out)
	}
	return req, fp[1]
}

func TestEndToEndOfflineEnrollment(t *testing.T) {
	h := newHarness(t)
	pass := "--passphrase-file=" + h.passFile

	out := h.run(exitOK, "network", "init", "--dir", h.netDir, pass)
	if !strings.Contains(out, "Ağ oluşturuldu") {
		t.Fatalf("unexpected init output:\n%s", out)
	}
	h.run(exitError, "network", "init", "--dir", h.netDir, pass)

	laptopReq, laptopFP := h.keygen(filepath.Join(t.TempDir(), "laptop"), "laptop")
	desktopReq, desktopFP := h.keygen(filepath.Join(t.TempDir(), "desktop"), "masaustu")

	out = h.run(exitOK, "device", "add", "--dir", h.netDir, "--request", laptopReq, "--fingerprint", strings.ToLower(laptopFP), pass)
	if !strings.Contains(out, "+ cihaz laptop") || !strings.Contains(out, "sürüm 2") {
		t.Fatalf("unexpected device add output:\n%s", out)
	}
	h.run(exitOK, "device", "add", "--dir", h.netDir, "--request", desktopReq, "--fingerprint", desktopFP, "--exit-node", pass)
	h.run(exitOK, "rule", "add", "--dir", h.netDir, "--from", "laptop", "--to", "masaustu", "--proto", "tcp", "--ports", "3389", "--description", "Uzak masaüstü", pass)

	out = h.run(exitOK, "network", "show", "--dir", h.netDir)
	for _, want := range []string{"sürüm 4", "Cihazlar (2)", "[çıkış düğümü]", "laptop.openscale.internal", "laptop -> masaustu tcp/3389", "Uzak masaüstü", "hiç yedeği yok"} {
		if !strings.Contains(out, want) {
			t.Errorf("network show missing %q:\n%s", want, out)
		}
	}

	h.run(exitOK, "device", "revoke", "--dir", h.netDir, "--name", "laptop", "--confirm", "laptop", pass)
	out = h.run(exitOK, "network", "show", "--dir", h.netDir)
	if !strings.Contains(out, "Cihazlar (1)") || !strings.Contains(out, "İptal edilmiş cihaz sayısı: 1") || !strings.Contains(out, "Kural yok") {
		t.Fatalf("unexpected state after revoke:\n%s", out)
	}

	// The revoked keys cannot come back under another name.
	out = h.run(exitError, "device", "add", "--dir", h.netDir, "--request", laptopReq, "--fingerprint", laptopFP, "--name", "laptop2", pass)
	if !strings.Contains(out, "iptal edilmiş") {
		t.Fatalf("expected revoked-key error, got:\n%s", out)
	}

	// A request that was already used for a current device is rejected.
	out = h.run(exitError, "device", "add", "--dir", h.netDir, "--request", desktopReq, "--fingerprint", desktopFP, "--name", "ikinci", pass)
	if !strings.Contains(out, "zaten kullanılmış") {
		t.Fatalf("expected duplicate-request error, got:\n%s", out)
	}

	// Dry run shows the diff and signs nothing.
	out = h.run(exitOK, "rule", "add", "--dir", h.netDir, "--from", "*", "--to", "masaustu", "--proto", "icmp", "--dry-run")
	if !strings.Contains(out, "+ kural * -> masaustu icmp") || !strings.Contains(out, "Kuru çalıştırma") {
		t.Fatalf("unexpected dry-run output:\n%s", out)
	}

	out = h.run(exitOK, "network", "verify", "--dir", h.netDir)
	if !strings.Contains(out, "Geçmiş doğrulandı") {
		t.Fatalf("history verification failed:\n%s", out)
	}

	history, err := os.ReadDir(filepath.Join(h.netDir, "history"))
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 5 {
		t.Fatalf("history has %d versions, want 5", len(history))
	}
}

func TestDeviceAddRejectsWrongFingerprint(t *testing.T) {
	h := newHarness(t)
	pass := "--passphrase-file=" + h.passFile
	h.run(exitOK, "network", "init", "--dir", h.netDir, pass)
	req, _ := h.keygen(filepath.Join(t.TempDir(), "pc"), "pc")

	out := h.run(exitError, "device", "add", "--dir", h.netDir, "--request", req, "--fingerprint", "AAAA-BBBB-CCCC-DDDD", pass)
	if !strings.Contains(out, "Parmak izleri eşleşmiyor") {
		t.Fatalf("unexpected output:\n%s", out)
	}
	out = h.run(exitUsage, "device", "add", "--dir", h.netDir, "--request", req, pass)
	if !strings.Contains(out, "--fingerprint") {
		t.Fatalf("non-interactive add without fingerprint must be refused:\n%s", out)
	}
	out = h.run(exitOK, "network", "show", "--dir", h.netDir)
	if !strings.Contains(out, "Cihazlar (0)") {
		t.Fatalf("no device should have been added:\n%s", out)
	}
}

func TestWrongPassphraseLeavesDocumentUntouched(t *testing.T) {
	h := newHarness(t)
	h.run(exitOK, "network", "init", "--dir", h.netDir, "--passphrase-file="+h.passFile)
	wrong := filepath.Join(t.TempDir(), "wrong.txt")
	if err := securefile.WriteNew(wrong, []byte("yanlış parola 1234")); err != nil {
		t.Fatal(err)
	}
	out := h.run(exitError, "network", "renew", "--dir", h.netDir, "--passphrase-file="+wrong)
	if !strings.Contains(out, "Parola yanlış") {
		t.Fatalf("unexpected output:\n%s", out)
	}
	if out := h.run(exitOK, "network", "show", "--dir", h.netDir); !strings.Contains(out, "sürüm 1") {
		t.Fatalf("document version changed after failed renew:\n%s", out)
	}
}

func TestTamperedDocumentIsRejected(t *testing.T) {
	h := newHarness(t)
	h.run(exitOK, "network", "init", "--dir", h.netDir, "--passphrase-file="+h.passFile)
	docPath := filepath.Join(h.netDir, "network.json")
	data, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatal(err)
	}
	envl, err := trust.UnmarshalEnvelope(data)
	if err != nil {
		t.Fatal(err)
	}
	envl.Payload = bytes.Replace(envl.Payload, []byte(`"version":1`), []byte(`"version":7`), 1)
	tampered, err := trust.MarshalEnvelope(envl)
	if err != nil {
		t.Fatal(err)
	}
	if err := securefile.Replace(docPath, tampered); err != nil {
		t.Fatal(err)
	}
	out := h.run(exitError, "network", "show", "--dir", h.netDir)
	if !strings.Contains(out, "İmza doğrulanamadı") {
		t.Fatalf("unexpected output:\n%s", out)
	}
}

func TestBackupPassphraseAndRestore(t *testing.T) {
	h := newHarness(t)
	pass := "--passphrase-file=" + h.passFile
	h.run(exitOK, "network", "init", "--dir", h.netDir, pass)

	backupPassFile := filepath.Join(t.TempDir(), "yedek-parola.txt")
	if err := securefile.WriteNew(backupPassFile, []byte("ayrı bir yedek parolası 5")); err != nil {
		t.Fatal(err)
	}
	backupPath := filepath.Join(t.TempDir(), "usb", "openscale-yedek.key")
	h.run(exitOK, "network", "backup", "--dir", h.netDir, "--out", backupPath, "--label", "usb-1", pass, "--backup-passphrase-file="+backupPassFile)
	if out := h.run(exitOK, "network", "show", "--dir", h.netDir); !strings.Contains(out, "Yedek sayısı:            1") {
		t.Fatalf("backup not recorded:\n%s", out)
	}

	newPassFile := filepath.Join(t.TempDir(), "yeni.txt")
	if err := securefile.WriteNew(newPassFile, []byte("tamamen yeni parola 88")); err != nil {
		t.Fatal(err)
	}
	h.run(exitOK, "network", "passphrase", "--dir", h.netDir, pass, "--new-passphrase-file="+newPassFile)
	h.run(exitError, "network", "renew", "--dir", h.netDir, pass)
	h.run(exitOK, "network", "renew", "--dir", h.netDir, "--passphrase-file="+newPassFile)

	if err := os.Remove(filepath.Join(h.netDir, "root.key")); err != nil {
		t.Fatal(err)
	}
	h.run(exitOK, "network", "restore", "--dir", h.netDir, "--from", backupPath, "--passphrase-file="+backupPassFile)
	h.run(exitOK, "network", "renew", "--dir", h.netDir, "--passphrase-file="+backupPassFile)
}

func TestUsageErrors(t *testing.T) {
	h := newHarness(t)
	h.run(exitUsage, "network", "init")
	h.run(exitUsage, "nonsense")
	h.run(exitUsage, "network", "init", "--dir", h.netDir, "--validity", "999")
	h.run(exitOK, "version")
	h.run(exitOK, "help")
	h.run(exitUsage, "network", "init", "--dir", h.netDir)
}
