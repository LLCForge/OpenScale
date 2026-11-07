package cli

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/openscale/openscale/internal/piv"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/tpm"
	"github.com/openscale/openscale/internal/trust"
)

var approverKeyLine = regexp.MustCompile(`Açık anahtar: (\S+)`)

func (h *harness) secretFile(name, text string) string {
	h.t.Helper()
	path := filepath.Join(h.t.TempDir(), name)
	if err := securefile.WriteNew(path, []byte(text+"\n")); err != nil {
		h.t.Fatal(err)
	}
	return path
}

func (h *harness) rootKeyText() string {
	h.t.Helper()
	sealed, err := readNetworkRootKey(h.netDir)
	if err != nil {
		h.t.Fatal(err)
	}
	var k trust.Key
	copy(k[:], sealed.RootPublicKey())
	return k.String()
}

func TestApprovalCommands(t *testing.T) {
	h := newHarness(t)
	pass := "--passphrase-file=" + h.passFile
	h.run(exitOK, "network", "init", "--dir", h.netDir, pass)

	keyDir := t.TempDir()
	pa := h.secretFile("pa", "laptop onaycı parolası 2026")
	pb := h.secretFile("pb", "jeton onaycı parolası 2027")
	out := h.run(exitOK, "approve", "keygen", "--out", filepath.Join(keyDir, "a.key"), "--passphrase-file", pa)
	ka := approverKeyLine.FindStringSubmatch(out)
	out = h.run(exitOK, "approve", "keygen", "--out", filepath.Join(keyDir, "b.key"), "--passphrase-file", pb)
	kb := approverKeyLine.FindStringSubmatch(out)
	if len(ka) != 2 || len(kb) != 2 {
		t.Fatalf("keygen output without public key:\n%s", out)
	}
	approvers := "laptop=" + ka[1] + ",token=" + kb[1]

	h.run(exitUsage, "network", "approval", "set", "--dir", h.netDir, "--threshold", "3", "--approvers", approvers, pass)
	h.run(exitUsage, "network", "approval", "set", "--dir", h.netDir, "--threshold", "1", "--approvers", "laptop=bozuk", pass)
	out = h.run(exitOK, "network", "approval", "set", "--dir", h.netDir, "--threshold", "1", "--approvers", approvers, "--dry-run")
	if !strings.Contains(out, "Kuru çalıştırma") {
		t.Fatalf("dry run:\n%s", out)
	}
	out = h.run(exitOK, "network", "approval", "show", "--dir", h.netDir)
	if !strings.Contains(out, "onay politikası yok") {
		t.Fatalf("show before set:\n%s", out)
	}
	h.run(exitOK, "network", "approval", "set", "--dir", h.netDir, "--threshold", "1", "--approvers", approvers, pass)
	out = h.run(exitOK, "network", "approval", "show", "--dir", h.netDir)
	if !strings.Contains(out, "1/2") || !strings.Contains(out, "Durum: eksik") {
		t.Fatalf("show after set:\n%s", out)
	}

	doc := filepath.Join(h.netDir, "network.json")
	approval := filepath.Join(keyDir, "onay.json")
	h.run(exitUsage, "approve", "sign", "--document", doc, "--key", filepath.Join(keyDir, "a.key"), "--token", "--dir", h.netDir, "--out", approval)
	out = h.run(exitOK, "approve", "sign", "--document", doc, "--root", h.rootKeyText(), "--dry-run")
	if !strings.Contains(out, "sürüm 2") || !strings.Contains(out, "Kuru çalıştırma") {
		t.Fatalf("sign dry run:\n%s", out)
	}
	h.run(exitOK, "approve", "sign", "--document", doc, "--key", filepath.Join(keyDir, "a.key"), "--passphrase-file", pa, "--dir", h.netDir, "--out", approval)

	bad := h.secretFile("bozuk.json", `{"key":"x"}`)
	h.run(exitError, "approve", "add", "--dir", h.netDir, "--approval", bad)
	out = h.run(exitOK, "approve", "add", "--dir", h.netDir, "--approval", approval)
	if !strings.Contains(out, "Durum: tamam") || !strings.Contains(out, "[onaylı]") {
		t.Fatalf("add:\n%s", out)
	}
}

func TestQuorumBackupCommands(t *testing.T) {
	h := newHarness(t)
	pass := "--passphrase-file=" + h.passFile
	h.run(exitOK, "network", "init", "--dir", h.netDir, pass)
	pa := h.secretFile("pa", "ayşe sahip parolası 11111")
	pb := h.secretFile("pb", "bora sahip parolası 22222")
	pc := h.secretFile("pc", "cem sahip parolası 333333")
	backup := filepath.Join(t.TempDir(), "quorum.json")

	h.run(exitUsage, "network", "quorum-backup", "--dir", h.netDir, "--out", backup, "--holders", "ayse,bora", "--threshold", "3", pass)
	out := h.run(exitOK, "network", "quorum-backup", "--dir", h.netDir, "--out", backup, "--holders", "ayse,bora,cem", "--threshold", "2",
		"--holder-passphrase-files", pa+","+pb+","+pc, pass)
	if !strings.Contains(out, "doğrulandı") || !strings.Contains(out, "3 mühürlü kopya") {
		t.Fatalf("quorum backup:\n%s", out)
	}
	if err := os.Remove(filepath.Join(h.netDir, "root.key")); err != nil {
		t.Fatal(err)
	}
	np := h.secretFile("np", "geri yüklenen yeni parola 9")
	h.run(exitError, "network", "quorum-restore", "--dir", h.netDir, "--from", backup, "--holders", "ayse", "--holder-passphrase-files", pa, "--new-passphrase-file", np)
	h.run(exitUsage, "network", "quorum-restore", "--dir", h.netDir, "--from", backup, "--holders", "yok,cem", "--holder-passphrase-files", pa+","+pc, "--new-passphrase-file", np)
	h.run(exitOK, "network", "quorum-restore", "--dir", h.netDir, "--from", backup, "--holders", "ayse,cem", "--holder-passphrase-files", pa+","+pc, "--new-passphrase-file", np)
	h.run(exitOK, "network", "renew", "--dir", h.netDir, "--passphrase-file", np)
}

func TestTravelCommands(t *testing.T) {
	h := newHarness(t)
	pass := "--passphrase-file=" + h.passFile
	h.run(exitOK, "network", "init", "--dir", h.netDir, pass)
	bp := h.secretFile("bp", "seyahat yedeği parolası 77")
	backup := filepath.Join(t.TempDir(), "yedek.key")
	h.run(exitOK, "network", "backup", "--dir", h.netDir, "--out", backup, "--backup-passphrase-file", bp, pass)
	archive := filepath.Join(t.TempDir(), "seyahat.arsiv")

	h.run(exitUsage, "travel", "start", "--dir", h.netDir, "--backup", backup, "--backup-passphrase-file", bp, "--out", archive)
	out := h.run(exitOK, "travel", "start", "--dir", h.netDir, "--backup", backup, "--backup-passphrase-file", bp, "--out", archive, "--confirm", "SEYAHAT")
	if !strings.Contains(out, "Seyahat kipi açık") {
		t.Fatalf("travel start:\n%s", out)
	}
	if out := h.run(exitOK, "travel", "status", "--dir", h.netDir); !strings.Contains(out, "açık") {
		t.Fatalf("travel status:\n%s", out)
	}
	h.run(exitError, "network", "show", "--dir", h.netDir)
	h.run(exitError, "travel", "start", "--dir", h.netDir, "--backup", backup, "--backup-passphrase-file", bp, "--out", archive+"2", "--confirm", "SEYAHAT")
	h.run(exitOK, "travel", "end", "--dir", h.netDir, "--backup", backup, "--backup-passphrase-file", bp, "--from", archive)
	if out := h.run(exitOK, "travel", "status", "--dir", h.netDir); !strings.Contains(out, "kapalı") {
		t.Fatalf("travel status after end:\n%s", out)
	}
	h.run(exitOK, "network", "renew", "--dir", h.netDir, pass)
}

func TestAirgapCommands(t *testing.T) {
	h := newHarness(t)
	pass := "--passphrase-file=" + h.passFile
	h.run(exitOK, "network", "init", "--dir", h.netDir, pass)
	usb := t.TempDir()
	out := h.run(exitOK, "airgap", "export", "--dir", h.netDir, "--out", usb)
	if !strings.Contains(out, "network.json") {
		t.Fatalf("export:\n%s", out)
	}
	h.run(exitError, "airgap", "export", "--dir", h.netDir, "--out", filepath.Join(h.netDir, "usb"))
	relay := filepath.Join(t.TempDir(), "relay")
	h.run(exitUsage, "airgap", "import", "--from", usb)
	out = h.run(exitOK, "airgap", "import", "--from", usb, "--network-dir", relay, "--root", h.rootKeyText())
	if !strings.Contains(out, "sürüm 1") {
		t.Fatalf("import:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(relay, "network.json")); err != nil {
		t.Fatal(err)
	}
	// A foreign root is refused.
	other := newHarness(t)
	other.run(exitOK, "network", "init", "--dir", other.netDir, "--passphrase-file="+other.passFile)
	h.run(exitError, "airgap", "import", "--from", usb, "--network-dir", filepath.Join(t.TempDir(), "r2"), "--root", other.rootKeyText())
}

func TestKeyHWCommandsWithoutToken(t *testing.T) {
	h := newHarness(t)
	pass := "--passphrase-file=" + h.passFile
	h.run(exitOK, "network", "init", "--dir", h.netDir, pass)
	old := openPIVCard
	t.Cleanup(func() { openPIVCard = old })
	opened := false
	openPIVCard = func(string) (pivCard, error) {
		opened = true
		return nil, piv.ErrUnsupported
	}

	h.run(exitUsage, "key", "hw", "import", "--dir", h.netDir, "--slot", "99", "--dry-run")
	h.run(exitUsage, "key", "hw", "import", "--dir", h.netDir, "--pin-policy", "ara-sira", "--dry-run")
	out := h.run(exitOK, "key", "hw", "import", "--dir", h.netDir, "--dry-run")
	if !strings.Contains(out, "donanımda denenmedi") || !strings.Contains(out, "Kuru çalıştırma") || !strings.Contains(out, "9C") {
		t.Fatalf("import dry run:\n%s", out)
	}
	h.run(exitUsage, "key", "hw", "import", "--dir", h.netDir, pass)
	if opened {
		t.Fatal("token was opened by a dry run or a usage error")
	}
	out = h.run(exitError, "key", "hw", "status", "--dir", h.netDir)
	if !opened || !strings.Contains(out, "donanımda denenmedi") {
		t.Fatalf("status:\n%s", out)
	}
	// The plain "key" command still works.
	h.run(exitUsage, "key")
}

func TestTPMStatus(t *testing.T) {
	h := newHarness(t)
	oldDetect, oldOpen := tpmDetect, tpmOpen
	t.Cleanup(func() { tpmDetect, tpmOpen = oldDetect, oldOpen })
	tpmOpen = func() (tpm.Transport, error) { return nil, errors.New("açılamadı") }

	tpmDetect = func() (tpm.Presence, error) { return tpm.Presence{}, tpm.ErrUnsupported }
	if out := h.run(exitOK, "tpm", "status"); !strings.Contains(out, "uygulanmadı") {
		t.Fatalf("unsupported:\n%s", out)
	}
	tpmDetect = func() (tpm.Presence, error) { return tpm.Presence{}, nil }
	if out := h.run(exitOK, "tpm", "status"); !strings.Contains(out, "bulunamadı") {
		t.Fatalf("absent:\n%s", out)
	}
	tpmDetect = func() (tpm.Presence, error) { return tpm.Presence{Present: true, Version: "1.2"}, nil }
	if out := h.run(exitOK, "tpm", "status"); !strings.Contains(out, "Yalnızca TPM 2.0") {
		t.Fatalf("tpm 1.2:\n%s", out)
	}
	tpmDetect = func() (tpm.Presence, error) { return tpm.Presence{Present: true, Version: "2.0"}, nil }
	h.run(exitError, "tpm", "status")
}

func TestCoordinatorLimitFlags(t *testing.T) {
	h := newHarness(t)
	state := t.TempDir()
	for _, bad := range [][]string{
		{"--control-rate", "5"},
		{"--control-burst", "200000"},
		{"--control-total-rate", "1"},
		{"--relay-max-peers", "-1"},
		{"--relay-total-rate", "10"},
	} {
		h.run(exitUsage, append([]string{"coordinator", "run", "--state-dir", state}, bad...)...)
	}
	fs := newFlagSet(h.env, "coordinator run")
	f := addCoordinatorLimitFlags(fs)
	if err := parseFlags(fs, []string{"--control-rate", "50", "--relay-max-peers", "8", "--relay-total-rate", "1048576", "--relay-require-sessions"}); err != nil {
		t.Fatal(err)
	}
	if err := f.resolve(); err != nil {
		t.Fatal(err)
	}
	if *f.controlRate != 50 || *f.relayMaxPeers != 8 || *f.relayTotalRate != 1<<20 || !*f.requireSessions {
		t.Fatalf("flags: %+v", f)
	}
}
