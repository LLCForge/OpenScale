package cli

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/openscale/openscale/internal/trust"
)

// scripted answers terminal prompts in order.
func (h *harness) scripted(lines, secrets []string) {
	h.env.IsTerminal = func() bool { return true }
	h.env.ReadSecret = func(prompt string) ([]byte, error) {
		if len(secrets) == 0 {
			return nil, errors.New("unexpected secret prompt: " + prompt)
		}
		next := secrets[0]
		secrets = secrets[1:]
		return []byte(next), nil
	}
	h.env.ReadLine = func(prompt string) (string, error) {
		if len(lines) == 0 {
			return "", errors.New("unexpected prompt: " + prompt)
		}
		next := lines[0]
		lines = lines[1:]
		return next, nil
	}
}

func TestSetupPlanAndWizard(t *testing.T) {
	h := newHarness(t)
	out := h.run(exitOK, "setup", "--dir", h.netDir, "--plan")
	if strings.Count(out, "[ yapılacak ]") != 4 {
		t.Fatalf("plan on an empty folder:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(h.netDir, "root.key")); err == nil {
		t.Fatal("--plan must not create anything")
	}
	// Without a terminal the wizard refuses instead of guessing.
	h.run(exitUsage, "setup", "--dir", h.netDir)

	backup := filepath.Join(t.TempDir(), "yedek.key")
	// create network, backup path, skip coordinator.
	root, other := "çok gizli parola 42", "başka bir yedek parolası 7"
	// "network init" asks for the backup path and its passphrase itself.
	h.scripted([]string{"", backup, ""}, []string{root, root, other, other})
	out = h.run(exitOK, "setup", "--dir", h.netDir)
	for _, want := range []string{"Ağ oluşturuldu", "Koordinatör atlandı", "openscale device add"} {
		if !strings.Contains(out, want) {
			t.Fatalf("setup output misses %q:\n%s", want, out)
		}
	}
	if _, err := os.Stat(backup); err != nil {
		t.Fatalf("backup not written: %v", err)
	}
	out = h.run(exitOK, "setup", "--dir", h.netDir, "--plan")
	if strings.Count(out, "[tamam]") != 2 {
		t.Fatalf("plan after setup:\n%s", out)
	}
}

func TestNetworkExportImport(t *testing.T) {
	h := newHarness(t)
	pass := "--passphrase-file=" + h.passFile
	h.run(exitOK, "network", "init", "--dir", h.netDir, pass)
	file := filepath.Join(t.TempDir(), "belge.json")
	out := h.run(exitOK, "network", "export", "--dir", h.netDir, "--out", file)
	if !strings.Contains(out, "sürüm 1") || !strings.Contains(out, "yedeği değildir") {
		t.Fatalf("export output:\n%s", out)
	}
	// Exporting again never overwrites.
	h.run(exitError, "network", "export", "--dir", h.netDir, "--out", file)

	h.run(exitOK, "network", "renew", "--dir", h.netDir, pass)
	out = h.run(exitOK, "network", "import", "--dir", h.netDir, "--file", file)
	if !strings.Contains(out, "İmza geçerli") || !strings.Contains(out, "eski bir sürüm") || !strings.Contains(out, "Hiçbir şey imzalanmadı") {
		t.Fatalf("import output:\n%s", out)
	}

	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(t.TempDir(), "bozuk.json")
	var env trust.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatal(err)
	}
	env.Signature[0] ^= 1
	raw, _ := json.Marshal(env)
	if err := os.WriteFile(bad, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	out = h.run(exitError, "network", "import", "--dir", h.netDir, "--file", bad)
	if !strings.Contains(out, "doğrulanamadı") {
		t.Fatalf("tampered import output:\n%s", out)
	}
}

func TestErrorHint(t *testing.T) {
	if errorHint(os.ErrPermission) == "" || errorHint(&os.PathError{Op: "open", Path: "x", Err: syscall.EACCES}) == "" {
		t.Fatal("permission errors need a hint")
	}
	if !strings.Contains(errorHint(errors.New("listen tcp 127.0.0.1:80: bind: address already in use")), "--port") {
		t.Fatal("port in use needs a hint")
	}
	if errorHint(errors.New("başka bir hata")) != "" {
		t.Fatal("unrelated errors get no hint")
	}
}
