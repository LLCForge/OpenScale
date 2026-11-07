package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openscale/openscale/internal/coordinator"
	"github.com/openscale/openscale/internal/tpm"
)

// xorSealer stands in for the TPM: no real device is written to.
type xorSealer struct{ k byte }

func (xorSealer) Kind() string { return "tpm2" }
func (s xorSealer) Seal(b []byte) ([]byte, error) {
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[i] ^ s.k
	}
	return out, nil
}
func (s xorSealer) Unseal(b []byte) ([]byte, error) { return s.Seal(b) }

func TestTPMSealDeviceKeyCommand(t *testing.T) {
	old := tpm.DeviceKeySealer
	t.Cleanup(func() { tpm.DeviceKeySealer = old })
	tpm.DeviceKeySealer = func() (tpm.Sealer, error) { return xorSealer{k: 0x5a}, nil }

	h := newHarness(t)
	dir := filepath.Join(t.TempDir(), "state")
	h.run(exitOK, "keygen", "--state-dir", dir)
	before, err := readSecrets(filepath.Join(dir, deviceKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	h.run(exitUsage, "tpm", "seal-device-key", "--state-dir", dir)
	if out := h.run(exitOK, "tpm", "key-status", "--state-dir", dir); !strings.Contains(out, "mühürlü değil") {
		t.Fatalf("status: %s", out)
	}
	h.run(exitOK, "tpm", "seal-device-key", "--state-dir", dir, "--yes")
	raw, err := os.ReadFile(filepath.Join(dir, deviceKeyFile))
	if err != nil || !tpm.IsEnvelope(raw) {
		t.Fatalf("not sealed: %v", err)
	}
	after, err := readSecrets(filepath.Join(dir, deviceKeyFile))
	if err != nil || after.DeviceID != before.DeviceID {
		t.Fatalf("sealed key unreadable: %v", err)
	}
	if out := h.run(exitOK, "tpm", "key-status", "--state-dir", dir); !strings.Contains(out, "mühürlü (tpm2)") {
		t.Fatalf("status: %s", out)
	}
	if _, err := os.Stat(filepath.Join(dir, deviceKeyFile+deviceKeyBackupSuffix)); err != nil {
		t.Fatalf("backup missing: %v", err)
	}
	h.run(exitError, "tpm", "seal-device-key", "--state-dir", dir, "--yes")
	// Another TPM cannot open it.
	tpm.DeviceKeySealer = func() (tpm.Sealer, error) { return xorSealer{k: 0x11}, nil }
	if _, err := readSecrets(filepath.Join(dir, deviceKeyFile)); err == nil {
		t.Fatal("foreign sealer opened the key")
	}
}

func TestCoordinatorObfsConfigCommand(t *testing.T) {
	h := newHarness(t)
	dir := t.TempDir()
	h.run(exitOK, "coordinator", "obfs-config", "--state-dir", dir, "--mode", "auto", "--tls-listen", ":443", "--name", "cdn.example.test")
	f, err := coordinator.LoadObfsFile(dir)
	if err != nil || f.Mode != "auto" || f.TLSListen != ":443" || len(f.Names) != 1 {
		t.Fatalf("%+v %v", f, err)
	}
	h.run(exitUsage, "coordinator", "obfs-config", "--state-dir", dir, "--mode", "on")
	h.run(exitOK, "coordinator", "obfs-config", "--state-dir", dir, "--tls-off")
	if f, _ := coordinator.LoadObfsFile(dir); f.TLSListen != "" || f.Mode != "auto" {
		t.Fatalf("%+v", f)
	}
}
