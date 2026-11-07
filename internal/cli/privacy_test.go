package cli

import (
	"bytes"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openscale/openscale/internal/privacy"
)

// stubPrivacySystem keeps the commands away from the real computer: the
// data directories are temporary and the service removal only counts.
func stubPrivacySystem(t *testing.T, dirs ...string) *int {
	t.Helper()
	calls := 0
	oldDirs, oldUninstall := knownDataDirs, uninstallSystem
	knownDataDirs = func(*Env) []privacy.DataDir {
		out := make([]privacy.DataDir, 0, len(dirs))
		for _, d := range dirs {
			out = append(out, privacy.DataDir{Path: d, Kind: "servis"})
		}
		return out
	}
	uninstallSystem = func() error { calls++; return nil }
	t.Cleanup(func() { knownDataDirs, uninstallSystem = oldDirs, oldUninstall })
	return &calls
}

func makeDataDir(t *testing.T, withRootKey bool) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "OpenScale")
	files := map[string]string{
		"device/device.key":  "device secret",
		"device/anchor.json": "{}",
		"settings.json":      `{"tunnel":{"log_level":"debug"}}`,
		"logs/service.log":   "{}\n",
	}
	if withRootKey {
		files["network/root.key"] = "encrypted root"
	}
	for name, data := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestUninstallPurgeRemovesDataDirectory(t *testing.T) {
	h := newHarness(t)
	dir := makeDataDir(t, false)
	calls := stubPrivacySystem(t, dir)
	out := h.run(exitOK, "uninstall", "--purge", "--yes")
	if _, err := os.Lstat(dir); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("data directory still exists: %v", err)
	}
	if !strings.Contains(out, "Silindi:") || !strings.Contains(out, "disk şifrelemesi") {
		t.Fatalf("output: %s", out)
	}
	if isWindows() && *calls != 1 {
		t.Fatalf("service removal called %d times", *calls)
	}
}

func TestUninstallPurgeKeepsRootKeyWithoutFlag(t *testing.T) {
	h := newHarness(t)
	dir := makeDataDir(t, true)
	calls := stubPrivacySystem(t, dir)
	h.run(exitError, "uninstall", "--purge", "--yes")
	if _, err := os.Stat(filepath.Join(dir, "device", "device.key")); err != nil {
		t.Fatalf("refused purge removed data: %v", err)
	}
	if *calls != 0 {
		t.Fatal("service removed although the purge was refused")
	}
	if !strings.Contains(h.stderr.String(), "kök anahtar") {
		t.Fatalf("stderr: %s", h.stderr.String())
	}
	h.run(exitOK, "uninstall", "--purge", "--yes", "--include-root-key")
	if _, err := os.Lstat(dir); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("data directory still exists: %v", err)
	}
}

func TestUninstallPurgeNeedsConfirmation(t *testing.T) {
	h := newHarness(t)
	dir := makeDataDir(t, false)
	stubPrivacySystem(t, dir)
	h.run(exitUsage, "uninstall", "--purge")
	h.env.IsTerminal = func() bool { return true }
	h.env.ReadLine = func(string) (string, error) { return "hayır", nil }
	h.run(exitError, "uninstall", "--purge")
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("unconfirmed purge removed data: %v", err)
	}
	h.env.ReadLine = func(string) (string, error) { return "SİL", nil }
	h.run(exitOK, "uninstall", "--purge")
	if _, err := os.Lstat(dir); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("data directory still exists: %v", err)
	}
}

func TestUninstallDryRunAndForeignDirectory(t *testing.T) {
	h := newHarness(t)
	dir := makeDataDir(t, false)
	calls := stubPrivacySystem(t, dir)
	out := h.run(exitOK, "uninstall", "--purge", "--dry-run")
	if _, err := os.Stat(dir); err != nil || *calls != 0 || !strings.Contains(out, dir) {
		t.Fatalf("dry run changed something or did not list %s: %v\n%s", dir, err, out)
	}
	foreign := t.TempDir()
	if err := os.WriteFile(filepath.Join(foreign, "notes.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.run(exitError, "uninstall", "--purge", "--yes", "--state-dir", foreign)
	if _, err := os.Stat(filepath.Join(foreign, "notes.txt")); err != nil || *calls != 0 {
		t.Fatalf("foreign directory touched: %v", err)
	}
	h.run(exitUsage, "uninstall", "--state-dir", foreign)
}

func TestPrivacyReportCommand(t *testing.T) {
	h := newHarness(t)
	dir := makeDataDir(t, false)
	stubPrivacySystem(t, dir)
	out := h.run(exitOK, "privacy", "report")
	for _, want := range []string{"gizlilik raporu", dir, "device.key", "Koordinatörün görebildikleri", "hata ayıklama günlüğü açık"} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "device secret") {
		t.Fatal("report printed key material")
	}
	js := h.run(exitOK, "privacy-check", "--json")
	if !strings.HasPrefix(strings.TrimSpace(js), "{") || !strings.Contains(js, `"findings"`) {
		t.Fatalf("json: %s", js)
	}
}

// TestCommandLoggerMasks: the loggers of up, coordinator run and panel go
// through the masking handler (#42).
func TestCommandLoggerMasks(t *testing.T) {
	var buf bytes.Buffer
	l := maskedJSONLogger(&buf, slog.LevelInfo)
	l.Info("coordinator endpoint 198.51.100.23:41820", "private_key", "abc")
	out := buf.String()
	if strings.Contains(out, "198.51.100.23") || strings.Contains(out, `"abc"`) {
		t.Fatalf("unmasked log: %s", out)
	}
}

func isWindows() bool { return filepath.Separator == '\\' }
