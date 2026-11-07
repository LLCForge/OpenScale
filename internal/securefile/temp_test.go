package securefile

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestIsTempName(t *testing.T) {
	for _, n := range []string{".settings.json.tmp-123", ".device.key.tmp-9", ".openscale-42.tmp"} {
		if !IsTempName(n) {
			t.Errorf("IsTempName(%q) = false", n)
		}
	}
	for _, n := range []string{"settings.json", "device.key", "notes.tmp", ".hidden", "service.log.1"} {
		if IsTempName(n) {
			t.Errorf("IsTempName(%q) = true", n)
		}
	}
}

func TestRemoveStaleTemps(t *testing.T) {
	dir := t.TempDir()
	old := time.Now().Add(-time.Hour)
	mk := func(rel string, mod time.Time) string {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, mod, mod); err != nil {
			t.Fatal(err)
		}
		return p
	}
	stale := []string{mk(".settings.json.tmp-1", old), mk("device/.device.key.tmp-2", old), mk("network/history/.v1.json.tmp-3", old)}
	keep := []string{
		mk("settings.json", old),
		mk(".fresh.json.tmp-4", time.Now()),
		mk("a/b/c/d/.deep.tmp-5", old),
	}
	n, err := RemoveStaleTemps(dir, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if n != len(stale) {
		t.Fatalf("removed %d, want %d", n, len(stale))
	}
	for _, p := range stale {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s still exists", p)
		}
	}
	for _, p := range keep {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s removed: %v", p, err)
		}
	}
	if n, err := RemoveStaleTemps(filepath.Join(dir, "missing"), time.Now()); n != 0 || err != nil {
		t.Fatalf("missing dir: %d, %v", n, err)
	}
}

// TestReplaceLeavesNoTemporaryFile: the temporary file of Replace lives in
// the target directory and is gone after success.
func TestReplaceLeavesNoTemporaryFile(t *testing.T) {
	dir := t.TempDir()
	if err := Replace(filepath.Join(dir, "settings.json"), []byte("{}")); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if IsTempName(e.Name()) {
			t.Fatalf("temporary file left: %s", e.Name())
		}
	}
}
