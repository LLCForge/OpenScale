package privacy

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestVaultRoundTripAndDestroy(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "kasa")
	v, err := OpenVault(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("cihaz anahtarı yedeği")
	if err := v.Put("device", secret); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "device"+vaultExt))
	if err != nil || bytes.Contains(raw, secret) {
		t.Fatal("plaintext on disk")
	}
	got, err := v.Get("device")
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("get: %v", err)
	}
	// Moving a ciphertext to another name fails authentication.
	if err := os.WriteFile(filepath.Join(dir, "other"+vaultExt), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Get("other"); !errors.Is(err, ErrVaultCorrupt) {
		t.Fatalf("renamed ciphertext: %v", err)
	}
	for _, bad := range []string{"", "../x", "a/b", ".hidden", vaultKeyName} {
		if err := v.Put(bad, nil); !errors.Is(err, ErrVaultName) {
			t.Fatalf("name %q accepted", bad)
		}
	}
	// A copy of the ciphertext taken before destruction stays unreadable.
	stolen := bytes.Clone(raw)
	res, err := v.Destroy()
	if err != nil || !res.KeyOverwritten || res.Files < 2 {
		t.Fatalf("destroy %+v %v", res, err)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("vault directory survived")
	}
	if _, err := v.Get("device"); !errors.Is(err, ErrVaultDestroyed) {
		t.Fatalf("get after destroy: %v", err)
	}
	if bytes.Contains(stolen, secret) {
		t.Fatal("stolen copy is plaintext")
	}
}

func TestSecureRemoveTree(t *testing.T) {
	root := filepath.Join(t.TempDir(), "gelen")
	if err := os.MkdirAll(filepath.Join(root, "alt"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"a.txt", "alt/b.txt"} {
		if err := os.WriteFile(filepath.Join(root, p), []byte("gizli içerik"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	res, err := SecureRemove(root)
	if err != nil {
		t.Fatal(err)
	}
	if res.Files != 2 || res.Overwritten != 2 {
		t.Fatalf("result %+v", res)
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("tree survived")
	}
	home, _ := os.UserHomeDir()
	if home != "" {
		if _, err := SecureRemove(home); !errors.Is(err, ErrUnsafePath) {
			t.Fatalf("home accepted: %v", err)
		}
	}
}

func TestClassifyProcesses(t *testing.T) {
	st := ClassifyProcesses([]string{"explorer.exe", "Zoom.exe", "chrome.exe"})
	if st.Level != SharePossible || !st.Blur || len(st.Apps) != 1 || st.Apps[0] != "Zoom" {
		t.Fatalf("zoom: %+v", st)
	}
	st = ClassifyProcesses([]string{"Zoom.exe", "CptHost.exe", "obs64.exe"})
	if st.Level != ShareActive || len(st.Apps) != 3 {
		t.Fatalf("active: %+v", st)
	}
	st = ClassifyProcesses([]string{"ms-teams.exe", "zoom.us"})
	if st.Level != SharePossible || len(st.Apps) != 2 {
		t.Fatalf("teams: %+v", st)
	}
	st = ClassifyProcesses([]string{"chrome", "firefox"})
	if st.Level != ShareNone || st.Blur || st.BrowserNote == "" {
		t.Fatalf("browser only: %+v", st)
	}
}

func TestDetectScreenShareRuns(t *testing.T) {
	// Reads this computer's process list (names only); the result depends
	// on what runs here, so only the shape is checked.
	st := DetectScreenShare(time.Now())
	if st.Level == "" || st.Apps == nil || st.CheckedAt.IsZero() {
		t.Fatalf("status %+v", st)
	}
}
