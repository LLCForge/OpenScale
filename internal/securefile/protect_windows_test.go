//go:build windows

package securefile

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// The tests use DPAPI in user scope with temporary data only; nothing in
// the system configuration changes.
func useUserScope(t *testing.T) {
	t.Helper()
	old := writeScheme
	writeScheme = SchemeDPAPIUser
	EnableKeyProtection(true)
	t.Cleanup(func() {
		writeScheme = old
		EnableKeyProtection(false)
	})
}

var testKey = []byte("{\n  \"format\": \"openscale-device-key-v1\",\n  \"device_id\": \"0123\"\n}\n")

func TestDPAPIRoundTrip(t *testing.T) {
	p, err := protectWith(testKey, SchemeDPAPIUser)
	if err != nil {
		t.Fatal(err)
	}
	if !IsProtected(p) || ProtectedScheme(p) != SchemeDPAPIUser || bytes.Contains(p, []byte("openscale-device-key-v1")) {
		t.Fatalf("protected form %q", p)
	}
	back, err := Unprotect(p)
	if err != nil || !bytes.Equal(back, testKey) {
		t.Fatalf("round trip %q %v", back, err)
	}
	// A changed blob is rejected.
	tampered := append([]byte(nil), p...)
	tampered[len(tampered)-5] ^= 0x01
	if _, err := Unprotect(tampered); err == nil {
		t.Fatal("tampered blob decrypted")
	}
}

func TestAutoProtectAndMigrate(t *testing.T) {
	useUserScope(t)
	dir := t.TempDir()

	// New key files are written protected.
	fresh := filepath.Join(dir, "device.key")
	if err := WriteNew(fresh, testKey); err != nil {
		t.Fatal(err)
	}
	if s, _ := FileScheme(fresh); s != SchemeDPAPIUser {
		t.Fatalf("new key scheme %q", s)
	}
	got, err := ReadPrivate(fresh, 4096)
	if err != nil || !bytes.Equal(got, testKey) {
		t.Fatalf("read protected %q %v", got, err)
	}

	// An old plaintext key file is migrated on first read.
	old := filepath.Join(dir, "coordinator.key")
	EnableKeyProtection(false)
	if err := WriteNew(old, testKey); err != nil {
		t.Fatal(err)
	}
	EnableKeyProtection(true)
	got, err = ReadPrivate(old, 4096)
	if err != nil || !bytes.Equal(got, testKey) {
		t.Fatalf("read plaintext %q %v", got, err)
	}
	if s, _ := FileScheme(old); s != SchemeDPAPIUser {
		t.Fatalf("plaintext key not migrated: %q", s)
	}

	// Other private files are never protected.
	other := filepath.Join(dir, "root.key")
	if err := WriteNew(other, testKey); err != nil {
		t.Fatal(err)
	}
	if raw, _ := os.ReadFile(other); !bytes.Equal(raw, testKey) {
		t.Fatal("root.key must stay as written")
	}

	// Rollback: unprotect writes the plaintext and opts the folder out.
	changed, err := UnprotectFile(fresh)
	if err != nil || !changed {
		t.Fatalf("unprotect %v %v", changed, err)
	}
	if raw, _ := os.ReadFile(fresh); !bytes.Equal(raw, testKey) {
		t.Fatal("unprotected file differs")
	}
	if _, err := ReadPrivate(fresh, 4096); err != nil {
		t.Fatal(err)
	}
	if s, _ := FileScheme(fresh); s != SchemeNone {
		t.Fatal("opted-out folder was protected again on read")
	}
	if err := Replace(fresh, testKey); err != nil {
		t.Fatal(err)
	}
	if s, _ := FileScheme(fresh); s != SchemeNone {
		t.Fatal("opted-out folder was protected again on write")
	}
	// Protect again removes the opt-out.
	if changed, err := ProtectFile(fresh); err != nil || !changed {
		t.Fatalf("protect %v %v", changed, err)
	}
	if _, err := os.Stat(filepath.Join(dir, OptOutFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("opt-out file must be removed")
	}
	if changed, err := ProtectFile(fresh); err != nil || changed {
		t.Fatalf("second protect %v %v", changed, err)
	}
}

func TestDamagedProtectedFileFailsClosed(t *testing.T) {
	useUserScope(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "device.key")
	if err := WriteNew(path, []byte(protectedMagic+" dpapi-user\nAAAAAAAA\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPrivate(path, 4096); !errors.Is(err, ErrBadProtectedFile) {
		t.Fatalf("damaged file: %v", err)
	}
}
