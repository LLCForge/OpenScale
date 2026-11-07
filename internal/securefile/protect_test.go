package securefile

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestProtectedFormat(t *testing.T) {
	if IsProtected([]byte(`{"format":"openscale-device-key-v1"}`)) {
		t.Fatal("plain JSON detected as protected")
	}
	if !IsProtected([]byte(protectedMagic + " dpapi-machine\nAAAA\n")) {
		t.Fatal("protected header not detected")
	}
	if s := ProtectedScheme([]byte(protectedMagic + " dpapi-user\nAAAA\n")); s != SchemeDPAPIUser {
		t.Fatalf("scheme %q", s)
	}
	if s := ProtectedScheme([]byte("{}")); s != SchemeNone {
		t.Fatalf("scheme %q", s)
	}
	for _, bad := range []string{
		protectedMagic + " dpapi-machine",
		protectedMagic + " rot13\nAAAA\n",
		protectedMagic + " dpapi-machine\n!!!\n",
		protectedMagic + " dpapi-machine\n\n",
	} {
		if _, err := Unprotect([]byte(bad)); !errors.Is(err, ErrBadProtectedFile) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	for _, name := range []string{"device.key", "device.key.next", "coordinator.key", "device.key.old-3"} {
		if !IsKeyFileName(name) {
			t.Errorf("%s must be protected", name)
		}
	}
	for _, name := range []string{"root.key", "network.json", "anchor.json", "app.token"} {
		if IsKeyFileName(name) {
			t.Errorf("%s must not be protected (root.key is passphrase sealed and portable)", name)
		}
	}
}

// Without automatic protection, nothing changes on disk (tests of other
// packages and older programs see plain files).
func TestProtectionOffByDefault(t *testing.T) {
	if KeyProtectionEnabled() {
		t.Fatal("protection must be off unless the binary enables it")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "device.key")
	if err := WriteNew(path, []byte("{\"k\":1}\n")); err != nil {
		t.Fatal(err)
	}
	got, err := ReadPrivate(path, 4096)
	if err != nil || !bytes.Equal(got, []byte("{\"k\":1}\n")) {
		t.Fatalf("read %q %v", got, err)
	}
	raw, _ := os.ReadFile(path)
	if IsProtected(raw) {
		t.Fatal("file protected while protection is off")
	}
}

func FuzzUnprotect(f *testing.F) {
	f.Add([]byte(protectedMagic + " dpapi-machine\nAAAA\n"))
	f.Add([]byte("{}"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if !protectionAvailable {
			_, _ = Unprotect(data)
			return
		}
		// DPAPI calls are skipped for fuzzing; only the parser runs.
		if _, _, ok := bytes.Cut(data, []byte("\n")); !ok || !IsProtected(data) {
			if _, err := Unprotect(data); !errors.Is(err, ErrBadProtectedFile) && !errors.Is(err, ErrTooLarge) {
				t.Fatalf("malformed input: %v", err)
			}
		}
	})
}
