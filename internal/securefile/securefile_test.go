package securefile

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWriteNewRefusesOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a", "secret")
	if err := WriteNew(path, []byte("one")); err != nil {
		t.Fatalf("WriteNew: %v", err)
	}
	if err := WriteNew(path, []byte("two")); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("second WriteNew error = %v, want fs.ErrExist", err)
	}
	got, err := ReadPrivate(path, 16)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "one" {
		t.Fatalf("content = %q, want original", got)
	}
}

func TestReplaceIsAtomicAndPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "doc.json")
	for _, content := range []string{"v1", "v2"} {
		if err := Replace(path, []byte(content)); err != nil {
			t.Fatalf("Replace(%s): %v", content, err)
		}
	}
	got, err := ReadPrivate(path, 16)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "v2" {
		t.Fatalf("content = %q, want v2", got)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("temporary files left behind: %v", entries)
	}
}

func TestReadEnforcesLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "big")
	if err := WriteNew(path, make([]byte, 100)); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPrivate(path, 99); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("error = %v, want ErrTooLarge", err)
	}
	if _, err := ReadLimited(path, 100); err != nil {
		t.Fatalf("ReadLimited at exact limit: %v", err)
	}
}

func TestReadPrivateRejectsOpenPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions are not enforced on Windows")
	}
	path := filepath.Join(t.TempDir(), "secret")
	if err := WriteNew(path, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPrivate(path, 16); !errors.Is(err, ErrInsecurePermissions) {
		t.Fatalf("error = %v, want ErrInsecurePermissions", err)
	}
	if _, err := ReadLimited(path, 16); err != nil {
		t.Fatalf("ReadLimited should not check permissions: %v", err)
	}
}

func TestReadRejectsDirectory(t *testing.T) {
	if _, err := ReadLimited(t.TempDir(), 16); err == nil {
		t.Fatal("expected error when reading a directory")
	}
}
