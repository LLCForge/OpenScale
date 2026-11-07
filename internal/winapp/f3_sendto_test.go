package winapp

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestCheckSendToArgs(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.txt")
	b := filepath.Join(dir, "b.bin")
	if err := os.WriteFile(a, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, make([]byte, 10), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := CheckSendToArgs([]string{a, b, a}, os.Lstat)
	if err != nil || len(got) != 2 || got[0].Name != "a.txt" || got[0].Size != 5 {
		t.Fatalf("got %+v, %v", got, err)
	}

	var ae *SendToArgError
	if _, err := CheckSendToArgs([]string{dir}, os.Lstat); !errors.As(err, &ae) {
		t.Fatalf("folder accepted: %v", err)
	}
	if _, err := CheckSendToArgs([]string{"relative.txt"}, os.Lstat); !errors.As(err, &ae) {
		t.Fatalf("relative path accepted: %v", err)
	}
	if _, err := CheckSendToArgs([]string{filepath.Join(dir, "missing")}, os.Lstat); !errors.As(err, &ae) {
		t.Fatalf("missing file accepted: %v", err)
	}
	if _, err := CheckSendToArgs(nil, os.Lstat); !errors.Is(err, ErrSendToNone) {
		t.Fatalf("empty: %v", err)
	}
	many := make([]string, MaxSendToFiles+1)
	for i := range many {
		many[i] = a
	}
	if _, err := CheckSendToArgs(many, os.Lstat); !errors.Is(err, ErrSendToTooMany) {
		t.Fatalf("too many: %v", err)
	}
	for _, dev := range []string{`\\.\PhysicalDrive0`, `\\?\C:\x`, `C:\dir\NUL`, `C:\dir\com1.txt`, "/dev/x\x00"} {
		if _, err := CheckSendToArgs([]string{dev}, os.Lstat); !errors.As(err, &ae) {
			t.Fatalf("device path %q accepted: %v", dev, err)
		}
	}
	link := filepath.Join(dir, "link.txt")
	if err := os.Symlink(a, link); err == nil {
		if _, err := CheckSendToArgs([]string{link}, os.Lstat); !errors.As(err, &ae) {
			t.Fatalf("symlink accepted: %v", err)
		}
	} else if runtime.GOOS != "windows" {
		t.Fatal(err)
	}
	// Sizes come from Lstat; a fake reports a huge file.
	huge := func(string) (os.FileInfo, error) { return fakeInfo{size: MaxSendToFile + 1}, nil }
	if _, err := CheckSendToArgs([]string{a}, huge); !errors.As(err, &ae) {
		t.Fatalf("huge file accepted: %v", err)
	}
	big := func(string) (os.FileInfo, error) { return fakeInfo{size: MaxSendToFile}, nil }
	paths := []string{filepath.Join(dir, "1"), filepath.Join(dir, "2"), filepath.Join(dir, "3"), filepath.Join(dir, "4"), filepath.Join(dir, "5")}
	if _, err := CheckSendToArgs(paths, big); !errors.Is(err, ErrSendToTooLarge) {
		t.Fatalf("total limit: %v", err)
	}
}

type fakeInfo struct{ size int64 }

func (f fakeInfo) Name() string       { return "x" }
func (f fakeInfo) Size() int64        { return f.size }
func (f fakeInfo) Mode() os.FileMode  { return 0o600 }
func (f fakeInfo) ModTime() time.Time { return time.Time{} }
func (f fakeInfo) IsDir() bool        { return false }
func (f fakeInfo) Sys() any           { return nil }
