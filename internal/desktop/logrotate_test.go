package desktop

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRotatingLogBySize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "service.log")
	now := time.Date(2026, 10, 30, 8, 0, 0, 0, time.UTC)
	l, err := openRotatingLog(path, 100, 2, 0, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	line := []byte(strings.Repeat("x", 59) + "\n")
	for i := 0; i < 7; i++ {
		if _, err := l.Write(line); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"service.log", "service.log.1", "service.log.2"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if info.Size() > 100 {
			t.Errorf("%s has %d bytes, over the limit", name, info.Size())
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "service.log.3")); !os.IsNotExist(err) {
		t.Fatal("more files kept than allowed")
	}
}

func TestRotatingLogPrunesOldFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "service.log")
	now := time.Date(2026, 10, 30, 8, 0, 0, 0, time.UTC)
	old := filepath.Join(dir, "service.log.1")
	if err := os.WriteFile(old, []byte("eski\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(old, now.Add(-30*24*time.Hour), now.Add(-30*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	stray := filepath.Join(dir, "service.log.9")
	if err := os.WriteFile(stray, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	notOurs := filepath.Join(dir, "service.log.yedek")
	if err := os.WriteFile(notOurs, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := openRotatingLog(path, 1<<20, logKeep, logMaxAge, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	for _, p := range []string{old, stray} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s not pruned", filepath.Base(p))
		}
	}
	if _, err := os.Stat(notOurs); err != nil {
		t.Error("a file that is not a rotated log was removed")
	}
}
