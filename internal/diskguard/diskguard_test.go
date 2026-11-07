package diskguard

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestFreeReportsSpace(t *testing.T) {
	free, err := Free(t.TempDir())
	if errors.Is(err, ErrUnsupported) {
		t.Skip(err)
	}
	if err != nil || free == 0 {
		t.Fatalf("Free = %d, %v", free, err)
	}
}

func TestIsDiskFull(t *testing.T) {
	if !IsDiskFull(fmt.Errorf("write: %w", syscall.ENOSPC)) {
		t.Fatal("ENOSPC not recognized")
	}
	if IsDiskFull(nil) || IsDiskFull(errors.New("other")) {
		t.Fatal("false positive")
	}
}

func TestReserveAndWriteCritical(t *testing.T) {
	dir := t.TempDir()
	if err := EnsureReserve(dir, 128<<10); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, ReserveFile))
	if free, ferr := Free(dir); ferr == nil && free < 1<<30 {
		t.Skip("test disk is nearly full")
	}
	if err != nil || info.Size() != 128<<10 {
		t.Fatalf("reserve %v %v", info, err)
	}
	calls := 0
	err = WriteCritical(dir, func() error {
		calls++
		if calls == 1 {
			return fmt.Errorf("replace: %w", syscall.ENOSPC)
		}
		return nil
	})
	if err != nil || calls != 2 {
		t.Fatalf("WriteCritical = %v after %d calls", err, calls)
	}
	if _, err := os.Stat(filepath.Join(dir, ReserveFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("reserve was not released for the critical write")
	}
	// No reserve left: the second failure is returned as is.
	calls = 0
	err = WriteCritical(dir, func() error { calls++; return syscall.ENOSPC })
	if !IsDiskFull(err) || calls != 1 {
		t.Fatalf("without a reserve: %v after %d calls", err, calls)
	}
	// Other errors are never retried.
	calls = 0
	if err := WriteCritical(dir, func() error { calls++; return errors.New("permission") }); err == nil || calls != 1 {
		t.Fatal("non disk-full error retried")
	}
}

func TestWriterDropsBelowLowWater(t *testing.T) {
	var buf bytes.Buffer
	free := uint64(10 << 20)
	now := time.Unix(1000, 0)
	g := NewWriter(&buf, "x", 64<<20)
	g.free = func(string) (uint64, error) { return free, nil }
	g.now = func() time.Time { return now }
	if n, err := g.Write([]byte("a\n")); err != nil || n != 2 {
		t.Fatal(n, err)
	}
	if buf.Len() != 0 || g.Dropped() != 1 {
		t.Fatalf("written %q, dropped %d", buf.String(), g.Dropped())
	}
	free = 1 << 30
	_, _ = g.Write([]byte("b\n")) // cached decision: still dropped
	now = now.Add(checkEvery)
	_, _ = g.Write([]byte("c\n"))
	if buf.String() != "c\n" || g.Dropped() != 2 {
		t.Fatalf("written %q, dropped %d", buf.String(), g.Dropped())
	}
	g.free = func(string) (uint64, error) { return 0, ErrUnsupported }
	now = now.Add(checkEvery)
	_, _ = g.Write([]byte("d\n"))
	if buf.String() != "c\nd\n" {
		t.Fatal("unknown free space must not stop the log")
	}
}

type fullWriter struct{}

func (fullWriter) Write([]byte) (int, error) { return 0, syscall.ENOSPC }

func TestWriterSwallowsDiskFull(t *testing.T) {
	g := NewWriter(fullWriter{}, "x", 1)
	g.free = func(string) (uint64, error) { return 1 << 40, nil }
	if n, err := g.Write([]byte("abc")); err != nil || n != 3 || g.Dropped() != 1 {
		t.Fatalf("n=%d err=%v dropped=%d", n, err, g.Dropped())
	}
}
