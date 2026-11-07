package peercred

import (
	"errors"
	"os"
	"runtime"
	"testing"
)

func TestWindowProcessRecordsNothing(t *testing.T) {
	b := NewWindowBinding(ProgramPolicy{Paths: []string{"openscale"}})
	b.image = func(pid int) (string, error) {
		if pid == 100 {
			return "openscale", nil
		}
		return "baska", nil
	}
	b.parent = func(pid int) (int, error) {
		switch pid {
		case 300:
			return 100, nil
		case 400:
			return 0, nil
		}
		return 0, errors.New("yok")
	}
	if got := b.WindowProcess(300); got != 100 {
		t.Fatalf("WindowProcess(300) = %d", got)
	}
	if got := b.WindowProcess(400); got != 0 {
		t.Fatalf("WindowProcess(400) = %d", got)
	}
	if len(b.bound) != 0 {
		t.Fatalf("bağlama yapıldı: %v", b.bound)
	}
}

func TestProcessUser(t *testing.T) {
	got, err := ProcessUser(os.Getpid())
	if runtime.GOOS != "windows" {
		if !errors.Is(err, ErrUnsupported) {
			t.Fatalf("err = %v", err)
		}
		return
	}
	if err != nil || len(got) < 4 || got[:4] != "S-1-" {
		t.Fatalf("ProcessUser = %q, %v", got, err)
	}
}
