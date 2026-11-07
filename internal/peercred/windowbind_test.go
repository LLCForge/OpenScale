package peercred

import (
	"errors"
	"fmt"
	"testing"
)

// fakeTree: 10 tray -> 20 panel-window -> 30 msedgewebview2 -> 40 network
// service; 50 is another browser.
func fakeBinding() *WindowBinding {
	images := map[int]string{10: "/opt/openscale", 20: "/opt/openscale", 30: "/x/msedgewebview2", 40: "/x/msedgewebview2", 50: "/x/chrome"}
	parents := map[int]int{20: 10, 30: 20, 40: 30, 50: 1}
	conn := map[string]int{"127.0.0.1:1": 40, "127.0.0.1:2": 50, "127.0.0.1:3": 30}
	b := NewWindowBinding(ProgramPolicy{Paths: []string{"/opt/openscale"}})
	b.lookup = func(remote, _ string) (int, error) {
		if pid, ok := conn[remote]; ok {
			return pid, nil
		}
		return 0, errors.New("unknown")
	}
	b.image = func(pid int) (string, error) {
		if p, ok := images[pid]; ok {
			return p, nil
		}
		return "", fmt.Errorf("no %d", pid)
	}
	b.parent = func(pid int) (int, error) { return parents[pid], nil }
	return b
}

func TestWindowBinding(t *testing.T) {
	b := fakeBinding()
	win, err := b.Bind("s1", "127.0.0.1:1", "127.0.0.1:9")
	if err != nil || win != 40 && win != 20 {
		t.Fatalf("Bind = %d, %v", win, err)
	}
	// The nearest OpenScale ancestor is the window process 20.
	if win != 20 {
		t.Fatalf("window = %d, want 20", win)
	}
	if err := b.Check("s1", "127.0.0.1:3", "127.0.0.1:9"); err != nil {
		t.Fatalf("same window, other child: %v", err)
	}
	if err := b.Check("s1", "127.0.0.1:2", "127.0.0.1:9"); !errors.Is(err, ErrWindowBinding) {
		t.Fatalf("copied cookie in another browser: %v", err)
	}
	if err := b.Check("s1", "127.0.0.1:7", "127.0.0.1:9"); !errors.Is(err, ErrWindowBinding) {
		t.Fatalf("unknown connection: %v", err)
	}
	// A browser sign-in is not bound and passes.
	if win, err := b.Bind("s2", "127.0.0.1:2", "127.0.0.1:9"); err != nil || win != 0 {
		t.Fatalf("browser bind = %d, %v", win, err)
	}
	if err := b.Check("s2", "127.0.0.1:2", "127.0.0.1:9"); err != nil {
		t.Fatal(err)
	}
	b.Forget("s1")
	if err := b.Check("s1", "127.0.0.1:2", "127.0.0.1:9"); err != nil {
		t.Fatal("forgotten session still bound")
	}
	if _, err := b.Bind("", "127.0.0.1:1", ""); err == nil {
		t.Fatal("empty session bound")
	}
}

func TestWindowBindingBounded(t *testing.T) {
	b := fakeBinding()
	for i := range maxBindings + 10 {
		if _, err := b.Bind(fmt.Sprint("s", i), "127.0.0.1:1", ""); err != nil {
			t.Fatal(err)
		}
	}
	if len(b.bound) != maxBindings || len(b.order) != maxBindings {
		t.Fatalf("table = %d/%d", len(b.bound), len(b.order))
	}
}
