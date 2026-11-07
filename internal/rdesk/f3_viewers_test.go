package rdesk

import (
	"errors"
	"strings"
	"sync"
	"testing"
)

type textFrame struct {
	mu    sync.Mutex
	texts []string
}

func (f *textFrame) Close() error { return nil }

func (f *textFrame) SetText(s string) {
	f.mu.Lock()
	f.texts = append(f.texts, s)
	f.mu.Unlock()
}

func (f *textFrame) last() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.texts) == 0 {
		return ""
	}
	return f.texts[len(f.texts)-1]
}

// TestSecondViewer covers #853: a second administrator device joins the
// screen as a viewer with its own keys and code, a second control request
// is answered with ErrControlTaken, input comes only from the controller
// and every frame names both devices.
func TestSecondViewer(t *testing.T) {
	var mu sync.Mutex
	frames := map[string]*textFrame{}
	h := newHarness(t, func(c *Config) {
		c.MaxSessions = 2
		c.NewFrame = func(fi FrameInfo) (SessionFrame, error) {
			f := &textFrame{}
			mu.Lock()
			frames[fi.Peer] = f
			mu.Unlock()
			return f, nil
		}
	})
	ctx := testCtx(t)

	h.allow.Store(&Decision{Allowed: true, Unattended: true, Peer: "admin-a"})
	ctl, err := Dial(ctx, h.addr, DialOptions{Mode: ModeControl})
	if err != nil {
		t.Fatal(err)
	}
	defer ctl.Close()
	if _, err := ctl.NextFrame(ctx); err != nil {
		t.Fatal(err)
	}

	h.allow.Store(&Decision{Allowed: true, Unattended: true, Peer: "admin-b"})
	_, err = Dial(ctx, h.addr, DialOptions{Mode: ModeControl})
	if !errors.Is(err, ErrControlTaken) || !errors.Is(err, ErrBusy) {
		t.Fatalf("second controller: %v", err)
	}
	view, err := Dial(ctx, h.addr, DialOptions{Mode: ModeView})
	if err != nil {
		t.Fatal(err)
	}
	defer view.Close()
	if _, err := view.NextFrame(ctx); err != nil {
		t.Fatal(err)
	}
	if ctl.VerificationCode() == "" || ctl.VerificationCode() == view.VerificationCode() {
		t.Fatalf("each viewer needs its own code: %q / %q", ctl.VerificationCode(), view.VerificationCode())
	}

	// Input from the viewer is not sent (and would be refused); input
	// from the controller arrives.
	_ = view.SendPointer(5, 5, 0)
	if err := ctl.SendPointer(10, 20, 0); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "controller input", func() bool {
		for _, e := range h.inj.snapshot() {
			if strings.HasPrefix(e, "pointer 10 20") {
				return true
			}
		}
		return false
	})
	for _, e := range h.inj.snapshot() {
		if strings.HasPrefix(e, "pointer 5 5") {
			t.Fatalf("viewer input reached the screen: %v", h.inj.snapshot())
		}
	}

	waitFor(t, "frames naming both devices", func() bool {
		mu.Lock()
		defer mu.Unlock()
		for _, peer := range []string{"admin-a", "admin-b"} {
			f := frames[peer]
			if f == nil {
				return false
			}
			txt := f.last()
			if !strings.Contains(txt, "admin-a") || !strings.Contains(txt, "admin-b") {
				return false
			}
		}
		return true
	})
	if n := len(h.srv.Viewers()); n != 2 {
		t.Fatalf("Viewers = %d", n)
	}

	view.Close()
	waitFor(t, "frame relabelled after the viewer left", func() bool {
		mu.Lock()
		defer mu.Unlock()
		txt := frames["admin-a"].last()
		return strings.Contains(txt, "admin-a") && !strings.Contains(txt, "admin-b")
	})
}

func TestFramesText(t *testing.T) {
	one := FramesText([]FrameInfo{{Peer: "a", Mode: ModeView}})
	if one != (FrameInfo{Peer: "a", Mode: ModeView}).Text() {
		t.Fatalf("one viewer: %q", one)
	}
	two := FramesText([]FrameInfo{{Peer: "a", Mode: ModeControl}, {Peer: "b", Mode: ModeView, Recording: true}})
	for _, want := range []string{"a (", "b (", "Ctrl+Alt+Shift+K", "2"} {
		if !strings.Contains(two, want) {
			t.Fatalf("%q lacks %q", two, want)
		}
	}
	if FramesText(nil) != "" {
		t.Fatal("empty")
	}
}
