package rdesk

import (
	"context"
	"testing"
	"time"
)

// The kill shortcut ends a live session over the loopback and blocks new
// ones; the global shortcut itself is never registered by the test.
func TestWatchKillShortcutEndsSessions(t *testing.T) {
	h := newHarness(t, nil)
	ctx := testCtx(t)
	press := make(chan func(), 1)
	old := watchHotkey
	watchHotkey = func(wctx context.Context, hk Hotkey, fn func()) error {
		if hk != DefaultKillHotkey {
			t.Errorf("hotkey %+v", hk)
		}
		press <- fn
		<-wctx.Done()
		return nil
	}
	t.Cleanup(func() { watchHotkey = old })
	wctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ended := make(chan int, 1)
	go func() { _ = WatchKillShortcut(wctx, h.srv, func(n int) { ended <- n }) }()

	c, err := Dial(ctx, h.addr, DialOptions{Mode: ModeControl, Scale: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.NextFrame(ctx); err != nil {
		t.Fatal(err)
	}
	(<-press)()
	if n := <-ended; n != 1 {
		t.Fatalf("ended %d", n)
	}
	waitFor(t, "session ended", func() bool { return h.srv.ActiveSessions() == 0 })
	until, ok := h.srv.KillBlockedUntil()
	if !ok || time.Until(until) < KillShortcutBlock-time.Minute {
		t.Fatalf("block %v %v", until, ok)
	}
}

func TestWithSessionFrameKeepsOwnFrame(t *testing.T) {
	if WithSessionFrame(Config{}).NewFrame == nil {
		t.Fatal("frame not set")
	}
	own := func(FrameInfo) (SessionFrame, error) { return nil, ErrUnsupported }
	cfg := WithSessionFrame(Config{NewFrame: own})
	if cfg.NewFrame == nil || cfg.RequireFrame {
		t.Fatal("own frame replaced or frame made mandatory")
	}
}
