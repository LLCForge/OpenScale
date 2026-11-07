package rdesk

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"image"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeScreen is a virtual desktop with two monitors side by side.
type fakeScreen struct {
	mu       sync.Mutex
	img      *image.RGBA
	monitors []Monitor
	opened   atomic.Int32
	closed   atomic.Int32
	fail     error
}

func newFakeScreen() *fakeScreen {
	ms := []Monitor{
		{Bounds: image.Rect(0, 0, 200, 120), Primary: true},
		{Bounds: image.Rect(200, 0, 330, 90)},
	}
	img := image.NewRGBA(image.Rect(0, 0, 330, 120))
	for y := 0; y < 120; y++ {
		for x := 0; x < 330; x++ {
			o := img.PixOffset(x, y)
			img.Pix[o], img.Pix[o+1], img.Pix[o+2], img.Pix[o+3] = uint8(x), uint8(y), uint8(x*y), 0xff
		}
	}
	return &fakeScreen{img: img, monitors: ms}
}

func (f *fakeScreen) set(x, y int, r uint8) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.img.Pix[f.img.PixOffset(x, y)] = r
}

func (f *fakeScreen) region(r image.Rectangle) *image.RGBA {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := image.NewRGBA(image.Rect(0, 0, r.Dx(), r.Dy()))
	for y := 0; y < r.Dy(); y++ {
		so := f.img.PixOffset(r.Min.X, r.Min.Y+y)
		copy(out.Pix[out.PixOffset(0, y):out.PixOffset(0, y)+r.Dx()*4], f.img.Pix[so:so+r.Dx()*4])
	}
	return out
}

type fakeCapturer struct{ f *fakeScreen }

func (c fakeCapturer) Monitors() ([]Monitor, error) {
	c.f.mu.Lock()
	defer c.f.mu.Unlock()
	return append([]Monitor(nil), c.f.monitors...), nil
}

func (c fakeCapturer) Capture(r image.Rectangle, _ *image.RGBA) (*image.RGBA, error) {
	return c.f.region(r), nil
}

func (c fakeCapturer) Close() error {
	c.f.closed.Add(1)
	return nil
}

type fakeInjector struct {
	mu     sync.Mutex
	events []string
	opened atomic.Int32
}

func (in *fakeInjector) log(format string, a ...any) error {
	in.mu.Lock()
	defer in.mu.Unlock()
	in.events = append(in.events, fmt.Sprintf(format, a...))
	return nil
}

func (in *fakeInjector) snapshot() []string {
	in.mu.Lock()
	defer in.mu.Unlock()
	return append([]string(nil), in.events...)
}

func (in *fakeInjector) Pointer(x, y int, b uint8) error { return in.log("pointer %d %d %d", x, y, b) }
func (in *fakeInjector) Wheel(dx, dy int) error          { return in.log("wheel %d %d", dx, dy) }
func (in *fakeInjector) Key(u uint16, down bool) error   { return in.log("key %#x %v", u, down) }
func (in *fakeInjector) Text(s string) error             { return in.log("text %q", s) }
func (in *fakeInjector) Close() error                    { return in.log("close") }

type fakeClipboard struct {
	mu   sync.Mutex
	seq  uint64
	text string
}

func (c *fakeClipboard) Sequence() (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.seq, nil
}

func (c *fakeClipboard) ReadText() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.text, nil
}

func (c *fakeClipboard) WriteText(s string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.text = s
	c.seq++
	return nil
}

func (c *fakeClipboard) Close() error { return nil }

type indicatorLog struct {
	mu     sync.Mutex
	events []SessionEvent
}

func (l *indicatorLog) add(e SessionEvent) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, e)
}

func (l *indicatorLog) list() []SessionEvent {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]SessionEvent(nil), l.events...)
}

type harness struct {
	srv    *Server
	addr   netip.AddrPort
	screen *fakeScreen
	inj    *fakeInjector
	clip   *fakeClipboard
	ind    *indicatorLog
	allow  atomic.Pointer[Decision]
	cancel context.CancelFunc
	done   chan error
}

func newHarness(t *testing.T, mutate func(*Config)) *harness {
	t.Helper()
	h := &harness{screen: newFakeScreen(), inj: &fakeInjector{}, clip: &fakeClipboard{}, ind: &indicatorLog{}}
	h.allow.Store(&Decision{Allowed: true, Unattended: true, Peer: "laptop"})
	cfg := Config{
		ListenAddr: netip.MustParseAddrPort("127.0.0.1:0"),
		Authorize: func(remote netip.Addr, mode Mode) Decision {
			if !remote.IsLoopback() {
				return Decision{}
			}
			d := *h.allow.Load()
			if mode == ModeControl && d.Reason == "view-only" {
				d.Allowed = false
			}
			return d
		},
		Indicator:   h.ind.add,
		NewCapturer: func() (Capturer, error) { h.screen.opened.Add(1); return fakeCapturer{h.screen}, nil },
		NewInjector: func() (Injector, error) {
			h.inj.opened.Add(1)
			return h.inj, nil
		},
		NewClipboard: func() (Clipboard, error) { return h.clip, nil },
		MaxFPS:       30,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h.srv = srv
	h.addr = ln.Addr().(*net.TCPAddr).AddrPort()
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	h.done = make(chan error, 1)
	go func() { h.done <- srv.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		_ = srv.Close()
		<-h.done
	})
	return h
}

func testCtx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestNewRequiresCallbacks(t *testing.T) {
	if _, err := New(Config{Indicator: func(SessionEvent) {}}); err == nil {
		t.Fatal("Authorize must be required")
	}
	if _, err := New(Config{Authorize: func(netip.Addr, Mode) Decision { return Decision{} }}); err == nil {
		t.Fatal("Indicator must be required")
	}
	for _, a := range []string{"0.0.0.0:4047", "[::]:4047", "127.0.0.1:0", "224.0.0.1:4047"} {
		if err := ValidateListenAddr(netip.MustParseAddrPort(a)); !errors.Is(err, ErrInvalidListenAddr) {
			t.Errorf("%s must be rejected", a)
		}
	}
	if ValidateListenAddr(netip.AddrPort{}) == nil || ValidateListenAddr(netip.MustParseAddrPort("100.64.0.2:4047")) != nil {
		t.Fatal("ValidateListenAddr")
	}
	srv, err := New(Config{Authorize: func(netip.Addr, Mode) Decision { return Decision{} }, Indicator: func(SessionEvent) {}, ListenAddr: netip.MustParseAddrPort("0.0.0.0:4047")})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.ListenAndServe(context.Background()); !errors.Is(err, ErrInvalidListenAddr) {
		t.Fatalf("wildcard listen: %v", err)
	}
}

func TestViewSessionSnapshot(t *testing.T) {
	h := newHarness(t, nil)
	img, mons, err := Snapshot(testCtx(t), h.addr, MonitorPrimary)
	if err != nil {
		t.Fatal(err)
	}
	if len(mons) != 2 || !mons[0].Primary {
		t.Fatalf("monitors %+v", mons)
	}
	want := h.screen.region(image.Rect(0, 0, 200, 120))
	if !bytes.Equal(img.Pix, want.Pix) {
		t.Fatal("snapshot differs from the screen")
	}
	if h.inj.opened.Load() != 0 {
		t.Fatal("a view session must not open input injection")
	}
	waitFor(t, "session end", func() bool { return len(h.ind.list()) == 2 })
	ev := h.ind.list()
	if ev[0].Kind != EventStart || ev[1].Kind != EventEnd || ev[0].Peer != "laptop" || !ev[0].Unattended || ev[0].Mode != ModeView || ev[0].ID != ev[1].ID {
		t.Fatalf("indicator events %+v", ev)
	}
	waitFor(t, "capturer close", func() bool { return h.screen.closed.Load() == 1 })
}

func TestIncrementalFramesAndMonitorSwitch(t *testing.T) {
	h := newHarness(t, nil)
	ctx := testCtx(t)
	c, err := Dial(ctx, h.addr, DialOptions{Monitor: 0, Scale: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.NextFrame(ctx); err != nil {
		t.Fatal(err)
	}
	h.screen.set(150, 100, 0xAB)
	img, err := c.NextFrame(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if img.Pix[img.PixOffset(150, 100)] != 0xAB {
		t.Fatal("changed pixel not received")
	}
	if err := c.SelectMonitor(1); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "monitor switch", func() bool { return c.Desktop().Monitor == 1 })
	img, err = c.NextFrame(ctx)
	for err == nil && img.Rect.Dx() != 130 {
		img, err = c.NextFrame(ctx)
	}
	if err != nil || !bytes.Equal(img.Pix, h.screen.region(image.Rect(200, 0, 330, 90)).Pix) {
		t.Fatalf("second monitor: %v", err)
	}
	if err := c.SelectMonitor(MonitorAll); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "all monitors", func() bool { return c.Desktop().Monitor == MonitorAll })
	if dk := c.Desktop(); dk.Width != 330 || dk.Height != 120 {
		t.Fatalf("all monitors desktop %+v", dk)
	}
	if err := c.SetQuality(5, 2); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "scale change", func() bool { return c.Desktop().Scale == 2 })
	if dk := c.Desktop(); dk.Width != 165 || dk.Height != 60 {
		t.Fatalf("scaled desktop %+v", dk)
	}
	if err := c.SendPointer(1, 1, 0); !errors.Is(err, errViewOnly) {
		t.Fatal("view client must refuse to send input")
	}
}

func TestViewSessionCannotInject(t *testing.T) {
	h := newHarness(t, nil)
	ctx := testCtx(t)
	c, err := Dial(ctx, h.addr, DialOptions{Mode: ModeView})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.NextFrame(ctx); err != nil {
		t.Fatal(err)
	}
	// Bypass the client-side check: the server must end the session.
	if err := c.write(pointerEvent{x: 1, y: 1, buttons: ButtonLeft}.encode()); err != nil {
		t.Fatal(err)
	}
	if err := c.write(encodeKey(0x04, true)); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Log(err)
	}
	waitFor(t, "session end", func() bool { return c.Err() != nil })
	if !errors.Is(c.Err(), ErrSessionEnded) {
		t.Fatalf("err = %v", c.Err())
	}
	if h.inj.opened.Load() != 0 || len(h.inj.snapshot()) != 0 {
		t.Fatal("input reached the injector in a view session")
	}
}

func TestControlSession(t *testing.T) {
	h := newHarness(t, nil)
	ctx := testCtx(t)
	got := make(chan string, 4)
	c, err := Dial(ctx, h.addr, DialOptions{Mode: ModeControl, Monitor: 1, Scale: 1, OnClipboard: func(s string) { got <- s }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.NextFrame(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.SendPointer(10, 20, ButtonLeft); err != nil {
		t.Fatal(err)
	}
	if err := c.SendWheel(0, -2); err != nil {
		t.Fatal(err)
	}
	if err := c.SendKey(0xE1, true); err != nil { // left shift, left pressed
		t.Fatal(err)
	}
	if err := c.SendText("ab\x07\r\nç"); err != nil {
		t.Fatal(err)
	}
	// Clipboard sharing is off until the viewer turns it on (#122).
	if c.ClipboardShared() || c.SendClipboard("erken") == nil {
		t.Fatal("clipboard must start off")
	}
	if err := c.SetClipboard(ctx, true); err != nil {
		t.Fatal(err)
	}
	if err := c.SendClipboard("uzaktan"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "clipboard write", func() bool { s, _ := h.clip.ReadText(); return s == "uzaktan" })
	// A local copy reaches the client; the client's own text is not echoed.
	if err := h.clip.WriteText("yerel"); err != nil {
		t.Fatal(err)
	}
	select {
	case s := <-got:
		if s != "yerel" {
			t.Fatalf("clipboard from server: %q", s)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("clipboard not shared")
	}
	_ = c.Close()
	waitFor(t, "injector close", func() bool {
		ev := h.inj.snapshot()
		return len(ev) > 0 && ev[len(ev)-1] == "close"
	})
	want := []string{
		"pointer 210 20 1",
		"wheel 0 -2",
		"key 0xe1 true",
		`text "ab\nç"`,
		"key 0xe1 false",   // released at session end
		"pointer 210 20 0", // button released where it was pressed
		"close",
	}
	ev := h.inj.snapshot()
	if fmt.Sprint(ev) != fmt.Sprint(want) {
		t.Fatalf("injected events\n got %q\nwant %q", ev, want)
	}
}

func TestDeniedRefusedAndBusy(t *testing.T) {
	consent := make(chan bool, 1)
	h := newHarness(t, func(c *Config) {
		c.MaxSessions = 2
		c.Consent = func(ctx context.Context, req ConsentRequest) bool {
			if req.Peer != "telefon" {
				return false
			}
			select {
			case ok := <-consent:
				return ok
			case <-ctx.Done():
				return false
			}
		}
		c.ConsentTimeout = 300 * time.Millisecond
	})
	ctx := testCtx(t)

	h.allow.Store(&Decision{Allowed: false, Peer: "laptop"})
	if _, err := Dial(ctx, h.addr, DialOptions{}); !errors.Is(err, ErrDenied) {
		t.Fatalf("denied: %v", err)
	}
	h.allow.Store(&Decision{Allowed: true, Unattended: true, Peer: "laptop", Reason: "view-only"})
	if _, err := Dial(ctx, h.addr, DialOptions{Mode: ModeControl}); !errors.Is(err, ErrDenied) {
		t.Fatalf("control without permission: %v", err)
	}

	// Attended: refused, timed out, accepted.
	h.allow.Store(&Decision{Allowed: true, Peer: "telefon"})
	consent <- false
	if _, err := Dial(ctx, h.addr, DialOptions{}); !errors.Is(err, ErrRefused) {
		t.Fatalf("refused: %v", err)
	}
	if _, err := Dial(ctx, h.addr, DialOptions{}); !errors.Is(err, ErrRefused) {
		t.Fatalf("consent timeout must refuse: %v", err)
	}
	consent <- true
	c1, err := Dial(ctx, h.addr, DialOptions{Mode: ModeControl})
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()
	if _, err := c1.NextFrame(ctx); err != nil {
		t.Fatal(err)
	}
	if ev := h.ind.list(); len(ev) != 1 || ev[0].Unattended {
		t.Fatalf("attended session must be marked attended: %+v", ev)
	}

	// Only one control session at a time.
	h.allow.Store(&Decision{Allowed: true, Unattended: true, Peer: "laptop"})
	if _, err := Dial(ctx, h.addr, DialOptions{Mode: ModeControl}); !errors.Is(err, ErrBusy) {
		t.Fatalf("second control session: %v", err)
	}
	c2, err := Dial(ctx, h.addr, DialOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	if _, err := Dial(ctx, h.addr, DialOptions{}); !errors.Is(err, ErrBusy) {
		t.Fatalf("session limit: %v", err)
	}
	if h.srv.ActiveSessions() != 2 {
		t.Fatal("ActiveSessions")
	}
}

func TestNoConsentCallbackRefuses(t *testing.T) {
	h := newHarness(t, nil)
	h.allow.Store(&Decision{Allowed: true, Peer: "laptop"})
	if _, err := Dial(testCtx(t), h.addr, DialOptions{}); !errors.Is(err, ErrRefused) {
		t.Fatalf("attended session without a consent prompt: %v", err)
	}
	if len(h.ind.list()) != 0 || h.screen.opened.Load() != 0 {
		t.Fatal("refused session must not open the screen")
	}
}

func TestRevalidateEndsSessions(t *testing.T) {
	h := newHarness(t, func(c *Config) {
		c.Consent = func(context.Context, ConsentRequest) bool { return true }
	})
	ctx := testCtx(t)
	h.allow.Store(&Decision{Allowed: true, Peer: "laptop"})
	attended, err := Dial(ctx, h.addr, DialOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer attended.Close()
	h.allow.Store(&Decision{Allowed: true, Unattended: true, Peer: "laptop"})
	unattended, err := Dial(ctx, h.addr, DialOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer unattended.Close()
	waitFor(t, "two sessions", func() bool { return h.srv.ActiveSessions() == 2 })

	// Unattended permission withdrawn: only the session that skipped the
	// prompt ends.
	h.allow.Store(&Decision{Allowed: true, Peer: "laptop"})
	if n := h.srv.Revalidate(); n != 1 {
		t.Fatalf("Revalidate closed %d", n)
	}
	waitFor(t, "unattended end", func() bool { return unattended.Err() != nil })
	if attended.Err() != nil {
		t.Fatal("approved session must survive")
	}
	// The client sees the close before the server drops the session from
	// its table; under load a second Revalidate could still count it.
	waitFor(t, "one session", func() bool { return h.srv.ActiveSessions() == 1 })
	h.allow.Store(&Decision{Allowed: false})
	if n := h.srv.Revalidate(); n != 1 {
		t.Fatalf("Revalidate closed %d", n)
	}
	waitFor(t, "attended end", func() bool { return attended.Err() != nil })
	waitFor(t, "end events", func() bool {
		n := 0
		for _, e := range h.ind.list() {
			if e.Kind == EventEnd && e.Reason == "izin geri alındı" {
				n++
			}
		}
		return n == 2
	})
}

func TestIdleTimeoutAndUnsupported(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.IdleTimeout = 300 * time.Millisecond })
	ctx := testCtx(t)
	c, err := Dial(ctx, h.addr, DialOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	waitFor(t, "idle end", func() bool { return c.Err() != nil })
	if !errors.Is(c.Err(), ErrSessionEnded) {
		t.Fatal(c.Err())
	}

	u := newHarness(t, func(c *Config) {
		c.NewCapturer = func() (Capturer, error) { return nil, ErrUnsupported }
	})
	if _, err := Dial(ctx, u.addr, DialOptions{}); !errors.Is(err, ErrRemoteUnsupported) {
		t.Fatalf("unsupported: %v", err)
	}
	if len(u.ind.list()) != 0 {
		t.Fatal("no indicator for a session that never started")
	}
}

func TestBadHello(t *testing.T) {
	h := newHarness(t, nil)
	conn, err := net.Dial("tcp", h.addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	bad := hello{version: 9, mode: ModeView}
	if _, err := conn.Write(bad.encode()); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64)
	n, _ := conn.Read(buf)
	if n < headerLen+1 || msgType(buf[0]) != msgWelcome || buf[headerLen] != statusBadRequest {
		t.Fatalf("bad version answer % x", buf[:n])
	}
	if h.ind.list() != nil {
		t.Fatal("no session for a bad hello")
	}
}

func TestServerClose(t *testing.T) {
	h := newHarness(t, nil)
	ctx := testCtx(t)
	c, err := Dial(ctx, h.addr, DialOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.NextFrame(ctx); err != nil {
		t.Fatal(err)
	}
	h.cancel()
	select {
	case err := <-h.done:
		h.done <- err
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not stop")
	}
	waitFor(t, "client end", func() bool { return c.Err() != nil })
}

type flakyCapturer struct {
	fakeCapturer
	fails *atomic.Int32
}

func (c flakyCapturer) Capture(r image.Rectangle, dst *image.RGBA) (*image.RGBA, error) {
	if c.fails.Add(-1) >= 0 {
		return nil, ErrScreenUnavailable
	}
	return c.fakeCapturer.Capture(r, dst)
}

func TestCaptureFailureIsRetried(t *testing.T) {
	var fails atomic.Int32
	fails.Store(2)
	var h *harness
	h = newHarness(t, func(c *Config) {
		c.NewCapturer = func() (Capturer, error) { return flakyCapturer{fakeCapturer{h.screen}, &fails}, nil }
	})
	img, _, err := Snapshot(testCtx(t), h.addr, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(img.Pix, h.screen.region(image.Rect(200, 0, 330, 90)).Pix) {
		t.Fatal("frame after the screen became readable")
	}
}
