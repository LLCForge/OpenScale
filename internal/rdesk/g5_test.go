package rdesk

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// g5Dir returns a per-test folder inside the package (never the system
// temporary directory) and removes it afterwards.
func g5Dir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join("testdata", ".g5tmp", strings.NewReplacer("/", "_", "\\", "_").Replace(t.Name()))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(dir)
		_ = os.Remove(filepath.Join("testdata", ".g5tmp"))
		_ = os.Remove("testdata")
	})
	return dir
}

type fakeVerifier struct {
	mu    sync.Mutex
	user  string
	pass  string
	calls int
	seen  [][]byte
}

func (v *fakeVerifier) Verify(_ context.Context, user string, pw []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.calls++
	v.seen = append(v.seen, pw) // the caller wipes this slice afterwards
	if user == v.user && string(pw) == v.pass {
		return nil
	}
	return ErrOSLoginFailed
}

func fastGuard(onBlock func(BlockEvent)) *LoginGuard {
	return NewLoginGuard(LoginGuardConfig{BaseDelay: time.Millisecond, MaxDelay: 4 * time.Millisecond, OnBlock: onBlock})
}

func TestLoginGuardDelaysAndBlocks(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	var blocked []BlockEvent
	g := NewLoginGuard(LoginGuardConfig{Now: func() time.Time { return now }, OnBlock: func(e BlockEvent) { blocked = append(blocked, e) }})
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second}
	for i, w := range want {
		d, until := g.Failure("10.0.0.2")
		if d != w || !until.IsZero() {
			t.Fatalf("failure %d: delay %v until %v", i+1, d, until)
		}
	}
	d, until := g.Failure("10.0.0.2")
	if d != 16*time.Second || !until.Equal(now.Add(15*time.Minute)) {
		t.Fatalf("fifth failure: %v %v", d, until)
	}
	if len(blocked) != 1 || blocked[0].Source != "10.0.0.2" || blocked[0].Failures != 5 {
		t.Fatalf("block event: %+v", blocked)
	}
	if _, ok := g.Blocked("10.0.0.2"); !ok {
		t.Fatal("source should be blocked")
	}
	g.Success("10.0.0.2")
	if _, ok := g.Blocked("10.0.0.2"); !ok {
		t.Fatal("success must not lift an active block")
	}
	if _, ok := g.Blocked("10.0.0.3"); ok {
		t.Fatal("other source blocked")
	}
	now = now.Add(15*time.Minute + time.Second)
	if _, ok := g.Blocked("10.0.0.2"); ok {
		t.Fatal("block should have expired")
	}
	// Failures outside the window are forgotten.
	g.Failure("10.0.0.4")
	now = now.Add(16 * time.Minute)
	if d, _ := g.Failure("10.0.0.4"); d != time.Second {
		t.Fatalf("old failure not forgotten: %v", d)
	}
}

func TestLoginGuardBounded(t *testing.T) {
	g := NewLoginGuard(LoginGuardConfig{MaxSources: 4})
	for i := range 50 {
		g.Failure(string(rune('a' + i)))
	}
	g.mu.Lock()
	n := len(g.sources)
	g.mu.Unlock()
	if n > 4 {
		t.Fatalf("guard grew to %d sources", n)
	}
}

func TestLoginWireRoundTrip(t *testing.T) {
	msg, err := encodeLogin("ofis\\ayşe", []byte("çok-gizli"))
	if err != nil {
		t.Fatal(err)
	}
	user, pw, err := decodeLogin(msg[headerLen:])
	if err != nil || user != "ofis\\ayşe" || string(pw) != "çok-gizli" {
		t.Fatalf("round trip: %q %q %v", user, pw, err)
	}
	for _, bad := range [][]byte{{}, {0}, {3, 'a', 'b'}, {1, 0x01, 0, 0}, {1, 'a', 0xff, 0xff}} {
		if _, _, err := decodeLogin(bad); err == nil {
			t.Fatalf("accepted %x", bad)
		}
	}
	if _, err := encodeLogin("", nil); err == nil {
		t.Fatal("empty user accepted")
	}
	if _, err := encodeLogin("u", make([]byte, maxLoginPassword+1)); err == nil {
		t.Fatal("long password accepted")
	}
}

func credsFrom(list ...LoginCredentials) (CredentialsFunc, *atomic.Int32) {
	var n atomic.Int32
	return func(_ context.Context, req LoginRequest) (LoginCredentials, error) {
		i := int(n.Add(1)) - 1
		if i >= len(list) {
			return LoginCredentials{}, errors.New("vazgeçildi")
		}
		c := list[i]
		c.Password = append([]byte(nil), c.Password...)
		return c, nil
	}, &n
}

func TestOSLoginSession(t *testing.T) {
	v := &fakeVerifier{user: "ayse", pass: "doğru-parola"}
	var summaries []SessionSummary
	var smu sync.Mutex
	h := newHarness(t, func(c *Config) {
		c.OSLogin = &OSLoginConfig{Verifier: v, Guard: fastGuard(nil), Hint: "Windows hesabı"}
		c.Summary = func(s SessionSummary) { smu.Lock(); summaries = append(summaries, s); smu.Unlock() }
	})
	ctx := testCtx(t)
	// No credentials callback: the viewer learns that an account is needed.
	if _, err := Dial(ctx, h.addr, DialOptions{Scale: 1}); !errors.Is(err, ErrLoginRequired) {
		t.Fatalf("without credentials: %v", err)
	}
	// One wrong password, then the right one.
	creds, n := credsFrom(LoginCredentials{User: "ayse", Password: []byte("yanlış")}, LoginCredentials{User: "ayse", Password: []byte("doğru-parola")})
	c, err := Dial(ctx, h.addr, DialOptions{Scale: 1, Credentials: creds})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.NextFrame(ctx); err != nil {
		t.Fatal(err)
	}
	if n.Load() != 2 {
		t.Fatalf("credentials asked %d times", n.Load())
	}
	_ = c.Close()
	waitFor(t, "summary", func() bool { smu.Lock(); defer smu.Unlock(); return len(summaries) == 1 })
	if summaries[0].OSUser != "ayse" || summaries[0].Peer != "laptop" || summaries[0].Mode != "view" {
		t.Fatalf("summary: %+v", summaries[0])
	}
	v.mu.Lock()
	for _, pw := range v.seen {
		for _, b := range pw {
			if b != 0 {
				t.Fatalf("password not wiped after verification: %q", pw)
			}
		}
	}
	v.mu.Unlock()
	for _, e := range h.ind.list() {
		if strings.Contains(e.Reason, "doğru-parola") {
			t.Fatal("password reached the indicator")
		}
	}
}

func TestOSLoginBlocksAfterFailures(t *testing.T) {
	var events atomic.Int32
	v := &fakeVerifier{user: "ayse", pass: "p"}
	h := newHarness(t, func(c *Config) {
		c.OSLogin = &OSLoginConfig{Verifier: v, Guard: fastGuard(func(BlockEvent) { events.Add(1) })}
	})
	ctx := testCtx(t)
	wrong := make([]LoginCredentials, 10)
	for i := range wrong {
		wrong[i] = LoginCredentials{User: "ayse", Password: []byte("x")}
	}
	creds, n := credsFrom(wrong...)
	_, err := Dial(ctx, h.addr, DialOptions{Scale: 1, Credentials: creds})
	if !errors.Is(err, ErrLoginBlocked) {
		t.Fatalf("expected block, got %v", err)
	}
	if n.Load() != 5 || events.Load() != 1 {
		t.Fatalf("attempts %d, block events %d", n.Load(), events.Load())
	}
	// While blocked even the right password is not checked.
	before := v.calls
	creds2, _ := credsFrom(LoginCredentials{User: "ayse", Password: []byte("p")})
	_, err = Dial(ctx, h.addr, DialOptions{Scale: 1, Credentials: creds2})
	if !errors.Is(err, ErrDenied) || !strings.Contains(err.Error(), "dakika") {
		t.Fatalf("blocked source: %v", err)
	}
	if v.calls != before {
		t.Fatal("verifier called while blocked")
	}
}

func TestOSLoginRefusesOldViewer(t *testing.T) {
	h := newHarness(t, func(c *Config) {
		c.OSLogin = &OSLoginConfig{Verifier: &fakeVerifier{user: "a", pass: "b"}}
	})
	ctx := testCtx(t)
	_, err := dialVersion(ctx, h.addr, DialOptions{Mode: ModeView, Scale: 1, HandshakeTimeout: 5 * time.Second}, ProtocolVersionExt)
	if !errors.Is(err, ErrDenied) || !strings.Contains(err.Error(), "güncelleyin") {
		t.Fatalf("version 3 viewer: %v", err)
	}
}

func TestOSLoginUnavailableIsNotCounted(t *testing.T) {
	g := fastGuard(nil)
	h := newHarness(t, func(c *Config) {
		c.OSLogin = &OSLoginConfig{Guard: g, Verifier: OSVerifierFunc(func(context.Context, string, []byte) error { return ErrOSLoginUnavailable })}
	})
	creds, _ := credsFrom(LoginCredentials{User: "a", Password: []byte("b")})
	if _, err := Dial(testCtx(t), h.addr, DialOptions{Scale: 1, Credentials: creds}); !errors.Is(err, ErrLoginRejected) {
		t.Fatalf("unavailable verifier: %v", err)
	}
	g.mu.Lock()
	n := len(g.sources)
	g.mu.Unlock()
	if n != 0 {
		t.Fatal("a broken verifier counted as a wrong password")
	}
}

func TestChannels(t *testing.T) {
	s := &Server{}
	if c := s.effectiveChannels(Decision{Allowed: true}, ModeControl); !c.Has(ChanView|ChanInput|ChanClipboard|ChanCurtain) || c.Has(ChanFiles) {
		t.Fatalf("legacy control: %s", c)
	}
	if c := s.effectiveChannels(Decision{Allowed: true, Files: true}, ModeView); c != ChanView {
		t.Fatalf("view session got %s", c)
	}
	s.cfg.StrictChannels = true
	if c := s.effectiveChannels(Decision{Allowed: true}, ModeControl); c != ChanView|ChanInput {
		t.Fatalf("strict control: %s", c)
	}
	if s.decisionPermits(Decision{Allowed: true, Channels: ChanView}, ModeControl) {
		t.Fatal("control without input permitted")
	}
	if !s.decisionPermits(Decision{Allowed: true, Channels: ChanView}, ModeView) {
		t.Fatal("view refused")
	}
	c, ok := ParseChannels("view, input,clipboard")
	if !ok || c != ChanView|ChanInput|ChanClipboard || c.String() != "view,input,clipboard" {
		t.Fatalf("parse: %v %s", ok, c)
	}
	if _, ok := ParseChannels("view,mikrofon"); ok {
		t.Fatal("unknown channel accepted")
	}
}

func TestClipboardAndCurtainNeedChannels(t *testing.T) {
	h := newHarness(t, func(c *Config) {
		c.NewLocalLock = func() (LocalLock, error) { return &fakeLock{}, nil }
	})
	h.allow.Store(&Decision{Allowed: true, Unattended: true, Peer: "laptop", Channels: ChanView | ChanInput})
	ctx := testCtx(t)
	c, err := Dial(ctx, h.addr, DialOptions{Mode: ModeControl, Scale: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.SetClipboard(ctx, true); !errors.Is(err, ErrExtRefused) {
		t.Fatalf("clipboard without channel: %v", err)
	}
	if err := c.SetLocalLock(ctx, LockState{Blank: true}); !errors.Is(err, ErrExtRefused) {
		t.Fatalf("curtain without channel: %v", err)
	}
	h.allow.Store(&Decision{Allowed: true, Unattended: true, Peer: "laptop", Channels: ChanView | ChanInput | ChanClipboard | ChanCurtain})
	if err := c.SetClipboard(ctx, true); err != nil {
		t.Fatalf("clipboard with channel: %v", err)
	}
	if err := c.SetLocalLock(ctx, LockState{Blank: true}); err != nil {
		t.Fatalf("curtain with channel: %v", err)
	}
	// A control session without the input channel does not start.
	h.allow.Store(&Decision{Allowed: true, Unattended: true, Peer: "laptop", Channels: ChanView})
	if _, err := Dial(ctx, h.addr, DialOptions{Mode: ModeControl, Scale: 1}); !errors.Is(err, ErrDenied) {
		t.Fatalf("control without input: %v", err)
	}
}

type fakeFrame struct {
	mu     sync.Mutex
	opened []FrameInfo
	closed int
	fail   bool
}

func (f *fakeFrame) open(fi FrameInfo) (SessionFrame, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return nil, errors.New("çerçeve yok")
	}
	f.opened = append(f.opened, fi)
	return frameCloser{f}, nil
}

type frameCloser struct{ f *fakeFrame }

func (c frameCloser) Close() error {
	c.f.mu.Lock()
	c.f.closed++
	c.f.mu.Unlock()
	return nil
}

func TestFrameShownAndRequired(t *testing.T) {
	ff := &fakeFrame{}
	h := newHarness(t, func(c *Config) { c.NewFrame = ff.open; c.RequireFrame = true })
	ctx := testCtx(t)
	c, err := Dial(ctx, h.addr, DialOptions{Scale: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.NextFrame(ctx); err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	waitFor(t, "frame closed", func() bool { ff.mu.Lock(); defer ff.mu.Unlock(); return ff.closed == 1 })
	if ff.opened[0].Peer != "laptop" || !strings.Contains(ff.opened[0].Text(), "Uzaktan bağlı: laptop") {
		t.Fatalf("frame: %+v %q", ff.opened[0], ff.opened[0].Text())
	}
	ff.mu.Lock()
	ff.fail = true
	ff.mu.Unlock()
	if _, err := Dial(ctx, h.addr, DialOptions{Scale: 1}); !errors.Is(err, ErrRemoteUnsupported) {
		t.Fatalf("required frame missing: %v", err)
	}
	// Without RequireFrame a missing frame does not stop the session.
	ff2 := &fakeFrame{fail: true}
	h2 := newHarness(t, func(c *Config) { c.NewFrame = ff2.open })
	c2, err := Dial(ctx, h2.addr, DialOptions{Scale: 1})
	if err != nil {
		t.Fatal(err)
	}
	_ = c2.Close()
}

func TestKillAllBlocksNewSessions(t *testing.T) {
	h := newHarness(t, nil)
	ctx := testCtx(t)
	c, err := Dial(ctx, h.addr, DialOptions{Mode: ModeControl, Scale: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.NextFrame(ctx); err != nil {
		t.Fatal(err)
	}
	if n := h.srv.KillAll(10*time.Minute, ""); n != 1 {
		t.Fatalf("killed %d", n)
	}
	waitFor(t, "session ended", func() bool { return h.srv.ActiveSessions() == 0 })
	if _, err := Dial(ctx, h.addr, DialOptions{Scale: 1}); !errors.Is(err, ErrDenied) || !strings.Contains(err.Error(), "kesti") {
		t.Fatalf("dial during block: %v", err)
	}
	if _, ok := h.srv.KillBlockedUntil(); !ok {
		t.Fatal("no block")
	}
	h.srv.LiftKillBlock()
	c2, err := Dial(ctx, h.addr, DialOptions{Scale: 1})
	if err != nil {
		t.Fatalf("after lifting the block: %v", err)
	}
	_ = c2.Close()
}

func TestHotkeyParse(t *testing.T) {
	h, ok := ParseHotkey("ctrl + alt + shift + k")
	if !ok || h != DefaultKillHotkey || h.String() != "Ctrl+Alt+Shift+K" {
		t.Fatalf("parse: %v %+v %s", ok, h, h)
	}
	for _, bad := range []string{"K", "Ctrl+K", "Ctrl+Alt+F1", "Ctrl++K", "Hyper+Alt+K", ""} {
		if _, ok := ParseHotkey(bad); ok {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func TestSummaryLogChain(t *testing.T) {
	dir := g5Dir(t)
	key, err := LoadOrCreateSummaryKey(filepath.Join(dir, "summary.key"))
	if err != nil {
		t.Fatal(err)
	}
	again, err := LoadOrCreateSummaryKey(filepath.Join(dir, "summary.key"))
	if err != nil || !bytes.Equal(key, again) {
		t.Fatal("summary key not stable")
	}
	path := filepath.Join(dir, "sessions.jsonl")
	log, err := OpenSummaryLog(path, key)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 10, 30, 9, 0, 0, 0, time.UTC)
	for i := range 3 {
		s := SessionSummary{Version: SummaryVersion, ID: uint64(i + 1), Peer: "laptop", Mode: "control", Start: start, End: start.Add(time.Minute), Seconds: 60,
			Files: []FileTransfer{{Path: "Belgeler/rapor.pdf", Size: 10, SHA256: strings.Repeat("ab", 32)}}}
		if _, err := log.Append(s); err != nil {
			t.Fatal(err)
		}
	}
	pub := key.Public().(ed25519.PublicKey)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifySummaryLog(bytes.NewReader(data), pub)
	if err != nil || len(got) != 3 || got[2].ID != 3 || got[0].Files[0].Path != "Belgeler/rapor.pdf" {
		t.Fatalf("verify: %v %+v", err, got)
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	// Removing a line breaks the chain.
	cut := bytes.Join([][]byte{lines[0], lines[2]}, []byte("\n"))
	if _, err := VerifySummaryLog(bytes.NewReader(cut), pub); err == nil || !strings.Contains(err.Error(), "zincir") {
		t.Fatalf("removed line not detected: %v", err)
	}
	// Editing a summary breaks the signature.
	edited := bytes.Replace(data, []byte(`"peer":"laptop"`), []byte(`"peer":"masaust"`), 1)
	if _, err := VerifySummaryLog(bytes.NewReader(edited), pub); err == nil {
		t.Fatal("edited summary accepted")
	}
	// Another key does not verify.
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := VerifySummaryLog(bytes.NewReader(data), other); err == nil {
		t.Fatal("foreign key accepted")
	}
}

func TestSummaryRecordsFiles(t *testing.T) {
	sess := &session{peer: "p", mode: ModeControl}
	var sum [32]byte
	for range maxSummaryFiles + 3 {
		sess.sum.addFile("a/b", 1, sum)
	}
	sess.sum.mark(true, false)
	s := sess.summary(time.Unix(0, 0), time.Unix(90, 0), "bitti")
	if len(s.Files) != maxSummaryFiles || s.FilesOmitted != 3 || !s.Clipboard || s.Curtain || s.Seconds != 90 || !s.Unattended {
		t.Fatalf("summary: files %d omitted %d %+v", len(s.Files), s.FilesOmitted, s)
	}
}

func TestMacKeyTable(t *testing.T) {
	// Letters, digits, arrows and modifiers are all mapped, and no two
	// letters share a code.
	seen := map[uint16]uint16{}
	for u := uint16(0x04); u <= 0x1d; u++ {
		c, ok := macKeyCodes[u]
		if !ok {
			t.Fatalf("letter %#x unmapped", u)
		}
		if prev, dup := seen[c]; dup {
			t.Fatalf("letters %#x and %#x share code %#x", prev, u, c)
		}
		seen[c] = u
	}
	for _, u := range []uint16{0x1e, 0x27, 0x28, 0x29, 0x2a, 0x4f, 0x50, 0x51, 0x52, 0xe0, 0xe3, 0xe7} {
		if _, ok := macKeyCodes[u]; !ok {
			t.Fatalf("usage %#x unmapped", u)
		}
	}
	if macModifierFlag(0xe1) != 1<<17 || macModifierFlag(0x04) != 0 {
		t.Fatal("modifier flags")
	}
}

// TestNoListenerOutsideLoopback guards the test rule: every G5 test server
// listens on 127.0.0.1.
func TestHarnessIsLoopback(t *testing.T) {
	h := newHarness(t, nil)
	if !h.addr.Addr().IsLoopback() {
		t.Fatal("test server not on loopback")
	}
	if _, ok := any(h.srv).(interface {
		KillAll(time.Duration, string) int
	}); !ok {
		t.Fatal("KillAll missing")
	}
	_ = net.IPv4len
}
