package rdesk

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"go/parser"
	"go/token"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestE2EVerificationCode(t *testing.T) {
	var mu sync.Mutex
	var req ConsentRequest
	h := newHarness(t, func(c *Config) {
		c.Consent = func(_ context.Context, r ConsentRequest) bool {
			mu.Lock()
			req = r
			mu.Unlock()
			return true
		}
	})
	h.allow.Store(&Decision{Allowed: true, Peer: "laptop"})
	ctx := testCtx(t)
	c, err := Dial(ctx, h.addr, DialOptions{Mode: ModeView, Scale: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.NextFrame(ctx); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	code := req.Code
	mu.Unlock()
	if len(code) != 7 || code != c.VerificationCode() {
		t.Fatalf("codes differ: prompt %q viewer %q", code, c.VerificationCode())
	}
	waitFor(t, "start event", func() bool { return len(h.ind.list()) > 0 })
	if ev := h.ind.list()[0]; ev.Code != code || ev.Recording {
		t.Fatalf("indicator event %+v", ev)
	}
}

// A version 1 hello is refused unless the device allows legacy clients.
func TestLegacyV1Refused(t *testing.T) {
	for _, allow := range []bool{false, true} {
		h := newHarness(t, func(c *Config) { c.AllowLegacyV1 = allow })
		conn, err := net.Dial("tcp", h.addr.String())
		if err != nil {
			t.Fatal(err)
		}
		hl := hello{version: ProtocolVersion, mode: ModeView, monitor: 0, scale: 1}
		if _, err := conn.Write(hl.encode()); err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		typ, p, err := readMsg(bufio.NewReader(conn), maxServerMsg)
		_ = conn.Close()
		if err != nil || typ != msgWelcome {
			t.Fatalf("allow=%v: %v %v", allow, typ, err)
		}
		st, _, _ := decodeWelcome(p)
		if allow != (st == statusOK) {
			t.Fatalf("allow=%v: status %d", allow, st)
		}
	}
}

// An accepting server that skips the key exchange is a downgrade.
func TestClientRejectsDowngrade(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _, _ = readMsg(bufio.NewReader(c), maxHelloBytes)
		_, _ = c.Write(encodeWelcome(statusOK, ""))
		time.Sleep(time.Second)
	}()
	_, err = Dial(testCtx(t), ln.Addr().(*net.TCPAddr).AddrPort(), DialOptions{})
	if !errors.Is(err, ErrProtocol) {
		t.Fatalf("downgrade accepted: %v", err)
	}
}

func TestWireTamperAndReplay(t *testing.T) {
	cpriv, _ := newE2EKey()
	hl := hello{mode: ModeView, scale: 1}.encodeV2(cpriv.PublicKey().Bytes())
	kex, sk, err := serverKex(hl[headerLen:], cpriv.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	ck, err := deriveE2E(cpriv, kex[headerLen:], hl[headerLen:], kex[headerLen:])
	if err != nil {
		t.Fatal(err)
	}
	if ck.code != sk.code {
		t.Fatal("codes differ")
	}
	tx := &wire{tx: sk.s2c}
	m1 := tx.seal(encodeMsg(msgKeepalive, nil))
	m2 := tx.seal(encodeSeq(msgFrameEnd, 7))
	read := func(data ...[]byte) (msgType, []byte, error) {
		w := &wire{br: bufio.NewReader(bytes.NewReader(bytes.Join(data, nil))), rx: ck.s2c}
		var t msgType
		var p []byte
		var err error
		for range data {
			if t, p, err = w.read(maxServerMsg); err != nil {
				return 0, nil, err
			}
		}
		return t, p, nil
	}
	if typ, p, err := read(m1, m2); err != nil || typ != msgFrameEnd || !bytes.Equal(p, []byte{0, 0, 0, 7}) {
		t.Fatalf("read %v %x %v", typ, p, err)
	}
	if _, _, err := read(m2); err == nil {
		t.Fatal("reordered record accepted")
	}
	if _, _, err := read(m1, m1); err == nil {
		t.Fatal("replayed record accepted")
	}
	bad := append([]byte(nil), m1...)
	bad[len(bad)-1] ^= 1
	if _, _, err := read(bad); err == nil {
		t.Fatal("tampered record accepted")
	}
	if _, _, err := read(encodeMsg(msgKeepalive, nil)); err == nil {
		t.Fatal("plaintext accepted after the key exchange")
	}
	if _, err := deriveE2E(cpriv, make([]byte, 32), hl, kex); err == nil {
		t.Fatal("low-order public key accepted")
	}
}

func TestClipboardOffByDefault(t *testing.T) {
	h := newHarness(t, nil)
	ctx := testCtx(t)
	got := make(chan string, 4)
	c, err := Dial(ctx, h.addr, DialOptions{Mode: ModeControl, Scale: 1, OnClipboard: func(s string) { got <- s }})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.NextFrame(ctx); err != nil {
		t.Fatal(err)
	}
	_ = h.clip.WriteText("gizli")
	select {
	case s := <-got:
		t.Fatalf("clipboard shared without opt-in: %q", s)
	case <-time.After(1500 * time.Millisecond):
	}
	// Opt-in through DialOptions.
	c2h := newHarness(t, nil)
	c2, err := Dial(ctx, c2h.addr, DialOptions{Mode: ModeControl, Scale: 1, Clipboard: true})
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	waitFor(t, "clipboard on", c2.ClipboardShared)
	// Refused when the device disables it.
	h3 := newHarness(t, func(c *Config) { c.DisableClipboard = true })
	c3, err := Dial(ctx, h3.addr, DialOptions{Mode: ModeControl, Scale: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer c3.Close()
	if err := c3.SetClipboard(ctx, true); !errors.Is(err, ErrExtRefused) {
		t.Fatalf("disabled clipboard: %v", err)
	}
}

type fakeLock struct {
	mu     sync.Mutex
	states []LockState
	notice string
	closed bool
}

func (l *fakeLock) Set(st LockState, notice string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.states = append(l.states, st)
	l.notice = notice
	return nil
}

func (l *fakeLock) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
	return nil
}

func TestLocalLock(t *testing.T) {
	lock := &fakeLock{}
	h := newHarness(t, func(c *Config) { c.NewLocalLock = func() (LocalLock, error) { return lock, nil } })
	ctx := testCtx(t)
	c, err := Dial(ctx, h.addr, DialOptions{Mode: ModeControl, Scale: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.SetLocalLock(ctx, LockState{Blank: true, Input: true}); err != nil {
		t.Fatal(err)
	}
	if c.LocalLock() != (LockState{Blank: true, Input: true}) {
		t.Fatal("lock state not confirmed")
	}
	lock.mu.Lock()
	notice := lock.notice
	lock.mu.Unlock()
	if !strings.Contains(notice, "laptop") {
		t.Fatalf("notice must name the viewer: %q", notice)
	}
	waitFor(t, "change event", func() bool {
		for _, ev := range h.ind.list() {
			if ev.Kind == EventChange && ev.LocalLock.Blank && ev.LocalLock.Input {
				return true
			}
		}
		return false
	})
	_ = c.Close()
	waitFor(t, "lock released", func() bool { lock.mu.Lock(); defer lock.mu.Unlock(); return lock.closed })

	// Refused without NewLocalLock; a view session cannot ask at all.
	h2 := newHarness(t, nil)
	c2, err := Dial(ctx, h2.addr, DialOptions{Mode: ModeControl, Scale: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	if err := c2.SetLocalLock(ctx, LockState{Blank: true}); !errors.Is(err, ErrExtRefused) {
		t.Fatalf("lock without permission: %v", err)
	}
	c3, err := Dial(ctx, h2.addr, DialOptions{Mode: ModeView, Scale: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer c3.Close()
	if err := c3.SetLocalLock(ctx, LockState{Blank: true}); !errors.Is(err, errViewOnly) {
		t.Fatalf("view session lock: %v", err)
	}
}

func TestRemoteRestart(t *testing.T) {
	reqs := make(chan PowerRequest, 2)
	h := newHarness(t, func(c *Config) {
		c.Power = func(_ context.Context, r PowerRequest) error { reqs <- r; return nil }
	})
	ctx := testCtx(t)
	c, err := Dial(ctx, h.addr, DialOptions{Mode: ModeControl, Scale: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.RequestRestart(ctx, true); err != nil {
		t.Fatal(err)
	}
	if r := <-reqs; !r.SafeMode || r.Peer != "laptop" {
		t.Fatalf("request %+v", r)
	}
	waitFor(t, "session end", func() bool { return c.Err() != nil })

	h2 := newHarness(t, nil)
	c2, err := Dial(ctx, h2.addr, DialOptions{Mode: ModeControl, Scale: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	if err := c2.RequestRestart(ctx, false); !errors.Is(err, ErrExtRefused) {
		t.Fatalf("restart without permission: %v", err)
	}
}

func TestDialRetryStopsOnDenial(t *testing.T) {
	h := newHarness(t, nil)
	h.allow.Store(&Decision{})
	start := time.Now()
	if _, err := DialRetry(testCtx(t), h.addr, DialOptions{}, time.Second); !errors.Is(err, ErrDenied) {
		t.Fatalf("denied: %v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("denial must not be retried")
	}
	// An unreachable device is retried until the context ends.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().(*net.TCPAddr).AddrPort()
	_ = ln.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	defer cancel()
	if _, err := DialRetry(ctx, addr, DialOptions{}, 2*time.Second); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("unreachable: %v", err)
	}
}

func TestControlSessionFrom(t *testing.T) {
	h := newHarness(t, nil)
	ctx := testCtx(t)
	lo := netip.MustParseAddr("127.0.0.1")
	if _, ok := h.srv.ControlSessionFrom(lo); ok {
		t.Fatal("no session yet")
	}
	v, err := Dial(ctx, h.addr, DialOptions{Mode: ModeView, Scale: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	if _, err := v.NextFrame(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := h.srv.ControlSessionFrom(lo); ok {
		t.Fatal("a view session must not count")
	}
	c, err := Dial(ctx, h.addr, DialOptions{Mode: ModeControl, Scale: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.NextFrame(ctx); err != nil {
		t.Fatal(err)
	}
	if peer, ok := h.srv.ControlSessionFrom(lo); !ok || peer != "laptop" {
		t.Fatalf("control session: %q %v", peer, ok)
	}
}

func TestRecording(t *testing.T) {
	dir := t.TempDir()
	key, err := LoadOrCreateRecordingKey(filepath.Join(dir, "keys", "recording.key"))
	if err != nil {
		t.Fatal(err)
	}
	again, err := LoadOrCreateRecordingKey(filepath.Join(dir, "keys", "recording.key"))
	if err != nil || again.key != key.key {
		t.Fatalf("key not reloaded: %v", err)
	}
	recDir := filepath.Join(dir, "rec")
	h := newHarness(t, func(c *Config) { c.Recording = &RecordingConfig{Dir: recDir, Key: key} })
	ctx := testCtx(t)
	c, err := Dial(ctx, h.addr, DialOptions{Mode: ModeView, Monitor: 0, Scale: 1})
	if err != nil {
		t.Fatal(err)
	}
	if !c.Recorded() {
		t.Fatal("viewer must learn that the session is recorded")
	}
	if _, err := c.NextFrame(ctx); err != nil {
		t.Fatal(err)
	}
	h.screen.set(5, 5, 0x42)
	last, err := c.NextFrame(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	waitFor(t, "end event", func() bool {
		evs := h.ind.list()
		return len(evs) == 2 && evs[1].Kind == EventEnd
	})
	if !h.ind.list()[0].Recording {
		t.Fatal("indicator must show recording")
	}
	files, _ := filepath.Glob(filepath.Join(recDir, "*"+recordingExt))
	if len(files) != 1 {
		t.Fatalf("recordings: %v", files)
	}
	data, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("laptop")) || bytes.Contains(data, last.Pix[:64]) {
		t.Fatal("recording holds plaintext")
	}
	p, err := OpenRecording(bytes.NewReader(data), key)
	if err != nil {
		t.Fatal(err)
	}
	if p.Meta().Peer != "laptop" || p.Meta().Mode != "view" || p.Meta().Code != c.VerificationCode() {
		t.Fatalf("meta %+v", p.Meta())
	}
	var frames []RecordedFrame
	for {
		f, err := p.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		frames = append(frames, f)
	}
	if len(frames) < 2 || !bytes.Equal(frames[len(frames)-1].Image.Pix, last.Pix) {
		t.Fatalf("replayed %d frames; last frame differs", len(frames))
	}

	// Wrong key, cut short.
	other := &RecordingKey{}
	if _, err := OpenRecording(bytes.NewReader(data), other); !errors.Is(err, ErrRecordingKey) {
		t.Fatalf("wrong key: %v", err)
	}
	p2, err := OpenRecording(bytes.NewReader(data[:len(data)-10]), key)
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err = p2.Next(); err != nil {
			break
		}
	}
	if !errors.Is(err, ErrRecordingTruncated) {
		t.Fatalf("truncated: %v", err)
	}
	if n, err := PruneRecordings(recDir, time.Hour, time.Now().Add(2*time.Hour)); err != nil || n != 1 {
		t.Fatalf("prune: %d %v", n, err)
	}
}

func TestRecordingFailureRefusesSession(t *testing.T) {
	dir := t.TempDir()
	key := &RecordingKey{}
	recDir := filepath.Join(dir, "rec")
	h := newHarness(t, func(c *Config) { c.Recording = &RecordingConfig{Dir: recDir, Key: key} })
	// The directory disappears: the session must not start unrecorded.
	if err := os.RemoveAll(recDir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(recDir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Dial(testCtx(t), h.addr, DialOptions{Scale: 1}); !errors.Is(err, ErrRemoteUnsupported) {
		t.Fatalf("unrecorded session started: %v", err)
	}
	if n := len(h.ind.list()); n != 0 {
		t.Fatalf("indicator called %d times", n)
	}
}

// TestNoImageProcessingImports enforces #249: screen pixels leave this
// package only through the session connection and the encrypted local
// recording. No HTTP client, process execution, plugin loading or image
// encoder that could hand frames to a processing or preview service is
// linked in.
func TestNoImageProcessingImports(t *testing.T) {
	allowed := map[string]bool{
		"bufio": true, "bytes": true, "compress/flate": true, "context": true, "crypto/aes": true,
		"cmp": true, "hash": true,
		"crypto/cipher": true, "crypto/ecdh": true, "crypto/hkdf": true, "crypto/rand": true,
		"crypto/sha256": true, "encoding/binary": true, "encoding/hex": true, "encoding/json": true,
		"errors": true, "fmt": true, "image": true, "io": true, "io/fs": true, "log/slog": true,
		"net": true, "net/netip": true, "os": true, "path/filepath": true, "runtime": true,
		"slices": true, "strconv": true, "strings": true, "sync": true, "sync/atomic": true,
		"time": true, "unicode": true, "unicode/utf8": true, "unicode/utf16": true, "unsafe": true,
		"math": true, "math/bits": true,
		"golang.org/x/sys/windows": true, "github.com/openscale/openscale/internal/securefile": true,
		// G5: signed session summaries (ADR-0201) and macOS cgo platform code
		// (ADR-0198, ADR-0202); none of them sends anything anywhere.
		"crypto/ed25519": true, "encoding/base64": true, "C": true,
		// Wayland (ADR-0236): only portal control calls go over the session
		// bus; frames come in from PipeWire and are never sent on it.
		"github.com/openscale/openscale/internal/dbuswire": true,
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range af.Imports {
			path, _ := strconv.Unquote(imp.Path.Value)
			if !allowed[path] {
				t.Errorf("%s imports %s; frames must not reach any other service (#249)", f, path)
			}
		}
	}
}

func FuzzRecordingPlayer(f *testing.F) {
	key := &RecordingKey{}
	f.Add([]byte(recordingMagic + strings.Repeat("\x00", recordingSaltLen)))
	f.Add([]byte("garbage"))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := OpenRecording(bytes.NewReader(data), key)
		if err != nil {
			return
		}
		for range 64 {
			if _, err := p.Next(); err != nil {
				return
			}
		}
	})
}

func FuzzHelloAndWire(f *testing.F) {
	cpriv, _ := newE2EKey()
	f.Add(hello{mode: ModeView, scale: 1}.encodeV2(cpriv.PublicKey().Bytes())[headerLen:])
	f.Add(hello{version: 1, mode: ModeControl}.encode()[headerLen:])
	f.Fuzz(func(t *testing.T, p []byte) {
		h, pub, err := decodeHelloAny(p)
		if err == nil && h.version == ProtocolVersionE2E {
			if _, _, err := serverKex(p, pub); err != nil && len(pub) != e2eKeyLen {
				t.Fatal("bad key length passed decode")
			}
		}
		k, err := newGCM(make([]byte, 32))
		if err != nil {
			t.Fatal(err)
		}
		w := &wire{br: bufio.NewReader(bytes.NewReader(p)), rx: k}
		_, _, _ = w.read(maxClientMsg)
		_, _, _, _ = decodeExtStatus(p)
	})
}
