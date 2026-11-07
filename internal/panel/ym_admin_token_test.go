package panel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/piv"
	"github.com/openscale/openscale/internal/secmem"
	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/internal/winapp"
)

// ---- fakes: clock, reader, token, and the tray's channel over loopback ----

type ymClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *ymClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *ymClock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type ymToken struct {
	priv   ed25519.PrivateKey
	mu     sync.Mutex
	signs  int
	closed bool
}

func (k *ymToken) PublicKey() ed25519.PublicKey { return k.priv.Public().(ed25519.PublicKey) }
func (k *ymToken) SignMessage(msg []byte) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.closed {
		return nil, errors.New("card removed")
	}
	k.signs++
	return ed25519.Sign(k.priv, msg), nil
}
func (k *ymToken) Close() error { k.mu.Lock(); k.closed = true; k.mu.Unlock(); return nil }

// ymChannel is the tray's channel (same requests as desktop's) over a real
// 127.0.0.1 connection.
type ymChannel struct {
	base, token string
	http        *http.Client
}

func (c *ymChannel) do(ctx context.Context, method, path string, body, out any) (bool, error) {
	var r io.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		r = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, r)
	if err != nil {
		return false, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return false, nil
	}
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("%d %s", resp.StatusCode, data)
	}
	if out == nil {
		return true, nil
	}
	return true, json.Unmarshal(data, out)
}

func (c *ymChannel) Trust(ctx context.Context) (winapp.TokenTrust, error) {
	var t TrayAdminTrust
	if _, err := c.do(ctx, http.MethodGet, "/api/app/tray/admin-mode/trust", nil, &t); err != nil {
		return winapp.TokenTrust{}, err
	}
	return winapp.TokenTrust{NetworkID: t.NetworkID, Root: t.Root, Revoked: t.Revoked}, nil
}

func (c *ymChannel) Report(ctx context.Context, st winapp.TokenModeReport) error {
	_, err := c.do(ctx, http.MethodPost, "/api/app/tray/admin-mode", TrayAdminState{Open: st.Open, Offer: st.Offer, Role: st.Role, Name: st.Name,
		Key: st.Key, Reader: st.Reader, Started: st.Started, Ends: st.Ends, IdleUntil: st.IdleUntil, Reason: st.Reason}, nil)
	return err
}

func (c *ymChannel) NextSign(ctx context.Context) (*winapp.TokenSignRequest, error) {
	var r TraySignRequest
	ok, err := c.do(ctx, http.MethodGet, "/api/app/tray/admin-mode/next", nil, &r)
	if err != nil || !ok {
		return nil, err
	}
	return &winapp.TokenSignRequest{ID: r.ID, Context: r.Context, Payload: r.Payload, Version: r.Version, Summary: r.Summary}, nil
}

func (c *ymChannel) SignResult(ctx context.Context, id string, sig []byte, reason string) error {
	_, err := c.do(ctx, http.MethodPost, "/api/app/tray/admin-mode/result", TraySignResult{ID: id, Signature: sig, Error: reason}, nil)
	return err
}

func ymRootKey(t *testing.T, srv *Server) ed25519.PrivateKey {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(srv.network().Dir(), "root.key"))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := trust.UnmarshalSealedRootKey(data)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := sealed.Open([]byte(testPass))
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

// TestTokenModeEndToEnd: plugged in -> offer -> PIN -> session in the
// tray -> panel state -> "YubiKey ile imzala" -> pulled out -> closed;
// then idle and a silent tray close it too.
func TestTokenModeEndToEnd(t *testing.T) {
	srv := newTestServer(t)
	srv.token = deskTestToken
	clk := &ymClock{t: time.Now()}
	srv.now = clk.Now
	cookie, csrf := login(t, srv)
	h := srv.Handler()

	ln, err := Listen(0)
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	srv.host = addr // Serve sets the same value
	owner := func(r *http.Request) {
		r.Host = addr
		r.AddCookie(cookie)
		r.Header.Set("Origin", "http://"+addr)
		r.Header.Set("X-CSRF-Token", csrf)
	}
	if !strings.HasPrefix(ln.Addr().String(), "127.0.0.1:") {
		t.Fatalf("listener not on loopback: %s", ln.Addr())
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln) }()
	defer func() {
		cancel()
		<-done
	}()
	ch := &ymChannel{base: "http://" + ln.Addr().String(), token: deskTestToken, http: &http.Client{Timeout: 40 * time.Second}}

	root := ymRootKey(t, srv)
	var (
		mu      sync.Mutex
		present bool
		tok     *ymToken
		notes   []string
		confirm = true
		asked   string
	)
	const reader = "Yubico YubiKey OTP+FIDO+CCID 0"
	c := &winapp.TokenModeController{
		Probe: func(_ context.Context, keys []ed25519.PublicKey) (piv.PresenceResult, error) {
			mu.Lock()
			defer mu.Unlock()
			if !present {
				return piv.PresenceResult{Match: -1}, nil
			}
			res := piv.PresenceResult{Present: true, Reader: reader, Kind: piv.KindPIV, PublicKey: root.Public().(ed25519.PublicKey), Match: -1}
			for i, k := range keys {
				if bytes.Equal(k, res.PublicKey) {
					res.Match = i
				}
			}
			return res, nil
		},
		Channel: ch,
		AskPIN:  func(context.Context) (*secmem.Buffer, error) { return secmem.Copy([]byte("123456")) },
		OpenToken: func(_ context.Context, r string, pin func() ([]byte, error)) (admin.TokenSigner, error) {
			p, err := pin()
			if err != nil || string(p) != "123456" || r != reader {
				return nil, errors.New("wrong PIN or reader")
			}
			mu.Lock()
			defer mu.Unlock()
			tok = &ymToken{priv: root}
			return tok, nil
		},
		Confirm: func(text string) bool { mu.Lock(); defer mu.Unlock(); asked = text; return confirm },
		Notify:  func(m string) { mu.Lock(); notes = append(notes, m); mu.Unlock() },
		Now:     clk.Now,
	}
	status := func() TokenModeStatus {
		t.Helper()
		rec := do(t, h, http.MethodGet, "/api/admin-mode/token", nil, owner)
		var st TokenModeStatus
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &st) != nil {
			t.Fatalf("status: %d %s", rec.Code, rec.Body)
		}
		return st
	}
	// The tray serves signing requests like Run does.
	sctx, scancel := context.WithCancel(ctx)
	defer scancel()
	go func() {
		for sctx.Err() == nil {
			req, err := ch.NextSign(sctx)
			if err == nil && req != nil {
				_ = c.HandleSign(sctx, req)
			}
		}
	}()
	renew := func() (int, string) {
		rec := do(t, h, http.MethodPost, "/api/network/renew", map[string]any{"token": true, "validityDays": 30}, owner)
		return rec.Code, rec.Body.String()
	}

	// 1. No token: nothing offered; the panel sees the tray, closed.
	if st := c.Step(ctx); st.Offer || st.Open {
		t.Fatalf("no token: %+v", st)
	}
	if st := status(); !st.Tray || st.Open || st.CanSign {
		t.Fatalf("panel without token: %+v", st)
	}
	if err := c.Enable(ctx); !errors.Is(err, winapp.ErrTokenModeNoToken) {
		t.Fatalf("enable without token: %v", err)
	}
	// 2. Plugged in: offered, the user is told, nothing opened yet.
	mu.Lock()
	present = true
	mu.Unlock()
	if st := c.Step(ctx); !st.Offer || st.Open {
		t.Fatalf("plugged: %+v", st)
	}
	if st := status(); !st.Offer || st.Open {
		t.Fatalf("panel offer: %+v", st)
	}
	if code, body := renew(); code != http.StatusConflict || !strings.Contains(body, "Yönetici kipini aç") {
		t.Fatalf("sign before the session: %d %s", code, body)
	}
	// 3. PIN -> session in the tray, proof signed.
	if err := c.Enable(ctx); err != nil {
		t.Fatal(err)
	}
	if tok.signs != 1 {
		t.Fatalf("proof signatures = %d", tok.signs)
	}
	st := status()
	if !st.Open || st.Role != admin.SessionRoot || !st.CanSign || st.Key != admin.KeyFingerprint(root.Public().(ed25519.PublicKey)) || st.LeftSec <= 0 || st.LeftSec > 15*60 {
		t.Fatalf("panel open: %+v", st)
	}
	// 4. "YubiKey ile imzala": the document is signed by the token.
	doc, _ := srv.network().Document()
	base := doc.Version
	if code, body := renew(); code != http.StatusOK {
		t.Fatalf("token sign: %d %s", code, body)
	}
	doc, _ = srv.network().Document()
	if doc.Version != base+1 || tok.signs != 2 || !strings.Contains(asked, fmt.Sprintf("sürüm %d", base+1)) {
		t.Fatalf("signed version %d (base %d), signs %d, asked %q", doc.Version, base, tok.signs, asked)
	}
	// The user can say no in the tray.
	mu.Lock()
	confirm = false
	mu.Unlock()
	if code, body := renew(); code != http.StatusConflict || !strings.Contains(body, "reddedildi") {
		t.Fatalf("refused sign: %d %s", code, body)
	}
	mu.Lock()
	confirm = true
	mu.Unlock()
	// 5. Pulled out: closed at once, token released, panel closed.
	mu.Lock()
	present = false
	mu.Unlock()
	if st := c.Step(ctx); st.Open || st.Reason != winapp.ReasonTokenRemoved {
		t.Fatalf("pulled: %+v", st)
	}
	if !tok.closed {
		t.Fatal("token left open")
	}
	if st := status(); st.Open || st.CanSign || st.Reason != winapp.ReasonTokenRemoved {
		t.Fatalf("panel after pull: %+v", st)
	}
	if code, _ := renew(); code != http.StatusConflict {
		t.Fatalf("sign after pull: %d", code)
	}
	// 6. Idle 15 minutes closes it.
	mu.Lock()
	present = true
	mu.Unlock()
	c.Step(ctx)
	if err := c.Enable(ctx); err != nil {
		t.Fatal(err)
	}
	clk.Add(15*time.Minute + time.Second)
	if st := c.Step(ctx); st.Open || st.Reason != winapp.ReasonTokenIdle {
		t.Fatalf("idle: %+v", st)
	}
	// 7. A tray that stops reporting counts as closed.
	c.Step(ctx)
	if err := c.Enable(ctx); err != nil {
		t.Fatal(err)
	}
	if st := status(); !st.Open {
		t.Fatalf("reopened: %+v", st)
	}
	clk.Add(trayAdminStale + time.Second)
	if st := status(); st.Open || st.Tray {
		t.Fatalf("silent tray: %+v", st)
	}
	c.Disable(ctx)
	mu.Lock()
	defer mu.Unlock()
	if len(notes) == 0 || !strings.Contains(notes[0], "Yönetici kipini aç") {
		t.Fatalf("notes: %q", notes)
	}
}

// TestTokenModeChannelNeedsAppToken: the tray endpoints refuse requests
// without the app token or from a browser.
func TestTokenModeChannelNeedsAppToken(t *testing.T) {
	srv := newTestServer(t)
	srv.token = deskTestToken
	h := srv.Handler()
	for _, p := range []struct{ m, path string }{
		{http.MethodPost, "/api/app/tray/admin-mode"},
		{http.MethodGet, "/api/app/tray/admin-mode/trust"},
		{http.MethodGet, "/api/app/tray/admin-mode/next"},
		{http.MethodPost, "/api/app/tray/admin-mode/result"},
	} {
		if rec := do(t, h, p.m, p.path, map[string]any{}, nil); rec.Code == http.StatusOK || rec.Code == http.StatusNoContent {
			t.Fatalf("%s without token: %d", p.path, rec.Code)
		}
		if rec := do(t, h, p.m, p.path, map[string]any{}, func(r *http.Request) { trayToken(r); withOrigin(r) }); rec.Code != http.StatusForbidden {
			t.Fatalf("%s from a browser: %d", p.path, rec.Code)
		}
	}
	// A bogus report is refused.
	bad := TrayAdminState{Open: true, Role: "superuser", Ends: time.Now().Add(time.Hour)}
	if rec := do(t, h, http.MethodPost, "/api/app/tray/admin-mode", bad, trayToken); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad role: %d", rec.Code)
	}
	// The panel status needs a session.
	if rec := do(t, h, http.MethodGet, "/api/admin-mode/token", nil, nil); rec.Code == http.StatusOK {
		t.Fatal("status without a session")
	}
}
