package panel

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const deskTestToken = "w2-masaustu-test-anahtari-0123456789abcdef"

// fakeBinder records the #646 calls.
type fakeBinder struct {
	mu     sync.Mutex
	bound  map[string]bool
	refuse bool
	forgot []string
}

func (b *fakeBinder) Bind(session, _, _ string) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.bound == nil {
		b.bound = map[string]bool{}
	}
	b.bound[session] = true
	return 4242, nil
}

func (b *fakeBinder) Check(session, _, _ string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.bound[session] && b.refuse {
		return errors.New("başka pencere")
	}
	return nil
}

func (b *fakeBinder) Forget(session string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.bound, session)
	b.forgot = append(b.forgot, session)
}

func trayToken(r *http.Request) { r.Header.Set("Authorization", "Bearer "+deskTestToken) }

func fromLoopback(r *http.Request) { r.RemoteAddr = "127.0.0.1:50123" }

func issueTestTicket(t *testing.T, h http.Handler) string {
	t.Helper()
	rec := do(t, h, http.MethodPost, "/api/app/ticket", nil, trayToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("ticket: %d %s", rec.Code, rec.Body)
	}
	var out struct{ Ticket string }
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.Ticket == "" {
		t.Fatalf("ticket body: %s", rec.Body)
	}
	return out.Ticket
}

func TestTicketSignInIsLoopbackOnceAndShortLived(t *testing.T) {
	srv := newTestServer(t)
	srv.token = deskTestToken
	binder := &fakeBinder{}
	srv.g5.desk.bindOverride = binder
	now := time.Now()
	srv.auth.now = func() time.Time { return now }
	h := srv.Handler()

	// Not from this computer: refused, and the ticket is not spent.
	tk := issueTestTicket(t, h)
	rec := do(t, h, http.MethodGet, "/auth/ticket?t="+url.QueryEscape(tk), nil, nil)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login/" || len(rec.Result().Cookies()) != 0 {
		t.Fatalf("remote ticket: %d %q %v", rec.Code, rec.Header().Get("Location"), rec.Result().Cookies())
	}
	// From loopback: a cookie, a redirect that drops the ticket, no cache.
	rec = do(t, h, http.MethodGet, "/auth/ticket?t="+url.QueryEscape(tk), nil, fromLoopback)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/" || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("loopback ticket: %d %q %q", rec.Code, rec.Header().Get("Location"), rec.Header().Get("Cache-Control"))
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != sessionCookie || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie: %+v", cookies)
	}
	if !binder.bound[cookies[0].Value] {
		t.Fatal("ticket session not bound to the window (#646)")
	}
	withCookie := func(r *http.Request) { fromLoopback(r); r.AddCookie(cookies[0]) }
	if rec := do(t, h, http.MethodGet, "/api/session", nil, withCookie); rec.Code != http.StatusOK {
		t.Fatalf("session after ticket: %d", rec.Code)
	}
	// The automatic session never holds the administrator mode.
	srv.auth.mu.Lock()
	sess := srv.auth.sessions[cookies[0].Value]
	srv.auth.mu.Unlock()
	if sess == nil || !sess.g5.viaTray || !sess.g5.elevatedAt.IsZero() {
		t.Fatalf("ticket session state: %+v", sess)
	}
	// Single use.
	rec = do(t, h, http.MethodGet, "/auth/ticket?t="+url.QueryEscape(tk), nil, fromLoopback)
	if rec.Header().Get("Location") != "/login/" || len(rec.Result().Cookies()) != 0 {
		t.Fatalf("second use: %q", rec.Header().Get("Location"))
	}
	// Expires after 30 seconds.
	tk2 := issueTestTicket(t, h)
	now = now.Add(ticketLife + time.Second)
	rec = do(t, h, http.MethodGet, "/auth/ticket?t="+url.QueryEscape(tk2), nil, fromLoopback)
	if rec.Header().Get("Location") != "/login/" {
		t.Fatalf("expired ticket: %q", rec.Header().Get("Location"))
	}
	if ticketLife != 30*time.Second {
		t.Fatalf("ticketLife = %v", ticketLife)
	}
	// A browser cannot ask for a ticket (Origin), nor without the token.
	if rec := do(t, h, http.MethodPost, "/api/app/ticket", nil, func(r *http.Request) { trayToken(r); withOrigin(r) }); rec.Code != http.StatusForbidden {
		t.Fatalf("ticket with Origin: %d", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/api/app/ticket", nil, nil); rec.Code == http.StatusOK {
		t.Fatal("ticket without the token")
	}
}

func TestTicketSessionBoundToWindow(t *testing.T) {
	srv := newTestServer(t)
	srv.token = deskTestToken
	binder := &fakeBinder{}
	srv.g5.desk.bindOverride = binder
	h := srv.Handler()
	tk := issueTestTicket(t, h)
	rec := do(t, h, http.MethodGet, "/auth/ticket?t="+url.QueryEscape(tk), nil, fromLoopback)
	c := rec.Result().Cookies()[0]
	withCookie := func(r *http.Request) { fromLoopback(r); r.AddCookie(c) }
	binder.mu.Lock()
	binder.refuse = true
	binder.mu.Unlock()
	if rec := do(t, h, http.MethodGet, "/api/session", nil, withCookie); rec.Code != http.StatusUnauthorized {
		t.Fatalf("other window: %d", rec.Code)
	}
	// The session is gone for good, even for the right window.
	binder.mu.Lock()
	binder.refuse = false
	binder.mu.Unlock()
	if rec := do(t, h, http.MethodGet, "/api/session", nil, withCookie); rec.Code != http.StatusUnauthorized {
		t.Fatalf("session after refusal: %d", rec.Code)
	}
}

func TestDuressSignInWipesRootKeyAndIsReadOnly(t *testing.T) {
	srv := newTestServer(t)
	n := srv.network()
	duress := []byte("baskı altında giriş parolası 7")
	if _, err := n.CreateBackup([]byte(testPass), []byte("yedek parola kasa 1234"), "kasa", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := n.SetDuressPassphrase([]byte(testPass), duress); err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()
	// The ordinary passphrase still signs in normally.
	login(t, srv)
	rec := do(t, h, http.MethodPost, "/api/login", map[string]string{"passphrase": string(duress)}, withOrigin)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"ok":true`) {
		t.Fatalf("duress sign-in: %d %s", rec.Code, rec.Body)
	}
	if _, err := os.Stat(filepath.Join(n.Dir(), "root.key")); !os.IsNotExist(err) {
		t.Fatalf("root key still present: %v", err)
	}
	c := rec.Result().Cookies()[0]
	rec = do(t, h, http.MethodGet, "/api/session", nil, func(r *http.Request) { r.AddCookie(c) })
	var sess struct{ CSRFToken string }
	if err := json.Unmarshal(rec.Body.Bytes(), &sess); err != nil || sess.CSRFToken == "" {
		t.Fatalf("duress session: %d %s", rec.Code, rec.Body)
	}
	signed := func(r *http.Request) { r.AddCookie(c); withOrigin(r); r.Header.Set("X-CSRF-Token", sess.CSRFToken) }
	rec = do(t, h, http.MethodPost, "/api/network/name", map[string]string{"name": "x"}, signed)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "salt okunur") {
		t.Fatalf("duress change: %d %s", rec.Code, rec.Body)
	}
	// Signing out still works.
	if rec := do(t, h, http.MethodPost, "/api/logout", nil, signed); rec.Code != http.StatusOK {
		t.Fatalf("duress logout: %d", rec.Code)
	}
	// A wrong passphrase is still wrong.
	if rec := do(t, h, http.MethodPost, "/api/login", map[string]string{"passphrase": "bambaşka bir parola 99"}, withOrigin); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong passphrase: %d", rec.Code)
	}
}

func TestTrayPanicNeedsTokenAndPassphrase(t *testing.T) {
	srv := newTestServer(t)
	srv.token = deskTestToken
	h := srv.Handler()
	if rec := do(t, h, http.MethodPost, "/api/app/tray/panic", TrayPanicRequest{Passphrase: testPass}, nil); rec.Code == http.StatusOK {
		t.Fatal("panic without the token")
	}
	if rec := do(t, h, http.MethodPost, "/api/app/tray/panic", TrayPanicRequest{Passphrase: testPass}, func(r *http.Request) { trayToken(r); withOrigin(r) }); rec.Code != http.StatusForbidden {
		t.Fatalf("panic from a browser: %d", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/api/app/tray/panic", TrayPanicRequest{}, trayToken); rec.Code != http.StatusBadRequest {
		t.Fatalf("panic without passphrase: %d", rec.Code)
	}
	// No prepared document in this network: a clear answer, nothing changes.
	rec := do(t, h, http.MethodPost, "/api/app/tray/panic", TrayPanicRequest{Passphrase: testPass}, trayToken)
	if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "emergency prepare") {
		t.Fatalf("panic without prepared document: %d %s", rec.Code, rec.Body)
	}
}

// TestTicketLoopbackRealServer runs the tray's flow over a real 127.0.0.1
// connection: app token -> ticket -> cookie, then the ticket is spent.
func TestTicketLoopbackRealServer(t *testing.T) {
	srv := newTestServer(t)
	srv.token = deskTestToken
	ln, err := Listen(0)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln) }()
	defer func() {
		cancel()
		<-done
	}()
	base := "http://" + ln.Addr().String()
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequest(http.MethodPost, base+"/api/app/ticket", nil)
	req.Header.Set("Authorization", "Bearer "+deskTestToken)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var out struct{ Ticket string }
	if resp.StatusCode != http.StatusOK || json.Unmarshal(body, &out) != nil || out.Ticket == "" {
		t.Fatalf("ticket: %d %s", resp.StatusCode, body)
	}
	link := base + "/auth/ticket?t=" + url.QueryEscape(out.Ticket)
	resp, err = client.Get(link)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/" || len(resp.Cookies()) != 1 {
		t.Fatalf("redeem: %d %q %v", resp.StatusCode, resp.Header.Get("Location"), resp.Cookies())
	}
	cookie := resp.Cookies()[0]
	req, _ = http.NewRequest(http.MethodGet, base+"/api/session", nil)
	req.AddCookie(cookie)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("session over loopback: %d", resp.StatusCode)
	}
	resp, err = client.Get(link)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.Header.Get("Location") != "/login/" {
		t.Fatalf("reused ticket: %q", resp.Header.Get("Location"))
	}
}
