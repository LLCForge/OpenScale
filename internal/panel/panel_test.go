package panel

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/trust"
)

const (
	testHost = "127.0.0.1:4321"
	inline   = `self.__next_f.push([1,"x"])`
)

var testPass = "panel test parolası 1"

func newTestServer(t *testing.T) *Server {
	t.Helper()
	n, err := admin.Init(t.TempDir(), admin.InitOptions{DNSDomain: trust.DefaultDNSDomain, IPv4Prefix: trust.DefaultIPv4Prefix, Validity: trust.DefaultValidity},
		[]byte(testPass), admin.Options{Argon2: trust.Argon2Params{Time: 1, MemoryKiB: 64 * 1024, Threads: 1}, Random: rand.Reader}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	files := fstest.MapFS{
		"index.html":         {Data: []byte(`<!doctype html><html><head><script src="/_next/static/a.js"></script></head><body><script>` + inline + `</script></body></html>`)},
		"devices/index.html": {Data: []byte(`<html><body>cihazlar</body></html>`)},
		"login/index.html":   {Data: []byte(`<html><body>giris</body></html>`)},
		"_next/static/a.js":  {Data: []byte(`console.log(1)`)},
		"404.html":           {Data: []byte(`<html><body>yok</body></html>`)},
	}
	srv, err := New(Config{Network: n, Files: files})
	if err != nil {
		t.Fatal(err)
	}
	srv.host = testHost
	return srv
}

func do(t *testing.T, h http.Handler, method, target string, body any, mutate func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, "http://"+testHost+target, &buf)
	req.Host = testHost
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if mutate != nil {
		mutate(req)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func withOrigin(r *http.Request) { r.Header.Set("Origin", "http://"+testHost) }

// login signs in with the root passphrase and returns the session cookie and CSRF token.
func login(t *testing.T, srv *Server) (*http.Cookie, string) {
	t.Helper()
	h := srv.Handler()
	rec := do(t, h, http.MethodPost, "/api/login", map[string]string{"passphrase": testPass}, withOrigin)
	if rec.Code != http.StatusOK {
		t.Fatalf("login status = %d: %s", rec.Code, rec.Body)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("unexpected cookie: %+v", cookies)
	}
	c := cookies[0]
	rec = do(t, h, http.MethodGet, "/api/session", nil, func(r *http.Request) { r.AddCookie(c) })
	var sess struct{ CSRFToken string }
	if err := json.Unmarshal(rec.Body.Bytes(), &sess); err != nil || sess.CSRFToken == "" {
		t.Fatalf("session response: %s", rec.Body)
	}
	return c, sess.CSRFToken
}

func TestLoginRequiresPassphraseAndOrigin(t *testing.T) {
	srv := newTestServer(t)
	h := srv.Handler()
	if rec := do(t, h, http.MethodPost, "/api/login", map[string]string{"passphrase": testPass}, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("login without Origin status = %d", rec.Code)
	}
	evil := func(r *http.Request) { r.Header.Set("Origin", "http://evil.example") }
	if rec := do(t, h, http.MethodPost, "/api/login", map[string]string{"passphrase": testPass}, evil); rec.Code != http.StatusForbidden {
		t.Fatalf("cross-origin login status = %d", rec.Code)
	}
	rec := do(t, h, http.MethodPost, "/api/login", map[string]string{"passphrase": "yanlış parola 123456"}, withOrigin)
	if rec.Code != http.StatusUnauthorized || len(rec.Result().Cookies()) != 0 {
		t.Fatalf("wrong passphrase: %d %v", rec.Code, rec.Result().Cookies())
	}
	// Sign-in failures lock further sign-in from the same source (lockout.go).
	for i := 1; i < lockoutFailures; i++ {
		do(t, h, http.MethodPost, "/api/login", map[string]string{"passphrase": "yanlış parola 123456"}, withOrigin)
	}
	if rec := do(t, h, http.MethodPost, "/api/login", map[string]string{"passphrase": testPass}, withOrigin); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status after %d failures = %d, want 429", lockoutFailures, rec.Code)
	}
}

func TestLoginPageRedirects(t *testing.T) {
	srv := newTestServer(t)
	h := srv.Handler()
	if rec := do(t, h, http.MethodGet, "/login/", nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("login page without session = %d", rec.Code)
	}
	cookie, _ := login(t, srv)
	rec := do(t, h, http.MethodGet, "/login/", nil, func(r *http.Request) { r.AddCookie(cookie) })
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/" {
		t.Fatalf("login page with session: %d %s", rec.Code, rec.Header().Get("Location"))
	}
}

func TestHostHeaderIsChecked(t *testing.T) {
	srv := newTestServer(t)
	rec := do(t, srv.Handler(), http.MethodGet, "/api/overview", nil, func(r *http.Request) { r.Host = "evil.example:4321" })
	if rec.Code != http.StatusMisdirectedRequest {
		t.Fatalf("status = %d, want 421", rec.Code)
	}
	rec = do(t, srv.Handler(), http.MethodGet, "/", nil, func(r *http.Request) { r.Host = "localhost:4321" })
	if rec.Code == http.StatusMisdirectedRequest {
		t.Fatal("localhost with the panel port must be accepted")
	}
}

func TestAPIRequiresSession(t *testing.T) {
	srv := newTestServer(t)
	if rec := do(t, srv.Handler(), http.MethodGet, "/api/overview", nil, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rec.Code)
	}
	rec := do(t, srv.Handler(), http.MethodGet, "/devices/", nil, nil)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login/" {
		t.Fatalf("page without session: %d %s", rec.Code, rec.Header().Get("Location"))
	}
}

func TestMutationsRequireCSRFAndOrigin(t *testing.T) {
	srv := newTestServer(t)
	cookie, csrf := login(t, srv)
	h := srv.Handler()
	body := map[string]any{"dryRun": true}
	withCookie := func(origin, token string) func(*http.Request) {
		return func(r *http.Request) {
			r.AddCookie(cookie)
			if origin != "" {
				r.Header.Set("Origin", origin)
			}
			if token != "" {
				r.Header.Set("X-CSRF-Token", token)
			}
		}
	}
	cases := []struct {
		name, origin, token string
		want                int
	}{
		{"no origin", "", csrf, http.StatusForbidden},
		{"foreign origin", "http://evil.example", csrf, http.StatusForbidden},
		{"no token", "http://" + testHost, "", http.StatusForbidden},
		{"wrong token", "http://" + testHost, "x" + csrf, http.StatusForbidden},
		{"valid", "http://" + testHost, csrf, http.StatusOK},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := do(t, h, http.MethodPost, "/api/network/renew", body, withCookie(c.origin, c.token))
			if rec.Code != c.want {
				t.Fatalf("status = %d, want %d: %s", rec.Code, c.want, rec.Body)
			}
		})
	}
}

func TestRenewDryRunThenSign(t *testing.T) {
	srv := newTestServer(t)
	cookie, csrf := login(t, srv)
	h := srv.Handler()
	auth := func(r *http.Request) {
		r.AddCookie(cookie)
		r.Header.Set("Origin", "http://"+testHost)
		r.Header.Set("X-CSRF-Token", csrf)
	}
	rec := do(t, h, http.MethodPost, "/api/network/renew", map[string]any{"dryRun": true, "validityDays": 30}, auth)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"dryRun":true`) {
		t.Fatalf("dry run: %d %s", rec.Code, rec.Body)
	}
	rec = do(t, h, http.MethodPost, "/api/network/renew", map[string]any{"passphrase": "yanlış parola 123456"}, auth)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong passphrase status = %d", rec.Code)
	}
	rec = do(t, h, http.MethodPost, "/api/network/renew", map[string]any{"passphrase": testPass}, auth)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"version":2`) {
		t.Fatalf("sign: %d %s", rec.Code, rec.Body)
	}
	rec = do(t, h, http.MethodPost, "/api/network/renew", map[string]any{"passphrase": testPass, "unexpected": 1}, auth)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown field status = %d", rec.Code)
	}
}

func TestPassphraseLockout(t *testing.T) {
	srv := newTestServer(t)
	cookie, csrf := login(t, srv)
	h := srv.Handler()
	auth := func(r *http.Request) {
		r.AddCookie(cookie)
		r.Header.Set("Origin", "http://"+testHost)
		r.Header.Set("X-CSRF-Token", csrf)
	}
	for i := 0; i < lockoutFailures; i++ {
		do(t, h, http.MethodPost, "/api/network/renew", map[string]any{"passphrase": "yanlış parola 123456"}, auth)
	}
	rec := do(t, h, http.MethodPost, "/api/network/renew", map[string]any{"passphrase": testPass}, auth)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status after %d failures = %d, want 429", lockoutFailures, rec.Code)
	}
}

func TestStaticCSPHashesInlineScripts(t *testing.T) {
	srv := newTestServer(t)
	cookie, _ := login(t, srv)
	rec := do(t, srv.Handler(), http.MethodGet, "/", nil, func(r *http.Request) { r.AddCookie(cookie) })
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	sum := sha256.Sum256([]byte(inline))
	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "'sha256-"+base64.StdEncoding.EncodeToString(sum[:])+"'") {
		t.Fatalf("CSP does not allow the inline script hash: %s", csp)
	}
	if strings.Contains(csp, "unsafe-inline';") && strings.Contains(strings.Split(csp, "script-src")[1], "unsafe-inline") {
		t.Fatalf("scripts must not allow unsafe-inline: %s", csp)
	}
	for _, p := range []string{"/devices", "/devices/"} {
		if rec := do(t, srv.Handler(), http.MethodGet, p, nil, func(r *http.Request) { r.AddCookie(cookie) }); rec.Code != http.StatusOK {
			t.Fatalf("%s status = %d", p, rec.Code)
		}
	}
	// ServeMux redirects unclean paths to their clean form; the clean form
	// stays inside the export root.
	if rec := do(t, srv.Handler(), http.MethodGet, "/../../etc/passwd", nil, func(r *http.Request) { r.AddCookie(cookie) }); rec.Code != http.StatusTemporaryRedirect || rec.Header().Get("Location") != "/etc/passwd" {
		t.Fatalf("traversal: %d %v", rec.Code, rec.Header())
	}
	if rec := do(t, srv.Handler(), http.MethodGet, "/etc/passwd", nil, func(r *http.Request) { r.AddCookie(cookie) }); rec.Code != http.StatusNotFound {
		t.Fatalf("clean traversal target status = %d", rec.Code)
	}
	if rec := do(t, srv.Handler(), http.MethodGet, "/_next/static/a.js", nil, nil); rec.Code != http.StatusOK || !strings.Contains(rec.Header().Get("Cache-Control"), "immutable") {
		t.Fatalf("static asset: %d %v", rec.Code, rec.Header())
	}
}

func TestSegmentPrefetchPath(t *testing.T) {
	cases := map[string]string{
		"cihazlar/__next.cihazlar.__PAGE__.txt": "cihazlar/__next.cihazlar/__PAGE__.txt",
		"a/b/__next.a.b.__PAGE__.txt":           "a/b/__next.a/b/__PAGE__.txt",
	}
	for in, want := range cases {
		got, ok := segmentPrefetchPath(in)
		if !ok || got != want {
			t.Errorf("segmentPrefetchPath(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	for _, in := range []string{"__next.__PAGE__.txt", "x/index.txt", "__next.a.js"} {
		if _, ok := segmentPrefetchPath(in); ok {
			t.Errorf("segmentPrefetchPath(%q) should not map", in)
		}
	}
}

func TestListenRefusesNonLoopback(t *testing.T) {
	ln, err := Listen(0)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if !strings.HasPrefix(ln.Addr().String(), "127.0.0.1:") {
		t.Fatalf("listener bound to %s", ln.Addr())
	}
}
