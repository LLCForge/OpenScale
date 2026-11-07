package panel

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/node"
)

// diagApp is a desktop app with diagnostics; it records the actions.
type diagApp struct {
	featureApp
	reconnects int
	pinged     string
	level      string
	set        map[string]string
}

func (a *diagApp) DiagStatus() (DiagStatus, error) {
	return DiagStatus{Schema: DiagSchema, Mode: ModeMember, Running: true, Peers: []DiagPeer{{Name: "nas", Path: PathDirect}}, Health: []HealthAlert{}}, nil
}
func (a *diagApp) DiagNetCheck(context.Context) (node.NetReport, error) {
	return node.NetReport{NAT: node.NATEasy}, nil
}
func (a *diagApp) DiagPaths() ([]node.PeerPath, error) { return nil, nil }
func (a *diagApp) DiagReconnect() error                { a.reconnects++; return nil }
func (a *diagApp) DiagRelayTest(context.Context, string) (time.Duration, error) {
	return 12 * time.Millisecond, nil
}
func (a *diagApp) DiagPing(_ context.Context, peer string) (PingResult, error) {
	a.pinged = peer
	ms := 1.5
	return PingResult{Schema: DiagSchema, Peer: peer, Path: PathRelay, RTTMS: &ms, Method: PingICMP}, nil
}
func (a *diagApp) DiagDNS() (DNSStatus, error) { return DNSStatus{Schema: DiagSchema}, nil }
func (a *diagApp) DiagDNSQuery(context.Context, string) (DNSQueryResult, error) {
	return DNSQueryResult{Schema: DiagSchema}, nil
}
func (a *diagApp) DiagWhois(q string) (WhoisResult, error) {
	if q == "yok" {
		return WhoisResult{}, errors.New("ağ belgesinde böyle bir cihaz yok")
	}
	return WhoisResult{Schema: DiagSchema, Query: q}, nil
}
func (a *diagApp) DiagEvents() []DiagEvent { return nil }
func (a *diagApp) DiagWireGuard() (WGShow, error) {
	return WGShow{Schema: DiagSchema}, nil
}
func (a *diagApp) DiagPacketTrace(req TraceRequest) (TraceResult, error) {
	return TraceResult{Schema: DiagSchema, Src: req.Src, Dst: req.Dst}, nil
}
func (a *diagApp) DiagHealth() HealthReport {
	return HealthReport{Schema: DiagSchema, Live: true, Ready: true, Reasons: []string{}, Alerts: []HealthAlert{}}
}
func (a *diagApp) DiagLogLevel() string { return a.level }
func (a *diagApp) DiagSetLogLevel(l string) error {
	if l != "debug" && l != "info" {
		return errors.New("geçersiz seviye")
	}
	a.level = l
	return nil
}
func (a *diagApp) DiagPrefs() ([]Pref, error) { return []Pref{{Key: "shields", Value: "false"}}, nil }
func (a *diagApp) DiagSetPrefs(c map[string]string) ([]Pref, error) {
	a.set = c
	return a.DiagPrefs()
}

func newDiagServer(t *testing.T) (*Server, *diagApp, *atomic.Bool) {
	t.Helper()
	srv := newTestServer(t)
	app := &diagApp{level: "info"}
	ro := &atomic.Bool{}
	srv.app, srv.token, srv.readOnly = app, "uygulama-anahtari-123", ro.Load
	return srv, app, ro
}

func TestDiagLocalAPINeedsAppToken(t *testing.T) {
	srv, app, _ := newDiagServer(t)
	h := srv.Handler()
	bearer := func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+srv.token) }

	if rec := do(t, h, http.MethodGet, "/api/local/status", nil, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", rec.Code)
	}
	// A browser (Origin header) never reaches the token API.
	if rec := do(t, h, http.MethodGet, "/api/local/status", nil, func(r *http.Request) { bearer(r); withOrigin(r) }); rec.Code != http.StatusForbidden {
		t.Fatalf("browser with token: %d", rec.Code)
	}
	rec := do(t, h, http.MethodGet, "/api/local/status", nil, bearer)
	var st DiagStatus
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &st) != nil || st.Schema != DiagSchema || len(st.Peers) != 1 {
		t.Fatalf("status: %d %s", rec.Code, rec.Body)
	}
	rec = do(t, h, http.MethodGet, "/api/local/netcheck", nil, bearer)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"schema":1`) || !strings.Contains(rec.Body.String(), `"nat":"kolay"`) {
		t.Fatalf("netcheck must carry the schema: %d %s", rec.Code, rec.Body)
	}
	if rec := do(t, h, http.MethodPost, "/api/local/ping", map[string]string{"peer": "nas"}, bearer); rec.Code != http.StatusOK || app.pinged != "nas" {
		t.Fatalf("ping: %d %s", rec.Code, rec.Body)
	}
	if rec := do(t, h, http.MethodPost, "/api/local/ping", map[string]string{"peer": "nas; rm -rf /"}, bearer); rec.Code != http.StatusBadRequest {
		t.Fatalf("a bad peer name must be refused: %d", rec.Code)
	}
	if rec := do(t, h, http.MethodGet, "/api/local/whois?q=yok", nil, bearer); rec.Code != http.StatusConflict {
		t.Fatalf("unknown whois: %d", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/api/local/log-level", map[string]string{"level": "debug"}, bearer); rec.Code != http.StatusOK || app.level != "debug" {
		t.Fatalf("log level: %d %s", rec.Code, rec.Body)
	}
	if rec := do(t, h, http.MethodPost, "/api/local/prefs", map[string]any{"set": map[string]string{"shields": "true"}}, bearer); rec.Code != http.StatusOK || app.set["shields"] != "true" {
		t.Fatalf("prefs: %d %s", rec.Code, rec.Body)
	}
	if rec := do(t, h, http.MethodPost, "/api/local/prefs", map[string]any{"set": map[string]string{}}, bearer); rec.Code != http.StatusBadRequest {
		t.Fatalf("empty prefs: %d", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/api/local/trace", TraceRequest{Src: "a", Dst: "b", Proto: "tcp", Port: 70000}, bearer); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad port: %d", rec.Code)
	}
}

func TestDiagPanelEndpointsAndReadOnly(t *testing.T) {
	srv, app, ro := newDiagServer(t)
	h := srv.Handler()
	cookie, csrf := login(t, srv)
	read := func(r *http.Request) { r.AddCookie(cookie) }
	signed := func(r *http.Request) { r.AddCookie(cookie); withOrigin(r); r.Header.Set("X-CSRF-Token", csrf) }

	if rec := do(t, h, http.MethodGet, "/api/app/diag/paths", nil, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("paths without session: %d", rec.Code)
	}
	rec := do(t, h, http.MethodGet, "/api/app/diag/paths", nil, read)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"peers":[]`) {
		t.Fatalf("paths: %d %s", rec.Code, rec.Body)
	}
	if rec := do(t, h, http.MethodPost, "/api/app/diag/reconnect", map[string]any{}, signed); rec.Code != http.StatusOK || app.reconnects != 1 {
		t.Fatalf("reconnect: %d %s", rec.Code, rec.Body)
	}
	// The panel has no command-line-only endpoints.
	if rec := do(t, h, http.MethodPost, "/api/app/diag/prefs", map[string]any{"set": map[string]string{"a": "b"}}, signed); rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("prefs through the panel: %d", rec.Code)
	}
	ro.Store(true)
	for _, path := range []string{"/api/app/diag/reconnect", "/api/app/diag/ping", "/api/app/diag/relay-test"} {
		rec := do(t, h, http.MethodPost, path, map[string]string{"peer": "nas"}, signed)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s in read-only mode: %d %s", path, rec.Code, rec.Body)
		}
	}
	if app.reconnects != 1 || app.pinged != "" {
		t.Fatal("a refused action reached the app")
	}
	if rec := do(t, h, http.MethodGet, "/api/app/diag/events", nil, read); rec.Code != http.StatusOK {
		t.Fatalf("reading in read-only mode: %d", rec.Code)
	}
}

func TestDiagNeedsDiagnosticsApp(t *testing.T) {
	srv, _, _ := newFeatureServer(t)
	rec := do(t, srv.Handler(), http.MethodGet, "/api/local/status", nil, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+srv.token)
	})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("an app without diagnostics: %d", rec.Code)
	}
}

func TestServeLocalAPI(t *testing.T) {
	ln, err := Listen(0)
	if err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("t", 40)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ServeLocalAPI(ctx, ln, LocalAPIConfig{Diag: &diagApp{level: "info"}, Token: token}) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}()
	base := "http://" + ln.Addr().String()
	get := func(path, auth, host string) int {
		req, _ := http.NewRequest(http.MethodGet, base+path, nil)
		if auth != "" {
			req.Header.Set("Authorization", "Bearer "+auth)
		}
		if host != "" {
			req.Host = host
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if c := get("/api/local/health", token, ""); c != http.StatusOK {
		t.Fatalf("health with token: %d", c)
	}
	if c := get("/api/local/health", "yanlis", ""); c != http.StatusUnauthorized {
		t.Fatalf("wrong token: %d", c)
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	if c := get("/api/local/health", token, "evil.example:"+port); c != http.StatusMisdirectedRequest {
		t.Fatalf("DNS rebinding host: %d", c)
	}
	if c := get("/api/app/status", token, ""); c != http.StatusNotFound {
		t.Fatalf("panel routes must not exist: %d", c)
	}
	if err := ServeLocalAPI(ctx, ln, LocalAPIConfig{Diag: &diagApp{}, Token: "kisa"}); err == nil {
		t.Fatal("a short token must be refused")
	}
}
