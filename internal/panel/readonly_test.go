package panel

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

// featureApp records the calls of the timed disconnect, pin and full exit
// endpoints; any other call panics through the nil embedded interface.
type featureApp struct {
	App
	disconnectFor string
	connected     *bool
	pinned        map[string]bool
	released      int
}

func (a *featureApp) Status() AppStatus { return AppStatus{Mode: ModeMember, Health: []HealthAlert{}} }

func (a *featureApp) SetConnected(on bool) error { a.connected = &on; return nil }

func (a *featureApp) DisconnectFor(choice string) error { a.disconnectFor = choice; return nil }

func (a *featureApp) SetPinned(name string, pinned bool) error {
	if a.pinned == nil {
		a.pinned = map[string]bool{}
	}
	a.pinned[name] = pinned
	return nil
}

func (a *featureApp) ReleaseKillSwitchOnStop() { a.released++ }

func newFeatureServer(t *testing.T) (*Server, *featureApp, *atomic.Bool) {
	t.Helper()
	srv := newTestServer(t)
	app := &featureApp{}
	ro := &atomic.Bool{}
	srv.app, srv.token, srv.readOnly = app, "uygulama-anahtari-123", ro.Load
	return srv, app, ro
}

func TestReadOnlyRefusesEveryPanelChange(t *testing.T) {
	srv, app, ro := newFeatureServer(t)
	h := srv.Handler()
	cookie, csrf := login(t, srv)
	signed := func(r *http.Request) { r.AddCookie(cookie); withOrigin(r); r.Header.Set("X-CSRF-Token", csrf) }
	ro.Store(true)

	rec := do(t, h, http.MethodGet, "/api/session", nil, func(r *http.Request) { r.AddCookie(cookie) })
	var sess sessionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &sess); err != nil || !sess.ReadOnly || sess.CSRFToken == "" {
		t.Fatalf("session must report read-only: %s", rec.Body)
	}
	writes := []string{
		"/api/network/coordinator", "/api/devices", "/api/devices/revoke", "/api/devices/exit-node",
		"/api/rules", "/api/rules/remove", "/api/network/renew", "/api/security/passphrase", "/api/security/backup",
		"/api/invites", "/api/invites/approve", "/api/invites/revoke",
		"/api/app/pin", "/api/app/reset", "/api/app/exit", "/api/app/exit/options", "/api/app/shields",
		"/api/app/security", "/api/app/connect", "/api/app/create", "/api/app/join", "/api/app/join/cancel",
	}
	for _, path := range writes {
		rec := do(t, h, http.MethodPost, path, map[string]any{}, signed)
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "salt okunur") {
			t.Errorf("%s in read-only mode: %d %s", path, rec.Code, rec.Body)
		}
	}
	if app.connected != nil || len(app.pinned) != 0 {
		t.Fatal("a refused request reached the app")
	}
	// Reading, checking a request and signing out still work.
	if rec := do(t, h, http.MethodGet, "/api/overview", nil, func(r *http.Request) { r.AddCookie(cookie) }); rec.Code != http.StatusOK {
		t.Fatalf("read in read-only mode: %d", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/api/devices/inspect", map[string]string{"request": "x"}, signed); rec.Code == http.StatusForbidden {
		t.Fatalf("inspect is not a change: %d %s", rec.Code, rec.Body)
	}
	// The tray is not the panel: it keeps working with the app token.
	tray := func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+srv.token) }
	if rec := do(t, h, http.MethodPost, "/api/app/tray/connect", map[string]bool{"connected": false}, tray); rec.Code != http.StatusOK {
		t.Fatalf("tray in read-only mode: %d %s", rec.Code, rec.Body)
	}

	// Off again: the same session may change things at once.
	ro.Store(false)
	if rec := do(t, h, http.MethodPost, "/api/app/connect", map[string]bool{"connected": true}, signed); rec.Code != http.StatusOK || app.connected == nil || !*app.connected {
		t.Fatalf("after read-only off: %d %s", rec.Code, rec.Body)
	}
	if rec := do(t, h, http.MethodPost, "/api/logout", map[string]any{}, signed); rec.Code != http.StatusOK {
		t.Fatalf("logout: %d", rec.Code)
	}
}

func TestTimedDisconnectEndpoints(t *testing.T) {
	srv, app, _ := newFeatureServer(t)
	h := srv.Handler()
	cookie, csrf := login(t, srv)
	signed := func(r *http.Request) { r.AddCookie(cookie); withOrigin(r); r.Header.Set("X-CSRF-Token", csrf) }
	for _, bad := range []map[string]any{
		{"connected": false, "for": "2d"},
		{"connected": true, "for": DisconnectMorning},
		{"connected": false, "for": 5},
	} {
		if rec := do(t, h, http.MethodPost, "/api/app/connect", bad, signed); rec.Code != http.StatusBadRequest {
			t.Fatalf("%v: %d", bad, rec.Code)
		}
	}
	if app.disconnectFor != "" {
		t.Fatal("an invalid choice reached the app")
	}
	if rec := do(t, h, http.MethodPost, "/api/app/connect", map[string]any{"connected": false, "for": Disconnect1Hour}, signed); rec.Code != http.StatusOK || app.disconnectFor != Disconnect1Hour {
		t.Fatalf("panel timed disconnect: %d %q", rec.Code, app.disconnectFor)
	}
	tray := func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+srv.token) }
	if rec := do(t, h, http.MethodPost, "/api/app/tray/disconnect", map[string]string{"for": "1y"}, tray); rec.Code != http.StatusBadRequest {
		t.Fatalf("tray invalid choice: %d", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/api/app/tray/disconnect", map[string]string{"for": Disconnect5Min}, func(r *http.Request) { r.Header.Set("Authorization", "Bearer yanlis") }); rec.Code != http.StatusUnauthorized {
		t.Fatalf("tray wrong token: %d", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/api/app/tray/disconnect", map[string]string{"for": Disconnect5Min}, tray); rec.Code != http.StatusOK || app.disconnectFor != Disconnect5Min {
		t.Fatalf("tray timed disconnect: %d %q", rec.Code, app.disconnectFor)
	}
}

func TestReleaseOnStopNeedsAppToken(t *testing.T) {
	srv, app, _ := newFeatureServer(t)
	h := srv.Handler()
	cookie, csrf := login(t, srv)
	signed := func(r *http.Request) { r.AddCookie(cookie); withOrigin(r); r.Header.Set("X-CSRF-Token", csrf) }
	if rec := do(t, h, http.MethodPost, "/api/app/tray/release-on-stop", map[string]any{}, signed); rec.Code != http.StatusForbidden {
		t.Fatalf("a browser session must not release the kill switch: %d", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/api/app/tray/release-on-stop", map[string]any{}, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+srv.token)
	}); rec.Code != http.StatusOK || app.released != 1 {
		t.Fatalf("tray release: %d released=%d", rec.Code, app.released)
	}
}

func TestPinEndpointValidates(t *testing.T) {
	srv, app, _ := newFeatureServer(t)
	h := srv.Handler()
	cookie, csrf := login(t, srv)
	signed := func(r *http.Request) { r.AddCookie(cookie); withOrigin(r); r.Header.Set("X-CSRF-Token", csrf) }
	for _, bad := range []map[string]any{
		{"name": "laptop"},
		{"name": "", "pinned": true},
		{"name": "Büyük Ad", "pinned": true},
		{"name": "-laptop", "pinned": true},
		{"name": strings.Repeat("a", 64), "pinned": true},
	} {
		if rec := do(t, h, http.MethodPost, "/api/app/pin", bad, signed); rec.Code != http.StatusBadRequest {
			t.Fatalf("%v: %d", bad, rec.Code)
		}
	}
	if rec := do(t, h, http.MethodPost, "/api/app/pin", map[string]any{"name": "nas-1", "pinned": true}, signed); rec.Code != http.StatusOK || !app.pinned["nas-1"] {
		t.Fatalf("pin: %d %v", rec.Code, app.pinned)
	}
}
