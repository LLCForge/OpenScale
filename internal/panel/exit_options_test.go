package panel

import (
	"errors"
	"net/http"
	"testing"
)

// optionsApp implements only what the exit option and shields endpoints
// use; any other call panics through the nil embedded interface.
type optionsApp struct {
	App
	killSwitch, allowLAN, shields bool
	calls                         int
	fail                          error
}

func (a *optionsApp) Status() AppStatus {
	return AppStatus{Mode: ModeMember, Device: &DeviceStatus{KillSwitch: a.killSwitch, ExitAllowLAN: a.allowLAN, Shields: a.shields}}
}

func (a *optionsApp) SetExitOptions(killSwitch, allowLAN bool) error {
	a.calls++
	if a.fail != nil {
		return a.fail
	}
	a.killSwitch, a.allowLAN = killSwitch, allowLAN
	return nil
}

func (a *optionsApp) SetShields(on bool) error {
	a.calls++
	if a.fail != nil {
		return a.fail
	}
	a.shields = on
	return nil
}

func newOptionsServer(t *testing.T) (*Server, *optionsApp) {
	t.Helper()
	srv := newTestServer(t)
	app := &optionsApp{killSwitch: true}
	srv.app, srv.token = app, "uygulama-anahtari-123"
	return srv, app
}

func TestExitOptionsEndpoint(t *testing.T) {
	srv, app := newOptionsServer(t)
	h := srv.Handler()
	body := map[string]bool{"killSwitch": false, "exitAllowLan": true}
	if rec := do(t, h, http.MethodPost, "/api/app/exit/options", body, withOrigin); rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden {
		t.Fatalf("without a session: %d", rec.Code)
	}
	cookie, csrf := login(t, srv)
	session := func(r *http.Request) { r.AddCookie(cookie); withOrigin(r) }
	if rec := do(t, h, http.MethodPost, "/api/app/exit/options", body, session); rec.Code != http.StatusForbidden {
		t.Fatalf("without the CSRF token: %d", rec.Code)
	}
	signed := func(r *http.Request) { session(r); r.Header.Set("X-CSRF-Token", csrf) }
	if rec := do(t, h, http.MethodPost, "/api/app/exit/options", map[string]bool{"killSwitch": false}, signed); rec.Code != http.StatusBadRequest {
		t.Fatalf("missing field: %d", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/api/app/exit/options", map[string]any{"killSwitch": false, "exitAllowLan": true, "extra": 1}, signed); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown field: %d", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/api/app/exit/options", map[string]any{"killSwitch": "hayır", "exitAllowLan": true}, signed); rec.Code != http.StatusBadRequest {
		t.Fatalf("wrong type: %d", rec.Code)
	}
	if app.calls != 0 {
		t.Fatalf("invalid requests reached the app %d times", app.calls)
	}
	rec := do(t, h, http.MethodPost, "/api/app/exit/options", body, signed)
	if rec.Code != http.StatusOK || app.killSwitch || !app.allowLAN {
		t.Fatalf("valid request: %d %s app=%+v", rec.Code, rec.Body, app)
	}
	app.fail = errors.New("kill switch kurulamadı")
	if rec := do(t, h, http.MethodPost, "/api/app/exit/options", body, signed); rec.Code != http.StatusConflict {
		t.Fatalf("app error: %d", rec.Code)
	}
}

func TestTrayExitOptionsNeedsAppToken(t *testing.T) {
	srv, app := newOptionsServer(t)
	h := srv.Handler()
	body := map[string]bool{"killSwitch": false, "exitAllowLan": false}
	bearer := func(tok string) func(*http.Request) {
		return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+tok) }
	}
	if rec := do(t, h, http.MethodPost, "/api/app/tray/exit/options", body, bearer("yanlis")); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token: %d", rec.Code)
	}
	browser := func(r *http.Request) { bearer(srv.token)(r); withOrigin(r) }
	if rec := do(t, h, http.MethodPost, "/api/app/tray/exit/options", body, browser); rec.Code != http.StatusForbidden {
		t.Fatalf("request with an Origin: %d", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/api/app/tray/exit/options", body, bearer(srv.token)); rec.Code != http.StatusOK || app.killSwitch {
		t.Fatalf("tray request: %d app=%+v", rec.Code, app)
	}
}

func TestShieldsEndpoint(t *testing.T) {
	srv, app := newOptionsServer(t)
	h := srv.Handler()
	cookie, csrf := login(t, srv)
	signed := func(r *http.Request) { r.AddCookie(cookie); withOrigin(r); r.Header.Set("X-CSRF-Token", csrf) }
	if rec := do(t, h, http.MethodPost, "/api/app/shields", map[string]bool{}, signed); rec.Code != http.StatusBadRequest {
		t.Fatalf("missing field: %d", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/api/app/shields", map[string]bool{"shields": true}, signed); rec.Code != http.StatusOK || !app.shields {
		t.Fatalf("shields on: %d app=%+v", rec.Code, app)
	}
	if rec := do(t, h, http.MethodPost, "/api/app/shields", map[string]bool{"shields": false}, func(r *http.Request) { r.AddCookie(cookie); withOrigin(r) }); rec.Code != http.StatusForbidden {
		t.Fatalf("without CSRF: %d", rec.Code)
	}
}
