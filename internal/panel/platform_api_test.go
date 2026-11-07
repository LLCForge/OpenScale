package panel

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

// platformApp implements only the platform endpoints.
type platformApp struct {
	App
	repairs int
}

func (a *platformApp) PlatformStatus() (PlatformStatus, error) {
	return PlatformStatus{OS: PlatformOS{Family: "windows", Build: "26100", Arch: "amd64"}, Memory: PlatformMemory{Profile: "low"}}, nil
}

func (a *platformApp) PlatformRepair(context.Context) (PlatformStatus, error) {
	a.repairs++
	st, _ := a.PlatformStatus()
	st.LastRepair = &PlatformRepair{Reason: "manual", Checks: []PlatformCheck{{Area: "kill switch", Level: PlatformRepaired}}}
	return st, nil
}

func TestPlatformRoutes(t *testing.T) {
	srv := newTestServer(t)
	app := &platformApp{}
	srv.app, srv.token = app, "uygulama-anahtari-123"
	h := srv.Handler()
	bearer := func(tok string) func(*http.Request) {
		return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+tok) }
	}
	if rec := do(t, h, http.MethodPost, LocalAPIPrefix+"/platform/repair", nil, bearer("yanlis")); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token: %d", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, LocalAPIPrefix+"/platform/repair", nil, func(r *http.Request) {
		bearer(srv.token)(r)
		withOrigin(r)
	}); rec.Code != http.StatusForbidden {
		t.Fatalf("browser origin on the token route: %d", rec.Code)
	}
	if app.repairs != 0 {
		t.Fatal("refused request reached the app")
	}
	rec := do(t, h, http.MethodGet, LocalAPIPrefix+"/platform", nil, bearer(srv.token))
	var st PlatformStatus
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &st) != nil || st.Schema != PlatformSchema || st.OS.Build != "26100" {
		t.Fatalf("status: %d %s", rec.Code, rec.Body)
	}
	if rec := do(t, h, http.MethodPost, LocalAPIPrefix+"/platform/repair", nil, bearer(srv.token)); rec.Code != http.StatusOK || app.repairs != 1 {
		t.Fatalf("token repair: %d %s", rec.Code, rec.Body)
	}

	// The browser panel: a session to read, a session and CSRF to repair.
	if rec := do(t, h, http.MethodGet, "/api/app/platform", nil, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no session: %d", rec.Code)
	}
	cookie, csrf := login(t, srv)
	withSession := func(r *http.Request) { r.AddCookie(cookie) }
	if rec := do(t, h, http.MethodGet, "/api/app/platform", nil, withSession); rec.Code != http.StatusOK {
		t.Fatalf("session status: %d %s", rec.Code, rec.Body)
	}
	if rec := do(t, h, http.MethodPost, "/api/app/platform/repair", nil, func(r *http.Request) {
		withSession(r)
		withOrigin(r)
	}); rec.Code != http.StatusForbidden || app.repairs != 1 {
		t.Fatalf("repair without CSRF: %d", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/api/app/platform/repair", nil, func(r *http.Request) {
		withSession(r)
		withOrigin(r)
		r.Header.Set("X-CSRF-Token", csrf)
	}); rec.Code != http.StatusOK || app.repairs != 2 {
		t.Fatalf("session repair: %d %s", rec.Code, rec.Body)
	}

	// A service without the platform features answers 404.
	srv.app = &optionsApp{}
	if rec := do(t, h, http.MethodGet, LocalAPIPrefix+"/platform", nil, bearer(srv.token)); rec.Code != http.StatusNotFound {
		t.Fatalf("no platform app: %d", rec.Code)
	}
}
