package panel

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/leaktest"
)

// leakFakeApp implements only the leak routes' calls.
type leakFakeApp struct {
	App
	tests    int
	captive  time.Duration
	revoked  int
	testFail error
}

func (a *leakFakeApp) Status() AppStatus { return AppStatus{Mode: ModeMember} }

func (a *leakFakeApp) ExitLeakTest(context.Context) (leaktest.Report, error) {
	a.tests++
	if a.testFail != nil {
		return leaktest.Report{}, a.testFail
	}
	return leaktest.Report{Schema: leaktest.Schema, ExitNode: "vps", Checks: []leaktest.Check{{ID: leaktest.CheckIP, Level: leaktest.LevelOK}}}, nil
}

func (a *leakFakeApp) AllowCaptivePortal(d time.Duration) (CaptiveGrant, error) {
	a.captive = d
	return CaptiveGrant{Addrs: []string{"192.168.1.1"}, Until: time.Unix(100, 0)}, nil
}

func (a *leakFakeApp) RevokeCaptivePortal() error { a.revoked++; return nil }

func TestLeakEndpoints(t *testing.T) {
	srv := newTestServer(t)
	app := &leakFakeApp{}
	srv.app, srv.token = app, "uygulama-anahtari-123"
	h := srv.Handler()
	if rec := do(t, h, http.MethodPost, "/api/app/exit/leak-test", map[string]any{}, withOrigin); rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden {
		t.Fatalf("without a session: %d", rec.Code)
	}
	cookie, csrf := login(t, srv)
	session := func(r *http.Request) { r.AddCookie(cookie); withOrigin(r) }
	if rec := do(t, h, http.MethodPost, "/api/app/exit/captive", map[string]int{"minutes": 5}, session); rec.Code != http.StatusForbidden {
		t.Fatalf("captive without CSRF: %d", rec.Code)
	}
	signed := func(r *http.Request) { session(r); r.Header.Set("X-CSRF-Token", csrf) }
	rec := do(t, h, http.MethodPost, "/api/app/exit/leak-test", map[string]any{}, signed)
	var rep leaktest.Report
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &rep) != nil || rep.ExitNode != "vps" || app.tests != 1 {
		t.Fatalf("leak test: %d %s", rec.Code, rec.Body)
	}
	app.testFail = leaktest.ErrNoExitNode
	if rec := do(t, h, http.MethodPost, "/api/app/exit/leak-test", map[string]any{}, signed); rec.Code != http.StatusConflict {
		t.Fatalf("no exit node: %d", rec.Code)
	}
	for _, bad := range []any{map[string]int{"minutes": 0}, map[string]int{"minutes": 16}, map[string]any{}, map[string]any{"minutes": "5"}} {
		if rec := do(t, h, http.MethodPost, "/api/app/exit/captive", bad, signed); rec.Code != http.StatusBadRequest {
			t.Fatalf("captive %v: %d", bad, rec.Code)
		}
	}
	if app.captive != 0 {
		t.Fatal("invalid request reached the app")
	}
	if rec := do(t, h, http.MethodPost, "/api/app/exit/captive", map[string]int{"minutes": 5}, signed); rec.Code != http.StatusOK || app.captive != 5*time.Minute {
		t.Fatalf("captive: %d %s", rec.Code, rec.Body)
	}
	if rec := do(t, h, http.MethodPost, "/api/app/exit/captive", map[string]bool{"off": true}, signed); rec.Code != http.StatusOK || app.revoked != 1 {
		t.Fatalf("captive off: %d", rec.Code)
	}

	// An App without the leak part answers 404.
	srv.app = &optionsApp{}
	if rec := do(t, h, http.MethodPost, "/api/app/exit/leak-test", map[string]any{}, signed); rec.Code != http.StatusNotFound {
		t.Fatalf("without LeakApp: %d", rec.Code)
	}
}
