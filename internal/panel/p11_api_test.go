package panel

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

// edgeApp implements only the edge endpoints.
type edgeApp struct {
	App
	mode   EdgeModeRequest
	locked *bool
	opts   EdgeOptionsChange
}

func (a *edgeApp) EdgeStatus() (EdgeStatus, error) { return EdgeStatus{Mode: a.mode.Mode}, nil }
func (a *edgeApp) EdgeSetMode(r EdgeModeRequest) (EdgeStatus, error) {
	a.mode = r
	return EdgeStatus{Mode: r.Mode}, nil
}
func (a *edgeApp) EdgeSetOptions(c EdgeOptionsChange) (EdgeStatus, error) {
	a.opts = c
	return EdgeStatus{}, nil
}
func (a *edgeApp) EdgeSessionLock(l bool) (EdgeStatus, error) {
	a.locked = &l
	return EdgeStatus{LockShield: l}, nil
}
func (a *edgeApp) EdgeSurface() (SurfaceReply, error) {
	return SurfaceReply{PID: 1, Entries: []SurfaceEntry{{Proto: "tcp", Port: 1}}}, nil
}
func (a *edgeApp) EdgeAudit(context.Context) (EdgeAuditReply, error) {
	return EdgeAuditReply{Checks: []EdgeCheck{{Area: "x", Level: "ok"}}}, nil
}

func TestEdgeRoutesNeedAppToken(t *testing.T) {
	srv := newTestServer(t)
	app := &edgeApp{}
	srv.app, srv.token = app, "uygulama-anahtari-123"
	h := srv.Handler()
	bearer := func(tok string) func(*http.Request) {
		return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+tok) }
	}
	if rec := do(t, h, http.MethodPost, LocalAPIPrefix+"/edge/mode", EdgeModeRequest{Mode: "game"}, bearer("yanlis")); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token: %d", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, LocalAPIPrefix+"/edge/mode", EdgeModeRequest{Mode: "game"}, func(r *http.Request) {
		bearer(srv.token)(r)
		withOrigin(r)
	}); rec.Code != http.StatusForbidden {
		t.Fatalf("browser origin: %d", rec.Code)
	}
	if app.mode.Mode != "" {
		t.Fatal("refused request reached the app")
	}
	ok := bearer(srv.token)
	rec := do(t, h, http.MethodPost, LocalAPIPrefix+"/edge/mode", EdgeModeRequest{Mode: "travel", ExitNode: "ev"}, ok)
	var st EdgeStatus
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &st) != nil || st.Schema != EdgeSchema || app.mode.ExitNode != "ev" {
		t.Fatalf("mode: %d %s", rec.Code, rec.Body)
	}
	if rec := do(t, h, http.MethodPost, LocalAPIPrefix+"/edge/lock", EdgeLockRequest{Locked: true}, ok); rec.Code != http.StatusOK || app.locked == nil || !*app.locked {
		t.Fatalf("lock: %d", rec.Code)
	}
	tru := true
	if rec := do(t, h, http.MethodPost, LocalAPIPrefix+"/edge/options", EdgeOptionsChange{LockShield: &tru}, ok); rec.Code != http.StatusOK || app.opts.LockShield == nil {
		t.Fatalf("options: %d", rec.Code)
	}
	for _, p := range []string{"/edge", "/edge/surface", "/edge/audit"} {
		if rec := do(t, h, http.MethodGet, LocalAPIPrefix+p, nil, ok); rec.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", p, rec.Code, rec.Body)
		}
	}
	long := make([]byte, 300)
	for i := range long {
		long[i] = 'a'
	}
	if rec := do(t, h, http.MethodPost, LocalAPIPrefix+"/edge/mode", EdgeModeRequest{Mode: "travel", ExitNode: string(long)}, ok); rec.Code != http.StatusBadRequest {
		t.Fatalf("long exit name: %d", rec.Code)
	}
	// A service without the edge features answers 404.
	srv.app = &optionsApp{}
	if rec := do(t, h, http.MethodGet, LocalAPIPrefix+"/edge", nil, ok); rec.Code != http.StatusNotFound {
		t.Fatalf("no edge app: %d", rec.Code)
	}
}

func TestStaticPagesReportTrustedTypes(t *testing.T) {
	srv := newTestServer(t)
	cookie, _ := login(t, srv)
	rec := do(t, srv.Handler(), http.MethodGet, "/", nil, func(r *http.Request) { r.AddCookie(cookie) })
	if got := rec.Header().Get("Content-Security-Policy-Report-Only"); got != "require-trusted-types-for 'script'" {
		t.Fatalf("report-only policy %q", got)
	}
}
