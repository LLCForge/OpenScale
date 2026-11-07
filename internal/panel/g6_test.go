package panel

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/p2psend"
)

type g6App struct {
	featureApp
	svc *p2psend.Service
}

func (a *g6App) E2ETransfers() []p2psend.TransferView   { return a.svc.E2ETransfers() }
func (a *g6App) E2EPending() []p2psend.Offer            { return a.svc.E2EPending() }
func (a *g6App) E2EDecide(id string, accept bool) error { return a.svc.E2EDecide(id, accept) }
func (a *g6App) E2EStart(r p2psend.SendRequest) error   { return a.svc.E2EStart(r) }
func (a *g6App) E2EQuarantine() p2psend.Quarantine      { return a.svc.E2EQuarantine() }
func (a *g6App) E2ERelay() bool                         { return a.svc.E2ERelay() }
func (a *g6App) SetE2ERelay(on bool) error              { return a.svc.SetE2ERelay(on) }

func TestG6E2ERoutes(t *testing.T) {
	srv := newTestServer(t)
	q := p2psend.Quarantine{Dir: t.TempDir(), Inbox: filepath.Join(t.TempDir(), "gelen")}
	if err := os.WriteFile(filepath.Join(q.Dir, "rapor.pdf"), []byte("%PDF-1.4"), 0o600); err != nil {
		t.Fatal(err)
	}
	app := &g6App{svc: &p2psend.Service{Approvals: p2psend.NewApprovals(time.Minute), Registry: p2psend.NewRegistry(), Q: q}}
	srv.app = app
	h := srv.Handler()
	cookie, csrf := login(t, srv)
	read := func(r *http.Request) { r.AddCookie(cookie) }
	signed := func(r *http.Request) { r.AddCookie(cookie); withOrigin(r); r.Header.Set("X-CSRF-Token", csrf) }

	rec := do(t, h, http.MethodGet, "/api/app/e2e", nil, read)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body)
	}
	if rec := do(t, h, http.MethodPost, "/api/app/e2e/relay", E2ERelayRequest{Enabled: true}, read); rec.Code != http.StatusForbidden {
		t.Fatalf("write without csrf: %d", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/api/app/e2e/relay", E2ERelayRequest{Enabled: true}, signed); rec.Code != http.StatusOK || !app.svc.E2ERelay() {
		t.Fatalf("relay: %d", rec.Code)
	}
	rec = do(t, h, http.MethodGet, "/api/app/e2e/quarantine", nil, read)
	var qs QuarantineStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &qs); err != nil || len(qs.Files) != 1 || qs.Files[0].Warning == "" {
		t.Fatalf("quarantine %s", rec.Body)
	}
	if rec := do(t, h, http.MethodPost, "/api/app/e2e/quarantine/release", FileNameRequest{Name: "../x"}, signed); rec.Code != http.StatusNotFound {
		t.Fatalf("traversal: %d", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/api/app/e2e/quarantine/release", FileNameRequest{Name: "rapor.pdf"}, signed); rec.Code != http.StatusOK {
		t.Fatalf("release: %d %s", rec.Code, rec.Body)
	}
	if rec := do(t, h, http.MethodPost, "/api/app/e2e/send", p2psend.SendRequest{Device: "masa", Path: "rel/yol"}, signed); rec.Code != http.StatusBadRequest {
		t.Fatalf("relative path: %d", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/api/app/e2e/decide", E2EDecision{ID: "yok", Accept: true}, signed); rec.Code != http.StatusNotFound {
		t.Fatalf("decide unknown: %d", rec.Code)
	}
	for _, p := range []string{"/api/app/privacy/screen-share", "/api/app/posture/extended", "/api/app/tpm"} {
		if rec := do(t, h, http.MethodGet, p, nil, read); rec.Code != http.StatusOK {
			t.Fatalf("%s: %d", p, rec.Code)
		}
		if rec := do(t, h, http.MethodGet, p, nil, func(*http.Request) {}); rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s without session: %d", p, rec.Code)
		}
	}
}

func TestG6IdleLock(t *testing.T) {
	srv := newTestServer(t)
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	srv.now = func() time.Time { return now }
	h := srv.Handler()
	cookie, csrf := login(t, srv)
	read := func(r *http.Request) { r.AddCookie(cookie) }
	signed := func(r *http.Request) { r.AddCookie(cookie); withOrigin(r); r.Header.Set("X-CSRF-Token", csrf) }

	// Off by default: nothing locks.
	now = now.Add(time.Hour)
	if rec := do(t, h, http.MethodGet, "/api/devices", nil, read); rec.Code != http.StatusOK {
		t.Fatalf("default: %d", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/api/app/privacy/lock/settings", LockSettings{Minutes: 999}, signed); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad minutes: %d", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/api/app/privacy/lock/settings", LockSettings{Minutes: 5}, signed); rec.Code != http.StatusOK {
		t.Fatalf("settings: %d %s", rec.Code, rec.Body)
	}
	now = now.Add(4 * time.Minute)
	if rec := do(t, h, http.MethodGet, "/api/devices", nil, read); rec.Code != http.StatusOK {
		t.Fatalf("before timeout: %d", rec.Code)
	}
	// Polling does not keep the panel open.
	do(t, h, http.MethodGet, "/api/app/privacy/screen-share", nil, read)
	now = now.Add(2 * time.Minute)
	if rec := do(t, h, http.MethodGet, "/api/devices", nil, read); rec.Code != http.StatusLocked {
		t.Fatalf("after timeout: %d", rec.Code)
	}
	rec := do(t, h, http.MethodGet, "/api/app/privacy/lock", nil, read)
	var st LockStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil || !st.Locked || st.Method != "passphrase" {
		t.Fatalf("status %s", rec.Body)
	}
	if rec := do(t, h, http.MethodPost, "/api/app/privacy/unlock", UnlockRequest{Secret: "yanlış parola"}, signed); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong secret: %d", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/api/app/privacy/unlock", UnlockRequest{Secret: testPass}, signed); rec.Code != http.StatusOK {
		t.Fatalf("unlock: %d %s", rec.Code, rec.Body)
	}
	if rec := do(t, h, http.MethodGet, "/api/devices", nil, read); rec.Code != http.StatusOK {
		t.Fatalf("after unlock: %d", rec.Code)
	}
	// Manual lock.
	if rec := do(t, h, http.MethodPost, "/api/app/privacy/lock", nil, signed); rec.Code != http.StatusOK {
		t.Fatalf("lock: %d", rec.Code)
	}
	if rec := do(t, h, http.MethodGet, "/api/devices", nil, read); rec.Code != http.StatusLocked {
		t.Fatalf("manual lock: %d", rec.Code)
	}
}
