package panel

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openscale/openscale/internal/svcmgr"
)

// The test never reads or writes the machine's ProgramData folder or the
// autostart registry: every source is replaced by a folder in testdata.
func TestPanelAEndpoints(t *testing.T) {
	dir := filepath.Join("testdata", ".pa-tmp", t.Name())
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(filepath.Join("testdata", ".pa-tmp")) })
	oldD, oldU, oldA := paDiscreetDir, paUpdateStateDir, paAutostartState
	t.Cleanup(func() { paDiscreetDir, paUpdateStateDir, paAutostartState = oldD, oldU, oldA })
	paDiscreetDir = func() string { return dir }
	paUpdateStateDir = func() string { return dir }
	paAutostartState = func(scope svcmgr.Scope) (svcmgr.AutostartEntry, error) {
		if scope == svcmgr.ScopeUser {
			return svcmgr.AutostartEntry{}, errors.New("unsupported")
		}
		return svcmgr.AutostartEntry{Scope: scope, Installed: true, Ours: true, Program: `C:\gizli\yol.exe`}, nil
	}

	srv := newTestServer(t)
	h := srv.Handler()
	cookie, csrf := login(t, srv)
	auth := func(r *http.Request) {
		r.AddCookie(cookie)
		withOrigin(r)
		r.Header.Set("X-CSRF-Token", csrf)
	}

	rec := do(t, h, http.MethodGet, "/api/about", nil, auth)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"update_channel":"stable"`) || !strings.Contains(rec.Body.String(), `"label"`) {
		t.Fatalf("about: %d %s", rec.Code, rec.Body)
	}
	if rec := do(t, h, http.MethodGet, "/api/about", nil, nil); rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden {
		t.Fatalf("about without session: %d", rec.Code)
	}

	rec = do(t, h, http.MethodGet, "/api/desktop/autostart", nil, auth)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"scope":"all"`) || strings.Contains(rec.Body.String(), "gizli") {
		t.Fatalf("autostart: %d %s", rec.Code, rec.Body)
	}

	rec = do(t, h, http.MethodGet, "/api/desktop/discreet", nil, auth)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"enabled":false`) || !strings.Contains(rec.Body.String(), `"supported":true`) {
		t.Fatalf("discreet: %d %s", rec.Code, rec.Body)
	}
	// A name with VPN wording is refused, nothing is written.
	rec = do(t, h, http.MethodPost, "/api/desktop/discreet", map[string]any{"enabled": true, "name": "Benim VPN"}, auth)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad name: %d %s", rec.Code, rec.Body)
	}
	// Without CSRF the change is refused.
	noCSRF := func(r *http.Request) { r.AddCookie(cookie); withOrigin(r) }
	if rec := do(t, h, http.MethodPost, "/api/desktop/discreet", map[string]any{"enabled": true}, noCSRF); rec.Code == http.StatusOK {
		t.Fatalf("discreet without CSRF: %d", rec.Code)
	}
	rec = do(t, h, http.MethodPost, "/api/desktop/discreet", map[string]any{"enabled": true, "name": "Yazıcı Yardımcısı"}, auth)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Yazıcı Yardımcısı") {
		t.Fatalf("save: %d %s", rec.Code, rec.Body)
	}
	rec = do(t, h, http.MethodGet, "/api/desktop/discreet", nil, auth)
	if !strings.Contains(rec.Body.String(), `"enabled":true`) {
		t.Fatalf("saved setting not read back: %s", rec.Body)
	}

	// Every dry run carries the risk summary.
	rec = do(t, h, http.MethodPost, "/api/g1/admins/revoke", map[string]any{"id": strings.Repeat("ab", 16), "dryRun": true}, auth)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"risk":{`) || !strings.Contains(rec.Body.String(), `"level"`) {
		t.Fatalf("dry run risk: %d %s", rec.Code, rec.Body)
	}

	// No discreet folder on this system: change refused, read says unsupported.
	paDiscreetDir = func() string { return "" }
	if rec := do(t, h, http.MethodPost, "/api/desktop/discreet", map[string]any{"enabled": true}, auth); rec.Code != http.StatusNotImplemented {
		t.Fatalf("unsupported save: %d %s", rec.Code, rec.Body)
	}
	if rec := do(t, h, http.MethodGet, "/api/desktop/discreet", nil, auth); !strings.Contains(rec.Body.String(), `"supported":false`) {
		t.Fatalf("unsupported read: %s", rec.Body)
	}
}
