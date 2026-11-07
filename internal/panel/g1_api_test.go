package panel

import (
	"net/http"
	"strings"
	"testing"
)

func TestG1API(t *testing.T) {
	srv := newTestServer(t)
	h := srv.Handler()
	cookie, csrf := login(t, srv)
	auth := func(r *http.Request) {
		r.AddCookie(cookie)
		withOrigin(r)
		r.Header.Set("X-CSRF-Token", csrf)
	}
	for _, c := range []struct{ path, want string }{
		{"/api/g1/admins", `"grants":[]`},
		{"/api/g1/risk", `"risk":null`},
		{"/api/g1/pii", `"warnings":[]`},
		{"/api/g1/sensitive", `"sensitive"`},
		{"/api/g1/duress", `"configured":false`},
		{"/api/g1/emergency", `"documents":[]`},
	} {
		rec := do(t, h, http.MethodGet, c.path, nil, auth)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), c.want) {
			t.Fatalf("%s: %d %s", c.path, rec.Code, rec.Body)
		}
		if rec := do(t, h, http.MethodGet, c.path, nil, nil); rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden {
			t.Fatalf("%s without session: %d", c.path, rec.Code)
		}
	}
	// A draft makes the risk summary appear.
	if rec := do(t, h, http.MethodPost, "/api/p01/lockdown", map[string]any{"on": true, "reason": "deneme", "draft": true}, auth); rec.Code != http.StatusOK {
		t.Fatalf("stage: %d %s", rec.Code, rec.Body)
	}
	if rec := do(t, h, http.MethodGet, "/api/g1/risk", nil, auth); !strings.Contains(rec.Body.String(), `"level"`) {
		t.Fatalf("risk with draft: %s", rec.Body)
	}
	// Panic without confirmation or a prepared document.
	if rec := do(t, h, http.MethodPost, "/api/g1/emergency/publish", map[string]any{"kind": "lockdown", "passphrase": "x"}, auth); rec.Code != http.StatusBadRequest {
		t.Fatalf("unconfirmed panic: %d %s", rec.Code, rec.Body)
	}
	if rec := do(t, h, http.MethodPost, "/api/g1/emergency/publish", map[string]any{"kind": "lockdown", "passphrase": "acil durum parolası 12", "confirm": "PANIK"}, auth); rec.Code != http.StatusNotFound {
		t.Fatalf("panic without documents: %d %s", rec.Code, rec.Body)
	}
	if rec := do(t, h, http.MethodPost, "/api/g1/admins/revoke", map[string]any{"id": "kisa", "passphrase": testPass}, auth); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad id: %d %s", rec.Code, rec.Body)
	}
	rec := do(t, h, http.MethodPost, "/api/g1/admins/revoke", map[string]any{"id": strings.Repeat("ab", 16), "dryRun": true}, auth)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Yönetici yetkisi geri alındı") {
		t.Fatalf("revoke dry run: %d %s", rec.Code, rec.Body)
	}
}
