package panel

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestP01DraftAndLockdownAPI(t *testing.T) {
	srv := newTestServer(t)
	h := srv.Handler()
	cookie, csrf := login(t, srv)
	auth := func(r *http.Request) {
		r.AddCookie(cookie)
		withOrigin(r)
		r.Header.Set("X-CSRF-Token", csrf)
	}
	// Lockdown without confirmation is refused.
	if rec := do(t, h, http.MethodPost, "/api/p01/lockdown", map[string]any{"on": true, "passphrase": testPass}, auth); rec.Code != http.StatusBadRequest {
		t.Fatalf("unconfirmed lockdown: %d %s", rec.Code, rec.Body)
	}
	// Staged into the draft, then signed once.
	rec := do(t, h, http.MethodPost, "/api/p01/lockdown", map[string]any{"on": true, "reason": "deneme", "draft": true}, auth)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"draft":true`) {
		t.Fatalf("stage: %d %s", rec.Code, rec.Body)
	}
	rec = do(t, h, http.MethodPost, "/api/p01/key-age", map[string]any{"days": 90, "draft": true}, auth)
	if rec.Code != http.StatusOK {
		t.Fatalf("stage 2: %d %s", rec.Code, rec.Body)
	}
	rec = do(t, h, http.MethodGet, "/api/overview", nil, auth)
	if !strings.Contains(rec.Body.String(), HealthDraftPending) {
		t.Fatalf("overview without draft warning: %s", rec.Body)
	}
	rec = do(t, h, http.MethodPost, "/api/p01/draft/sign", map[string]any{"passphrase": testPass}, auth)
	if rec.Code != http.StatusOK {
		t.Fatalf("sign: %d %s", rec.Code, rec.Body)
	}
	var resp changeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || resp.Version != 2 {
		t.Fatalf("one version for the draft: %+v %v", resp, err)
	}
	rec = do(t, h, http.MethodGet, "/api/overview", nil, auth)
	if !strings.Contains(rec.Body.String(), HealthLockdown) {
		t.Fatalf("overview without lockdown warning: %s", rec.Body)
	}
	for _, path := range []string{"/api/p01/ledger", "/api/p01/limits", "/api/p01/fingerprints", "/api/p01/key-ages", "/api/p01/draft"} {
		if rec := do(t, h, http.MethodGet, path, nil, auth); rec.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", path, rec.Code, rec.Body)
		}
	}
	if rec := do(t, h, http.MethodPost, "/api/p01/devices/bulk", map[string]any{"names": []string{"Yok!"}, "expire": true}, auth); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad bulk name: %d", rec.Code)
	}
	if rec := do(t, h, http.MethodGet, "/api/p01/ledger", nil, nil); rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden {
		t.Fatalf("ledger without session: %d", rec.Code)
	}
}
