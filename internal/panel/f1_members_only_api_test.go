package panel

import (
	"net/http"
	"strings"
	"testing"
)

func TestMembersOnlySwitchAPI(t *testing.T) {
	srv := newTestServer(t)
	h := srv.Handler()
	cookie, csrf := login(t, srv)
	auth := func(r *http.Request) {
		r.AddCookie(cookie)
		withOrigin(r)
		r.Header.Set("X-CSRF-Token", csrf)
	}
	const path = "/api/g1/members-only"
	if rec := do(t, h, http.MethodGet, path, nil, nil); rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden {
		t.Fatalf("without session: %d", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, path, map[string]any{"enabled": true, "dryRun": true}, nil); rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden {
		t.Fatalf("write without session: %d", rec.Code)
	}
	// No device yet: it cannot be sealed and the switch says why.
	rec := do(t, h, http.MethodGet, path, nil, auth)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"enabled":false`) || !strings.Contains(rec.Body.String(), "en az bir cihaz") {
		t.Fatalf("status: %d %s", rec.Code, rec.Body)
	}
	if rec := do(t, h, http.MethodPost, path, map[string]any{"enabled": true, "dryRun": true}, auth); rec.Code != http.StatusBadRequest {
		t.Fatalf("blocked: %d %s", rec.Code, rec.Body)
	}
	addTestDevices(t, srv, []string{"nas"}, nil)
	rec = do(t, h, http.MethodGet, path, nil, auth)
	if !strings.Contains(rec.Body.String(), `"raisesMinClient":true`) || !strings.Contains(rec.Body.String(), "Asgari istemci") {
		t.Fatalf("warning missing: %s", rec.Body)
	}
	// The dry run shows the client minimum and signs nothing.
	rec = do(t, h, http.MethodPost, path, map[string]any{"enabled": true, "dryRun": true}, auth)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Asgari istemci") {
		t.Fatalf("dry run: %d %s", rec.Code, rec.Body)
	}
	if srv.network().MembersOnlyEnabled() {
		t.Fatal("the dry run changed the setting")
	}
	if rec := do(t, h, http.MethodPost, path, map[string]any{"enabled": true, "draft": true}, auth); rec.Code != http.StatusBadRequest {
		t.Fatalf("draft: %d %s", rec.Code, rec.Body)
	}
	if rec := do(t, h, http.MethodPost, path, map[string]any{"enabled": true, "passphrase": "yanlış parola 1234"}, auth); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong passphrase: %d %s", rec.Code, rec.Body)
	}
	if srv.network().MembersOnlyEnabled() {
		t.Fatal("a failed signature left the setting on")
	}
	rec = do(t, h, http.MethodPost, path, map[string]any{"enabled": true, "passphrase": testPass}, auth)
	if rec.Code != http.StatusOK {
		t.Fatalf("turning on: %d %s", rec.Code, rec.Body)
	}
	rec = do(t, h, http.MethodGet, path, nil, auth)
	if !strings.Contains(rec.Body.String(), `"enabled":true`) || !strings.Contains(rec.Body.String(), `"sealed":true`) {
		t.Fatalf("status after on: %s", rec.Body)
	}
	if rec := do(t, h, http.MethodPost, path, map[string]any{"enabled": true, "dryRun": true}, auth); rec.Code != http.StatusBadRequest {
		t.Fatalf("on while on: %d %s", rec.Code, rec.Body)
	}
	rec = do(t, h, http.MethodPost, path, map[string]any{"enabled": false, "passphrase": testPass}, auth)
	if rec.Code != http.StatusOK {
		t.Fatalf("turning off: %d %s", rec.Code, rec.Body)
	}
	rec = do(t, h, http.MethodGet, path, nil, auth)
	if !strings.Contains(rec.Body.String(), `"enabled":false`) || !strings.Contains(rec.Body.String(), `"sealed":false`) {
		t.Fatalf("status after off: %s", rec.Body)
	}
}
