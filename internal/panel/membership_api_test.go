package panel

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestMembershipEndpoints(t *testing.T) {
	srv := newTestServer(t)
	cookie, csrf := login(t, srv)
	h := srv.Handler()
	auth := func(r *http.Request) {
		r.AddCookie(cookie)
		r.Header.Set("Origin", "http://"+testHost)
		r.Header.Set("X-CSRF-Token", csrf)
	}
	// Without the desktop service the live lists explain why they are empty.
	rec := do(t, h, http.MethodGet, "/api/membership?days=30", nil, auth)
	if rec.Code != http.StatusOK {
		t.Fatalf("membership: %d %s", rec.Code, rec.Body)
	}
	var resp membershipResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || resp.LiveError == "" || resp.Inactive == nil {
		t.Fatalf("membership body: %s", rec.Body)
	}
	if rec := do(t, h, http.MethodGet, "/api/membership?days=0", nil, auth); rec.Code != http.StatusBadRequest {
		t.Fatalf("days=0 status %d", rec.Code)
	}
	// The minimum version is validated and signed.
	if rec := do(t, h, http.MethodPost, "/api/membership/min-version", map[string]any{"passphrase": testPass, "version": "1.2"}, auth); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad version status %d %s", rec.Code, rec.Body)
	}
	rec = do(t, h, http.MethodPost, "/api/membership/min-version", map[string]any{"passphrase": testPass, "version": "1.2.3"}, auth)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Asgari istemci sürümü") {
		t.Fatalf("min version: %d %s", rec.Code, rec.Body)
	}
	// Preauthorized keys need a coordinator-free network too and return the key once.
	rec = do(t, h, http.MethodPost, "/api/membership/preauth", map[string]any{"passphrase": testPass, "name": "ci", "ephemeral": true, "hours": 2}, auth)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "osauth1.") {
		t.Fatalf("preauth: %d %s", rec.Code, rec.Body)
	}
	rec = do(t, h, http.MethodPost, "/api/membership/preauth", map[string]any{"passphrase": testPass, "name": "ci2", "ephemeral": true, "hours": 24 * 31}, auth)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("too long ephemeral: %d", rec.Code)
	}
	rec = do(t, h, http.MethodPost, "/api/membership/remove", map[string]any{"passphrase": testPass, "names": []string{"ci"}}, auth)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "- cihaz ci") {
		t.Fatalf("remove: %d %s", rec.Code, rec.Body)
	}
	// Mutations need CSRF.
	rec = do(t, h, http.MethodPost, "/api/membership/remove", map[string]any{"passphrase": testPass, "names": []string{"x"}}, func(r *http.Request) { r.AddCookie(cookie) })
	if rec.Code == http.StatusOK {
		t.Fatal("remove without CSRF accepted")
	}
	// Leaving needs the desktop service.
	if rec := do(t, h, http.MethodPost, "/api/app/leave", map[string]any{}, auth); rec.Code == http.StatusOK {
		t.Fatal("leave without the service accepted")
	}
}
