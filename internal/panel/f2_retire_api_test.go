package panel

import (
	"net/http"
	"strings"
	"testing"
)

func TestRetireDeviceAPI(t *testing.T) {
	srv := newTestServer(t)
	// server.go registers the routes with one line; the test mounts them
	// on their own mux so it does not depend on that line.
	mux := http.NewServeMux()
	srv.f2RetireRoutes(mux)
	cookie, csrf := login(t, srv)
	auth := func(r *http.Request) {
		r.AddCookie(cookie)
		withOrigin(r)
		r.Header.Set("X-CSRF-Token", csrf)
	}
	const path = "/api/f2/retire"
	if rec := do(t, mux, http.MethodGet, path+"?name=nas", nil, nil); rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden {
		t.Fatalf("without session: %d", rec.Code)
	}
	if rec := do(t, mux, http.MethodPost, path, map[string]any{"name": "nas", "dryRun": true}, nil); rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden {
		t.Fatalf("write without session: %d", rec.Code)
	}
	addTestDevices(t, srv, []string{"laptop", "nas"}, nil)
	if rec := do(t, mux, http.MethodPost, "/api/rules", nil, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("mux mounts only the retire routes: %d", rec.Code)
	}
	signRule := srv.Handler()
	if rec := do(t, signRule, http.MethodPost, "/api/rules", map[string]any{"from": []string{"laptop"}, "to": []string{"nas"}, "protocol": "tcp", "ports": []string{"445"}, "passphrase": testPass}, auth); rec.Code != http.StatusOK {
		t.Fatalf("rule: %d %s", rec.Code, rec.Body)
	}

	rec := do(t, mux, http.MethodGet, path+"?name=nas", nil, auth)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"device":"nas"`) || !strings.Contains(rec.Body.String(), "Kural silinir") {
		t.Fatalf("preview: %d %s", rec.Code, rec.Body)
	}
	if rec := do(t, mux, http.MethodGet, path+"?name=yok", nil, auth); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown: %d %s", rec.Code, rec.Body)
	}
	if rec := do(t, mux, http.MethodGet, path+"?name="+strings.Repeat("a", 80), nil, auth); rec.Code != http.StatusBadRequest {
		t.Fatalf("long name: %d", rec.Code)
	}
	rec = do(t, mux, http.MethodPost, path, map[string]any{"name": "nas", "dryRun": true}, auth)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "nas") {
		t.Fatalf("dry run: %d %s", rec.Code, rec.Body)
	}
	doc, _ := srv.network().Document()
	if _, ok := doc.DeviceByName("nas"); !ok {
		t.Fatal("dry run revoked the device")
	}
	if rec := do(t, mux, http.MethodPost, path, map[string]any{"name": "nas", "passphrase": "yanlış parola 1234"}, auth); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong passphrase: %d %s", rec.Code, rec.Body)
	}
	rec = do(t, mux, http.MethodPost, path, map[string]any{"name": "nas", "passphrase": testPass}, auth)
	if rec.Code != http.StatusOK {
		t.Fatalf("retire: %d %s", rec.Code, rec.Body)
	}
	doc, _ = srv.network().Document()
	if _, ok := doc.DeviceByName("nas"); ok || len(doc.Rules) != 0 {
		t.Fatalf("not retired: %+v", doc.Rules)
	}
}
