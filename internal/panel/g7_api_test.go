package panel

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestG7ExtensionsAPI(t *testing.T) {
	srv := newTestServer(t)
	h := srv.Handler()
	cookie, csrf := login(t, srv)
	auth := func(r *http.Request) {
		r.AddCookie(cookie)
		withOrigin(r)
		r.Header.Set("X-CSRF-Token", csrf)
	}
	if rec := do(t, h, http.MethodGet, "/api/g7/extensions", nil, nil); rec.Code == http.StatusOK {
		t.Fatal("extensions without a session")
	}
	blocking := map[string]any{
		"policy":    map[string]any{"default": []string{"ads", "trackers"}},
		"block_doh": []string{"doh.example.net"},
	}
	// Dry run shows the difference without the passphrase.
	rec := do(t, h, http.MethodPost, "/api/g7/blocking", map[string]any{"dryRun": true, "blocking": blocking}, auth)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"dryRun":true`) {
		t.Fatalf("dry run: %d %s", rec.Code, rec.Body)
	}
	// Telemetry without a keep list is refused before signing.
	bad := map[string]any{"policy": map[string]any{"default": []string{"os-telemetry"}}}
	if rec := do(t, h, http.MethodPost, "/api/g7/blocking", map[string]any{"passphrase": testPass, "blocking": bad}, auth); rec.Code == http.StatusOK {
		t.Fatal("telemetry without keep list signed")
	}
	if rec := do(t, h, http.MethodPost, "/api/g7/blocking", map[string]any{"passphrase": "yanlış parola 1234", "blocking": blocking}, auth); rec.Code == http.StatusOK {
		t.Fatal("wrong passphrase signed")
	}
	if rec := do(t, h, http.MethodPost, "/api/g7/blocking", map[string]any{"passphrase": testPass, "blocking": blocking}, auth); rec.Code != http.StatusOK {
		t.Fatalf("sign: %d %s", rec.Code, rec.Body)
	}
	digest := strings.Repeat("ab", 32)
	if rec := do(t, h, http.MethodPost, "/api/g7/plugins/pin", map[string]any{"passphrase": testPass, "pin": map[string]string{"name": "ornek", "module_sha256": digest, "manifest_sha256": "xyz"}}, auth); rec.Code == http.StatusOK {
		t.Fatal("bad pin signed")
	}
	if rec := do(t, h, http.MethodPost, "/api/g7/plugins/pin", map[string]any{"passphrase": testPass, "pin": map[string]string{"name": "ornek", "module_sha256": digest, "manifest_sha256": digest}}, auth); rec.Code != http.StatusOK {
		t.Fatalf("pin: %d %s", rec.Code, rec.Body)
	}
	rec = do(t, h, http.MethodGet, "/api/g7/extensions", nil, auth)
	var v ExtensionsView
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("%v %s", err, rec.Body)
	}
	if v.Blocking == nil || len(v.Blocking.BlockDoH) != 1 || len(v.Pins) != 1 || v.Pins[0].Name != "ornek" || len(v.Categories) != 5 {
		t.Fatalf("view %+v", v)
	}
	if rec := do(t, h, http.MethodPost, "/api/g7/plugins/unpin", map[string]any{"passphrase": testPass, "name": "ornek"}, auth); rec.Code != http.StatusOK {
		t.Fatalf("unpin: %d %s", rec.Code, rec.Body)
	}
	// The resolver is not running in this process: runtime calls say so.
	if rec := do(t, h, http.MethodPost, "/api/g7/adblock/allow-once", map[string]any{"device": "a", "name": "x.test", "minutes": 5}, auth); rec.Code != http.StatusConflict {
		t.Fatalf("allow once without engine: %d", rec.Code)
	}
	if rec := do(t, h, http.MethodGet, "/api/g7/adblock/top", nil, auth); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"active":false`) {
		t.Fatalf("top: %d %s", rec.Code, rec.Body)
	}
	// Monitoring needs the desktop service.
	if rec := do(t, h, http.MethodGet, "/api/g7/monitor", nil, auth); rec.Code != http.StatusNotImplemented {
		t.Fatalf("monitor without app: %d", rec.Code)
	}
}
