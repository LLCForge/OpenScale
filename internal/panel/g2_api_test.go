package panel

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/coordinator"
)

func TestG2CanaryAndCoordinatorAPI(t *testing.T) {
	srv := newTestServer(t)
	h := srv.Handler()
	cookie, csrf := login(t, srv)
	auth := func(r *http.Request) {
		r.AddCookie(cookie)
		withOrigin(r)
		r.Header.Set("X-CSRF-Token", csrf)
	}
	// Signing needs a sane validity and the root key passphrase.
	if rec := do(t, h, http.MethodPost, "/api/g2/canary/sign", map[string]any{"passphrase": testPass, "statement": "x", "days": 200}, auth); rec.Code != http.StatusBadRequest {
		t.Fatalf("days: %d %s", rec.Code, rec.Body)
	}
	if rec := do(t, h, http.MethodPost, "/api/g2/canary/sign", map[string]any{"passphrase": "yanlış parola 1234", "statement": "x", "days": 30}, auth); rec.Code == http.StatusOK {
		t.Fatal("wrong passphrase signed")
	}
	rec := do(t, h, http.MethodPost, "/api/g2/canary/sign", map[string]any{"passphrase": testPass, "statement": "Gizli talep almadım.", "days": 30}, auth)
	if rec.Code != http.StatusOK {
		t.Fatalf("sign: %d %s", rec.Code, rec.Body)
	}
	var signed CanaryReply
	if err := json.Unmarshal(rec.Body.Bytes(), &signed); err != nil || len(signed.Canary) == 0 || signed.State != "valid" {
		t.Fatalf("signed %+v %v", signed, err)
	}
	rec = do(t, h, http.MethodPost, "/api/g2/canary/verify", map[string]any{"canary": signed.Canary}, auth)
	var v CanaryReply
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil || v.State != "valid" || v.Statement != "Gizli talep almadım." {
		t.Fatalf("verify %+v %v %s", v, err, rec.Body)
	}
	bad := append([]byte(nil), signed.Canary...)
	bad[len(bad)/2] ^= 1
	rec = do(t, h, http.MethodPost, "/api/g2/canary/verify", map[string]any{"canary": bad}, auth)
	if !strings.Contains(rec.Body.String(), `"state":"invalid"`) {
		t.Fatalf("tampered: %s", rec.Body)
	}
	// Sealed blob: garbage is reported invalid, never echoed.
	rec = do(t, h, http.MethodPost, "/api/g2/sealed-blob/verify", map[string]any{"blob": []byte("x")}, auth)
	if !strings.Contains(rec.Body.String(), `"valid":false`) {
		t.Fatalf("blob: %s", rec.Body)
	}
	// Cross-check and independence.
	head := coordinator.Head{Schema: 1, Version: 3, Digest: strings.Repeat("ab", 32), ServedAt: time.Now()}
	other := head
	other.Digest = strings.Repeat("cd", 32)
	rec = do(t, h, http.MethodPost, "/api/g2/coordinators/cross-check", map[string]any{"observations": []coordinator.HeadObservation{{Coordinator: "a", Head: &head}, {Coordinator: "b", Head: &other}}}, auth)
	if !strings.Contains(rec.Body.String(), coordinator.FindingEquivocation) {
		t.Fatalf("cross-check: %d %s", rec.Code, rec.Body)
	}
	if rec := do(t, h, http.MethodPost, "/api/g2/coordinators/cross-check", map[string]any{"observations": []any{}}, auth); rec.Code != http.StatusBadRequest {
		t.Fatalf("empty cross-check: %d", rec.Code)
	}
	if rec := do(t, h, http.MethodGet, "/api/g2/coordinators/independence", nil, auth); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"findings"`) {
		t.Fatalf("independence: %d %s", rec.Code, rec.Body)
	}
	if rec := do(t, h, http.MethodGet, "/api/g2/coordinators/independence", nil, nil); rec.Code == http.StatusOK {
		t.Fatal("independence without a session")
	}
}
