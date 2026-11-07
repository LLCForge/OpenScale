package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openscale/openscale/internal/panel"
)

// fakeEdgeService answers the edge endpoints like the service would.
func fakeEdgeService(t *testing.T) *[]string {
	t.Helper()
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		body, _ := io.ReadAll(r.Body)
		seen = append(seen, r.Method+" "+r.URL.Path+" "+string(body))
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case panel.LocalAPIPrefix + "/health":
			_ = json.NewEncoder(w).Encode(panel.HealthReport{})
		case panel.LocalAPIPrefix + "/edge", panel.LocalAPIPrefix + "/edge/mode", panel.LocalAPIPrefix + "/edge/options":
			_ = json.NewEncoder(w).Encode(panel.EdgeStatus{Schema: 1, Mode: "game",
				Changes: []panel.EdgeChange{{Key: "padding", From: "buckets", To: "off"}},
				Options: panel.EdgeOptions{LockShield: true}})
		case panel.LocalAPIPrefix + "/edge/surface":
			_ = json.NewEncoder(w).Encode(panel.SurfaceReply{Schema: 1, PID: 7, Entries: []panel.SurfaceEntry{
				{Proto: "tcp", Address: "127.0.0.1", Port: 41641, Purpose: "yerel panel", Reach: "yalnızca bu bilgisayar", Rule: "loopback"},
				{Proto: "udp", Address: "::", Port: 51820, Purpose: "WireGuard", Reach: "bütün arayüzler", Rule: "güvenlik duvarı"},
			}})
		case panel.LocalAPIPrefix + "/edge/audit":
			_ = json.NewEncoder(w).Encode(panel.EdgeAuditReply{Schema: 1, Checks: []panel.EdgeCheck{{Area: "wfp", Level: "ok", Message: "temiz"}}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	saved := localAPI
	t.Cleanup(func() { localAPI = saved })
	localAPI.dataDir = func() string { return "svc" }
	localAPI.readToken = func(string) (string, error) { return "tok", nil }
	localAPI.serviceBase = srv.URL
	return &seen
}

func TestEdgeCommands(t *testing.T) {
	h := newHarness(t)
	seen := fakeEdgeService(t)
	out := h.run(exitOK, "edge")
	if !strings.Contains(out, "Kip: game") || !strings.Contains(out, "padding: buckets -> off") || !strings.Contains(out, "Ekran kilitlenince kalkan: açık") {
		t.Fatalf("status:\n%s", out)
	}
	h.run(exitOK, "edge", "mode", "travel", "--exit", "ev-sunucu")
	h.run(exitOK, "edge", "options", "--lock-shield=false", "--travel-exit", "ev")
	h.run(exitOK, "edge", "options")
	joined := strings.Join(*seen, "\n")
	for _, want := range []string{
		`POST /api/local/edge/mode {"mode":"travel","exit_node":"ev-sunucu"}`,
		`POST /api/local/edge/options {"lock_shield":false,"travel_exit":"ev"}`,
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %s in\n%s", want, joined)
		}
	}
	out = h.run(exitOK, "surface")
	if !strings.Contains(out, "127.0.0.1:41641") || !strings.Contains(out, "[::]:51820") {
		t.Fatalf("surface:\n%s", out)
	}
	if out := h.run(exitOK, "edge", "audit"); !strings.Contains(out, "[OK] wfp: temiz") {
		t.Fatalf("audit:\n%s", out)
	}
	if out := h.run(exitOK, "surface", "--json"); !strings.Contains(out, `"pid": 7`) {
		t.Fatalf("json:\n%s", out)
	}
	h.run(exitUsage, "edge", "mode")
	h.run(exitUsage, "edge", "mode", "uçak")
}
