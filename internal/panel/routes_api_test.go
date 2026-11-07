package panel

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// Routes page endpoints (ADR-0133).
func TestP10RouteEndpoints(t *testing.T) {
	_, _, call := policyServer(t)

	set := signed(map[string]any{"device": "masaustu", "routes": []string{"192.168.1.0/24"}})
	if code, body := call(http.MethodPost, "/api/routes/set", set); code != http.StatusOK || !strings.Contains(body, "+ alt ağ rotası 192.168.1.0/24") {
		t.Fatalf("set: %d %s", code, body)
	}
	for _, bad := range []map[string]any{
		{"device": "masaustu", "routes": []string{"8.8.8.0/24"}, "dryRun": true},
		{"device": "masaustu", "routes": []string{"192.168.1.1/24"}, "dryRun": true},
		{"device": "", "routes": []string{}, "dryRun": true},
	} {
		if code, _ := call(http.MethodPost, "/api/routes/set", bad); code != http.StatusBadRequest {
			t.Fatalf("bad set %v: %d", bad, code)
		}
	}
	code, body := call(http.MethodGet, "/api/routes", nil)
	var res routesResponse
	if code != http.StatusOK || json.Unmarshal([]byte(body), &res) != nil {
		t.Fatalf("list: %d %s", code, body)
	}
	found := false
	for _, d := range res.Devices {
		found = found || (d.Name == "masaustu" && len(d.Routes) == 1 && d.Routes[0] == "192.168.1.0/24")
	}
	if !found || res.Strategy != "first" {
		t.Fatalf("list: %s", body)
	}
	// A rule for the route makes laptop a client of the router.
	rule := signed(map[string]any{"from": []string{"laptop"}, "to": []string{"192.168.1.0/24"}, "protocol": "tcp", "ports": []string{"445"}})
	if code, body := call(http.MethodPost, "/api/rules", rule); code != http.StatusOK {
		t.Fatalf("route rule: %d %s", code, body)
	}
	_, body = call(http.MethodGet, "/api/routes", nil)
	if !strings.Contains(body, `"clients":["laptop"]`) {
		t.Fatalf("clients: %s", body)
	}
	if code, _ := call(http.MethodPost, "/api/routes/inspect", map[string]any{"advertisement": "osroute1.bozuk"}); code != http.StatusBadRequest {
		t.Fatalf("a broken advertisement must be refused, got %d", code)
	}
	if code, _ := call(http.MethodPost, "/api/routes/approve", map[string]any{"advertisement": "osroute1.bozuk", "dryRun": true}); code == http.StatusOK {
		t.Fatal("a broken advertisement must not be approved")
	}
}
