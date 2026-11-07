package panel

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// Rule language endpoints (ADR-0120).
func TestP09PolicyEndpoints(t *testing.T) {
	srv, _, call := policyServer(t)

	// Port names, bidirectional and a one-time window on a new rule.
	rule := signed(map[string]any{"from": []string{"laptop"}, "to": []string{"masaustu"}, "protocol": "tcp", "ports": []string{"rdp"},
		"bidirectional": true, "windowMinutes": 30})
	if code, body := call(http.MethodPost, "/api/rules", rule); code != http.StatusOK || !strings.Contains(body, "tcp/3389 [çift yönlü; bitiş") {
		t.Fatalf("add rule: %d %s", code, body)
	}
	if code, _ := call(http.MethodPost, "/api/rules", signed(map[string]any{"from": []string{"laptop"}, "to": []string{"masaustu"},
		"protocol": "tcp", "ports": []string{"22"}, "windowMinutes": 50000})); code != http.StatusBadRequest {
		t.Fatalf("an over-long window must be refused, got %d", code)
	}

	// A broad rule needs explicit confirmation; the dry run does not.
	broad := map[string]any{"from": []string{"*"}, "to": []string{"*"}, "protocol": "any"}
	if code, _ := call(http.MethodPost, "/api/rules", map[string]any{"from": []string{"*"}, "to": []string{"*"}, "protocol": "any", "dryRun": true}); code != http.StatusOK {
		t.Fatalf("broad dry run: %d", code)
	}
	if code, body := call(http.MethodPost, "/api/rules", signed(broad)); code != http.StatusBadRequest || !strings.Contains(body, "açıkça onayla") {
		t.Fatalf("unconfirmed broad rule: %d %s", code, body)
	}

	// Simulator: the bidirectional rule allows the reverse direction.
	code, body := call(http.MethodPost, "/api/policy/check", map[string]any{"from": "masaustu", "to": "laptop", "protocol": "tcp", "port": "3389"})
	var res policyCheckResponse
	if code != http.StatusOK || json.Unmarshal([]byte(body), &res) != nil || !res.Allowed || res.Rule != 0 {
		t.Fatalf("check: %d %s", code, body)
	}
	code, body = call(http.MethodPost, "/api/policy/check", map[string]any{"from": "masaustu", "to": "laptop", "protocol": "udp", "port": "53"})
	if code != http.StatusOK || json.Unmarshal([]byte(body), &res) != nil || res.Allowed || res.Reason != "default_deny" {
		t.Fatalf("check deny: %d %s", code, body)
	}
	if code, _ := call(http.MethodPost, "/api/policy/check", map[string]any{"from": "yok", "to": "laptop", "protocol": "icmp"}); code != http.StatusBadRequest {
		t.Fatalf("unknown device must be refused, got %d", code)
	}

	// Text export and import with a test.
	code, body = call(http.MethodGet, "/api/policy/text", nil)
	var text struct{ Text string }
	if code != http.StatusOK || json.Unmarshal([]byte(body), &text) != nil || !strings.Contains(text.Text, `"rules": [`) {
		t.Fatalf("export: %d %s", code, body)
	}
	edited := strings.Replace(text.Text, `"tests": []`, `"tests": [{"from":"laptop","to":"masaustu","protocol":"tcp","port":22,"expect":"allow"}]`, 1)
	if code, body := call(http.MethodPost, "/api/policy/text", map[string]any{"text": edited, "dryRun": true}); code != http.StatusBadRequest || !strings.Contains(body, "kural testi başarısız") {
		t.Fatalf("a failing test must refuse the change: %d %s", code, body)
	}
	edited = strings.Replace(text.Text, `"tests": []`, `"tests": [{"from":"laptop","to":"masaustu","protocol":"tcp","port":3389,"expect":"allow"}]`, 1)
	if code, body := call(http.MethodPost, "/api/policy/text", signed(map[string]any{"text": edited})); code != http.StatusOK || !strings.Contains(body, "kural testi laptop") {
		t.Fatalf("import: %d %s", code, body)
	}
	if code, body := call(http.MethodPost, "/api/policy/text", map[string]any{"text": "{", "dryRun": true}); code != http.StatusBadRequest || !strings.Contains(body, "politika dosyası geçersiz") {
		t.Fatalf("bad text: %d %s", code, body)
	}

	// Report lists the passing test and the clock warning.
	code, body = call(http.MethodGet, "/api/policy/report", nil)
	if code != http.StatusOK || !strings.Contains(body, `"passed":true`) || !strings.Contains(body, `"code":"clock"`) {
		t.Fatalf("report: %d %s", code, body)
	}
	doc, err := srv.network().Document()
	if err != nil || len(doc.PolicyTests) != 1 {
		t.Fatalf("document tests: %v %+v", err, doc)
	}
}
