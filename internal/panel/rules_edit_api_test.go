package panel

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/trust"
)

// Editing a rule in place with one signature.
func TestEditRuleEndpoint(t *testing.T) {
	srv, _, call := policyServer(t)
	n := srv.network()

	add := signed(map[string]any{"from": []string{"laptop"}, "to": []string{"masaustu"}, "protocol": "tcp", "ports": []string{"22"}, "description": "SSH"})
	if code, body := call(http.MethodPost, "/api/rules", add); code != http.StatusOK {
		t.Fatalf("add rule: %d %s", code, body)
	}
	deny := signed(map[string]any{"from": []string{"masaustu"}, "to": []string{"laptop"}, "protocol": "any", "action": "deny"})
	if code, body := call(http.MethodPost, "/api/rules", deny); code != http.StatusOK {
		t.Fatalf("add deny rule: %d %s", code, body)
	}
	if code, body := call(http.MethodPost, "/api/rules/state", signed(map[string]any{"index": 0, "disabled": true})); code != http.StatusOK {
		t.Fatalf("disable: %d %s", code, body)
	}
	before, err := n.Document()
	if err != nil {
		t.Fatal(err)
	}

	edit := map[string]any{"index": 0, "from": []string{"laptop"}, "to": []string{"masaustu"}, "protocol": "tcp",
		"ports": []string{"3389"}, "description": "Uzak masaüstü", "bidirectional": true}

	// The dry run shows the diff and signs nothing.
	dry := map[string]any{"dryRun": true}
	for k, v := range edit {
		dry[k] = v
	}
	code, body := call(http.MethodPost, "/api/rules/edit", dry)
	if code != http.StatusOK || !strings.Contains(body, "3389") {
		t.Fatalf("dry run: %d %s", code, body)
	}
	if doc, _ := n.Document(); doc.Version != before.Version {
		t.Fatalf("dry run signed version %d", doc.Version)
	}

	// Signed: same position, new ports, disabled state kept, one version.
	if code, body := call(http.MethodPost, "/api/rules/edit", signed(edit)); code != http.StatusOK {
		t.Fatalf("edit: %d %s", code, body)
	}
	doc, err := n.Document()
	if err != nil {
		t.Fatal(err)
	}
	if doc.Version != before.Version+1 {
		t.Fatalf("version %d, want %d", doc.Version, before.Version+1)
	}
	if len(doc.Rules) != 2 {
		t.Fatalf("rules %d, want 2", len(doc.Rules))
	}
	r := doc.Rules[0]
	if strings.Join(r.Ports, ",") != "3389" || r.Description != "Uzak masaüstü" || !r.Bidirectional || !r.Disabled || r.Action != "" {
		t.Fatalf("edited rule = %+v", r)
	}
	if !doc.Rules[1].IsDeny() {
		t.Fatalf("the deny rule moved: %+v", doc.Rules)
	}

	// GET /api/rules shows the new fields the edit form reads.
	code, body = call(http.MethodGet, "/api/rules", nil)
	var list rulesResponse
	if code != http.StatusOK || json.Unmarshal([]byte(body), &list) != nil || !list.Rules[0].Bidirectional {
		t.Fatalf("rules: %d %s", code, body)
	}

	// Refused: unknown index, kind change, invalid rule, wrong passphrase.
	bad := []struct {
		name string
		body map[string]any
		code int
	}{
		{"index out of range", signed(map[string]any{"index": 7, "from": []string{"laptop"}, "to": []string{"masaustu"}, "protocol": "icmp"}), http.StatusBadRequest},
		{"negative index", signed(map[string]any{"index": -1, "from": []string{"laptop"}, "to": []string{"masaustu"}, "protocol": "icmp"}), http.StatusBadRequest},
		{"kind change", signed(map[string]any{"index": 0, "from": []string{"laptop"}, "to": []string{"masaustu"}, "service": "ssh", "users": []string{"ali"}}), http.StatusBadRequest},
		{"unknown device", signed(map[string]any{"index": 0, "from": []string{"yok"}, "to": []string{"masaustu"}, "protocol": "icmp"}), http.StatusBadRequest},
		{"bad action", signed(map[string]any{"index": 0, "from": []string{"laptop"}, "to": []string{"masaustu"}, "protocol": "icmp", "action": "maybe"}), http.StatusBadRequest},
		{"wrong passphrase", map[string]any{"index": 0, "from": []string{"laptop"}, "to": []string{"masaustu"}, "protocol": "icmp", "passphrase": "yanlis-parola-1234"}, http.StatusUnauthorized},
	}
	for _, c := range bad {
		if code, body := call(http.MethodPost, "/api/rules/edit", c.body); code != c.code {
			t.Errorf("%s: %d %s, want %d", c.name, code, body, c.code)
		}
	}
	if after, _ := n.Document(); after.Version != doc.Version {
		t.Fatalf("a refused edit signed version %d", after.Version)
	}

	// A broad rule needs the same explicit confirmation as a new one.
	broad := signed(map[string]any{"index": 0, "from": []string{"*"}, "to": []string{"*"}, "protocol": "any"})
	if code, body := call(http.MethodPost, "/api/rules/edit", broad); code != http.StatusBadRequest || !strings.Contains(body, "açıkça onayla") {
		t.Fatalf("unconfirmed broad edit: %d %s", code, body)
	}
}

// replaceRule keeps what the form does not carry and leaves the document
// unchanged when the new rule is invalid.
func TestReplaceRuleKeepsLimits(t *testing.T) {
	end := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	start := time.Date(2029, 1, 2, 3, 4, 5, 0, time.UTC)
	doc := &trust.Document{Rules: []trust.Rule{{
		From: []string{"a"}, To: []string{"b"}, Protocol: "tcp", Ports: []string{"22"},
		Disabled: true, NotBefore: start, NotAfter: end,
	}}}
	// Validate fails on this bare document, so the old rule must stay.
	if err := replaceRule(doc, 0, trust.Rule{From: []string{"a"}, To: []string{"b"}, Protocol: "udp"}, false); err == nil {
		t.Fatal("an invalid document must be refused")
	}
	if doc.Rules[0].Protocol != "tcp" || !doc.Rules[0].NotAfter.Equal(end) {
		t.Fatalf("rule changed on error: %+v", doc.Rules[0])
	}
	if err := replaceRule(doc, 3, trust.Rule{}, false); err != errRuleNotFound {
		t.Fatalf("out of range: %v", err)
	}
	if err := replaceRule(doc, 0, trust.Rule{From: []string{"a"}, To: []string{"b"}, Service: "ssh"}, false); err != errRuleKindChange {
		t.Fatalf("kind change: %v", err)
	}
}
