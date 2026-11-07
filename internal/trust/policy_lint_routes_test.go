package trust

import (
	"testing"
	"time"
)

func TestPolicyLintRoutedRuleCovers(t *testing.T) {
	doc := routedDoc(t)
	if err := doc.AddRule(Rule{From: []string{"laptop"}, To: []string{"192.168.1.0/24"}, Protocol: ProtocolTCP, Ports: []string{"445"}}); err != nil {
		t.Fatal(err)
	}
	for _, w := range doc.PolicyWarnings(time.Now()) {
		if w.Code == WarnMatchesNothing {
			t.Fatalf("routed CIDR rule reported as matching nothing: %s", w.Message)
		}
	}
	// A rule from the router itself to its own LAN covers no tunnel pair.
	if err := doc.AddRule(Rule{From: []string{"vps"}, To: []string{"192.168.1.0/24"}, Protocol: ProtocolTCP, Ports: []string{"22"}}); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, w := range doc.PolicyWarnings(time.Now()) {
		if w.Code == WarnMatchesNothing && w.Rule == len(doc.Rules)-1 {
			found = true
		}
	}
	if !found {
		t.Fatal("router-to-own-LAN rule must still be reported")
	}
}
