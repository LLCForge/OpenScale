package osnet

import (
	"strings"
	"testing"
)

func TestNRPTGroupPolicyConflict(t *testing.T) {
	const domain, resolver = "openscale.internal", "100.100.100.100"
	none := NRPTGroupPolicyConflict(DNSSystemStatus{}, domain, resolver)
	if none.Active || none.Message(domain) != "" {
		t.Fatalf("no policy: %+v", none)
	}
	cases := []struct {
		name       string
		rules      []NRPTRuleInfo
		covered    bool
		namespace  string
		toResolver bool
		mention    string
	}{
		{"other domains only", []NRPTRuleInfo{{Namespaces: []string{".corp.example"}, Servers: []string{"10.0.0.1"}}}, false, "", false, "kural yok"},
		{"catch-all to corporate DNS", []NRPTRuleInfo{{Namespaces: []string{"."}, Servers: []string{"10.0.0.1"}}}, true, ".", false, "başka DNS"},
		{"suffix beats catch-all", []NRPTRuleInfo{
			{Namespaces: []string{"."}, Servers: []string{"10.0.0.1"}},
			{Namespaces: []string{".OpenScale.Internal"}, Servers: []string{resolver}},
		}, true, ".OpenScale.Internal", true, "çözülmeye devam"},
		{"parent suffix", []NRPTRuleInfo{{Namespaces: []string{".internal"}, Servers: []string{"10.0.0.2"}}}, true, ".internal", false, "başka DNS"},
		{"look-alike is not a parent", []NRPTRuleInfo{{Namespaces: []string{".scale.internal"}, Servers: []string{resolver}}}, false, "", false, "kural yok"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := NRPTGroupPolicyConflict(DNSSystemStatus{GroupPolicyNRPT: true, GroupPolicyRules: c.rules}, domain, resolver)
			if !got.Active || got.Covered != c.covered || got.Namespace != c.namespace || got.ToResolver != c.toResolver {
				t.Fatalf("%+v", got)
			}
			msg := got.Message(domain)
			if !strings.Contains(msg, c.mention) || !strings.Contains(msg, "yok sayar") {
				t.Fatalf("message %q", msg)
			}
		})
	}
	// The flag alone (rules unreadable) still warns.
	if msg := NRPTGroupPolicyConflict(DNSSystemStatus{GroupPolicyNRPT: true}, domain, resolver).Message(domain); !strings.Contains(msg, "Grup İlkesi") {
		t.Fatalf("flag only: %q", msg)
	}
}
