package trust

import (
	"strings"
	"testing"
)

func rdeskDoc(t *testing.T) *Document {
	t.Helper()
	_, doc := policyDoc(t)
	rules := []Rule{
		{From: []string{"laptop"}, To: []string{"masaustu"}, Service: ServiceRemoteDesktop, AllowControl: true},
		{From: []string{"telefon"}, To: []string{"masaustu"}, Service: ServiceRemoteDesktop},
		{From: []string{"laptop"}, To: []string{"vps"}, Service: ServiceRemoteDesktop, AllowUnattended: true},
		{From: []string{"telefon"}, To: []string{"vps"}, Service: ServiceRemoteDesktop, AllowControl: true, AllowUnattended: true},
	}
	for i, r := range rules {
		if err := doc.AddRule(r); err != nil {
			t.Fatalf("rule %d: %v", i, err)
		}
	}
	return doc
}

func TestRemoteDesktopRuleValidation(t *testing.T) {
	_, doc := policyDoc(t)
	bad := []Rule{
		{From: []string{"laptop"}, To: []string{"vps"}, Service: ServiceRemoteDesktop, Users: []string{"ali"}},
		{From: []string{"laptop"}, To: []string{"vps"}, Service: ServiceRemoteDesktop, AllowRoot: true},
		{From: []string{"laptop"}, To: []string{"vps"}, Service: ServiceRemoteDesktop, AllowForward: true},
		{From: []string{"laptop"}, To: []string{"vps"}, Service: ServiceRemoteDesktop, Via: []string{"masaustu"}},
		{From: []string{"laptop"}, To: []string{"vps"}, Service: ServiceRemoteDesktop, Protocol: ProtocolTCP, Ports: []string{"4047"}},
		{From: []string{"laptop"}, To: []string{"vps"}, Service: ServiceRemoteDesktop, Action: RuleDeny, AllowControl: true},
		{From: []string{"laptop"}, To: []string{"vps"}, Service: ServiceRemoteDesktop, Action: RuleDeny, AllowUnattended: true},
		{From: []string{"laptop"}, To: []string{"vps"}, Service: ServiceSSH, Users: []string{"ali"}, AllowControl: true},
		{From: []string{"laptop"}, To: []string{"vps"}, Service: ServiceFiles, AllowUnattended: true},
		{From: []string{"laptop"}, To: []string{"vps"}, Service: ServiceWake, Via: []string{"masaustu"}, AllowControl: true},
		{From: []string{"laptop"}, To: []string{"vps"}, Protocol: ProtocolAny, AllowControl: true},
		{From: []string{"laptop"}, To: []string{"vps"}, Protocol: ProtocolTCP, Ports: []string{"22"}, AllowUnattended: true},
	}
	n := len(doc.Rules)
	for i, r := range bad {
		if err := doc.AddRule(r); err == nil {
			t.Errorf("rule %d should be rejected: %+v", i, r)
		}
	}
	if len(doc.Rules) != n {
		t.Fatal("rejected rules must not be kept")
	}
	good := []Rule{
		{From: []string{"laptop"}, To: []string{"vps"}, Service: ServiceRemoteDesktop},
		{From: []string{"laptop"}, To: []string{"vps"}, Service: ServiceRemoteDesktop, AllowControl: true, AllowUnattended: true},
		{From: []string{"*"}, To: []string{"vps"}, Service: ServiceRemoteDesktop, Action: RuleDeny},
	}
	for i, r := range good {
		if err := doc.AddRule(r); err != nil {
			t.Errorf("rule %d rejected: %v", i, err)
		}
	}
	if ServiceRemoteDesktop.Port() != RemoteDesktopPort || RemoteDesktopPort != 4047 {
		t.Fatal("rdesk port")
	}
	found := false
	for _, s := range Services() {
		if s == ServiceRemoteDesktop {
			found = true
		}
	}
	if !found {
		t.Fatal("Services must list rdesk")
	}
}

func TestAllowsRemoteDesktop(t *testing.T) {
	doc := rdeskDoc(t)
	cases := []struct {
		from, to   string
		mode       RemoteDesktopMode
		allowed    bool
		unattended bool
	}{
		{"laptop", "masaustu", RemoteDesktopView, true, false},
		{"laptop", "masaustu", RemoteDesktopControl, true, false},
		{"telefon", "masaustu", RemoteDesktopView, true, false},
		{"telefon", "masaustu", RemoteDesktopControl, false, false},
		{"laptop", "vps", RemoteDesktopView, true, true},
		{"laptop", "vps", RemoteDesktopControl, false, false},
		{"telefon", "vps", RemoteDesktopView, true, true},
		{"telefon", "vps", RemoteDesktopControl, true, true},
		{"masaustu", "laptop", RemoteDesktopView, false, false},
		{"vps", "masaustu", RemoteDesktopView, false, false},
		{"laptop", "laptop", RemoteDesktopView, false, false},
		{"laptop", "masaustu", "", false, false},
		{"laptop", "masaustu", "admin", false, false},
		{"", "masaustu", RemoteDesktopView, false, false},
		{"yok", "masaustu", RemoteDesktopView, false, false},
	}
	for _, c := range cases {
		if got := doc.AllowsRemoteDesktop(c.from, c.to, c.mode); got != c.allowed {
			t.Errorf("AllowsRemoteDesktop(%s, %s, %q) = %v, want %v", c.from, c.to, c.mode, got, c.allowed)
		}
		if got := doc.RemoteDesktopUnattended(c.from, c.to, c.mode); got != c.unattended {
			t.Errorf("RemoteDesktopUnattended(%s, %s, %q) = %v, want %v", c.from, c.to, c.mode, got, c.unattended)
		}
	}
	if !doc.HostsService("masaustu", ServiceRemoteDesktop) || !doc.HostsService("vps", ServiceRemoteDesktop) || doc.HostsService("laptop", ServiceRemoteDesktop) {
		t.Fatal("HostsService rdesk")
	}
	// The rule opens only the rdesk port, and a broad rule never grants it.
	if !doc.Allows("laptop", "masaustu", ProtocolTCP, RemoteDesktopPort) || doc.Allows("telefon", "masaustu", ProtocolTCP, 3389) {
		t.Fatal("rdesk rule must open exactly its port")
	}
	if err := doc.AddRule(Rule{From: []string{"vps"}, To: []string{"laptop"}, Protocol: ProtocolAny}); err != nil {
		t.Fatal(err)
	}
	if doc.AllowsRemoteDesktop("vps", "laptop", RemoteDesktopView) {
		t.Fatal("an any rule must not grant rdesk")
	}
}

func TestRemoteDesktopDenyAndDisabled(t *testing.T) {
	doc := rdeskDoc(t)
	// A packet deny over the port closes the service.
	if err := doc.AddRule(Rule{From: []string{"telefon"}, To: []string{"vps"}, Protocol: ProtocolTCP, Ports: []string{"4040-4050"}, Action: RuleDeny}); err != nil {
		t.Fatal(err)
	}
	if doc.AllowsRemoteDesktop("telefon", "vps", RemoteDesktopView) || doc.RemoteDesktopUnattended("telefon", "vps", RemoteDesktopControl) {
		t.Fatal("packet deny must close rdesk")
	}
	// An rdesk deny rule wins over the allow rules.
	if err := doc.AddRule(Rule{From: []string{"*"}, To: []string{"masaustu"}, Service: ServiceRemoteDesktop, Action: RuleDeny}); err != nil {
		t.Fatal(err)
	}
	if doc.AllowsRemoteDesktop("laptop", "masaustu", RemoteDesktopView) {
		t.Fatal("rdesk deny must win")
	}
	if err := doc.SetRuleDisabled(len(doc.Rules)-1, true); err != nil {
		t.Fatal(err)
	}
	if !doc.AllowsRemoteDesktop("laptop", "masaustu", RemoteDesktopControl) {
		t.Fatal("disabled deny must not apply")
	}
	// Disabling the unattended rule leaves the view-only grant attended.
	for i, r := range doc.Rules {
		if r.Service == ServiceRemoteDesktop && r.AllowUnattended && !r.AllowControl {
			if err := doc.SetRuleDisabled(i, true); err != nil {
				t.Fatal(err)
			}
		}
	}
	if doc.AllowsRemoteDesktop("laptop", "vps", RemoteDesktopView) || doc.RemoteDesktopUnattended("laptop", "vps", RemoteDesktopView) {
		t.Fatal("disabled rdesk rule must not apply")
	}
}

func TestRemoteDesktopEncoding(t *testing.T) {
	_, doc := policyDoc(t)
	data, err := jsonBytes(doc)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"allow_control"`, `"allow_unattended"`} {
		if strings.Contains(string(data), field) {
			t.Errorf("document without rdesk rules encodes %s", field)
		}
	}
	doc = rdeskDoc(t)
	data, err = jsonBytes(doc)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"service":"rdesk"`) || !strings.Contains(string(data), `"allow_control":true`) || !strings.Contains(string(data), `"allow_unattended":true`) {
		t.Fatal("rdesk rule fields must be encoded")
	}
}
