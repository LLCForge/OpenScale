package trust

import (
	"strings"
	"testing"
	"time"
)

func serviceDoc(t *testing.T) *Document {
	t.Helper()
	_, doc := policyDoc(t)
	if err := doc.SetDeviceTags("vps", []string{"sunucu"}); err != nil {
		t.Fatal(err)
	}
	rules := []Rule{
		{From: []string{"laptop"}, To: []string{"tag:sunucu"}, Service: ServiceSSH, Users: []string{"ali", "deploy"}, AllowForward: true},
		{From: []string{"telefon"}, To: []string{"vps"}, Service: ServiceSSH, Users: []string{"ali"}},
		{From: []string{"laptop"}, To: []string{"masaustu"}, Service: ServiceSSH, Users: []string{SSHWindowsUser}},
		{From: []string{"laptop"}, To: []string{"vps"}, Service: ServiceSSH, AllowRoot: true},
		{From: []string{"*"}, To: []string{"laptop"}, Service: ServiceFiles},
		{From: []string{"telefon"}, To: []string{"masaustu"}, Service: ServiceWake, Via: []string{"vps"}},
		{From: []string{"laptop"}, To: []string{"vps"}, Service: ServiceSpeedtest},
	}
	for i, r := range rules {
		if err := doc.AddRule(r); err != nil {
			t.Fatalf("rule %d: %v", i, err)
		}
	}
	return doc
}

func TestServiceRuleValidation(t *testing.T) {
	_, doc := policyDoc(t)
	bad := []Rule{
		{From: []string{"laptop"}, To: []string{"vps"}, Service: "ftp"},
		{From: []string{"laptop"}, To: []string{"vps"}, Service: ServiceSSH},
		{From: []string{"laptop"}, To: []string{"vps"}, Service: ServiceSSH, Users: []string{"root"}},
		{From: []string{"laptop"}, To: []string{"vps"}, Service: ServiceSSH, Users: []string{"Ali"}},
		{From: []string{"laptop"}, To: []string{"vps"}, Service: ServiceSSH, Users: []string{"*"}},
		{From: []string{"laptop"}, To: []string{"vps"}, Service: ServiceSSH, Users: []string{"-x"}},
		{From: []string{"laptop"}, To: []string{"vps"}, Service: ServiceSSH, Users: []string{"ali", "ali"}},
		{From: []string{"laptop"}, To: []string{"vps"}, Service: ServiceSSH, Users: []string{"ali"}, Protocol: ProtocolTCP, Ports: []string{"22"}},
		{From: []string{"laptop"}, To: []string{"vps"}, Service: ServiceSSH, Users: []string{"ali"}, Via: []string{"vps"}},
		{From: []string{"laptop"}, To: []string{"vps"}, Service: ServiceFiles, Users: []string{"ali"}},
		{From: []string{"laptop"}, To: []string{"vps"}, Service: ServiceSpeedtest, AllowForward: true},
		{From: []string{"laptop"}, To: []string{"vps"}, Service: ServiceWake},
		{From: []string{"laptop"}, To: []string{"vps"}, Service: ServiceWake, Via: []string{"*"}},
		{From: []string{"laptop"}, To: []string{"vps"}, Service: ServiceWake, Via: []string{"yok"}},
		{From: []string{"laptop"}, To: []string{"vps"}, Service: ServiceWake, Via: []string{"masaustu"}, AllowRoot: true},
		{From: []string{"laptop"}, To: []string{"vps"}, Service: ServiceSSH, Action: RuleDeny, Users: []string{"ali"}},
		{From: []string{"laptop"}, To: []string{"vps"}, Protocol: ProtocolAny, Users: []string{"ali"}},
		{From: []string{"laptop"}, To: []string{"vps"}, Protocol: ProtocolAny, Via: []string{"vps"}},
		{From: []string{"laptop"}, To: []string{"vps"}, Service: ServiceFiles, Description: "a\nb"},
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
		{From: []string{"laptop"}, To: []string{"vps"}, Service: ServiceSSH, AllowRoot: true},
		{From: []string{"*"}, To: []string{"vps"}, Service: ServiceSSH, Action: RuleDeny},
		{From: []string{"laptop"}, To: []string{"vps"}, Service: ServiceWake, Action: RuleDeny},
		{From: []string{"laptop"}, To: []string{"masaustu"}, Service: ServiceWake, Via: []string{"tag:yeni"}},
	}
	for i, r := range good {
		if err := doc.AddRule(r); err != nil {
			t.Errorf("rule %d rejected: %v", i, err)
		}
	}
}

func TestAllowsSSH(t *testing.T) {
	doc := serviceDoc(t)
	cases := []struct {
		from, to, user string
		want           bool
	}{
		{"laptop", "vps", "ali", true},
		{"laptop", "vps", "deploy", true},
		{"laptop", "vps", "root", true}, // allow_root rule
		{"laptop", "vps", "mehmet", false},
		{"laptop", "vps", "", false},
		{"telefon", "vps", "ali", true},
		{"telefon", "vps", "deploy", false},
		{"telefon", "vps", "root", false},
		{"vps", "laptop", "ali", false},
		{"laptop", "laptop", "ali", false},
		{"laptop", "masaustu", SSHWindowsUser, true},
		{"laptop", "masaustu", "ali", false},
		{"telefon", "masaustu", SSHWindowsUser, false},
	}
	for _, c := range cases {
		if got := doc.AllowsSSH(c.from, c.to, c.user); got != c.want {
			t.Errorf("AllowsSSH(%s, %s, %q) = %v, want %v", c.from, c.to, c.user, got, c.want)
		}
	}
	if !doc.AllowsSSHForward("laptop", "vps", "ali") {
		t.Error("forwarding rule must allow ali")
	}
	if doc.AllowsSSHForward("telefon", "vps", "ali") || doc.AllowsSSHForward("laptop", "vps", "root") {
		t.Error("forwarding must need allow_forward on a rule that permits the user")
	}
	// The packet filter admits the service port, and only it.
	if !doc.Allows("telefon", "vps", ProtocolTCP, SSHPort) || doc.Allows("telefon", "vps", ProtocolTCP, 22) {
		t.Error("ssh rule must open exactly the service port")
	}
	if !doc.Visible("telefon", "vps") {
		t.Error("service rules make devices visible")
	}
}

func TestServiceDenyAndDisabled(t *testing.T) {
	doc := serviceDoc(t)
	// A broad rule opens the port but never grants the service.
	if err := doc.AddRule(Rule{From: []string{"masaustu"}, To: []string{"vps"}, Protocol: ProtocolAny}); err != nil {
		t.Fatal(err)
	}
	if doc.AllowsSSH("masaustu", "vps", "ali") || doc.AllowsFileSend("masaustu", "vps") || doc.AllowsSpeedtest("masaustu", "vps") {
		t.Fatal("an any rule must not grant services")
	}
	// A generic deny covering the port denies the service too.
	if err := doc.AddRule(Rule{From: []string{"telefon"}, To: []string{"vps"}, Protocol: ProtocolTCP, Ports: []string{"4000-4100"}, Action: RuleDeny}); err != nil {
		t.Fatal(err)
	}
	if doc.AllowsSSH("telefon", "vps", "ali") {
		t.Fatal("deny tcp rule over the port must deny ssh")
	}
	// A service deny rule wins over its allow rules.
	if err := doc.AddRule(Rule{From: []string{"*"}, To: []string{"laptop"}, Service: ServiceFiles, Action: RuleDeny}); err != nil {
		t.Fatal(err)
	}
	if doc.AllowsFileSend("vps", "laptop") {
		t.Fatal("files deny rule must win")
	}
	if err := doc.SetRuleDisabled(len(doc.Rules)-1, true); err != nil {
		t.Fatal(err)
	}
	if !doc.AllowsFileSend("vps", "laptop") {
		t.Fatal("disabled deny rule must not apply")
	}
	// Disabling the allow rule closes the service.
	for i, r := range doc.Rules {
		if r.Service == ServiceSpeedtest {
			if err := doc.SetRuleDisabled(i, true); err != nil {
				t.Fatal(err)
			}
		}
	}
	if doc.AllowsSpeedtest("laptop", "vps") || doc.HostsService("vps", ServiceSpeedtest) {
		t.Fatal("disabled speedtest rule must not apply")
	}
}

func TestAllowsWake(t *testing.T) {
	doc := serviceDoc(t)
	if !doc.AllowsWake("telefon", "masaustu", "vps") {
		t.Fatal("wake through the listed relay must be allowed")
	}
	if doc.AllowsWake("telefon", "masaustu", "laptop") {
		t.Fatal("unlisted relay must be refused")
	}
	if doc.AllowsWake("laptop", "masaustu", "vps") || doc.AllowsWake("telefon", "masaustu", "masaustu") {
		t.Fatal("other requesters and self relay must be refused")
	}
	if got := doc.WakeRelays("telefon", "masaustu"); len(got) != 1 || got[0] != "vps" {
		t.Fatalf("WakeRelays = %v", got)
	}
	// Packets go to the relay, not to the sleeping target.
	if !doc.Allows("telefon", "vps", ProtocolTCP, WakePort) || doc.Allows("telefon", "masaustu", ProtocolTCP, WakePort) {
		t.Fatal("wake rule must open the relay's wake port only")
	}
	if !doc.HostsService("vps", ServiceWake) || doc.HostsService("masaustu", ServiceWake) {
		t.Fatal("only the relay runs the wake service")
	}
	if err := doc.AddRule(Rule{From: []string{"telefon"}, To: []string{"masaustu"}, Service: ServiceWake, Action: RuleDeny}); err != nil {
		t.Fatal(err)
	}
	if doc.AllowsWake("telefon", "masaustu", "vps") {
		t.Fatal("deny wake rule must win")
	}
}

func TestHostsService(t *testing.T) {
	doc := serviceDoc(t)
	cases := []struct {
		name string
		svc  RuleService
		want bool
	}{
		{"vps", ServiceSSH, true},
		{"masaustu", ServiceSSH, true},
		{"laptop", ServiceSSH, false},
		{"laptop", ServiceFiles, true},
		{"vps", ServiceFiles, false},
		{"vps", ServiceSpeedtest, true},
		{"yok", ServiceSSH, false},
	}
	for _, c := range cases {
		if got := doc.HostsService(c.name, c.svc); got != c.want {
			t.Errorf("HostsService(%s, %s) = %v, want %v", c.name, c.svc, got, c.want)
		}
	}
}

func TestServiceRulesFollowDeviceChanges(t *testing.T) {
	doc := serviceDoc(t)
	if err := doc.RenameDevice("vps", "sunucu1"); err != nil {
		t.Fatal(err)
	}
	if !doc.AllowsWake("telefon", "masaustu", "sunucu1") {
		t.Fatal("rename must update via")
	}
	before := len(doc.Rules)
	dropped, err := doc.RevokeDevice("sunucu1", testNow.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	// Rules naming only sunucu1 as destination and the wake rule left
	// without a relay are dropped; the tag rule stays.
	if dropped == 0 || len(doc.Rules) != before-dropped {
		t.Fatalf("dropped %d of %d", dropped, before)
	}
	for _, r := range doc.Rules {
		if r.Service == ServiceWake {
			t.Fatal("wake rule without relay must be dropped")
		}
	}
	if err := doc.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestServiceRuleEncoding(t *testing.T) {
	_, doc := policyDoc(t)
	data, err := jsonBytes(doc)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"service"`, `"users"`, `"allow_root"`, `"allow_forward"`, `"via"`} {
		if strings.Contains(string(data), field) {
			t.Errorf("document without service rules encodes %s", field)
		}
	}
	if !ValidSSHUser("system") || ValidSSHUser("1abc") || ValidSSHUser(strings.Repeat("a", 33)) {
		t.Fatal("ValidSSHUser")
	}
	d, ok := doc.DeviceByAddr(doc.Devices[0].IPv4)
	if !ok || d.Name != doc.Devices[0].Name {
		t.Fatal("DeviceByAddr")
	}
	if _, ok := doc.DeviceByAddr(doc.DNSResolverIPv4()); ok {
		t.Fatal("resolver is no device")
	}
}
