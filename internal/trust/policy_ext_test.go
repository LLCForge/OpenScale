package trust

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func jsonBytes(doc *Document) ([]byte, error) { return json.Marshal(doc) }

func peerNames(ds []Device) map[string]bool {
	m := map[string]bool{}
	for _, d := range ds {
		m[d.Name] = true
	}
	return m
}

// A document that uses none of the ADR-0021/0024/0020 features must encode
// without any of the new fields, so old devices keep accepting it.
func TestLegacyDocumentEncodingUnchanged(t *testing.T) {
	_, doc := policyDoc(t)
	data, err := jsonBytes(doc)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"tags"`, `"action"`, `"disabled"`, `"groups"`, `"exit_users"`, `"dns"`, `"retired_keys"`} {
		if strings.Contains(string(data), field) {
			t.Errorf("legacy document encodes new field %s", field)
		}
	}
	// "allow" given explicitly is stored as the default.
	if err := doc.AddRule(Rule{From: []string{"vps"}, To: []string{"laptop"}, Protocol: ProtocolICMP, Action: RuleAllow}); err != nil {
		t.Fatal(err)
	}
	if doc.Rules[len(doc.Rules)-1].Action != "" {
		t.Fatal("allow action must be stored empty")
	}
}

func TestNewRuleValidation(t *testing.T) {
	_, doc := policyDoc(t)
	if err := doc.SetGroup("ofis", []string{"laptop"}); err != nil {
		t.Fatal(err)
	}
	bad := []Rule{
		{From: []string{"group:yok"}, To: []string{"vps"}, Protocol: ProtocolAny},
		{From: []string{"tag:Bad"}, To: []string{"vps"}, Protocol: ProtocolAny},
		{From: []string{"tag:"}, To: []string{"vps"}, Protocol: ProtocolAny},
		{From: []string{"laptop"}, To: []string{"vps"}, Protocol: ProtocolAny, Action: "drop"},
		{From: []string{"laptop"}, To: []string{"vps"}, Protocol: "256"},
		{From: []string{"laptop"}, To: []string{"vps"}, Protocol: "047"},
		{From: []string{"laptop"}, To: []string{"vps"}, Protocol: "-1"},
		{From: []string{"laptop"}, To: []string{"vps"}, Protocol: "6"},
		{From: []string{"laptop"}, To: []string{"vps"}, Protocol: "17"},
		{From: []string{"laptop"}, To: []string{"vps"}, Protocol: "1"},
		{From: []string{"laptop"}, To: []string{"vps"}, Protocol: "58"},
		{From: []string{"laptop"}, To: []string{"vps"}, Protocol: "47", Ports: []string{"22"}},
		{From: []string{"laptop"}, To: []string{"vps"}, Protocol: "gre"},
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
		{From: []string{"group:ofis"}, To: []string{"tag:sunucu"}, Protocol: "47"},
		{From: []string{"laptop"}, To: []string{"vps"}, Protocol: "0"},
		{From: []string{"*"}, To: []string{"vps"}, Protocol: "255", Action: RuleDeny, Disabled: true},
	}
	for i, r := range good {
		if err := doc.AddRule(r); err != nil {
			t.Errorf("rule %d rejected: %v", i, err)
		}
	}
}

func TestOldRulesKeepTheirMeaning(t *testing.T) {
	// Regression: the evaluation table of the original policy, unchanged.
	_, doc := policyDoc(t)
	cases := []struct {
		src, dst string
		proto    Protocol
		port     uint16
		want     bool
	}{
		{"laptop", "masaustu", ProtocolTCP, 3389, true},
		{"laptop", "masaustu", ProtocolTCP, 5910, true},
		{"laptop", "masaustu", ProtocolTCP, 5911, false},
		{"laptop", "masaustu", ProtocolUDP, 3389, false},
		{"laptop", "masaustu", ProtocolICMP, 0, false},
		{"masaustu", "laptop", ProtocolTCP, 3389, false},
		{"telefon", "vps", ProtocolICMP, 0, true},
		{"vps", "vps", ProtocolICMP, 0, false},
		{"laptop", "vps", "other", 0, false},
		{"laptop", "vps", ProtocolAny, 0, false},
	}
	for _, c := range cases {
		if got := doc.Allows(c.src, c.dst, c.proto, c.port); got != c.want {
			t.Errorf("Allows(%s -> %s %s/%d) = %v, want %v", c.src, c.dst, c.proto, c.port, got, c.want)
		}
	}
	// "any" rules still allow protocols the filter cannot name.
	if err := doc.AddRule(Rule{From: []string{"laptop"}, To: []string{"telefon"}, Protocol: ProtocolAny}); err != nil {
		t.Fatal(err)
	}
	if !doc.Allows("laptop", "telefon", "other", 0) || !doc.AllowsIP("laptop", "telefon", 47, 0) {
		t.Fatal("any rule must allow every protocol")
	}
	// ICMP rules cover ICMPv6 for the packet-level API.
	if !doc.AllowsIP("telefon", "vps", 58, 0) || !doc.AllowsIP("telefon", "vps", 1, 0) {
		t.Fatal("icmp rule must cover ICMP and ICMPv6")
	}
	tunnel := peerNames(doc.TunnelPeersOf("telefon"))
	if !tunnel["vps"] || tunnel["masaustu"] {
		t.Fatalf("tunnel peers changed: %v", tunnel)
	}
}

func TestTagsAndGroups(t *testing.T) {
	_, doc := policyDoc(t)
	if err := doc.SetDeviceTags("vps", []string{"tag:sunucu"}); err != nil {
		t.Fatal(err)
	}
	if d, _ := doc.DeviceByName("vps"); len(d.Tags) != 1 || d.Tags[0] != "sunucu" {
		t.Fatalf("tag prefix not stripped: %v", d.Tags)
	}
	if err := doc.SetDeviceTags("telefon", []string{"mobil"}); err != nil {
		t.Fatal(err)
	}
	if err := doc.SetGroup("aile", []string{"masaustu", "tag:mobil"}); err != nil {
		t.Fatal(err)
	}
	if err := doc.AddRule(Rule{From: []string{"group:aile"}, To: []string{"tag:sunucu"}, Protocol: ProtocolTCP, Ports: []string{"22"}}); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		src  string
		want bool
	}{{"masaustu", true}, {"telefon", true}, {"laptop", false}}
	for _, c := range cases {
		if got := doc.Allows(c.src, "vps", ProtocolTCP, 22); got != c.want {
			t.Errorf("%s -> vps tcp/22 = %v, want %v", c.src, got, c.want)
		}
	}
	if !doc.Visible("telefon", "vps") {
		t.Fatal("tag rule must make devices visible")
	}

	bad := [][]string{{"*"}, {"group:aile"}, {"yok"}, {"tag:X"}, {"laptop", "laptop"}}
	for _, members := range bad {
		if err := doc.SetGroup("x", members); err == nil {
			t.Errorf("group members %v should be rejected", members)
		}
	}
	if _, ok := doc.GroupByName("x"); ok {
		t.Fatal("rejected group must not be kept")
	}
	if err := doc.RemoveGroup("aile"); err == nil {
		t.Fatal("a group used by a rule must not be removable")
	}
	if err := doc.RemoveGroup("yok"); !errors.Is(err, ErrGroupNotFound) {
		t.Fatalf("remove unknown group error = %v", err)
	}
	tooMany := make([]string, MaxTags+1)
	for i := range tooMany {
		tooMany[i] = "t" + string(rune('a'+i))
	}
	if err := doc.SetDeviceTags("laptop", tooMany); err == nil {
		t.Fatal("too many tags must be rejected")
	}
	if err := doc.SetDeviceTags("laptop", []string{"a", "a"}); err == nil {
		t.Fatal("duplicate tags must be rejected")
	}
	if err := doc.AddRule(Rule{From: []string{"tag:yazici"}, To: []string{"vps"}, Protocol: ProtocolAny, Action: RuleDeny}); err != nil {
		t.Fatal(err)
	}
	if unused := doc.TagUsage(); len(unused) != 1 || unused[0] != "yazici" {
		t.Fatalf("TagUsage = %v", unused)
	}
}

func TestDenyRulesWinAndDisabledRulesAreIgnored(t *testing.T) {
	_, doc := policyDoc(t)
	// Broad allow with a narrow deny exception.
	rules := []Rule{
		{From: []string{"*"}, To: []string{"masaustu"}, Protocol: ProtocolAny},
		{From: []string{"telefon"}, To: []string{"masaustu"}, Protocol: ProtocolTCP, Ports: []string{"3389"}, Action: RuleDeny},
	}
	for _, r := range rules {
		if err := doc.AddRule(r); err != nil {
			t.Fatal(err)
		}
	}
	if doc.Allows("telefon", "masaustu", ProtocolTCP, 3389) {
		t.Fatal("deny rule must win over an earlier allow")
	}
	if !doc.Allows("telefon", "masaustu", ProtocolTCP, 22) || !doc.Allows("vps", "masaustu", ProtocolTCP, 3389) {
		t.Fatal("deny must only cover what it matches")
	}
	if !doc.Visible("telefon", "masaustu") {
		t.Fatal("a partial deny keeps the peer visible")
	}

	// A deny-any rule placed before the allow still wins, and hides the
	// direction from visibility.
	if err := doc.AddRule(Rule{From: []string{"laptop"}, To: []string{"masaustu"}, Protocol: ProtocolAny, Action: RuleDeny}); err != nil {
		t.Fatal(err)
	}
	if doc.Allows("laptop", "masaustu", ProtocolTCP, 3389) || doc.AllowsIP("laptop", "masaustu", 47, 0) {
		t.Fatal("deny any must block every protocol")
	}
	// laptop -> masaustu is fully denied and nothing allows the reverse
	// direction, so the pair is no longer visible.
	if doc.Visible("laptop", "masaustu") {
		t.Fatal("fully denied pair must not be visible")
	}

	idx := len(doc.Rules) - 1
	if err := doc.SetRuleDisabled(idx, true); err != nil {
		t.Fatal(err)
	}
	if !doc.Allows("laptop", "masaustu", ProtocolTCP, 3389) || !doc.Visible("laptop", "masaustu") {
		t.Fatal("disabled deny rule must be ignored")
	}
	// Disable both allow rules that cover laptop -> masaustu tcp/3389:
	// rule 0 (laptop -> masaustu) and rule 2 (* -> masaustu).
	for _, i := range []int{0, 2} {
		if err := doc.SetRuleDisabled(i, true); err != nil {
			t.Fatal(err)
		}
	}
	if doc.Allows("laptop", "masaustu", ProtocolTCP, 3389) || doc.Visible("laptop", "masaustu") {
		t.Fatal("disabled allow rules must not allow")
	}
	if err := doc.SetRuleDisabled(99, true); err == nil {
		t.Fatal("unknown rule index must be rejected")
	}
}

func TestNumericProtocolRules(t *testing.T) {
	_, doc := policyDoc(t)
	if err := doc.AddRule(Rule{From: []string{"laptop"}, To: []string{"vps"}, Protocol: "47"}); err != nil {
		t.Fatal(err)
	}
	if !doc.AllowsIP("laptop", "vps", 47, 0) || !doc.Allows("laptop", "vps", "47", 0) {
		t.Fatal("gre rule must allow gre")
	}
	if doc.AllowsIP("laptop", "vps", 50, 0) || doc.AllowsIP("laptop", "vps", 6, 22) || doc.Allows("laptop", "vps", "other", 0) {
		t.Fatal("numeric rule must match only its protocol")
	}
}

func TestExitUsers(t *testing.T) {
	_, doc := policyDoc(t)
	// Drop "* -> vps icmp" so only the exit node role links devices to vps.
	if _, err := doc.RemoveRule(1); err != nil {
		t.Fatal(err)
	}
	if err := doc.SetExitNode("vps", true); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"laptop", "telefon", "masaustu"} {
		if !doc.MayUseExitNode(name) || !peerNames(doc.TunnelPeersOf(name))["vps"] {
			t.Fatalf("without exit_users %s must reach the exit node", name)
		}
	}
	if err := doc.SetDeviceTags("telefon", []string{"mobil"}); err != nil {
		t.Fatal(err)
	}
	if err := doc.SetExitUsers([]string{"laptop", "tag:mobil"}); err != nil {
		t.Fatal(err)
	}
	if !doc.MayUseExitNode("laptop") || !doc.MayUseExitNode("telefon") || doc.MayUseExitNode("masaustu") {
		t.Fatal("exit_users not applied")
	}
	vpsPeers := peerNames(doc.TunnelPeersOf("vps"))
	if !vpsPeers["laptop"] || !vpsPeers["telefon"] || vpsPeers["masaustu"] {
		t.Fatalf("exit node peers = %v", vpsPeers)
	}
	if peerNames(doc.TunnelPeersOf("masaustu"))["vps"] {
		t.Fatal("masaustu must not get the exit node as peer")
	}
	for _, bad := range [][]string{{"*"}, {"yok"}, {"group:yok"}, {"laptop", "laptop"}} {
		if err := doc.SetExitUsers(bad); err == nil {
			t.Errorf("exit_users %v should be rejected", bad)
		}
	}

	// Revoking the only listed device must not open the exit node to all.
	if err := doc.SetExitUsers([]string{"laptop"}); err != nil {
		t.Fatal(err)
	}
	if _, err := doc.RevokeDevice("laptop", testNow); err != nil {
		t.Fatal(err)
	}
	users, set := doc.ExitUsersList()
	if !set || len(users) != 0 || doc.MayUseExitNode("telefon") {
		t.Fatalf("emptied exit_users must deny everyone, got %v %v", users, set)
	}
	data, _ := jsonBytes(doc)
	if !strings.Contains(string(data), `"exit_users":[]`) {
		t.Fatal("empty exit_users must stay in the encoding")
	}
	if err := doc.ClearExitUsers(); err != nil || !doc.MayUseExitNode("telefon") {
		t.Fatal("ClearExitUsers must allow everyone again")
	}
}

func TestRevokeCleansGroups(t *testing.T) {
	_, doc := policyDoc(t)
	if err := doc.SetGroup("ofis", []string{"laptop", "masaustu"}); err != nil {
		t.Fatal(err)
	}
	if _, err := doc.RevokeDevice("laptop", testNow); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if g, _ := doc.GroupByName("ofis"); len(g.Members) != 1 || g.Members[0] != "masaustu" {
		t.Fatalf("group not cleaned: %v", g.Members)
	}
}
