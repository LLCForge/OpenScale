package trust

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// Tests of the rule language extensions (ADR-0120).

func devAddr(t *testing.T, doc *Document, name string) Device {
	t.Helper()
	d, ok := doc.DeviceByName(name)
	if !ok {
		t.Fatalf("no device %s", name)
	}
	return d
}

func tcpQ(port uint16) PacketQuery { return PacketQuery{Proto: ipProtoTCP, Port: port, ICMPType: -1} }

// A document without the new fields must encode without them, and every
// old-style decision must be the same through the new evaluation.
func TestP09LegacyEncodingAndDecisionsUnchanged(t *testing.T) {
	_, doc := policyDoc(t)
	if err := doc.AddRule(Rule{From: []string{"telefon"}, To: []string{"*"}, Protocol: ProtocolAny, Action: RuleDeny}); err != nil {
		t.Fatal(err)
	}
	data, err := jsonBytes(doc)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"bidirectional"`, `"icmp_types"`, `"not_before"`, `"not_after"`, `"schedule"`, `"hosts"`, `"policy_tests"`} {
		if strings.Contains(string(data), field) {
			t.Errorf("legacy document encodes new field %s", field)
		}
	}
	names := []string{"laptop", "masaustu", "vps", "telefon", "yok"}
	for _, a := range names {
		for _, b := range names {
			for _, p := range []uint8{1, 6, 17, 47, 58} {
				for _, port := range []uint16{0, 22, 3389, 5905} {
					old := doc.AllowsIP(a, b, p, port)
					got := doc.AllowsPacketAt(a, b, PacketQuery{Proto: int(p), Port: port, ICMPType: -1})
					typed := doc.AllowsPacketAt(a, b, PacketQuery{Proto: int(p), Port: port, ICMPType: 8, At: testNow})
					if old != got || old != typed {
						t.Fatalf("%s->%s %d/%d: old %v new %v typed %v", a, b, p, port, old, got, typed)
					}
				}
			}
		}
	}
}

func TestP09CIDRAndNamedAddresses(t *testing.T) {
	_, doc := policyDoc(t)
	laptop := devAddr(t, doc, "laptop")
	one := netip.PrefixFrom(laptop.IPv4, 32).String()
	if err := doc.AddRule(Rule{From: []string{one}, To: []string{"vps"}, Protocol: ProtocolTCP, Ports: []string{"22"}}); err != nil {
		t.Fatal(err)
	}
	if !doc.AllowsPacketAt("laptop", "vps", tcpQ(22)) || doc.AllowsPacketAt("telefon", "vps", tcpQ(22)) {
		t.Fatal("CIDR source must match exactly the device holding the address")
	}
	if err := doc.SetHost("evagi", doc.IPv4Prefix); err != nil {
		t.Fatal(err)
	}
	if err := doc.AddRule(Rule{From: []string{"telefon"}, To: []string{"host:evagi"}, Protocol: ProtocolUDP, Ports: []string{"53"}}); err != nil {
		t.Fatal(err)
	}
	q := PacketQuery{Proto: ipProtoUDP, Port: 53, ICMPType: -1}
	if !doc.AllowsPacketAt("telefon", "masaustu", q) || doc.AllowsPacketAt("laptop", "masaustu", q) {
		t.Fatal("named address must cover every device in the range")
	}
	if err := doc.RemoveHost("evagi"); err == nil {
		t.Fatal("a used named address must not be removable")
	}
	bad := []Rule{
		{From: []string{"192.168.1.0/24"}, To: []string{"vps"}, Protocol: ProtocolAny},
		{From: []string{"100.80.0.1/16"}, To: []string{"vps"}, Protocol: ProtocolAny},
		{From: []string{"100.80.0.0/8"}, To: []string{"vps"}, Protocol: ProtocolAny},
		{From: []string{"host:yok"}, To: []string{"vps"}, Protocol: ProtocolAny},
		{From: []string{"laptop"}, To: []string{"bozuk/"}, Protocol: ProtocolAny},
		{From: []string{"laptop"}, To: []string{"wake-target"}, Service: ServiceWake, Via: []string{one}},
	}
	for i, r := range bad {
		if err := doc.AddRule(r); err == nil {
			t.Errorf("rule %d must be rejected", i)
		}
	}
	if err := doc.SetHost("dis", netip.MustParsePrefix("192.168.1.0/24")); err == nil {
		t.Fatal("a named address outside the overlay must be rejected")
	}
	// Since ADR-0232 (#277) groups and exit_users may hold ranges; they
	// raise the client minimum (f4a_test.go has the details).
	if err := doc.SetGroup("g", []string{one}); err != nil {
		t.Fatalf("groups hold CIDR entries since ADR-0232: %v", err)
	}
	if err := doc.SetExitUsers([]string{one}); err != nil {
		t.Fatalf("exit_users hold CIDR entries since ADR-0232: %v", err)
	}
	if doc.MinClientVersion != SchemaV2MinClientVersion {
		t.Fatalf("ranges must raise the minimum, got %q", doc.MinClientVersion)
	}
}

func TestP09Bidirectional(t *testing.T) {
	_, doc := policyDoc(t)
	if doc.Visible("telefon", "laptop") {
		t.Fatal("setup: telefon and laptop must not see each other")
	}
	if err := doc.AddRule(Rule{From: []string{"telefon"}, To: []string{"laptop"}, Protocol: ProtocolTCP, Ports: []string{"8080"}, Bidirectional: true}); err != nil {
		t.Fatal(err)
	}
	if !doc.AllowsPacketAt("telefon", "laptop", tcpQ(8080)) || !doc.AllowsPacketAt("laptop", "telefon", tcpQ(8080)) {
		t.Fatal("bidirectional rule must allow both directions")
	}
	if doc.AllowsPacketAt("laptop", "telefon", tcpQ(8081)) || !doc.Visible("laptop", "telefon") {
		t.Fatal("bidirectional rule keeps its port and makes both visible")
	}
	if err := doc.AddRule(Rule{From: []string{"telefon"}, To: []string{"laptop"}, Service: ServiceFiles, Bidirectional: true}); err == nil {
		t.Fatal("service rules cannot be bidirectional")
	}
	if err := doc.AddRule(Rule{From: []string{"laptop"}, To: []string{"telefon"}, Protocol: ProtocolAny, Action: RuleDeny, Bidirectional: true}); err != nil {
		t.Fatal(err)
	}
	if doc.AllowsPacketAt("telefon", "laptop", tcpQ(8080)) {
		t.Fatal("a bidirectional deny must win in both directions")
	}
}

func TestP09ICMPTypes(t *testing.T) {
	_, doc := policyDoc(t)
	if err := doc.AddRule(Rule{From: []string{"telefon"}, To: []string{"laptop"}, Protocol: ProtocolICMP, ICMPTypes: []string{"echo"}}); err != nil {
		t.Fatal(err)
	}
	echo4 := PacketQuery{Proto: ipProtoICMP, ICMPType: 8}
	echo6 := PacketQuery{Proto: ipProtoICMPv6, ICMPType: 128}
	ts := PacketQuery{Proto: ipProtoICMP, ICMPType: 13}
	unknown := PacketQuery{Proto: ipProtoICMP, ICMPType: -1}
	if !doc.AllowsPacketAt("telefon", "laptop", echo4) || !doc.AllowsPacketAt("telefon", "laptop", echo6) {
		t.Fatal("echo must be allowed for both ICMP versions")
	}
	if doc.AllowsPacketAt("telefon", "laptop", ts) || doc.AllowsPacketAt("telefon", "laptop", unknown) {
		t.Fatal("other or unknown types must not pass a type-limited allow rule")
	}
	// A type-limited deny refuses the unknown type (fail closed).
	if err := doc.AddRule(Rule{From: []string{"*"}, To: []string{"vps"}, Protocol: ProtocolICMP, ICMPTypes: []string{"v4:13"}, Action: RuleDeny}); err != nil {
		t.Fatal(err)
	}
	if doc.AllowsPacketAt("laptop", "vps", unknown) || doc.AllowsPacketAt("laptop", "vps", ts) {
		t.Fatal("type-limited deny must refuse its type and unknown types")
	}
	if !doc.AllowsPacketAt("laptop", "vps", echo4) {
		t.Fatal("type-limited deny must leave other types to the allow rule")
	}
	for _, types := range [][]string{{"v4:0"}, {"v4:3"}, {"v4:11"}, {"v6:1"}, {"v6:129"}, {"v4:256"}, {"ping"}, {"echo", "echo"}} {
		if err := doc.AddRule(Rule{From: []string{"laptop"}, To: []string{"vps"}, Protocol: ProtocolICMP, ICMPTypes: types}); err == nil {
			t.Errorf("icmp_types %v must be rejected", types)
		}
	}
	if err := doc.AddRule(Rule{From: []string{"laptop"}, To: []string{"vps"}, Protocol: ProtocolTCP, Ports: []string{"1"}, ICMPTypes: []string{"echo"}}); err == nil {
		t.Fatal("icmp_types needs protocol icmp")
	}
}

func TestP09TimeWindowsAndSchedules(t *testing.T) {
	_, doc := policyDoc(t)
	end := testNow.Add(30 * time.Minute)
	if err := doc.AddRule(Rule{From: []string{"telefon"}, To: []string{"masaustu"}, Protocol: ProtocolTCP, Ports: []string{"3389"}, NotAfter: end}); err != nil {
		t.Fatal(err)
	}
	q := tcpQ(3389)
	at := func(t0 time.Time) PacketQuery { q.At = t0; return q }
	if !doc.AllowsPacketAt("telefon", "masaustu", at(testNow)) || doc.AllowsPacketAt("telefon", "masaustu", at(end)) {
		t.Fatal("one-time window must open before and close at not_after")
	}
	if !doc.AllowsPacketAt("telefon", "masaustu", at(time.Time{})) {
		t.Fatal("zero time ignores time conditions")
	}
	// 09:00-18:00 at UTC+03:00 on weekdays. testNow is Thursday 12:00 UTC (15:00 local).
	sched := &RuleSchedule{Days: []string{"mon", "tue", "wed", "thu", "fri"}, Start: "09:00", End: "18:00", UTCOffset: "+03:00"}
	if err := doc.AddRule(Rule{From: []string{"vps"}, To: []string{"laptop"}, Protocol: ProtocolTCP, Ports: []string{"22"}, Schedule: sched}); err != nil {
		t.Fatal(err)
	}
	q = tcpQ(22)
	cases := map[time.Time]bool{
		testNow: true,
		time.Date(2026, 10, 29, 15, 0, 0, 0, time.UTC): false, // 18:00 local
		time.Date(2026, 10, 29, 5, 59, 0, 0, time.UTC): false, // 08:59 local
		time.Date(2026, 10, 29, 6, 0, 0, 0, time.UTC):  true,
		time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC): false, // Saturday
	}
	for t0, want := range cases {
		if got := doc.AllowsPacketAt("vps", "laptop", at(t0)); got != want {
			t.Errorf("schedule at %s: got %v want %v", t0, got, want)
		}
	}
	night := &RuleSchedule{Days: []string{"fri"}, Start: "22:00", End: "06:00"}
	if !night.Contains(time.Date(2026, 10, 30, 23, 0, 0, 0, time.UTC)) || !night.Contains(time.Date(2026, 10, 31, 5, 0, 0, 0, time.UTC)) ||
		night.Contains(time.Date(2026, 10, 31, 23, 0, 0, 0, time.UTC)) || night.Contains(time.Date(2026, 10, 30, 5, 0, 0, 0, time.UTC)) {
		t.Fatal("overnight window belongs to the day it starts on")
	}
	ist := time.FixedZone("x", 3*3600)
	bad := []Rule{
		{From: []string{"laptop"}, To: []string{"vps"}, Protocol: ProtocolAny, NotAfter: testNow.In(ist)},
		{From: []string{"laptop"}, To: []string{"vps"}, Protocol: ProtocolAny, NotAfter: testNow.Add(time.Millisecond)},
		{From: []string{"laptop"}, To: []string{"vps"}, Protocol: ProtocolAny, NotBefore: end, NotAfter: testNow},
		{From: []string{"laptop"}, To: []string{"vps"}, Protocol: ProtocolAny, Schedule: &RuleSchedule{Start: "9:00", End: "18:00"}},
		{From: []string{"laptop"}, To: []string{"vps"}, Protocol: ProtocolAny, Schedule: &RuleSchedule{Start: "09:00", End: "09:00"}},
		{From: []string{"laptop"}, To: []string{"vps"}, Protocol: ProtocolAny, Schedule: &RuleSchedule{Start: "09:00", End: "10:00", UTCOffset: "+3"}},
		{From: []string{"laptop"}, To: []string{"vps"}, Protocol: ProtocolAny, Schedule: &RuleSchedule{Days: []string{"pzt"}, Start: "09:00", End: "10:00"}},
		{From: []string{"laptop"}, To: []string{"vps"}, Protocol: ProtocolAny, Schedule: &RuleSchedule{Start: "24:00", End: "10:00"}},
	}
	for i, r := range bad {
		if err := doc.AddRule(r); err == nil {
			t.Errorf("time rule %d must be rejected", i)
		}
	}
	if doc.TimeRuleState(testNow) == doc.TimeRuleState(end.Add(time.Hour)) {
		t.Fatal("time rule state must change when the window closes")
	}
}

func TestP09ServiceRuleTimeWindow(t *testing.T) {
	_, doc := policyDoc(t)
	if err := doc.AddRule(Rule{From: []string{"laptop"}, To: []string{"vps"}, Service: ServiceFiles, NotAfter: testNow.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	old := timeNow
	defer func() { timeNow = old }()
	timeNow = func() time.Time { return testNow }
	if !doc.AllowsFileSend("laptop", "vps") {
		t.Fatal("service rule must apply inside its window")
	}
	timeNow = func() time.Time { return testNow.Add(2 * time.Hour) }
	if doc.AllowsFileSend("laptop", "vps") {
		t.Fatal("service rule must stop after its window")
	}
}

func TestP09PolicyTestsGateSigning(t *testing.T) {
	f, doc := policyDoc(t)
	doc.PolicyTests = []PolicyTest{
		{From: "laptop", To: "masaustu", Protocol: ProtocolTCP, Port: 3389, Expect: RuleAllow},
		{From: "telefon", To: "masaustu", Protocol: ProtocolTCP, Port: 3389, Expect: RuleDeny},
		{From: "telefon", To: "vps", Protocol: ProtocolICMP, Expect: RuleAllow},
	}
	if err := doc.Validate(); err != nil {
		t.Fatal(err)
	}
	env := f.sign(t, doc)
	if _, err := VerifyDocumentSignature(env, f.rootPub); err != nil {
		t.Fatal(err)
	}
	// A rule change that breaks a test refuses the signature.
	if err := doc.AddRule(Rule{From: []string{"telefon"}, To: []string{"masaustu"}, Protocol: ProtocolAny}); err != nil {
		t.Fatal(err)
	}
	if _, err := SignDocument(doc, f.rootPriv); !errors.Is(err, ErrPolicyTestFailed) {
		t.Fatalf("SignDocument = %v, want ErrPolicyTestFailed", err)
	}
	res := doc.RunPolicyTests()
	if !res[0].Passed || res[1].Passed || res[1].Decision.Reason != ReasonAllow {
		t.Fatalf("unexpected results %+v", res)
	}
	if _, err := doc.RemoveRule(len(doc.Rules) - 1); err != nil {
		t.Fatal(err)
	}
	// Renaming follows tests; revoking drops tests naming the device.
	if err := doc.RenameDevice("telefon", "cep"); err != nil {
		t.Fatal(err)
	}
	if doc.PolicyTests[1].From != "cep" {
		t.Fatal("rename must update tests")
	}
	if _, err := doc.RevokeDevice("cep", testNow); err != nil {
		t.Fatal(err)
	}
	if len(doc.PolicyTests) != 1 {
		t.Fatalf("revoke must drop tests naming the device, have %d", len(doc.PolicyTests))
	}
	f.sign(t, doc)
	badTests := []PolicyTest{
		{From: "laptop", To: "yok", Protocol: ProtocolTCP, Port: 1, Expect: RuleAllow},
		{From: "laptop", To: "laptop", Protocol: ProtocolTCP, Port: 1, Expect: RuleAllow},
		{From: "laptop", To: "vps", Protocol: ProtocolTCP, Expect: RuleAllow},
		{From: "laptop", To: "vps", Protocol: ProtocolICMP, Port: 1, Expect: RuleAllow},
		{From: "laptop", To: "vps", Protocol: "6", Expect: RuleAllow},
		{From: "laptop", To: "vps", Protocol: ProtocolTCP, Port: 1, Expect: "maybe"},
		{From: "laptop", To: "vps", Service: ServiceSSH, Expect: RuleAllow},
		{From: "laptop", To: "vps", Service: ServiceWake, Expect: RuleAllow},
		{From: "laptop", To: "vps", Service: ServiceFiles, User: "x", Expect: RuleAllow},
	}
	for i, bt := range badTests {
		doc.PolicyTests = []PolicyTest{bt}
		if err := doc.Validate(); err == nil {
			t.Errorf("test %d must be rejected", i)
		}
	}
	doc.PolicyTests = nil
}

func TestP09ServicePolicyTest(t *testing.T) {
	_, doc := policyDoc(t)
	if err := doc.AddRule(Rule{From: []string{"laptop"}, To: []string{"vps"}, Service: ServiceSSH, Users: []string{"deploy"}}); err != nil {
		t.Fatal(err)
	}
	doc.PolicyTests = []PolicyTest{
		{From: "laptop", To: "vps", Service: ServiceSSH, User: "deploy", Expect: RuleAllow},
		{From: "laptop", To: "vps", Service: ServiceSSH, User: "root", Expect: RuleDeny},
		{From: "vps", To: "laptop", Service: ServiceSSH, User: "deploy", Expect: RuleDeny},
	}
	if err := doc.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := doc.CheckPolicyTests(); err != nil {
		t.Fatal(err)
	}
}

func TestP09PolicyTextRoundTrip(t *testing.T) {
	_, doc := policyDoc(t)
	if err := doc.SetGroup("ofis", []string{"laptop", "tag:sunucu"}); err != nil {
		t.Fatal(err)
	}
	if err := doc.SetHost("hepsi", doc.IPv4Prefix); err != nil {
		t.Fatal(err)
	}
	extra := []Rule{
		{From: []string{"group:ofis"}, To: []string{"host:hepsi"}, Protocol: ProtocolTCP, Ports: []string{"22"}, Bidirectional: true, Description: "açıklama // değil yorum"},
		{From: []string{"telefon"}, To: []string{"vps"}, Protocol: ProtocolICMP, ICMPTypes: []string{"echo"}, NotAfter: testNow.Add(time.Hour),
			Schedule: &RuleSchedule{Start: "09:00", End: "17:00", UTCOffset: "+03:00"}},
		{From: []string{"laptop"}, To: []string{"vps"}, Service: ServiceSSH, Users: []string{"deploy"}, AllowForward: true},
	}
	for _, r := range extra {
		if err := doc.AddRule(r); err != nil {
			t.Fatal(err)
		}
	}
	doc.PolicyTests = []PolicyTest{{From: "laptop", To: "masaustu", Protocol: ProtocolTCP, Port: 3389, Expect: RuleAllow}}
	text, err := FormatPolicyText(doc)
	if err != nil {
		t.Fatal(err)
	}
	p, err := ParsePolicyText(text)
	if err != nil {
		t.Fatalf("parse exported text: %v\n%s", err, text)
	}
	before, _ := jsonBytes(doc)
	if err := doc.ApplyPolicy(p); err != nil {
		t.Fatal(err)
	}
	after, _ := jsonBytes(doc)
	if string(before) != string(after) {
		t.Fatalf("round trip changed the document:\n%s\n%s", before, after)
	}
}

func TestP09PolicyTextSyntax(t *testing.T) {
	_, doc := policyDoc(t)
	src := `# başlık
{
  /* çok
     satırlı */
  "groups": [],
  "hosts": [],
  "rules": [
    // rdp adla
    {"from":["laptop"],"to":["masaustu"],"protocol":"tcp","ports":["rdp","5900-5910"],"description":"x # y",},
    {"from":["*"],"to":["vps"],"protocol":"icmp","ports":[],"description":"","action":"allow"},
  ],
  "tests": [
    {"from":"telefon","to":"masaustu","protocol":"tcp","port":3389,"expect":"deny"},
  ],
}
`
	p, err := ParsePolicyText([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if p.Rules[0].Ports[0] != "3389" || p.Rules[0].Description != "x # y" || p.Rules[1].Action != "" {
		t.Fatalf("unexpected parse %+v", p.Rules)
	}
	if err := doc.ApplyPolicy(p); err != nil {
		t.Fatal(err)
	}
	if err := doc.CheckPolicyTests(); err != nil {
		t.Fatal(err)
	}
	bad := map[string]string{
		"missing section": `{"groups":[],"hosts":[],"rules":[]}`,
		"unknown field":   "{\"groups\":[],\"hosts\":[],\"tests\":[],\n\"rules\":[{\"from\":[\"a\"],\"to\":[\"b\"],\"protocol\":\"any\",\"ports\":[],\"description\":\"\",\"bogus\":1}]}",
		"open comment":    `{"groups":[] /* `,
		"unknown port":    `{"groups":[],"hosts":[],"tests":[],"rules":[{"from":["a"],"to":["b"],"protocol":"tcp","ports":["gopher"],"description":""}]}`,
		"syntax":          "{\n\"groups\": [,\n}",
	}
	for name, s := range bad {
		if _, err := ParsePolicyText([]byte(s)); !errors.Is(err, ErrPolicyText) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if _, err := ParsePolicyText([]byte("{\n\n\"groups\": [1 2],\n}")); err == nil || !strings.Contains(err.Error(), "satır 3") {
		t.Errorf("syntax error must name the line: %v", err)
	}
}

func TestP09PolicyWarnings(t *testing.T) {
	_, doc := policyDoc(t)
	rules := []Rule{
		{From: []string{"*"}, To: []string{"*"}, Protocol: ProtocolAny},                                           // 3 broad
		{From: []string{"vps"}, To: []string{"*"}, Protocol: ProtocolAny, Action: RuleDeny},                       // 4
		{From: []string{"vps"}, To: []string{"laptop"}, Protocol: ProtocolTCP, Ports: []string{"22"}},             // 5 shadowed
		{From: []string{"tag:yok"}, To: []string{"laptop"}, Protocol: ProtocolAny, Action: RuleDeny},              // 6 nothing
		{From: []string{"laptop"}, To: []string{"vps"}, Protocol: ProtocolAny, NotAfter: testNow.Add(-time.Hour)}, // 7 expired
	}
	for _, r := range rules {
		if err := doc.AddRule(r); err != nil {
			t.Fatal(err)
		}
	}
	got := map[string][]int{}
	for _, w := range doc.PolicyWarnings(testNow) {
		got[w.Code] = append(got[w.Code], w.Rule)
	}
	want := map[string]int{WarnBroad: 2, WarnShadowed: 4, WarnMatchesNothing: 5, WarnExpired: 6, WarnClock: 6}
	for code, idx := range want {
		found := false
		for _, i := range got[code] {
			found = found || i == idx
		}
		if !found {
			t.Errorf("missing %s for rule %d: %v", code, idx, got)
		}
	}
	if len(NewBroadRules(doc, doc)) != 0 || len(NewBroadRules(nil, doc)) != 1 {
		t.Fatal("NewBroadRules must report only added broad rules")
	}
}

func TestP09PortNames(t *testing.T) {
	got, err := ExpandPortNames(ProtocolTCP, []string{"RDP", "22", "5900-5910", "https"})
	if err != nil || strings.Join(got, ",") != "3389,22,5900-5910,443" {
		t.Fatalf("got %v %v", got, err)
	}
	if _, err := ExpandPortNames(ProtocolUDP, []string{"smb"}); err == nil {
		t.Fatal("smb is not a udp name")
	}
	if _, err := ExpandPortNames(ProtocolICMP, []string{"rdp"}); err == nil {
		t.Fatal("names need tcp or udp")
	}
}

func FuzzParsePolicyText(f *testing.F) {
	f.Add([]byte(`{"groups":[],"hosts":[],"rules":[],"tests":[]}`))
	f.Add([]byte("# c\n{\"groups\":[/* x */],\"hosts\":[],\"rules\":[{\"from\":[\"*\"],\"to\":[\"*\"],\"protocol\":\"tcp\",\"ports\":[\"ssh\"],\"description\":\"\",},],\"tests\":[],}"))
	f.Add([]byte(`{"groups":[],"hosts":[{"name":"a","prefix":"100.80.0.0/24"}],"rules":[],"tests":[{"from":"a","to":"b","protocol":"icmp","expect":"allow"}]}`))
	f.Add([]byte(`"\"//`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<16 {
			return
		}
		clean, err := stripJSONC(data)
		if err == nil && len(clean) != len(data) {
			t.Fatalf("stripJSONC changed the length")
		}
		p, err := ParsePolicyText(data)
		if err != nil {
			return
		}
		doc := &Document{IPv4Prefix: DefaultIPv4Prefix}
		_ = doc.validatePolicyExt(map[string]bool{})
		_ = p
	})
}
