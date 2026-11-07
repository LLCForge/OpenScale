package trust

import (
	"crypto/rand"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// ADR-0232: device icons (#233), ranges in groups, exit_users and via
// (#277), support rules (#852) and the client minimum they need.

func addr32(t *testing.T, doc *Document, name string) string {
	t.Helper()
	d, ok := doc.DeviceByName(name)
	if !ok {
		t.Fatalf("no device %s", name)
	}
	return NormalizeAddrEntry(d.IPv4.String())
}

func TestF4ALegacyEncodingUnchanged(t *testing.T) {
	_, doc := policyDoc(t)
	data, err := jsonBytes(doc)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"icon"`, `"allow_kill"`, `"min_client_version"`} {
		if strings.Contains(string(data), field) {
			t.Errorf("legacy document encodes %s", field)
		}
	}
	if f := doc.SchemaV2Features(); len(f) != 0 {
		t.Fatalf("legacy document reports features %v", f)
	}
}

func TestF4AIcons(t *testing.T) {
	_, doc := policyDoc(t)
	if err := doc.SetDeviceIcon("laptop", "toaster"); !errors.Is(err, ErrUnknownIcon) {
		t.Fatalf("unknown icon accepted: %v", err)
	}
	if err := doc.SetDeviceIcon("nope", IconLaptop); !errors.Is(err, ErrUnknownDevice) {
		t.Fatalf("unknown device: %v", err)
	}
	for _, i := range DeviceIcons() {
		if err := doc.SetDeviceIcon("vps", i); err != nil {
			t.Fatalf("%s: %v", i, err)
		}
	}
	if doc.MinClientVersion != SchemaV2MinClientVersion {
		t.Fatalf("the edit must raise the minimum, got %q", doc.MinClientVersion)
	}
	// A document that carries an icon without the minimum is invalid: a
	// forged or hand-built document fails closed.
	bad := *doc
	bad.MinClientVersion = "1.0.0-beta.1"
	if err := bad.Validate(); !errors.Is(err, ErrSchemaNeedsClients) {
		t.Fatalf("icon below the minimum: %v", err)
	}
	bad.MinClientVersion = ""
	if err := bad.Validate(); !errors.Is(err, ErrSchemaNeedsClients) {
		t.Fatalf("icon without a minimum: %v", err)
	}
	if err := doc.SetDeviceIcon("vps", ""); err != nil || doc.Devices[2].Icon != "" {
		t.Fatalf("clearing the icon: %v", err)
	}
}

func TestF4AMinVersionOrdering(t *testing.T) {
	cases := []struct {
		have, min string
		ok        bool
	}{
		{"1.0.0-beta.2", "1.0.0-beta.2", true},
		{"1.0.0-beta.2 (20261107.1200)", "1.0.0-beta.2", true},
		{"1.0.0-beta.10", "1.0.0-beta.2", true},
		{"1.0.0-beta.1", "1.0.0-beta.2", false},
		{"1.0.0", "1.0.0-beta.2", true},
		{"0.9.9", "1.0.0-beta.2", false},
		{"1.0.1-beta.1", "1.0.0-beta.2", true},
		{"1.0.0-beta.1", "1.0.0", true}, // unchanged: a release minimum ignores the suffix
	}
	for _, c := range cases {
		if got := ClientVersionAtLeast(c.have, c.min); got != c.ok {
			t.Errorf("%q >= %q: got %v", c.have, c.min, got)
		}
	}
	for _, c := range []struct {
		min, need string
		ok        bool
	}{{"1.0.0-beta.2", "1.0.0-beta.2", true}, {"1.0.0", "1.0.0-beta.2", true}, {"1.0.0-beta.1", "1.0.0-beta.2", false}, {"", "1.0.0-beta.2", false}, {"2.0.0", "1.0.0-beta.2", true}} {
		if got := MinVersionAtLeast(c.min, c.need); got != c.ok {
			t.Errorf("min %q >= %q: got %v", c.min, c.need, got)
		}
	}
	f := newFixture(t)
	for _, bad := range []string{"1.0.0-beta.0", "1.0.0-beta.01", "1.0.0-rc.1", "1.0.0-beta."} {
		if err := f.doc.SetMinClientVersion(bad); !errors.Is(err, ErrInvalidClientVersion) {
			t.Errorf("%q accepted", bad)
		}
	}
	if err := f.doc.SetMinClientVersion("1.0.0-beta.2"); err != nil {
		t.Fatal(err)
	}
}

func TestF4AGroupRanges(t *testing.T) {
	_, doc := policyDoc(t)
	laptop := addr32(t, doc, "laptop")
	if err := doc.SetGroup("ofis", []string{laptop, "telefon"}); err != nil {
		t.Fatal(err)
	}
	if err := doc.AddRule(Rule{From: []string{"group:ofis"}, To: []string{"vps"}, Protocol: ProtocolTCP, Ports: []string{"22"}}); err != nil {
		t.Fatal(err)
	}
	if !doc.Allows("laptop", "vps", ProtocolTCP, 22) || !doc.Allows("telefon", "vps", ProtocolTCP, 22) {
		t.Fatal("a range member must match the device it holds")
	}
	if doc.Allows("masaustu", "vps", ProtocolTCP, 22) {
		t.Fatal("a device outside the range must not match")
	}
	// Non-canonical and outside ranges are refused.
	for _, bad := range []string{"100.80.0.1/8", "8.8.8.8/32", "host:yok", "100.80.0.0/33"} {
		if err := doc.SetGroup("kotu", []string{bad}); err == nil {
			t.Errorf("group member %q accepted", bad)
		}
	}
	// A named address member works too.
	p := netip.MustParsePrefix(laptop)
	if err := doc.SetHost("dizustu", p); err != nil {
		t.Fatal(err)
	}
	if err := doc.SetGroup("adli", []string{"host:dizustu"}); err != nil {
		t.Fatal(err)
	}
	if err := doc.RemoveHost("dizustu"); err == nil {
		t.Fatal("a named address a group uses must not be removable")
	}
}

func TestF4ARoutedGroupRange(t *testing.T) {
	doc := routedDoc(t)
	if err := doc.SetGroup("kameralar", []string{"192.168.1.16/28"}); err != nil {
		t.Fatal(err)
	}
	if err := doc.AddRule(Rule{From: []string{"laptop"}, To: []string{"group:kameralar"}, Protocol: ProtocolTCP, Ports: []string{"554"}}); err != nil {
		t.Fatal(err)
	}
	cam := netip.MustParseAddr("192.168.1.20")
	q := PacketQuery{Proto: ipProtoTCP, Port: 554, ICMPType: -1}
	if !doc.AllowsRoutedPacketAt(DeviceEnd("laptop"), AddrEnd(cam), q) {
		t.Fatal("a group with a routed range must reach that range")
	}
	if doc.AllowsRoutedPacketAt(DeviceEnd("laptop"), AddrEnd(nasAddr), q) {
		t.Fatal("addresses outside the group's range stay closed")
	}
	if !doc.RouteVisible("laptop", "vps") {
		t.Fatal("the router must become a peer for a group range rule")
	}
	// The wildcard still never covers routed hosts.
	if err := doc.AddRule(Rule{From: []string{"*"}, To: []string{"*"}, Protocol: ProtocolTCP, Ports: []string{"80"}}); err != nil {
		t.Fatal(err)
	}
	if doc.AllowsRoutedPacketAt(DeviceEnd("telefon"), AddrEnd(cam), PacketQuery{Proto: ipProtoTCP, Port: 80, ICMPType: -1}) {
		t.Fatal("* must not reach routed hosts")
	}
	for _, w := range doc.PolicyWarnings(testNow) {
		if w.Code == WarnMatchesNothing && w.Rule == len(doc.Rules)-2 {
			t.Fatalf("a routed group rule is not empty: %v", w)
		}
	}
}

func TestF4AExitUsersAndViaRanges(t *testing.T) {
	_, doc := policyDoc(t)
	telefon := addr32(t, doc, "telefon")
	if err := doc.SetExitUsers([]string{telefon}); err != nil {
		t.Fatal(err)
	}
	if !doc.MayUseExitNode("telefon") || doc.MayUseExitNode("laptop") {
		t.Fatal("exit_users ranges must select by address")
	}
	doc2 := routedDoc(t)
	if err := doc2.SetExitUsers([]string{"192.168.1.0/24"}); err == nil {
		t.Fatal("exit_users ranges must lie inside the network prefixes")
	}
	vps := addr32(t, doc, "vps")
	wake := Rule{From: []string{"laptop"}, To: []string{"masaustu"}, Service: ServiceWake, Via: []string{vps}}
	if err := doc.AddRule(wake); err != nil {
		t.Fatal(err)
	}
	if !doc.AllowsWake("laptop", "masaustu", "vps") || doc.AllowsWake("laptop", "masaustu", "telefon") {
		t.Fatal("via ranges must select the relay by address")
	}
	// An empty overlay range is reported, not refused.
	if err := doc.SetGroup("bos", []string{"100.80.200.0/24"}); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, w := range doc.PolicyWarnings(testNow) {
		found = found || (w.Code == WarnEmptyRange && strings.Contains(w.Message, "group:bos"))
	}
	if !found {
		t.Fatal("an empty range must be a lint warning")
	}
	if NormalizeAddrEntry(" fd00::1 ") != "fd00::1/128" || NormalizeAddrEntry("laptop") != "laptop" || NormalizeAddrEntry("host:x") != "host:x" {
		t.Fatal("NormalizeAddrEntry")
	}
}

func TestF4ASupportRules(t *testing.T) {
	_, doc := policyDoc(t)
	read := Rule{From: []string{"laptop"}, To: []string{"masaustu"}, Service: ServiceSupport}
	kill := Rule{From: []string{"vps"}, To: []string{"masaustu"}, Service: ServiceSupport, AllowKill: true}
	for _, r := range []Rule{read, kill} {
		if err := doc.AddRule(r); err != nil {
			t.Fatal(err)
		}
	}
	switch {
	case !doc.AllowsSupport("laptop", "masaustu", SupportRead):
		t.Fatal("support read")
	case doc.AllowsSupport("laptop", "masaustu", SupportKill):
		t.Fatal("kill is a separate permission")
	case !doc.AllowsSupport("vps", "masaustu", SupportKill):
		t.Fatal("support.kill")
	case doc.AllowsSupport("telefon", "masaustu", SupportRead):
		t.Fatal("no rule, no support")
	case doc.AllowsSupport("laptop", "masaustu", "root"):
		t.Fatal("unknown mode")
	case !doc.HostsService("masaustu", ServiceSupport) || doc.HostsService("laptop", ServiceSupport):
		t.Fatal("only the destination hosts the service")
	}
	// A broad any rule opens the port but never grants the service.
	if err := doc.AddRule(Rule{From: []string{"telefon"}, To: []string{"masaustu"}, Protocol: ProtocolAny}); err != nil {
		t.Fatal(err)
	}
	if doc.AllowsSupport("telefon", "masaustu", SupportRead) {
		t.Fatal("an any rule must not grant support")
	}
	// A deny support rule wins.
	if err := doc.AddRule(Rule{From: []string{"vps"}, To: []string{"masaustu"}, Service: ServiceSupport, Action: RuleDeny}); err != nil {
		t.Fatal(err)
	}
	if doc.AllowsSupport("vps", "masaustu", SupportRead) {
		t.Fatal("deny wins")
	}
	for _, bad := range []Rule{
		{From: []string{"laptop"}, To: []string{"vps"}, Protocol: ProtocolTCP, Ports: []string{"1"}, AllowKill: true},
		{From: []string{"laptop"}, To: []string{"vps"}, Service: ServiceRemoteDesktop, AllowKill: true},
		{From: []string{"laptop"}, To: []string{"vps"}, Service: ServiceSupport, Action: RuleDeny, AllowKill: true},
		{From: []string{"laptop"}, To: []string{"vps"}, Service: ServiceSupport, Users: []string{"ali"}},
	} {
		if err := doc.AddRule(bad); err == nil {
			t.Errorf("rule %+v accepted", bad)
		}
	}
	if SupportPort != 4053 || ServiceSupport.Port() != SupportPort {
		t.Fatal("support port")
	}
}

func TestF4AMembersOnlySealsIcon(t *testing.T) {
	f, doc := policyDoc(t)
	if err := doc.SetMinClientVersion("1.0.0"); err != nil {
		t.Fatal(err)
	}
	if err := doc.SetDeviceIcon("laptop", IconCamera); err != nil {
		t.Fatal(err)
	}
	pub, plain, err := SealMembersOnly(doc, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range pub.Devices {
		if d.Icon != "" {
			t.Fatal("the public part must not carry icons")
		}
	}
	env := f.sign(t, pub)
	verified, err := VerifyDocumentSignature(env, f.rootPub)
	if err != nil {
		t.Fatal(err)
	}
	full, err := MergeMembersPlain(verified, plain)
	if err != nil {
		t.Fatal(err)
	}
	if d, _ := full.DeviceByName("laptop"); d.Icon != IconCamera {
		t.Fatal("the members part must restore the icon")
	}
}
