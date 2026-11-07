package trust

import (
	"bytes"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// Tests of subnet routing, route advertisements, plain WireGuard exits and
// the address strategy (ADR-0133).

var (
	lan     = netip.MustParsePrefix("192.168.1.0/24")
	nasAddr = netip.MustParseAddr("192.168.1.10")
)

// routedDoc is policyDoc with a router ("vps") approved for lan.
func routedDoc(t *testing.T) *Document {
	t.Helper()
	_, doc := policyDoc(t)
	if err := doc.SetDeviceRoutes("vps", []netip.Prefix{lan}); err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestP10LegacyEncodingUnchanged(t *testing.T) {
	_, doc := policyDoc(t)
	data, err := jsonBytes(doc)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"routes"`, `"external_exits"`, `"addressing"`} {
		if strings.Contains(string(data), field) {
			t.Errorf("legacy document encodes new field %s", field)
		}
	}
	// Existing decisions are untouched by an approved route.
	routed := routedDoc(t)
	for _, a := range []string{"laptop", "masaustu", "vps", "telefon"} {
		for _, b := range []string{"laptop", "masaustu", "vps", "telefon"} {
			for _, port := range []uint16{22, 3389, 5905} {
				if doc.AllowsIP(a, b, 6, port) != routed.AllowsIP(a, b, 6, port) {
					t.Fatalf("%s->%s/%d changed by a route", a, b, port)
				}
			}
		}
	}
}

func TestP10OutsideCIDRNeedsApprovedRoute(t *testing.T) {
	_, doc := policyDoc(t)
	rule := Rule{From: []string{"laptop"}, To: []string{"192.168.1.0/24"}, Protocol: ProtocolTCP, Ports: []string{"445"}}
	if err := doc.AddRule(rule); err == nil {
		t.Fatal("a range outside the overlay must be refused without an approved route")
	}
	doc = routedDoc(t)
	if err := doc.AddRule(rule); err != nil {
		t.Fatalf("a range inside an approved route must be accepted: %v", err)
	}
	for _, e := range []string{"192.168.0.0/16", "192.168.2.0/24", "10.0.0.0/8"} {
		r := rule
		r.To = []string{e}
		if err := doc.AddRule(r); err == nil {
			t.Errorf("%s is not inside one approved route but was accepted", e)
		}
	}
	if err := doc.SetHost("nas", netip.MustParsePrefix("192.168.1.10/32")); err != nil {
		t.Fatalf("named address inside a route: %v", err)
	}
	// Withdrawing a route that a rule still uses fails.
	if err := doc.RemoveDeviceRoute("vps", lan); err == nil {
		t.Fatal("a route used by a rule must not be removable")
	}
}

func TestP10RoutedDecisions(t *testing.T) {
	doc := routedDoc(t)
	if err := doc.AddRule(Rule{From: []string{"laptop"}, To: []string{"192.168.1.0/24"}, Protocol: ProtocolTCP, Ports: []string{"445"}}); err != nil {
		t.Fatal(err)
	}
	if err := doc.AddRule(Rule{From: []string{"*"}, To: []string{"*"}, Protocol: ProtocolTCP, Ports: []string{"80"}}); err != nil {
		t.Fatal(err)
	}
	nas := AddrEnd(nasAddr)
	if !doc.AllowsRoutedPacketAt(DeviceEnd("laptop"), nas, tcpQ(445)) {
		t.Fatal("explicit CIDR rule must allow the routed address")
	}
	if doc.AllowsRoutedPacketAt(DeviceEnd("telefon"), nas, tcpQ(445)) {
		t.Fatal("other devices must stay denied")
	}
	// "*" never covers routed addresses.
	if doc.AllowsRoutedPacketAt(DeviceEnd("laptop"), nas, tcpQ(80)) {
		t.Fatal("wildcard must not reach addresses behind a router")
	}
	// The reverse direction needs its own rule.
	if doc.AllowsRoutedPacketAt(nas, DeviceEnd("laptop"), tcpQ(445)) {
		t.Fatal("routed host must not open connections without a rule")
	}
	// Addresses outside every approved route are refused.
	if doc.AllowsRoutedPacketAt(DeviceEnd("laptop"), AddrEnd(netip.MustParseAddr("192.168.2.1")), tcpQ(445)) {
		t.Fatal("address outside the routes must be refused")
	}
	// A deny rule wins.
	if err := doc.AddRule(Rule{From: []string{"laptop"}, To: []string{"192.168.1.10/32"}, Protocol: ProtocolAny, Action: RuleDeny}); err != nil {
		t.Fatal(err)
	}
	if doc.AllowsRoutedPacketAt(DeviceEnd("laptop"), nas, tcpQ(445)) {
		t.Fatal("deny rule must win")
	}
	if !doc.AllowsRoutedPacketAt(DeviceEnd("laptop"), AddrEnd(netip.MustParseAddr("192.168.1.11")), tcpQ(445)) {
		t.Fatal("deny of one host must not cover the rest")
	}
}

func TestP10TunnelPeersFollowRouteRules(t *testing.T) {
	_, doc := policyDoc(t)
	if err := doc.SetDeviceRoutes("masaustu", []netip.Prefix{lan}); err != nil {
		t.Fatal(err)
	}
	if peerNames(doc.TunnelPeersOf("telefon"))["masaustu"] {
		t.Fatal("no rule: the router must not be a peer")
	}
	if err := doc.AddRule(Rule{From: []string{"telefon"}, To: []string{"192.168.1.0/25"}, Protocol: ProtocolTCP, Ports: []string{"80"}}); err != nil {
		t.Fatal(err)
	}
	if !peerNames(doc.TunnelPeersOf("telefon"))["masaustu"] || !peerNames(doc.TunnelPeersOf("masaustu"))["telefon"] {
		t.Fatal("route rule must make the router and the device peers")
	}
	if got := doc.RoutesVia("telefon", "masaustu"); len(got) != 1 || got[0] != lan {
		t.Fatalf("RoutesVia = %v", got)
	}
	if got := doc.RoutesVia("vps", "masaustu"); got != nil {
		t.Fatalf("vps has no rule but got %v", got)
	}
}

func TestP10RouteValidation(t *testing.T) {
	_, doc := policyDoc(t)
	bad := []string{"8.8.8.0/24", "192.168.1.1/24", "10.0.0.0/7", "fe80::/64", "2001:db8::/48", doc.IPv4Prefix.String()}
	for _, s := range bad {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			t.Fatal(err)
		}
		if err := doc.SetDeviceRoutes("vps", []netip.Prefix{p}); err == nil {
			t.Errorf("route %s must be refused", s)
		}
	}
	if err := doc.SetDeviceRoutes("vps", []netip.Prefix{lan}); err != nil {
		t.Fatal(err)
	}
	// Overlapping routes of two routers (F-040) are refused.
	if err := doc.SetDeviceRoutes("masaustu", []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")}); err == nil {
		t.Fatal("overlapping routes must be refused")
	}
	if err := doc.SetDeviceRoutes("masaustu", []netip.Prefix{netip.MustParsePrefix("fd12:3456::/48")}); err != nil {
		t.Fatalf("ULA route: %v", err)
	}
	// Ephemeral devices cannot route.
	d := devAddr(t, doc, "telefon")
	d.Ephemeral, d.Routes = true, []netip.Prefix{netip.MustParsePrefix("10.9.0.0/16")}
	for i := range doc.Devices {
		if doc.Devices[i].Name == "telefon" {
			doc.Devices[i] = d
		}
	}
	if err := doc.Validate(); err == nil {
		t.Fatal("ephemeral router must be refused")
	}
}

func TestP10RevokingRouterDropsRouteRules(t *testing.T) {
	doc := routedDoc(t)
	if err := doc.SetHost("nas", netip.MustParsePrefix("192.168.1.10/32")); err != nil {
		t.Fatal(err)
	}
	for _, r := range []Rule{
		{From: []string{"laptop"}, To: []string{"192.168.1.0/24"}, Protocol: ProtocolTCP, Ports: []string{"445"}},
		{From: []string{"telefon"}, To: []string{"host:nas", "masaustu"}, Protocol: ProtocolTCP, Ports: []string{"80"}},
	} {
		if err := doc.AddRule(r); err != nil {
			t.Fatal(err)
		}
	}
	before := len(doc.Rules)
	dropped, err := doc.RevokeDevice("vps", testNow)
	if err != nil {
		t.Fatalf("revoking a router must not fail: %v", err)
	}
	if dropped < 1 || len(doc.Rules) != before-dropped || len(doc.Hosts) != 0 {
		t.Fatalf("dropped %d, rules %d -> %d, hosts %v", dropped, before, len(doc.Rules), doc.Hosts)
	}
}

func TestP10RouteAdvertisement(t *testing.T) {
	f := newFixture(t)
	doc, err := f.doc.Next(testNow, DefaultValidity)
	if err != nil {
		t.Fatal(err)
	}
	secrets, req := newRequest(t, "router")
	dev, err := doc.AddDevice(req, "router", nil, testNow, DefaultDeviceLife)
	if err != nil {
		t.Fatal(err)
	}
	other, req2 := newRequest(t, "laptop")
	if _, err := doc.AddDevice(req2, "laptop", nil, testNow, DefaultDeviceLife); err != nil {
		t.Fatal(err)
	}
	routes := []netip.Prefix{lan, netip.MustParsePrefix("10.20.0.0/16")}
	line, err := NewRouteAdvertisement(secrets, doc.NetworkID, dev.ID, routes, testNow)
	if err != nil {
		t.Fatal(err)
	}
	a, signer, err := doc.OpenRouteAdvertisement(line, testNow.Add(time.Hour))
	if err != nil || signer.Name != "router" || len(a.Routes) != 2 {
		t.Fatalf("open: %v %v %v", a, signer.Name, err)
	}
	// Signed by another device's key: refused.
	forged, err := NewRouteAdvertisement(other, doc.NetworkID, dev.ID, routes, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := doc.OpenRouteAdvertisement(forged, testNow); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("forged advertisement: %v", err)
	}
	// Too old: refused.
	if _, _, err := doc.OpenRouteAdvertisement(line, testNow.Add(MaxRouteAdvertAge+time.Hour)); !errors.Is(err, ErrRouteAdvertExpired) {
		t.Fatalf("old advertisement: %v", err)
	}
	// Only listed and advertised routes are approved.
	if _, _, err := doc.ApproveRouteAdvertisement(line, []netip.Prefix{netip.MustParsePrefix("10.30.0.0/16")}, testNow); err == nil {
		t.Fatal("a route that was not advertised must not be approved")
	}
	if _, got, err := doc.ApproveRouteAdvertisement(line, []netip.Prefix{lan}, testNow); err != nil || len(got) != 1 {
		t.Fatalf("approve: %v %v", got, err)
	}
	if d := devAddr(t, doc, "router"); len(d.Routes) != 1 || d.Routes[0] != lan {
		t.Fatalf("routes = %v", d.Routes)
	}
	for _, s := range []string{"", "osroute1.", "osroute1.!!!", "oscmd1.abc", strings.Repeat("a", 9000)} {
		if _, err := DecodeRouteAdvertisement(s); err == nil {
			t.Errorf("decoded %q", s)
		}
	}
}

func TestP10ExternalExit(t *testing.T) {
	_, doc := policyDoc(t)
	_, req := newRequest(t, "x")
	x := ExternalExit{Name: "evwg", WireGuardKey: req.WireGuardKey, Endpoint: "wg.example.com:51820", DNS: netip.MustParseAddr("10.66.0.1")}
	if err := doc.SetExternalExit(x); err != nil {
		t.Fatal(err)
	}
	if got, ok := doc.ExternalExitByName("evwg"); !ok || got != x {
		t.Fatal("external exit not stored")
	}
	for _, bad := range []ExternalExit{
		{Name: "laptop", WireGuardKey: x.WireGuardKey, Endpoint: x.Endpoint, DNS: x.DNS},
		{Name: "b", WireGuardKey: devAddr(t, doc, "laptop").WireGuardKey, Endpoint: x.Endpoint, DNS: x.DNS},
		{Name: "c", WireGuardKey: x.WireGuardKey, Endpoint: "nohost", DNS: x.DNS},
		{Name: "d", WireGuardKey: x.WireGuardKey, Endpoint: x.Endpoint, DNS: devAddr(t, doc, "laptop").IPv4},
		{Name: "e", WireGuardKey: x.WireGuardKey, Endpoint: x.Endpoint},
	} {
		c, _ := doc.clone()
		if err := c.SetExternalExit(bad); err == nil {
			t.Errorf("external exit %+v must be refused", bad)
		}
	}
	cfg := doc.ExternalExitPeerConfig()
	if !strings.Contains(cfg, "[Peer]") || !strings.Contains(cfg, devAddr(t, doc, "laptop").WireGuardKey.String()) {
		t.Fatalf("peer config: %s", cfg)
	}
	if err := doc.RemoveExternalExit("evwg"); err != nil || doc.ExternalExits != nil {
		t.Fatalf("remove: %v", err)
	}
}

func TestP10Addressing(t *testing.T) {
	_, doc := policyDoc(t)
	reserved := netip.MustParsePrefix(doc.IPv4Prefix.Addr().Next().String() + "/30").Masked()
	if err := doc.SetAddressing(&Addressing{Strategy: AssignSequential, Reserved: []netip.Prefix{reserved}}); err != nil {
		t.Fatal(err)
	}
	_, req := newRequest(t, "yeni")
	d, err := doc.AddDevice(req, "yeni", nil, testNow, DefaultDeviceLife)
	if err != nil {
		t.Fatal(err)
	}
	if reserved.Contains(d.IPv4) {
		t.Fatalf("assigned reserved address %s", d.IPv4)
	}
	high := netip.Addr{}
	for _, o := range doc.Devices {
		if o.Name != "yeni" && (!high.IsValid() || o.IPv4.Compare(high) > 0) {
			high = o.IPv4
		}
	}
	if d.IPv4.Compare(high) <= 0 {
		t.Fatalf("sequential address %s not after %s", d.IPv4, high)
	}
	// Random strategy with a fixed source gives a free, valid address.
	old := addrRandom
	addrRandom = bytes.NewReader(bytes.Repeat([]byte{0x5a}, 4096))
	defer func() { addrRandom = old }()
	if err := doc.SetAddressing(&Addressing{Strategy: AssignRandom}); err != nil {
		t.Fatal(err)
	}
	_, req = newRequest(t, "rastgele")
	r, err := doc.AddDevice(req, "rastgele", nil, testNow, DefaultDeviceLife)
	if err != nil {
		t.Fatal(err)
	}
	if !doc.IPv4Prefix.Contains(r.IPv4) || !doc.IPv6Prefix.Contains(r.IPv6) {
		t.Fatalf("random address outside the network: %s %s", r.IPv4, r.IPv6)
	}
	if err := doc.SetAddressing(&Addressing{Strategy: "weird"}); err == nil {
		t.Fatal("unknown strategy must be refused")
	}
	if err := doc.SetAddressing(&Addressing{}); err != nil || doc.Addressing != nil {
		t.Fatal("empty addressing must be stored as nil")
	}
	// Moving a device into the reserved pool.
	if err := doc.SetDeviceAddress("laptop", reserved.Addr().Next()); err != nil {
		t.Fatal(err)
	}
	if err := doc.SetDeviceAddress("laptop", devAddr(t, doc, "vps").IPv4); err == nil {
		t.Fatal("duplicate address must be refused")
	}
}

func FuzzP10DecodeRouteAdvertisement(f *testing.F) {
	f.Add("osroute1.eyJjb250ZXh0IjoieCJ9")
	f.Add("osroute1.")
	f.Add("")
	var doc *Document
	f.Fuzz(func(t *testing.T, line string) {
		if _, err := DecodeRouteAdvertisement(line); err != nil {
			return
		}
		if doc == nil {
			_, doc = policyDoc(t)
		}
		_, _, _ = doc.OpenRouteAdvertisement(line, testNow)
	})
}
