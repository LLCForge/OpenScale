package dnsguard

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

var testNow = time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)

func mustName(s string) dnsmessage.Name {
	if !strings.HasSuffix(s, ".") {
		s += "."
	}
	return dnsmessage.MustNewName(s)
}

type rr struct {
	name string
	ttl  uint32
	body dnsmessage.ResourceBody
}

func response(t testing.TB, q string, qt dnsmessage.Type, rcode dnsmessage.RCode, ans, auth []rr) []byte {
	t.Helper()
	m := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 7, Response: true, RCode: rcode, RecursionAvailable: true},
		Questions: []dnsmessage.Question{{Name: mustName(q), Type: qt, Class: dnsmessage.ClassINET}},
	}
	conv := func(in []rr) []dnsmessage.Resource {
		var out []dnsmessage.Resource
		for _, r := range in {
			out = append(out, dnsmessage.Resource{
				Header: dnsmessage.ResourceHeader{Name: mustName(r.name), Class: dnsmessage.ClassINET, TTL: r.ttl},
				Body:   r.body,
			})
		}
		return out
	}
	m.Answers, m.Authorities = conv(ans), conv(auth)
	b, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func a4(s string) *dnsmessage.AResource {
	return &dnsmessage.AResource{A: netip.MustParseAddr(s).As4()}
}
func a6(s string) *dnsmessage.AAAAResource {
	return &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr(s).As16()}
}

func TestDoHListAndRules(t *testing.T) {
	l, err := ParseDoHList(strings.NewReader("# owner list\n192.0.2.10\n2001:db8::53 # v6\n198.51.100.0/24\ndoh.example\nDoH.example.\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Prefixes) != 3 || len(l.Names) != 1 || !l.BlocksName("a.doh.example") || l.BlocksName("doh.example.net") {
		t.Fatalf("%+v", l)
	}
	for _, bad := range []string{"0.0.0.0/0\n", "::/8\n", "not a name\n", "com\n"} {
		if _, err := ParseDoHList(strings.NewReader(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	cfg := EnforceConfig{Tunnel: "openscale0", Resolvers: []netip.Addr{netip.MustParseAddr("100.64.0.53")}, AllowLoopback: true, DoH: l}
	rules, err := EnforceRules(cfg)
	if err != nil {
		t.Fatal(err)
	}
	type c struct {
		iface string
		proto Proto
		dst   string
		port  uint16
		want  Action
		hit   bool
	}
	for _, tc := range []c{
		{"openscale0", ProtoUDP, "100.64.0.53", 53, ActionAllow, true},
		{"openscale0", ProtoTCP, "100.64.0.53", 853, ActionAllow, true},
		{"lo", ProtoUDP, "127.0.0.53", 53, ActionAllow, true},
		{"eth0", ProtoUDP, "192.0.2.1", 53, ActionDrop, true},
		{"wlan0", ProtoTCP, "192.0.2.1", 853, ActionDrop, true},
		{"wlan0", ProtoUDP, "192.0.2.1", 853, ActionDrop, true},
		{"eth0", ProtoTCP, "192.0.2.10", 443, ActionDrop, true},
		{"openscale0", ProtoUDP, "198.51.100.7", 443, ActionDrop, true},
		{"eth0", ProtoTCP, "2001:db8::53", 443, ActionDrop, true},
		{"eth0", ProtoTCP, "192.0.2.11", 443, "", false},
		{"openscale0", ProtoUDP, "100.64.0.9", 53, "", false},
	} {
		got, hit := Evaluate(rules, tc.iface, tc.proto, netip.MustParseAddr(tc.dst), tc.port)
		if got != tc.want || hit != tc.hit {
			t.Errorf("%+v: %s %v", tc, got, hit)
		}
	}
	for _, bad := range []EnforceConfig{
		{Tunnel: "", Resolvers: cfg.Resolvers},
		{Tunnel: "a;b", Resolvers: cfg.Resolvers},
		{Tunnel: "openscale0"},
		{Tunnel: "openscale0", Resolvers: []netip.Addr{netip.IPv4Unspecified()}},
	} {
		if _, err := EnforceRules(bad); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

func TestOnionDecision(t *testing.T) {
	v3 := strings.Repeat("a", 55) + "d"
	cases := []struct {
		name string
		tor  bool
		want OnionAction
	}{
		{"www.example", true, OnionNotOnion},
		{"onion.example", false, OnionNotOnion},
		{v3 + ".onion", true, OnionViaTor},
		{"www." + v3 + ".ONION.", true, OnionViaTor},
		{v3 + ".onion", false, OnionNXDOMAIN},
		{"onion.", true, OnionNXDOMAIN},
		{"abcdefghijklmnop.onion", true, OnionNXDOMAIN}, // retired v2
		{strings.Repeat("a", 56) + ".onion", true, OnionNXDOMAIN},
		{strings.Repeat("1", 55) + "d.onion", true, OnionNXDOMAIN},
	}
	for _, c := range cases {
		if got := OnionDecision(c.name, c.tor); got != c.want {
			t.Errorf("%s tor=%v: %s, want %s", c.name, c.tor, got, c.want)
		}
	}
}

func TestRebindAddr(t *testing.T) {
	for _, s := range []string{"10.1.2.3", "192.168.1.1", "172.16.0.1", "127.0.0.1", "169.254.1.1", "100.64.1.1",
		"0.1.2.3", "224.0.0.1", "::1", "fe80::1", "fd00::1", "fec0::1", "::ffff:10.0.0.1", "64:ff9b::a00:1", "0.0.0.0"} {
		if !RebindAddr(netip.MustParseAddr(s)) {
			t.Errorf("%s not flagged", s)
		}
	}
	for _, s := range []string{"192.0.2.1", "198.51.100.1", "2001:db8::1", "64:ff9b::c000:201"} {
		if RebindAddr(netip.MustParseAddr(s)) {
			t.Errorf("%s flagged", s)
		}
	}
}

func TestRebindFilter(t *testing.T) {
	f, err := NewRebindFilter([]string{"ag.test"}, []string{"nas.example"})
	if err != nil {
		t.Fatal(err)
	}
	// Mixed answer: the private record goes, the public one stays.
	msg := response(t, "www.example", dnsmessage.TypeA, dnsmessage.RCodeSuccess,
		[]rr{{"www.example", 60, a4("192.0.2.1")}, {"www.example", 60, a4("10.0.0.5")}}, nil)
	out, n, err := f.Filter(msg)
	if err != nil || n != 1 {
		t.Fatal(n, err)
	}
	var m dnsmessage.Message
	if err := m.Unpack(out); err != nil || len(m.Answers) != 1 {
		t.Fatal(err, m.Answers)
	}
	// Only private through a CNAME: NODATA.
	msg = response(t, "evil.example", dnsmessage.TypeAAAA, dnsmessage.RCodeSuccess,
		[]rr{{"evil.example", 60, &dnsmessage.CNAMEResource{CNAME: mustName("x.evil.example.")}}, {"x.evil.example", 60, a6("fd12::1")}}, nil)
	out, n, err = f.Filter(msg)
	if err != nil || n != 1 {
		t.Fatal(n, err)
	}
	if err := m.Unpack(out); err != nil || len(m.Answers) != 0 || m.RCode != dnsmessage.RCodeSuccess {
		t.Fatal(err, m.Answers, m.RCode)
	}
	// Exempt names keep private answers.
	for _, q := range []string{"nas.example", "files.nas.example", "printer.ag.test", "router.lan", "nas"} {
		msg = response(t, q, dnsmessage.TypeA, dnsmessage.RCodeSuccess, []rr{{q, 60, a4("192.168.1.2")}}, nil)
		out, n, err = f.Filter(msg)
		if err != nil || n != 0 || &out[0] != &msg[0] {
			t.Errorf("%s: %d %v", q, n, err)
		}
	}
	if _, _, err := f.Filter([]byte{1, 2, 3}); err == nil {
		t.Fatal("garbage accepted")
	}
	if _, err := NewRebindFilter([]string{"bad name"}, nil); err == nil {
		t.Fatal("bad name accepted")
	}
}

func FuzzRebindFilter(f *testing.F) {
	f.Add(response(f, "www.example", dnsmessage.TypeA, dnsmessage.RCodeSuccess, []rr{{"www.example", 60, a4("10.0.0.1")}}, nil))
	f.Add(response(f, "x.example", dnsmessage.TypeAAAA, dnsmessage.RCodeSuccess, []rr{{"x.example", 60, a6("::1")}, {"x.example", 1, a6("2001:db8::1")}}, nil))
	f.Add([]byte{0, 0, 0x80, 0, 0, 1, 0, 1, 0, 0, 0, 0})
	rf, err := NewRebindFilter([]string{"ag.test"}, nil)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, msg []byte) {
		out, removed, err := rf.Filter(msg)
		if err != nil {
			return
		}
		var m dnsmessage.Message
		if err := m.Unpack(out); err != nil {
			t.Fatalf("output does not parse: %v", err)
		}
		if removed == 0 {
			return
		}
		for _, r := range append(m.Answers, m.Additionals...) {
			if bad(r) {
				t.Fatalf("rebinding address left: %v", r)
			}
		}
	})
}

func TestCache(t *testing.T) {
	c, err := NewCache(CacheOptions{MaxEntries: 2, PrefetchHits: 2})
	if err != nil {
		t.Fatal(err)
	}
	q := dnsmessage.Question{Name: mustName("www.example."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
	if ok, err := c.Put(response(t, "www.example.", dnsmessage.TypeA, dnsmessage.RCodeSuccess, []rr{{"www.example", 100, a4("192.0.2.1")}}, nil), false, testNow); !ok || err != nil {
		t.Fatal(ok, err)
	}
	out, ok := c.Get(q, false, 99, testNow.Add(30*time.Second))
	if !ok {
		t.Fatal("miss")
	}
	var m dnsmessage.Message
	if err := m.Unpack(out); err != nil || m.Header.ID != 99 || m.Answers[0].Header.TTL != 70 {
		t.Fatal(err, m.Header.ID, m.Answers)
	}
	if _, ok := c.Get(q, true, 1, testNow); ok {
		t.Fatal("DNSSEC key shared with plain answers")
	}
	// Popular entry near expiry becomes a prefetch candidate once.
	c.Get(q, false, 1, testNow.Add(40*time.Second))
	if k := c.PrefetchCandidates(testNow.Add(50*time.Second), 5); len(k) != 0 {
		t.Fatal("prefetch too early", k)
	}
	if k := c.PrefetchCandidates(testNow.Add(95*time.Second), 5); len(k) != 1 || k[0].Name != "www.example." {
		t.Fatal("prefetch", k)
	}
	if k := c.PrefetchCandidates(testNow.Add(96*time.Second), 5); len(k) != 0 {
		t.Fatal("prefetch twice", k)
	}
	if _, ok := c.Get(q, false, 1, testNow.Add(100*time.Second)); ok {
		t.Fatal("expired entry served")
	}
	// Negative answers: SOA minimum, capped; without SOA not stored.
	soa := &dnsmessage.SOAResource{NS: mustName("ns.example."), MBox: mustName("h.example."), Serial: 1, Refresh: 1, Retry: 1, Expire: 1, MinTTL: 30}
	nx := response(t, "no.example.", dnsmessage.TypeA, dnsmessage.RCodeNameError, nil, []rr{{"example", 3600, soa}})
	if ok, _ := c.Put(nx, false, testNow); !ok {
		t.Fatal("negative not stored")
	}
	nq := dnsmessage.Question{Name: mustName("no.example."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
	if _, ok := c.Get(nq, false, 1, testNow.Add(29*time.Second)); !ok {
		t.Fatal("negative miss")
	}
	if _, ok := c.Get(nq, false, 1, testNow.Add(31*time.Second)); ok {
		t.Fatal("negative TTL ignored")
	}
	if ok, _ := c.Put(response(t, "x.example.", dnsmessage.TypeA, dnsmessage.RCodeNameError, nil, nil), false, testNow); ok {
		t.Fatal("negative without SOA stored")
	}
	if ok, _ := c.Put(response(t, "x.example.", dnsmessage.TypeA, dnsmessage.RCodeServerFailure, nil, nil), false, testNow); ok {
		t.Fatal("SERVFAIL stored")
	}
	if ok, _ := c.Put(response(t, "z.example.", dnsmessage.TypeA, dnsmessage.RCodeSuccess, []rr{{"z.example", 0, a4("192.0.2.1")}}, nil), false, testNow); ok {
		t.Fatal("zero TTL stored")
	}
	// LRU bound.
	for _, n := range []string{"a.example.", "b.example.", "c.example."} {
		c.Put(response(t, n, dnsmessage.TypeA, dnsmessage.RCodeSuccess, []rr{{n, 300, a4("192.0.2.1")}}, nil), false, testNow)
	}
	if s := c.Stats(); s.Entries != 2 || s.Evictions == 0 {
		t.Fatalf("%+v", s)
	}
	if _, err := NewCache(CacheOptions{MaxEntries: -1}); err == nil {
		t.Fatal("bad options accepted")
	}
	c.Purge()
	if c.Stats().Entries != 0 {
		t.Fatal("purge")
	}
}
