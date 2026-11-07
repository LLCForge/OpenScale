package node

import (
	"context"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// fakeAuth is a tiny authoritative hierarchy:
//
//	.            192.0.2.1  -> test. at 192.0.2.2 (glue)
//	test.        192.0.2.2  -> example.test. at 192.0.2.3 (glue),
//	                           other.test. via ns.elsewhere.test. (no glue)
//	example.test 192.0.2.3  www A, alias CNAME www, NXDOMAIN otherwise
//
// Servers also try to slip in records they are not responsible for.
type fakeAuth struct {
	mu   sync.Mutex
	seen map[netip.Addr][]string
}

func rrA(name string, a [4]byte) dnsmessage.Resource {
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 300},
		Body:   &dnsmessage.AResource{A: a},
	}
}

func rrNS(zone, ns string) dnsmessage.Resource {
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(zone), Type: dnsmessage.TypeNS, Class: dnsmessage.ClassINET, TTL: 3600},
		Body:   &dnsmessage.NSResource{NS: dnsmessage.MustNewName(ns)},
	}
}

func (f *fakeAuth) query(_ context.Context, server netip.Addr, name dnsmessage.Name, qtype dnsmessage.Type) (*dnsmessage.Message, error) {
	n := strings.ToLower(name.String())
	f.mu.Lock()
	f.seen[server] = append(f.seen[server], n)
	f.mu.Unlock()
	m := &dnsmessage.Message{Header: dnsmessage.Header{Response: true}, Questions: []dnsmessage.Question{{Name: name, Type: qtype, Class: dnsmessage.ClassINET}}}
	switch server.String() {
	case "192.0.2.1": // root
		if !under(n, "test.") {
			m.RCode = dnsmessage.RCodeNameError
			return m, nil
		}
		m.Authorities = []dnsmessage.Resource{rrNS("test.", "ns.test.")}
		// Poison attempt: an answer for a name the root does not serve.
		m.Additionals = []dnsmessage.Resource{rrA("ns.test.", [4]byte{192, 0, 2, 2}), rrA("www.example.test.", [4]byte{6, 6, 6, 6})}
	case "192.0.2.2": // test.
		switch {
		case under(n, "example.test."):
			m.Authorities = []dnsmessage.Resource{rrNS("example.test.", "ns.example.test.")}
			m.Additionals = []dnsmessage.Resource{rrA("ns.example.test.", [4]byte{192, 0, 2, 3}), rrA("evil.", [4]byte{6, 6, 6, 6})}
		case under(n, "other.test."):
			m.Authorities = []dnsmessage.Resource{rrNS("other.test.", "ns.example.test.")}
		default:
			m.RCode = dnsmessage.RCodeNameError
		}
	case "192.0.2.3": // example.test. and, without glue, other.test.
		m.Header.Authoritative = true
		switch n {
		case "www.example.test.", "www.other.test.":
			if qtype == dnsmessage.TypeA {
				m.Answers = []dnsmessage.Resource{rrA(n, [4]byte{198, 51, 100, 7})}
			}
		case "ns.example.test.":
			m.Answers = []dnsmessage.Resource{rrA(n, [4]byte{192, 0, 2, 3})}
		case "alias.example.test.":
			m.Answers = []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 300},
				Body:   &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName("www.example.test.")},
			}, rrA("www.example.test.", [4]byte{198, 51, 100, 7}), rrA("bank.test.", [4]byte{6, 6, 6, 6})}
		case "example.test.":
		default:
			m.RCode = dnsmessage.RCodeNameError
			m.Authorities = []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("example.test."), Type: dnsmessage.TypeSOA, Class: dnsmessage.ClassINET, TTL: 60},
				Body: &dnsmessage.SOAResource{NS: dnsmessage.MustNewName("ns.example.test."), MBox: dnsmessage.MustNewName("root.example.test."),
					Serial: 1, Refresh: 1, Retry: 1, Expire: 1, MinTTL: 60},
			}}
		}
	default:
		return nil, context.DeadlineExceeded
	}
	return m, nil
}

func testRecursive() (*recursiveResolver, *fakeAuth) {
	f := &fakeAuth{seen: map[netip.Addr][]string{}}
	r := newRecursiveResolver()
	r.roots = []netip.Addr{netip.MustParseAddr("192.0.2.1")}
	r.query = f.query
	return r, f
}

func resolveA(t *testing.T, r *recursiveResolver, name string) dnsmessage.Message {
	t.Helper()
	q := dnsQuery(t, 99, name, dnsmessage.TypeA, 0)
	out, err := r.resolve(context.Background(), q, 99, dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	var m dnsmessage.Message
	if err := m.Unpack(out); err != nil {
		t.Fatal(err)
	}
	return m
}

func answerAddrs(m dnsmessage.Message) []string {
	var out []string
	for _, rr := range m.Answers {
		switch b := rr.Body.(type) {
		case *dnsmessage.AResource:
			out = append(out, netip.AddrFrom4(b.A).String())
		case *dnsmessage.CNAMEResource:
			out = append(out, "cname:"+b.CNAME.String())
		}
	}
	return out
}

func TestRecursiveResolves(t *testing.T) {
	r, f := testRecursive()
	m := resolveA(t, r, "www.example.test.")
	if got := answerAddrs(m); len(got) != 1 || got[0] != "198.51.100.7" || m.ID != 99 || !m.RecursionAvailable {
		t.Fatalf("www: %v %+v", got, m.Header)
	}
	// QNAME minimisation: the root saw only "test.".
	for _, n := range f.seen[netip.MustParseAddr("192.0.2.1")] {
		if n != "test." {
			t.Fatalf("root saw %q", n)
		}
	}
	// The delegation is cached: the next name skips the root.
	before := len(f.seen[netip.MustParseAddr("192.0.2.1")])
	m = resolveA(t, r, "alias.example.test.")
	if got := answerAddrs(m); len(got) != 2 || got[0] != "cname:www.example.test." || got[1] != "198.51.100.7" {
		t.Fatalf("alias: %v", got)
	}
	if len(f.seen[netip.MustParseAddr("192.0.2.1")]) != before {
		t.Fatal("cached delegation not used")
	}
	m = resolveA(t, r, "yok.example.test.")
	if m.RCode != dnsmessage.RCodeNameError || len(m.Authorities) != 1 {
		t.Fatalf("NXDOMAIN %+v", m)
	}
	// A server without glue is looked up first.
	m = resolveA(t, r, "www.other.test.")
	if got := answerAddrs(m); len(got) != 1 || got[0] != "198.51.100.7" {
		t.Fatalf("no glue: %v", got)
	}
	for _, rr := range append(m.Answers, m.Additionals...) {
		if a, ok := rr.Body.(*dnsmessage.AResource); ok && a.A == [4]byte{6, 6, 6, 6} {
			t.Fatal("out-of-bailiwick record accepted")
		}
	}
}

func TestRecursiveFailsClosed(t *testing.T) {
	r, _ := testRecursive()
	r.roots = []netip.Addr{netip.MustParseAddr("192.0.2.99")} // never answers
	q := dnsQuery(t, 5, "www.example.test.", dnsmessage.TypeA, 0)
	if _, err := r.resolve(context.Background(), q, 5, dnsmessage.Question{Name: dnsmessage.MustNewName("www.example.test."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}); err == nil {
		t.Fatal("resolved without any server")
	}
	// A referral loop is bounded by the query budget.
	loop := func(_ context.Context, _ netip.Addr, name dnsmessage.Name, qtype dnsmessage.Type) (*dnsmessage.Message, error) {
		return &dnsmessage.Message{Header: dnsmessage.Header{Response: true}, Authorities: []dnsmessage.Resource{rrNS("test.", "ns.nowhere.")}}, nil
	}
	r, _ = testRecursive()
	r.query = loop
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := r.resolve(ctx, q, 5, dnsmessage.Question{Name: dnsmessage.MustNewName("www.example.test."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}); err == nil {
		t.Fatal("referral loop resolved")
	}
}

func TestParseRecursiveUpstream(t *testing.T) {
	up, err := parseDNSUpstream("recursive")
	if err != nil || up.kind != upstreamRecursive {
		t.Fatalf("%+v %v", up, err)
	}
	if f := newDNSForwarder(up, nil); f.recursive == nil {
		t.Fatal("no recursive resolver")
	}
	for _, s := range []string{"recursive", "", "9.9.9.9"} {
		if err := ValidateExitDNSUpstream(s); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
}

func TestZoneHelpers(t *testing.T) {
	if lastLabels("a.b.example.test.", 2) != "example.test." || lastLabels("test.", 3) != "test." {
		t.Fatal("lastLabels")
	}
	if !under("A.Example.test.", "example.test.") || under("badexample.test.", "example.test.") || !under("x.", ".") {
		t.Fatal("under")
	}
	if parentZone("a.b.") != "b." || parentZone("b.") != "." {
		t.Fatal("parentZone")
	}
}
