package node

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.zx2c4.com/wireguard/conn"

	"github.com/openscale/openscale/internal/magicdns"
	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/internal/wgconf"
)

func TestLocalCandidates(t *testing.T) {
	ia := func(iface, a string) interfaceAddr { return interfaceAddr{iface: iface, addr: netip.MustParseAddr(a)} }
	overlay := []netip.Prefix{netip.MustParsePrefix("100.80.0.0/16"), netip.MustParsePrefix("fd7a:115c::/48")}
	addrs := []interfaceAddr{
		ia("eth0", "203.0.113.7"),
		ia("eth0", "2001:db8::1"),
		ia("eth0", "2001:db8::2"),
		ia("eth0", "2001:db8::3"), // third privacy address: left out
		ia("wlan0", "192.168.1.5"),
		ia("wlan0", "fe80::1"),
		ia("docker0", "172.17.0.1"),
		ia("vEthernet (WSL)", "172.20.0.1"),
		ia("openscale0", "100.80.0.5"),
		ia("eth1", "100.80.0.9"), // overlay address on another interface
		ia("lab0", "10.9.0.1"),
		ia("lo", "127.0.0.1"),
	}
	got := localCandidates(addrs, 41641, "openscale0", overlay, []string{"lab"}, 8)
	want := []string{"192.168.1.5:41641", "[2001:db8::1]:41641", "[2001:db8::2]:41641", "203.0.113.7:41641"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	if got := localCandidates(addrs, 41641, "openscale0", overlay, nil, 2); len(got) != 2 {
		t.Fatalf("limit not applied: %v", got)
	}
}

func TestClassifyOrder(t *testing.T) {
	lan, v6, pub := netip.MustParseAddrPort("10.0.0.1:1"), netip.MustParseAddrPort("[2001:db8::1]:1"), netip.MustParseAddrPort("198.51.100.1:1")
	if !(classify(lan) > classify(v6) && classify(v6) > classify(pub) && classify(pub) > classRelay && classRelay > classify(netip.AddrPort{})) {
		t.Fatal("LAN > IPv6 > public > relay order broken")
	}
	if classify(netip.MustParseAddrPort("[fd00::1]:1")) != classLAN {
		t.Fatal("ULA is a LAN address")
	}
}

func TestEstimateNAT(t *testing.T) {
	mapped := netip.MustParseAddrPort("198.51.100.4:40000")
	local := map[netip.Addr]bool{netip.MustParseAddr("192.168.1.2"): true}
	obs := func(s ...string) []netip.AddrPort {
		var out []netip.AddrPort
		for _, x := range s {
			out = append(out, netip.MustParseAddrPort(x))
		}
		return out
	}
	cases := []struct {
		name string
		got  NATType
		want NATType
	}{
		{"no mapping", estimateNAT(netip.AddrPort{}, local, nil), NATUnknown},
		{"public on interface", estimateNAT(mapped, map[netip.Addr]bool{mapped.Addr(): true}, nil), NATNone},
		{"no peers", estimateNAT(mapped, local, nil), NATUnknown},
		{"same port", estimateNAT(mapped, local, obs("198.51.100.4:40000")), NATEasy},
		{"other port", estimateNAT(mapped, local, obs("198.51.100.4:40000", "198.51.100.4:51234")), NATHard},
		{"lan view ignored", estimateNAT(mapped, local, obs("192.168.1.2:41641")), NATUnknown},
		{"other address ignored", estimateNAT(mapped, local, obs("203.0.113.1:1")), NATUnknown},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s: %s, want %s", c.name, c.got, c.want)
		}
	}
}

type fakeCaptive struct {
	status int
	loc    string
	err    error
	asked  []netip.Addr
}

func (f *fakeCaptive) get(_ context.Context, gw netip.Addr) (int, string, error) {
	f.asked = append(f.asked, gw)
	return f.status, f.loc, f.err
}

func TestDetectCaptivePortal(t *testing.T) {
	gw := netip.MustParseAddr("192.168.4.1")
	now := time.Now()
	cases := []struct {
		name   string
		f      fakeCaptive
		detect bool
	}{
		{"511", fakeCaptive{status: http.StatusNetworkAuthenticationRequired}, true},
		{"redirect elsewhere", fakeCaptive{status: http.StatusFound, loc: "http://login.hotel.example/portal?x=1"}, true},
		{"redirect to other ip", fakeCaptive{status: http.StatusFound, loc: "http://10.1.1.1/login"}, true},
		{"router login page", fakeCaptive{status: http.StatusFound, loc: "/login.html"}, false},
		{"router absolute self", fakeCaptive{status: http.StatusMovedPermanently, loc: "http://192.168.4.1/admin"}, false},
		{"plain page", fakeCaptive{status: http.StatusOK}, false},
		{"no answer", fakeCaptive{err: errors.New("timeout")}, false},
	}
	for _, c := range cases {
		st := detectCaptivePortal(context.Background(), &c.f, []netip.Addr{gw}, now)
		if st.Detected != c.detect {
			t.Errorf("%s: detected=%v (%s)", c.name, st.Detected, st.Reason)
		}
	}
	// Public next hops are never asked.
	f := &fakeCaptive{status: http.StatusNetworkAuthenticationRequired}
	if st := detectCaptivePortal(context.Background(), f, []netip.Addr{netip.MustParseAddr("8.8.8.8")}, now); st.Detected || len(f.asked) != 0 {
		t.Fatal("a public gateway was contacted")
	}
}

// The real prober talks plain HTTP to the gateway and does not follow the
// redirect. The test server listens on loopback only.
func TestHTTPCaptiveProberDoesNotFollowRedirects(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	followed := make(chan struct{}, 1)
	srv := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/portal" {
			followed <- struct{}{}
		}
		if r.Header.Get("User-Agent") != captiveUserAgent {
			w.WriteHeader(http.StatusTeapot)
			return
		}
		http.Redirect(w, r, "http://login.example/portal", http.StatusFound)
	})}
	go func() { _ = srv.Serve(l) }()
	defer srv.Close()
	p := httpCaptiveProber{port: uint16(l.Addr().(*net.TCPAddr).Port)}
	code, loc, err := p.get(context.Background(), netip.MustParseAddr("127.0.0.1"))
	if err != nil || code != http.StatusFound || loc != "http://login.example/portal" {
		t.Fatalf("get = %d %q %v", code, loc, err)
	}
	select {
	case <-followed:
		t.Fatal("redirect followed")
	default:
	}
}

func TestMagicDNSViewHidesUnconnectedDevices(t *testing.T) {
	doc := &trust.Document{NetworkID: "n", Version: 3, DNSDomain: "ag.internal",
		IPv4Prefix: netip.MustParsePrefix("100.80.0.0/16"),
		Devices: []trust.Device{
			{Name: "laptop", IPv4: netip.MustParseAddr("100.80.0.1"), WireGuardKey: trust.Key{1}},
			{Name: "nas", IPv4: netip.MustParseAddr("100.80.0.2"), WireGuardKey: trust.Key{2}},
			{Name: "telefon", IPv4: netip.MustParseAddr("100.80.0.3"), WireGuardKey: trust.Key{3}},
		}}
	self := doc.Devices[0]
	want := map[trust.Key]wgconf.Peer{{2}: {}}
	e := &Engine{}
	view := e.magicDNSView(doc, self, want)
	e.dnsView = view
	q := func(name string) dnsmessage.RCode {
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 1, RecursionDesired: true})
		_ = b.StartQuestions()
		_ = b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
		msg, _ := b.Finish()
		var p dnsmessage.Parser
		h, err := p.Start(magicdns.Answer(e.dnsDocument(doc), msg))
		if err != nil {
			t.Fatal(err)
		}
		return h.RCode
	}
	if q("nas.ag.internal.") != dnsmessage.RCodeSuccess || q("laptop.ag.internal.") != dnsmessage.RCodeSuccess {
		t.Fatal("connected devices must resolve")
	}
	if q("telefon.ag.internal.") != dnsmessage.RCodeNameError {
		t.Fatal("unconnected device resolved")
	}
	// The original document is untouched, and the opt-out answers all.
	if len(doc.Devices) != 3 {
		t.Fatal("document modified")
	}
	e.cfg.MagicDNSAllDevices = true
	e.dnsView = e.magicDNSView(doc, self, want)
	if q("telefon.ag.internal.") != dnsmessage.RCodeSuccess {
		t.Fatal("opt-out ignored")
	}
	// A newer document than the view falls back to the full document.
	e.cfg.MagicDNSAllDevices = false
	e.dnsView = e.magicDNSView(doc, self, want)
	newer := *doc
	newer.Version = 4
	if e.dnsDocument(&newer) != &newer {
		t.Fatal("stale view used")
	}
}

func TestPlainBindLoopback(t *testing.T) {
	a := newPlainBind(netip.MustParseAddr("127.0.0.1"), netip.Addr{})
	b := newPlainBind(netip.MustParseAddr("127.0.0.1"), netip.Addr{})
	fa, pa, err := a.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	_, pb, err := b.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if pa == 0 || pb == 0 || a.BatchSize() != 1 {
		t.Fatal("ports not assigned")
	}
	if _, _, err := a.Open(0); err == nil {
		t.Fatal("double open")
	}
	ep, err := b.ParseEndpoint(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), pa).String())
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Send([][]byte{[]byte("merhaba")}, ep); err != nil {
		t.Fatal(err)
	}
	bufs, sizes, eps := [][]byte{make([]byte, 64)}, []int{0}, make([]conn.Endpoint, 1)
	n, err := fa[0](bufs, sizes, eps)
	if err != nil || n != 1 || string(bufs[0][:sizes[0]]) != "merhaba" {
		t.Fatalf("receive: %d %v %q", n, err, bufs[0][:sizes[0]])
	}
	if err := a.SetMark(0x4f53); err != nil {
		t.Fatal(err)
	}
}
