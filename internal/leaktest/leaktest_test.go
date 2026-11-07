package leaktest

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/control"
)

type fakeProber struct {
	seen     map[netip.AddrPort]netip.AddrPort
	resolved []netip.Addr
	queryErr error
	queried  []string
}

func (f *fakeProber) WhoAmI(_ context.Context, a netip.AddrPort) (netip.AddrPort, error) {
	s, ok := f.seen[a]
	if !ok {
		return netip.AddrPort{}, errors.New("timeout")
	}
	return s, nil
}

func (f *fakeProber) Resolve(context.Context, string) ([]netip.Addr, error) { return f.resolved, nil }

func (f *fakeProber) Query(_ context.Context, server netip.Addr, name string) error {
	f.queried = append(f.queried, server.String()+" "+name)
	return f.queryErr
}

var (
	coord4  = netip.MustParseAddr("198.51.100.10")
	coord6  = netip.MustParseAddr("2001:db8:c::10")
	exitPub = netip.MustParseAddr("203.0.113.50")
	ownPub  = netip.MustParseAddr("192.0.2.77")
)

func baseInput() Input {
	return Input{
		ExitNode:            "vps",
		CoordinatorEndpoint: "coord.example.org:41820",
		Overlay4:            netip.MustParsePrefix("100.80.0.0/16"),
		Overlay6:            netip.MustParsePrefix("fd7a:1:2::/48"),
		ExitPublic:          exitPub,
		OwnPublic:           ownPub,
		ExitDNS:             netip.MustParseAddr("100.80.0.7"),
		TunnelLink:          "OpenScale",
		Resolvers:           []Resolver{{Addr: netip.MustParseAddr("127.0.0.53")}, {Link: "OpenScale", Addr: netip.MustParseAddr("100.80.0.7")}},
		DNSGuard:            true,
		IPv6Guard:           true,
		KillSwitch:          true,
		KillSwitchKnown:     true,
		LocalAddrs:          []netip.Addr{netip.MustParseAddr("192.168.1.20")},
	}
}

func level(t *testing.T, r Report, id string) Check {
	t.Helper()
	for _, c := range r.Checks {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("check %s missing: %+v", id, r.Checks)
	return Check{}
}

func TestLeakTestThroughExit(t *testing.T) {
	p := &fakeProber{resolved: []netip.Addr{coord4}, seen: map[netip.AddrPort]netip.AddrPort{
		netip.AddrPortFrom(coord4, 41820): netip.AddrPortFrom(exitPub, 40000),
	}}
	rep, err := Run(context.Background(), baseInput(), p, time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Leak || rep.SeenIPv4 != exitPub.String() {
		t.Fatalf("report %+v", rep)
	}
	for _, id := range []string{CheckIP, CheckIPv6, CheckDNS, CheckKillSwitch} {
		if c := level(t, rep, id); c.Level != LevelOK {
			t.Fatalf("%s: %+v", id, c)
		}
	}
	if c := level(t, rep, CheckWebRTC); c.Level != LevelInfo || !strings.Contains(c.Detail, "WebRtcIPHandling") {
		t.Fatalf("webrtc: %+v", c)
	}
	if len(p.queried) != 1 || p.queried[0] != "100.80.0.7 coord.example.org" {
		t.Fatalf("queried %v: only the exit node's resolver may be asked", p.queried)
	}
}

func TestLeakTestDetectsLeaks(t *testing.T) {
	in := baseInput()
	in.DNSGuard, in.IPv6Guard, in.KillSwitch = false, false, false
	in.Resolvers = append(in.Resolvers, Resolver{Link: "wlan0", Addr: netip.MustParseAddr("192.168.1.1")})
	in.LocalAddrs = append(in.LocalAddrs, netip.MustParseAddr("2001:db8:1::99"))
	p := &fakeProber{resolved: []netip.Addr{coord4, coord6}, seen: map[netip.AddrPort]netip.AddrPort{
		netip.AddrPortFrom(coord4, 41820): netip.AddrPortFrom(ownPub, 41641),
		netip.AddrPortFrom(coord6, 41820): netip.AddrPortFrom(netip.MustParseAddr("2001:db8:1::99"), 41641),
	}}
	rep, err := Run(context.Background(), in, p, time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Leak {
		t.Fatalf("no leak reported: %+v", rep)
	}
	for _, id := range []string{CheckIP, CheckIPv6, CheckDNS} {
		if c := level(t, rep, id); c.Level != LevelLeak {
			t.Fatalf("%s: %+v", id, c)
		}
	}
	if c := level(t, rep, CheckKillSwitch); c.Level != LevelWarn {
		t.Fatalf("killswitch: %+v", c)
	}
	if c := level(t, rep, CheckWebRTC); c.Level != LevelWarn || !strings.Contains(c.Detail, "2001:db8:1::99") {
		t.Fatalf("webrtc: %+v", c)
	}
}

func TestLeakTestEdgeCases(t *testing.T) {
	if _, err := Run(context.Background(), Input{}, &fakeProber{}, time.Now()); !errors.Is(err, ErrNoExitNode) {
		t.Fatalf("no exit node: %v", err)
	}
	in := baseInput()
	in.CoordinatorEndpoint = "bad"
	if _, err := Run(context.Background(), in, &fakeProber{}, time.Now()); err == nil {
		t.Fatal("bad endpoint accepted")
	}
	// Coordinator on the exit node: the request arrives from the overlay.
	in = baseInput()
	in.CoordinatorEndpoint = "198.51.100.10:41820"
	p := &fakeProber{seen: map[netip.AddrPort]netip.AddrPort{
		netip.AddrPortFrom(coord4, 41820): netip.MustParseAddrPort("100.80.0.3:5000"),
	}}
	rep, err := Run(context.Background(), in, p, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if c := level(t, rep, CheckIP); c.Level != LevelOK || len(p.queried) != 0 {
		t.Fatalf("overlay source: %+v queried %v", c, p.queried)
	}
	// Same NAT for the device and the exit node: cannot tell.
	in = baseInput()
	in.ExitPublic = ownPub
	p = &fakeProber{resolved: []netip.Addr{coord4}, seen: map[netip.AddrPort]netip.AddrPort{
		netip.AddrPortFrom(coord4, 41820): netip.AddrPortFrom(ownPub, 1),
	}}
	rep, _ = Run(context.Background(), in, p, time.Now())
	if c := level(t, rep, CheckIP); c.Level != LevelWarn || rep.Leak {
		t.Fatalf("shared NAT: %+v", c)
	}
	// An old coordinator without the echo.
	p = &fakeProber{resolved: []netip.Addr{coord4}}
	rep, _ = Run(context.Background(), baseInput(), p, time.Now())
	if c := level(t, rep, CheckIP); c.Level != LevelWarn {
		t.Fatalf("no answer: %+v", c)
	}
}

func TestDNSQueryEncoding(t *testing.T) {
	q, id, err := dnsQuery("coord.example.org.")
	if err != nil {
		t.Fatal(err)
	}
	if len(q) != 12+len("coord.example.org")+2+4 || q[12] != 5 || string(q[13:18]) != "coord" {
		t.Fatalf("query % x", q)
	}
	reply := append([]byte{}, q...)
	reply[2] |= 0x80
	if err := dnsAnswerOK(reply, id); err != nil {
		t.Fatal(err)
	}
	reply[3] = 2
	if dnsAnswerOK(reply, id) == nil {
		t.Fatal("SERVFAIL accepted")
	}
	if dnsAnswerOK(q, id) == nil {
		t.Fatal("query accepted as answer")
	}
	for _, bad := range []string{"", strings.Repeat("a", 64) + ".org", "a..b"} {
		if _, _, err := dnsQuery(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

// The real prober against a local echo on 127.0.0.1 only.
func TestNetProberWhoAmI(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if control.IsWhoAmI(buf[:n], control.WhoAmIRequest) {
				ap := from.(*net.UDPAddr).AddrPort()
				_, _ = pc.WriteTo(control.WhoAmIAnswer(buf[:n], ap), from)
			}
		}
	}()
	addr := pc.LocalAddr().(*net.UDPAddr).AddrPort()
	seen, err := NetProber{}.WhoAmI(context.Background(), addr)
	if err != nil {
		t.Fatal(err)
	}
	if seen.Addr().Unmap() != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("seen %v", seen)
	}
}
