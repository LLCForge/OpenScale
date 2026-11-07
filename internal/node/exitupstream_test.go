package node

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// TestExitDNSViaUpstream: while an upstream exit is in use, members'
// queries go to the provider resolver from the tunnel address; a wanted
// upstream without a tunnel drops them; otherwise ExitDNSUpstream applies.
func TestExitDNSViaUpstream(t *testing.T) {
	// The "provider resolver" on loopback records the source address.
	srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	var mu sync.Mutex
	var sources []netip.Addr
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := srv.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			mu.Lock()
			sources = append(sources, from.Addr().Unmap())
			mu.Unlock()
			if resp := answerFor(append([]byte(nil), buf[:n]...), 1, 30); resp != nil {
				_, _ = srv.WriteToUDPAddrPort(resp, from)
			}
		}
	}()
	source := netip.MustParseAddr("127.0.0.1")

	// The forwarder the via path builds, pointed at the test port.
	f := newDNSForwarder(dnsUpstream{kind: upstreamUDP, addr: srv.LocalAddr().String(), local: source}, nil)
	resp, err := f.forward(context.Background(), dnsQuery(t, 7, "uye.example.", dnsmessage.TypeA, 0))
	if err != nil {
		t.Fatal(err)
	}
	if m := unpack(t, resp); m.ID != 7 || len(m.Answers) != 1 {
		t.Fatalf("answer %+v", m)
	}
	mu.Lock()
	got := append([]netip.Addr(nil), sources...)
	mu.Unlock()
	if len(got) != 1 || got[0] != source {
		t.Fatalf("resolver saw queries from %v, want %v", got, source)
	}

	var via struct {
		server netip.AddrPort
		source netip.Addr
		ok     bool
	}
	e := &Engine{cfg: Config{
		ExitDNSUpstream: "192.0.2.53",
		ExitDNSVia:      func() (netip.AddrPort, netip.Addr, bool) { return via.server, via.source, via.ok },
	}}

	// No upstream: the owner's ExitDNSUpstream.
	fwd, err := e.exitDNSForwarder()
	if err != nil || fwd.up.addr != "192.0.2.53:53" || fwd.up.local.IsValid() {
		t.Fatalf("normal forwarder %+v %v", fwd, err)
	}
	// Upstream in use: the provider resolver from the tunnel address.
	via.server, via.source, via.ok = netip.MustParseAddrPort("10.64.0.1:53"), netip.MustParseAddr("10.68.12.34"), true
	fwd, err = e.exitDNSForwarder()
	if err != nil || fwd.up.addr != "10.64.0.1:53" || fwd.up.local != via.source || fwd.up.kind != upstreamUDP {
		t.Fatalf("upstream forwarder %+v %v", fwd, err)
	}
	if again, _ := e.exitDNSForwarder(); again != fwd {
		t.Fatal("upstream forwarder (and its cache) not shared")
	}
	// Tor exit: Tor's DNSPort on loopback, not port 53.
	via.server, via.source = netip.MustParseAddrPort("127.0.0.1:5353"), netip.MustParseAddr("127.0.0.1")
	fwd, err = e.exitDNSForwarder()
	if err != nil || fwd.up.addr != "127.0.0.1:5353" || fwd.up.local != via.source {
		t.Fatalf("tor forwarder %+v %v", fwd, err)
	}
	// Upstream wanted but no tunnel: dropped, never the normal resolver.
	via.server, via.source = netip.AddrPort{}, netip.Addr{}
	if _, err := e.exitDNSForwarder(); !errors.Is(err, errUpstreamDNSDown) {
		t.Fatalf("down upstream: %v", err)
	}
	// Mismatched families are refused.
	if _, err := viaForwarder(netip.MustParseAddrPort("10.64.0.1:53"), netip.MustParseAddr("fc00::1")); err == nil {
		t.Fatal("IPv4 resolver from an IPv6 source accepted")
	}
}
