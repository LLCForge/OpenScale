package control

import (
	"net/netip"
	"testing"
)

func TestWhoAmIRoundTrip(t *testing.T) {
	var nonce [WhoAmINonce]byte
	nonce[0], nonce[15] = 1, 2
	req := NewWhoAmIRequest(nonce)
	if len(req) != WhoAmILen || !IsWhoAmI(req, WhoAmIRequest) || ValidWireGuardMessage(req) {
		t.Fatalf("bad request %q", req)
	}
	for _, s := range []string{"198.51.100.4:51820", "[2001:db8::5]:443"} {
		ap := netip.MustParseAddrPort(s)
		rep := WhoAmIAnswer(req, ap)
		if len(rep) != len(req) {
			t.Fatal("reply larger than the request")
		}
		got, ok := ParseWhoAmIReply(rep, nonce)
		if !ok || got != ap {
			t.Fatalf("%s: got %v %v", s, got, ok)
		}
	}
	if _, ok := ParseWhoAmIReply(req, nonce); ok {
		t.Fatal("request parsed as reply")
	}
	if _, ok := ParseWhoAmIReply(WhoAmIAnswer(req, netip.AddrPortFrom(netip.IPv4Unspecified(), 1)), nonce); ok {
		t.Fatal("unspecified address accepted")
	}
}
