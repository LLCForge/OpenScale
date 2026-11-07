package osnet

import (
	"net/netip"
	"testing"
)

func TestParseResolvers(t *testing.T) {
	got := parseResolvectlDNS("Global:\nLink 2 (eth0): 192.168.1.1 fe80::1%2\nLink 5 (OpenScale): 100.80.0.7#openscale.internal\n")
	want := []SystemResolver{
		{Link: "eth0", Addr: netip.MustParseAddr("192.168.1.1")},
		{Link: "eth0", Addr: netip.MustParseAddr("fe80::1")},
		{Link: "OpenScale", Addr: netip.MustParseAddr("100.80.0.7")},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %+v, want %+v", got, want)
		}
	}
	rc := parseResolvConf("# generated\nnameserver 127.0.0.53\noptions edns0\nnameserver fe80::1%eth0\nsearch lan\n")
	if len(rc) != 2 || rc[0].Addr != netip.MustParseAddr("127.0.0.53") || rc[1].Addr != netip.MustParseAddr("fe80::1") {
		t.Fatalf("resolv.conf %+v", rc)
	}
}
