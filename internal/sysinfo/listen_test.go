package sysinfo

import (
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func TestPickPortsSkipsLoopbackAndNormalizes(t *testing.T) {
	entries := []listenEntry{
		{addr: netip.MustParseAddr("127.0.0.1"), port: 47821},
		{addr: netip.MustParseAddr("::1"), port: 5432},
		{addr: netip.MustParseAddr("0.0.0.0"), port: 3389},
		{addr: netip.MustParseAddr("::"), port: 3389},
		{addr: netip.MustParseAddr("192.168.1.5"), port: 22},
		{addr: netip.MustParseAddr("100.80.0.2"), port: 0},
		{addr: netip.MustParseAddr("::ffff:127.0.0.1"), port: 8080},
	}
	got := pickPorts(entries)
	if !slices.Equal(got, []uint16{22, 3389}) {
		t.Fatalf("ports = %v", got)
	}
	many := make([]uint16, 0, 100)
	for p := uint16(100); p > 0; p-- {
		many = append(many, p)
	}
	if n := normalizePorts(many); len(n) != MaxListen || n[0] != 1 {
		t.Fatalf("cap/sort: %v", n)
	}
	if normalizePorts([]uint16{0, 0}) != nil {
		t.Fatal("zero ports must vanish")
	}
}

func TestEncodeShortensListeningPorts(t *testing.T) {
	in := Info{Version: "1.0.0", OS: "linux", Arch: "amd64", CPU: strings.Repeat("c", 60), OSName: strings.Repeat("o", 60),
		Model: strings.Repeat("m", 60), Virt: "kvm", Pkg: "deb", PublicIP: "203.0.113.9"}
	for p := 1; p <= MaxListen; p++ {
		in.Listen = append(in.Listen, uint16(60000+p))
	}
	data, err := in.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if len(data) > MaxEncoded {
		t.Fatalf("encoded %d bytes", len(data))
	}
	out, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Listen) > maxListenCompact && len(out.Listen) != MaxListen {
		t.Fatalf("listen kept %d", len(out.Listen))
	}
	// A hostile peer cannot smuggle a huge or unsorted list.
	evil := []byte(`{"v":"1","os":"linux","lp":[9,9,0,3,2,1]}`)
	got, err := Decode(evil)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.Listen, []uint16{1, 2, 3, 9}) {
		t.Fatalf("decoded = %v", got.Listen)
	}
}

func TestListeningPortsFindsOwnListener(t *testing.T) {
	// Listening on loopback must never be reported; the call must not fail.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	if slices.Contains(ListeningPorts(), port) {
		t.Fatal("a loopback-only listener was reported")
	}
}
