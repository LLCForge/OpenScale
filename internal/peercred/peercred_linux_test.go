//go:build linux

package peercred

import (
	"net/netip"
	"testing"
)

const sampleTCP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:B5A8 0100007F:BABE 01 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 20 4 30 10 -1
   1: 0100007F:BABE 0100007F:B5A8 01 00000000:00000000 00:00000000 00000000     0        0 12346 1 0000000000000000 20 4 30 10 -1
`

func TestFindUID(t *testing.T) {
	client := netip.MustParseAddrPort("127.0.0.1:46504")
	server := netip.MustParseAddrPort("127.0.0.1:47806")
	if uid, ok := findUID([]byte(sampleTCP), client, server); !ok || uid != 1000 {
		t.Fatalf("client uid = %d, %t", uid, ok)
	}
	if uid, ok := findUID([]byte(sampleTCP), server, client); !ok || uid != 0 {
		t.Fatalf("server uid = %d, %t", uid, ok)
	}
	if _, ok := findUID([]byte(sampleTCP), netip.MustParseAddrPort("127.0.0.1:1"), server); ok {
		t.Fatal("unknown connection found")
	}
}

func TestParseProcAddrIPv6(t *testing.T) {
	// ::ffff:127.0.0.1 as /proc/net/tcp6 prints it.
	ap, ok := parseProcAddr("0000000000000000FFFF00000100007F:1F90")
	if !ok || ap != netip.MustParseAddrPort("127.0.0.1:8080") {
		t.Fatalf("parsed %v, %t", ap, ok)
	}
	if _, ok := parseProcAddr("zz:1"); ok {
		t.Fatal("bad hex accepted")
	}
}

func TestGroupPolicy(t *testing.T) {
	old := lookupGroup
	defer func() { lookupGroup = old }()
	lookupGroup = func(name string) (string, bool) { return "990", name == "openscale" }
	p := Policy{Group: "openscale"}
	if !p.allows(Identity{UID: 1001, Groups: []string{"100", "990"}}) {
		t.Fatal("operator group member denied")
	}
	if p.allows(Identity{UID: 1002, Groups: []string{"100"}}) {
		t.Fatal("non-member allowed")
	}
}
