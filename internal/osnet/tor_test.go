package osnet

import (
	"net/netip"
	"testing"
)

// Socket tables in the kernel's format: 100.80.0.1:9040 listening,
// 127.0.0.1:9040 listening, 127.0.0.1:5353 UDP, one established socket.
const (
	testProcTCP = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 01005064:2350 00000000:0000 0A 00000000:00000000 00:00000000 00000000   107        0 1 1 0 100 0 0 10 0\n" +
		"   1: 0100007F:2350 00000000:0000 0A 00000000:00000000 00:00000000 00000000   107        0 2 1 0 100 0 0 10 0\n" +
		"   2: 0100007F:1F90 0100007F:D431 01 00000000:00000000 00:00000000 00000000     0        0 3 1 0 20 4 30 10 -1\n" +
		"garbage line\n"
	testProcUDP = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n" +
		"  10: 0100007F:14E9 00000000:0000 07 00000000:00000000 00:00000000 00000000   107        0 4 2 0 0\n"
	testProcTCP6 = "  sl  local_address                         remote_address                        st\n" +
		"   0: 00000000000000000000000000000000:2350 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 5\n"
)

func TestParseProcNet(t *testing.T) {
	s := parseProcNet([]byte(testProcTCP))
	if len(s) != 3 {
		t.Fatalf("sockets %+v", s)
	}
	if s[0].local != netip.MustParseAddrPort("100.80.0.1:9040") || s[0].state != procTCPListen {
		t.Fatalf("first %+v", s[0])
	}
	if s[2].local != netip.MustParseAddrPort("127.0.0.1:8080") {
		t.Fatalf("third %+v", s[2])
	}
	s6 := parseProcNet([]byte(testProcTCP6))
	if len(s6) != 1 || s6[0].local != netip.MustParseAddrPort("[::]:9040") {
		t.Fatalf("tcp6 %+v", s6)
	}
}

func TestTorHealthFrom(t *testing.T) {
	r := TorRoute{Self4: netip.MustParseAddr("100.80.0.1"), TransPort: 9040, DNSPort: 5353}
	tcp, udp := parseProcNet([]byte(testProcTCP)), parseProcNet([]byte(testProcUDP))
	if h := torHealthFrom(r, tcp, udp); !h.Up() || h.TransLoopbackOnly {
		t.Fatalf("health %+v", h)
	}
	// Only the loopback listener: redirected connections cannot reach it.
	h := torHealthFrom(r, tcp[1:], udp)
	if h.Trans || !h.TransLoopbackOnly || h.Up() {
		t.Fatalf("loopback-only health %+v", h)
	}
	// A wildcard IPv6 listener covers the OpenScale address.
	if h := torHealthFrom(r, parseProcNet([]byte(testProcTCP6)), udp); !h.Trans {
		t.Fatalf("wildcard health %+v", h)
	}
	// Another port, or no DNS socket: down.
	other := r
	other.TransPort, other.DNSPort = 9041, 5354
	if h := torHealthFrom(other, tcp, udp); h.Trans || h.DNS {
		t.Fatalf("wrong ports %+v", h)
	}
	if h := torHealthFrom(r, tcp, nil); h.DNS || h.Up() {
		t.Fatalf("no DNS %+v", h)
	}
	// Own address unknown: a non-loopback listener counts.
	unknown := r
	unknown.Self4 = netip.Addr{}
	if h := torHealthFrom(unknown, tcp, udp); !h.Trans {
		t.Fatalf("unknown self %+v", h)
	}
}
