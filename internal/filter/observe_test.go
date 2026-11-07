package filter

import (
	"net/netip"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/packet"
)

func TestDenyLogReasons(t *testing.T) {
	m := filterFor("masaustu")
	stranger := netip.MustParseAddr("100.80.0.99")
	m.Inbound(tcp(laptopIP, masaustuIP, 50001, 22, packet.TCPSyn))
	m.Inbound(tcp(laptopIP, masaustuIP, 50002, 22, packet.TCPSyn))
	m.Inbound(tcp(stranger, masaustuIP, 50003, 80, packet.TCPSyn))
	m.Inbound(tcp(laptopIP, telefonIP, 50004, 80, packet.TCPSyn))
	m.Outbound(tcp(masaustuIP, laptopIP, 40000, 3389, packet.TCPSyn))
	// Multicast chatter is not logged.
	m.Outbound(tcp(masaustuIP, netip.MustParseAddr("224.0.0.251"), 5353, 5353, 0))
	m.Inbound([]byte{1, 2, 3})

	want := map[string]string{"in:laptop:22": DenyRules, "in::80": DenyUnknownPeer, "out:laptop:3389": DenyRules}
	got := map[string]string{}
	for _, d := range m.DenyLog().List() {
		dir := "out"
		if d.Inbound {
			dir = "in"
		}
		key := dir + ":" + d.Peer + ":" + itoa(d.Port)
		if d.Reason == DenyNotForDevice {
			continue
		}
		got[key] = d.Reason
		if key == "in:laptop:22" && d.Count != 2 {
			t.Fatalf("count = %d", d.Count)
		}
		if d.Document == nil || d.Self != "masaustu" {
			t.Fatalf("missing context: %+v", d)
		}
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("%s = %q, want %q (all %v)", k, got[k], v, got)
		}
	}
	tot := m.DenyLog().Totals()
	if tot[DenyMalformed] != 1 || tot[DenyRules] != 3 || tot[DenyNotForDevice] != 1 {
		t.Fatalf("totals = %v", tot)
	}
	st := m.Stats()
	if st.DeniedIn != 5 || st.DeniedOut != 2 {
		t.Fatalf("stats = %+v", st)
	}

	m.SetShields(true)
	m.Inbound(tcp(laptopIP, masaustuIP, 50010, 3389, packet.TCPSyn))
	found := false
	for _, d := range m.DenyLog().List() {
		if d.Port == 3389 && d.Inbound {
			found = d.Reason == DenyShields && d.Shields
		}
	}
	if !found {
		t.Fatalf("shields refusal not logged: %+v", m.DenyLog().List())
	}
}

func itoa(p uint16) string {
	if p == 0 {
		return "0"
	}
	var b []byte
	for p > 0 {
		b = append([]byte{byte('0' + p%10)}, b...)
		p /= 10
	}
	return string(b)
}

func TestDenyLogBounded(t *testing.T) {
	m := filterFor("masaustu")
	for port := 1; port <= MaxDenials+50; port++ {
		m.Inbound(tcp(laptopIP, masaustuIP, 50000, uint16(port), packet.TCPSyn))
	}
	if n := len(m.DenyLog().List()); n != MaxDenials {
		t.Fatalf("entries = %d", n)
	}
}

func TestCapture(t *testing.T) {
	m := filterFor("masaustu")
	c, err := m.StartCapture(CaptureOptions{Addrs: []netip.Addr{laptopIP}, Proto: packet.ProtoTCP, Port: 3389, Denied: true, Snap: 20})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.StartCapture(CaptureOptions{}); err != ErrCaptureBusy {
		t.Fatalf("second capture: %v", err)
	}
	m.Inbound(tcp(laptopIP, masaustuIP, 50000, 3389, packet.TCPSyn))  // allowed, matches
	m.Inbound(tcp(laptopIP, masaustuIP, 50001, 22, packet.TCPSyn))    // other port
	m.Inbound(tcp(telefonIP, masaustuIP, 50002, 3389, packet.TCPSyn)) // denied, other host
	m.Outbound(tcp(masaustuIP, laptopIP, 40000, 3389, packet.TCPSyn)) // denied, matches
	var got []CapturedPacket
	for len(got) < 2 {
		select {
		case p := <-c.Packets():
			got = append(got, p)
		case <-time.After(time.Second):
			t.Fatalf("captured %d", len(got))
		}
	}
	if !got[0].Allowed || !got[0].Inbound || len(got[0].Data) != 20 || got[0].Length != 40 {
		t.Fatalf("first = %+v", got[0])
	}
	if got[1].Allowed || got[1].Inbound {
		t.Fatalf("second = %+v", got[1])
	}
	select {
	case p := <-c.Packets():
		t.Fatalf("unexpected %+v", p)
	default:
	}
	c.Stop()
	if c2, err := m.StartCapture(CaptureOptions{}); err != nil {
		t.Fatal(err)
	} else {
		c2.Stop()
	}
}
