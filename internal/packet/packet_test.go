package packet

import (
	"bytes"
	"net/netip"
	"testing"

	"golang.zx2c4.com/wireguard/tun/tuntest"
)

var (
	a4 = netip.MustParseAddr("100.80.0.1")
	b4 = netip.MustParseAddr("100.80.0.2")
)

func TestBuildAndParseUDP4(t *testing.T) {
	pkt, err := BuildUDP4(a4, b4, 40000, 4040, []byte("merhaba"))
	if err != nil {
		t.Fatal(err)
	}
	if checksum(pkt[:ipv4HeaderMin], 0) != 0xffff {
		t.Fatal("IPv4 header checksum does not verify")
	}
	info, err := Parse(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if info.Src != a4 || info.Dst != b4 || info.Proto != ProtoUDP || info.SrcPort != 40000 || info.DstPort != 4040 {
		t.Fatalf("unexpected info: %+v", info)
	}
	if !bytes.Equal(info.Payload, []byte("merhaba")) {
		t.Fatalf("payload = %q", info.Payload)
	}
}

func TestParseICMPFromWireguardHelper(t *testing.T) {
	info, err := Parse(tuntest.Ping(b4, a4))
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsICMP() || info.Src != a4 || info.Dst != b4 {
		t.Fatalf("unexpected info: %+v", info)
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	good, _ := BuildUDP4(a4, b4, 1, 2, []byte("x"))
	cases := map[string][]byte{
		"empty":           nil,
		"bad version":     {0x55},
		"short ipv4":      good[:10],
		"total too large": append([]byte{0x45, 0, 0xff, 0xff}, good[4:]...),
		"short udp":       good[:ipv4HeaderMin+4],
		"short ipv6":      append([]byte{0x60}, make([]byte, 20)...),
	}
	for name, pkt := range cases {
		if _, err := Parse(pkt); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestParseIPv6WithExtensionHeader(t *testing.T) {
	src := netip.MustParseAddr("fd00::1").As16()
	dst := netip.MustParseAddr("fd00::2").As16()
	udp := []byte{0x9c, 0x40, 0x00, 0x16, 0x00, 0x08, 0x00, 0x00} // 40000 -> 22, empty payload
	hop := []byte{ProtoUDP, 0, 0, 0, 0, 0, 0, 0}                  // hop-by-hop, 8 bytes
	body := append(hop, udp...)
	pkt := make([]byte, ipv6HeaderLen)
	pkt[0] = 0x60
	pkt[4], pkt[5] = 0, byte(len(body))
	pkt[6] = 0 // next header: hop-by-hop
	copy(pkt[8:24], src[:])
	copy(pkt[24:40], dst[:])
	pkt = append(pkt, body...)
	info, err := Parse(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if info.Proto != ProtoUDP || info.DstPort != 22 {
		t.Fatalf("unexpected info: %+v", info)
	}
}

func FuzzParse(f *testing.F) {
	good, _ := BuildUDP4(a4, b4, 1, 2, []byte("x"))
	f.Add(good)
	f.Add(tuntest.Ping(b4, a4))
	f.Fuzz(func(t *testing.T, pkt []byte) {
		info, err := Parse(pkt)
		if err == nil && info.Proto == ProtoUDP && !info.Fragment && len(info.Payload) > len(pkt) {
			t.Fatal("payload longer than packet")
		}
	})
}

func TestParseFragmentFields(t *testing.T) {
	pkt, _ := BuildUDP4(a4, b4, 40000, 53, make([]byte, 32))
	// First fragment: more fragments set, UDP length covering more than
	// this fragment.
	first := append([]byte(nil), pkt...)
	first[4], first[5] = 0x12, 0x34
	first[6], first[7] = 0x20, 0x00
	first[24], first[25] = 0x05, 0xdc // UDP length 1500
	info, err := Parse(first)
	if err != nil {
		t.Fatalf("first fragment: %v", err)
	}
	if !info.FirstFragment() || info.Fragment || info.FragID != 0x1234 || info.DstPort != 53 || info.Payload != nil {
		t.Fatalf("first fragment info %+v", info)
	}
	later := append([]byte(nil), pkt...)
	later[4], later[5] = 0x12, 0x34
	later[6], later[7] = 0x00, 0x04 // offset 4, last fragment
	info, err = Parse(later)
	if err != nil || !info.Fragment || info.MoreFragments || info.FragID != 0x1234 || info.DstPort != 0 {
		t.Fatalf("later fragment %+v %v", info, err)
	}
	if whole, _ := Parse(pkt); whole.FragID != 0 || whole.MoreFragments || whole.FirstFragment() {
		t.Fatalf("unfragmented packet %+v", whole)
	}
}

func TestParseEmbedded(t *testing.T) {
	orig, _ := BuildUDP4(a4, b4, 40000, 4040, make([]byte, 100))
	// Quotes are cut short: header plus eight bytes is enough.
	info, err := ParseEmbedded(orig[:28])
	if err != nil {
		t.Fatal(err)
	}
	if info.Src != a4 || info.Dst != b4 || info.Proto != ProtoUDP || info.SrcPort != 40000 || info.DstPort != 4040 {
		t.Fatalf("embedded %+v", info)
	}
	for name, b := range map[string][]byte{
		"empty":         nil,
		"short header":  orig[:12],
		"no ports":      orig[:24],
		"bad version":   append([]byte{0x75}, orig[1:28]...),
		"short ipv6":    append([]byte{0x60}, make([]byte, 30)...),
		"bad ihl":       append([]byte{0x41}, orig[1:28]...),
		"short icmpv6":  append(append([]byte{0x60, 0, 0, 0, 0, 0, 58, 64}, make([]byte, 32)...), 128, 0),
		"ipv6 ext loop": ipv6Ext(10),
	} {
		if _, err := ParseEmbedded(b); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	// A non-first fragment quoted: no ports, marked as fragment.
	frag := append([]byte(nil), orig[:28]...)
	frag[7] = 0x10
	if info, err := ParseEmbedded(frag); err != nil || !info.Fragment {
		t.Fatalf("quoted fragment %+v %v", info, err)
	}
}

// ipv6Ext builds an IPv6 header followed by n hop-by-hop headers.
func ipv6Ext(n int) []byte {
	b := make([]byte, 40)
	b[0], b[6] = 0x60, 0
	for i := 0; i < n; i++ {
		b = append(b, 0, 0, 0, 0, 0, 0, 0, 0)
	}
	return b
}

func TestICMPErrorCarriesQuote(t *testing.T) {
	orig, _ := BuildUDP4(a4, b4, 40000, 4040, nil)
	msg := append([]byte{3, 4, 0, 0, 0, 0, 0x05, 0xdc}, orig...)
	pkt, _ := BuildUDP4(b4, a4, 1, 1, nil)
	pkt = append(pkt[:ipv4HeaderMin], msg...)
	pkt[9] = ProtoICMPv4
	pkt[2], pkt[3] = 0, byte(len(pkt))
	info, err := Parse(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsICMPError() || info.ICMPCode != 4 || len(info.Embedded) != len(orig) {
		t.Fatalf("ICMP error %+v", info)
	}
	if _, err := Parse(pkt[:ipv4HeaderMin+6]); err == nil {
		t.Fatal("short ICMP error accepted")
	}
}

func FuzzParseEmbedded(f *testing.F) {
	good, _ := BuildUDP4(a4, b4, 1, 2, []byte("x"))
	f.Add(good[:28])
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = ParseEmbedded(b)
	})
}
