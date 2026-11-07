package packet

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
)

// buildTCP returns an IPv4 or IPv6 TCP packet with a valid checksum. ext,
// for IPv6, is inserted as a hop-by-hop options header.
func buildTCP(t *testing.T, src, dst netip.Addr, flags uint8, opts []byte, ext bool) []byte {
	t.Helper()
	if len(opts)%4 != 0 {
		t.Fatal("options must be padded to 4 bytes")
	}
	tcp := make([]byte, tcpHeaderMin+len(opts)+3) // 3 payload bytes
	binary.BigEndian.PutUint16(tcp[0:2], 40000)
	binary.BigEndian.PutUint16(tcp[2:4], 443)
	tcp[12] = byte((tcpHeaderMin+len(opts))/4) << 4
	tcp[13] = flags
	copy(tcp[tcpHeaderMin:], opts)
	copy(tcp[tcpHeaderMin+len(opts):], "abc")

	var pkt []byte
	if src.Is4() {
		pkt = make([]byte, ipv4HeaderMin+len(tcp))
		pkt[0] = 0x45
		binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
		pkt[8], pkt[9] = 64, ProtoTCP
		s, d := src.As4(), dst.As4()
		copy(pkt[12:16], s[:])
		copy(pkt[16:20], d[:])
		copy(pkt[ipv4HeaderMin:], tcp)
	} else {
		var hbh []byte
		next := ProtoTCP
		if ext {
			hbh = []byte{ProtoTCP, 0, 1, 4, 0, 0, 0, 0} // PadN
			next = 0
		}
		pkt = make([]byte, ipv6HeaderLen+len(hbh)+len(tcp))
		pkt[0] = 0x60
		binary.BigEndian.PutUint16(pkt[4:6], uint16(len(hbh)+len(tcp)))
		pkt[6], pkt[7] = next, 64
		s, d := src.As16(), dst.As16()
		copy(pkt[8:24], s[:])
		copy(pkt[24:40], d[:])
		copy(pkt[ipv6HeaderLen:], hbh)
		copy(pkt[ipv6HeaderLen+len(hbh):], tcp)
	}
	seg := pkt[len(pkt)-len(tcp):]
	binary.BigEndian.PutUint16(seg[16:18], ^tcpSum(src, dst, seg))
	return pkt
}

// tcpSum is the one's complement sum of the pseudo header and segment.
func tcpSum(src, dst netip.Addr, seg []byte) uint16 {
	var pseudo []byte
	pseudo = append(pseudo, src.AsSlice()...)
	pseudo = append(pseudo, dst.AsSlice()...)
	if src.Is4() {
		pseudo = append(pseudo, 0, ProtoTCP, byte(len(seg)>>8), byte(len(seg)))
	} else {
		pseudo = append(pseudo, 0, 0, byte(len(seg)>>8), byte(len(seg)), 0, 0, 0, ProtoTCP)
	}
	return checksum(seg, uint32(checksum(pseudo, 0)))
}

func segmentOf(pkt []byte) []byte {
	seg := pkt[ipv4HeaderMin:]
	if pkt[0]>>4 == 6 {
		seg = pkt[ipv6HeaderLen:]
		if pkt[6] == 0 {
			seg = seg[8:]
		}
	}
	return seg
}

func checksumOK(src, dst netip.Addr, pkt []byte) bool {
	return tcpSum(src, dst, segmentOf(pkt)) == 0xffff
}

// mssOf returns the MSS option value at byte offset off of the options.
func mssOf(pkt []byte, off int) uint16 {
	seg := segmentOf(pkt)
	return binary.BigEndian.Uint16(seg[tcpHeaderMin+off+2:])
}

var (
	v4a, v4b = netip.MustParseAddr("100.80.0.1"), netip.MustParseAddr("192.168.1.20")
	v6a, v6b = netip.MustParseAddr("fd7a:115c:a1e0::1"), netip.MustParseAddr("2001:db8::20")
)

func mssOpt(v uint16) []byte { return []byte{tcpOptMSS, tcpOptMSSLen, byte(v >> 8), byte(v)} }

func TestMSSLimit(t *testing.T) {
	for _, c := range []struct {
		mtu  int
		v6   bool
		want int
	}{{1280, false, 1240}, {1280, true, 1220}, {1420, false, 1380}, {1420, true, 1360}, {40, false, 0}, {60, true, 0}, {0, false, 0}} {
		if got := MSSLimit(c.mtu, c.v6); got != c.want {
			t.Errorf("MSSLimit(%d, %v) = %d, want %d", c.mtu, c.v6, got, c.want)
		}
	}
}

func TestClampMSS(t *testing.T) {
	sackPerm := []byte{4, 2}
	wscale := []byte{3, 3, 7}
	cases := []struct {
		name     string
		src, dst netip.Addr
		flags    uint8
		opts     []byte
		ext      bool
		mssAt    int
		want     uint16
		changed  bool
	}{
		{"v4 SYN", v4a, v4b, TCPSyn, mssOpt(1460), false, 0, 1240, true},
		{"v4 SYN-ACK", v4b, v4a, TCPSyn | TCPAck, mssOpt(1460), false, 0, 1240, true},
		{"v6 SYN", v6a, v6b, TCPSyn, mssOpt(1440), false, 0, 1220, true},
		{"v6 SYN after hop-by-hop", v6a, v6b, TCPSyn, mssOpt(1440), true, 0, 1220, true},
		{"v4 small MSS kept", v4a, v4b, TCPSyn, mssOpt(536), false, 0, 536, false},
		{"v4 equal MSS kept", v4a, v4b, TCPSyn, mssOpt(1240), false, 0, 1240, false},
		{"v4 ACK untouched", v4a, v4b, TCPAck, mssOpt(1460), false, 0, 1460, false},
		// NOP, then MSS at an odd offset, then window scale and SACK.
		{"v4 odd offset", v4a, v4b, TCPSyn, append(append(append([]byte{tcpOptNOP}, mssOpt(1460)...), wscale...), append(sackPerm, tcpOptNOP, tcpOptEnd)...), false, 1, 1240, true},
		{"v6 odd offset", v6a, v6b, TCPSyn, append(append(append([]byte{tcpOptNOP}, mssOpt(65535)...), wscale...), append(sackPerm, tcpOptNOP, tcpOptEnd)...), false, 1, 1220, true},
		{"v4 MSS after SACK", v4a, v4b, TCPSyn, append(append([]byte{}, sackPerm...), append(mssOpt(9000), tcpOptNOP, tcpOptNOP)...), false, 2, 1240, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pkt := buildTCP(t, c.src, c.dst, c.flags, c.opts, c.ext)
			if !checksumOK(c.src, c.dst, pkt) {
				t.Fatal("test packet has a bad checksum")
			}
			before := append([]byte(nil), pkt...)
			if got := ClampMSS(pkt, 1280); got != c.changed {
				t.Fatalf("ClampMSS = %v, want %v", got, c.changed)
			}
			if got := mssOf(pkt, c.mssAt); got != c.want {
				t.Fatalf("MSS %d, want %d", got, c.want)
			}
			if !checksumOK(c.src, c.dst, pkt) {
				t.Fatal("checksum invalid after clamping")
			}
			if !c.changed && !bytes.Equal(pkt, before) {
				t.Fatal("packet changed although nothing was clamped")
			}
			if _, err := Parse(pkt); err != nil {
				t.Fatalf("clamped packet does not parse: %v", err)
			}
		})
	}
}

func TestClampMSSLeavesOddPacketsAlone(t *testing.T) {
	syn := func() []byte { return buildTCP(t, v4a, v4b, TCPSyn, mssOpt(1460), false) }
	cases := map[string]func([]byte) []byte{
		"fragment offset": func(p []byte) []byte { p[7] = 1; return p },
		"more fragments":  func(p []byte) []byte { p[6] |= 0x20; return p },
		"truncated":       func(p []byte) []byte { return p[:30] },
		"bad data offset": func(p []byte) []byte { p[ipv4HeaderMin+12] = 0xf0; return p },
		"bad option len":  func(p []byte) []byte { p[ipv4HeaderMin+tcpHeaderMin+1] = 9; return p },
		"zero option len": func(p []byte) []byte { p[ipv4HeaderMin+tcpHeaderMin+1] = 0; return p },
		"short MSS len": func(p []byte) []byte {
			p[ipv4HeaderMin+tcpHeaderMin+1] = 2 // kind 2 with length 2 is skipped
			return p
		},
		"udp":         func(p []byte) []byte { p[9] = ProtoUDP; return p },
		"bad version": func(p []byte) []byte { p[0] = 0x55; return p },
		"empty":       func([]byte) []byte { return nil },
	}
	for name, mutate := range cases {
		pkt := mutate(syn())
		before := append([]byte(nil), pkt...)
		if ClampMSS(pkt, 1280) {
			t.Errorf("%s: clamped", name)
		}
		if !bytes.Equal(pkt, before) {
			t.Errorf("%s: packet modified", name)
		}
	}
	// IPv6 fragment header: left alone.
	p := buildTCP(t, v6a, v6b, TCPSyn, mssOpt(1440), true)
	p[6] = 44
	if ClampMSS(p, 1280) {
		t.Error("IPv6 fragment clamped")
	}
	// An MTU too small to compute a limit changes nothing.
	if ClampMSS(syn(), 40) {
		t.Error("clamped with a nonsensical MTU")
	}
}

func FuzzClampMSS(f *testing.F) {
	f.Add([]byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8}, 1280)
	f.Fuzz(func(t *testing.T, pkt []byte, mtu int) {
		cp := append([]byte(nil), pkt...)
		changed := ClampMSS(cp, mtu)
		if !changed && !bytes.Equal(cp, pkt) {
			t.Fatal("unchanged report but bytes differ")
		}
		if len(cp) != len(pkt) {
			t.Fatal("length changed")
		}
	})
}
