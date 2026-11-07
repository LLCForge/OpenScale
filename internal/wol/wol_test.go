package wol

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestParseMAC(t *testing.T) {
	want := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	for _, s := range []string{"00:11:22:33:44:55", "00-11-22-33-44-55", "0011.2233.4455", "001122334455", " 00:11:22:33:44:55 "} {
		got, err := ParseMAC(s)
		if err != nil {
			t.Fatalf("ParseMAC(%q): %v", s, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("ParseMAC(%q) = %v", s, got)
		}
	}
	for _, s := range []string{"", "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "01:00:5e:00:00:01", "00:11:22:33:44", "00:11:22:33:44:55:66:77", "zz:11:22:33:44:55", "00112233445", "0011223344556"} {
		if _, err := ParseMAC(s); !errors.Is(err, ErrInvalidMAC) {
			t.Fatalf("ParseMAC(%q) error = %v, want ErrInvalidMAC", s, err)
		}
	}
}

func TestParsePassword(t *testing.T) {
	p, err := ParsePassword("")
	if err != nil || p != nil {
		t.Fatalf("empty password = %v, %v", p, err)
	}
	p, err = ParsePassword("192.168.1.2")
	if err != nil || !bytes.Equal(p, []byte{192, 168, 1, 2}) {
		t.Fatalf("ipv4 password = %v, %v", p, err)
	}
	p, err = ParsePassword("01:02:03:04:05:06")
	if err != nil || !bytes.Equal(p, []byte{1, 2, 3, 4, 5, 6}) {
		t.Fatalf("hex password = %v, %v", p, err)
	}
	if _, err := ParsePassword("01:02:03"); !errors.Is(err, ErrInvalidPassword) {
		t.Fatalf("short password error = %v", err)
	}
}

func TestMagicPacket(t *testing.T) {
	mac := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	pkt, err := MagicPacket(mac, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkt) != 102 {
		t.Fatalf("len = %d, want 102", len(pkt))
	}
	if !bytes.Equal(pkt[:6], bytes.Repeat([]byte{0xFF}, 6)) {
		t.Fatalf("sync stream = %x", pkt[:6])
	}
	for i := range 16 {
		off := 6 + i*6
		if !bytes.Equal(pkt[off:off+6], mac) {
			t.Fatalf("repetition %d = %x", i, pkt[off:off+6])
		}
	}
	pw := []byte{1, 2, 3, 4, 5, 6}
	pkt, err = MagicPacket(mac, pw)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkt) != 108 || !bytes.Equal(pkt[102:], pw) {
		t.Fatalf("SecureOn packet = %x", pkt)
	}
	if _, err := MagicPacket(mac, []byte{1, 2, 3}); !errors.Is(err, ErrInvalidPassword) {
		t.Fatalf("bad password error = %v", err)
	}
	if _, err := MagicPacket(net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, nil); !errors.Is(err, ErrInvalidMAC) {
		t.Fatalf("broadcast MAC error = %v", err)
	}
}

func TestBroadcastAddr(t *testing.T) {
	cases := map[string]string{
		"192.168.1.20/24": "192.168.1.255",
		"10.0.0.1/8":      "10.255.255.255",
		"172.16.5.4/20":   "172.16.15.255",
		"192.168.1.1/30":  "192.168.1.3",
	}
	for in, want := range cases {
		got, err := BroadcastAddr(netip.MustParsePrefix(in))
		if err != nil || got.String() != want {
			t.Fatalf("BroadcastAddr(%s) = %v, %v; want %s", in, got, err, want)
		}
	}
	for _, in := range []string{"192.168.1.1/31", "192.168.1.1/32", "fd00::1/64"} {
		if _, err := BroadcastAddr(netip.MustParsePrefix(in)); !errors.Is(err, ErrInvalidTarget) {
			t.Fatalf("BroadcastAddr(%s) error = %v", in, err)
		}
	}
}

func TestSendRejectsBadTargets(t *testing.T) {
	mac := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	ctx := context.Background()
	if err := Send(ctx, Options{MAC: mac, Broadcast: netip.MustParseAddr("127.0.0.1")}); !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("loopback target error = %v", err)
	}
	if err := Send(ctx, Options{MAC: mac, Broadcast: netip.MustParseAddr("0.0.0.0")}); !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("unspecified target error = %v", err)
	}
	if err := Send(ctx, Options{MAC: mac, Broadcast: netip.MustParseAddr("fd00::1")}); !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("ipv6 target error = %v", err)
	}
	if err := Send(ctx, Options{MAC: mac, Broadcast: netip.MustParseAddr("192.168.1.255"), Port: 53}); !errors.Is(err, ErrInvalidPort) {
		t.Fatalf("port error = %v", err)
	}
}

func TestSendLoopback(t *testing.T) {
	rx, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer rx.Close()
	dst := rx.LocalAddr().(*net.UDPAddr).AddrPort()

	mac := net.HardwareAddr{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee}
	pw := []byte{9, 8, 7, 6}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	opts := Options{MAC: mac, Password: pw, Source: netip.MustParseAddr("127.0.0.1"), Repeat: 2}
	if err := send(ctx, opts, dst); err != nil {
		t.Fatal(err)
	}
	want, _ := MagicPacket(mac, pw)
	_ = rx.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 512)
	for i := range 2 {
		n, _, err := rx.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		if !bytes.Equal(buf[:n], want) {
			t.Fatalf("packet %d = %x", i, buf[:n])
		}
	}
}
