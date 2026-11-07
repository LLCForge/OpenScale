package edgenet

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"
	"time"
)

const procARP = `IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         AA:bb:cc:dd:ee:01     *        wlan0
192.168.1.7      0x1         0x0         00:00:00:00:00:00     *        wlan0
192.168.1.9      0x1         0x2         00:00:00:00:00:00     *        wlan0
192.168.1.10     0x1         0x2         01:00:5e:00:00:01     *        wlan0
bozuk satır
fe80::1          0x1         0x2         aa:bb:cc:dd:ee:02     *        wlan0
`

func TestParseProcARP(t *testing.T) {
	got := ParseProcARP([]byte(procARP))
	if len(got) != 1 || got[0].Addr != netip.MustParseAddr("192.168.1.1") || got[0].MAC != "aa:bb:cc:dd:ee:01" {
		t.Fatalf("got %+v", got)
	}
	mac, ok := GatewayMAC(got, netip.MustParseAddr("::ffff:192.168.1.1"))
	if !ok || mac != "aa:bb:cc:dd:ee:01" {
		t.Fatalf("gateway mac %q %v", mac, ok)
	}
}

func ipNetRow(addr [4]byte, mac []byte, typ uint32) []byte {
	row := make([]byte, ipNetRowSize)
	binary.LittleEndian.PutUint32(row[4:], uint32(len(mac)))
	copy(row[8:16], mac)
	copy(row[16:20], addr[:])
	binary.LittleEndian.PutUint32(row[20:], typ)
	return row
}

func TestParseIPNetTable(t *testing.T) {
	table := binary.LittleEndian.AppendUint32(nil, 99) // count larger than the rows
	table = append(table, ipNetRow([4]byte{10, 0, 0, 1}, []byte{2, 1, 2, 3, 4, 5}, 3)...)
	table = append(table, ipNetRow([4]byte{10, 0, 0, 2}, []byte{2, 1, 2, 3, 4, 6}, ipNetTypeInvald)...)
	table = append(table, ipNetRow([4]byte{10, 0, 0, 3}, []byte{2, 1, 2, 3}, 3)...)
	table = append(table, 1, 2, 3) // partial row
	got := ParseIPNetTable(table)
	if len(got) != 1 || got[0].Addr != netip.MustParseAddr("10.0.0.1") || got[0].MAC != "02:01:02:03:04:05" {
		t.Fatalf("got %+v", got)
	}
	if ParseIPNetTable([]byte{1}) != nil {
		t.Fatal("short buffer")
	}
}

func TestDetectorGatewayChange(t *testing.T) {
	d := NewDetector()
	gw := netip.MustParseAddr("192.168.1.1")
	now := time.Unix(1_700_000_000, 0)
	if _, ok := d.Observe("Ev", gw, "aa:aa:aa:aa:aa:01", now); ok {
		t.Fatal("first sight alerted")
	}
	if _, ok := d.Observe("Ev", gw, "aa:aa:aa:aa:aa:01", now); ok {
		t.Fatal("same address alerted")
	}
	// Another network with the same gateway address is not a change.
	if _, ok := d.Observe("Kafe", gw, "bb:bb:bb:bb:bb:01", now); ok {
		t.Fatal("other network alerted")
	}
	a, ok := d.Observe("Ev", gw, "cc:cc:cc:cc:cc:01", now)
	if !ok || a.Kind != AlertGatewayMAC || a.Old != "aa:aa:aa:aa:aa:01" || a.New != "cc:cc:cc:cc:cc:01" {
		t.Fatalf("alert %+v %v", a, ok)
	}
	if !strings.Contains(a.Message(), "ARP") {
		t.Fatalf("message %q", a.Message())
	}
	// Reported once per change.
	if _, ok := d.Observe("Ev", gw, "cc:cc:cc:cc:cc:01", now); ok {
		t.Fatal("repeated alert")
	}
	if _, ok := d.Observe("Ev", netip.Addr{}, "x", now); ok {
		t.Fatal("invalid gateway")
	}
}

func TestDetectorBounded(t *testing.T) {
	d := NewDetector()
	base := time.Unix(1_700_000_000, 0)
	for i := range maxWatched * 3 {
		gw := netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 1})
		d.Observe("n", gw, "aa:aa:aa:aa:aa:01", base.Add(time.Duration(i)*time.Second))
	}
	if len(d.seen) > maxWatched {
		t.Fatalf("%d entries kept", len(d.seen))
	}
}

func FuzzParseProcARP(f *testing.F) {
	f.Add([]byte(procARP))
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, n := range ParseProcARP(data) {
			if !n.Addr.Is4() || len(n.MAC) != 17 {
				t.Fatalf("bad entry %+v", n)
			}
		}
	})
}

func FuzzParseIPNetTable(f *testing.F) {
	table := binary.LittleEndian.AppendUint32(nil, 1)
	f.Add(append(table, ipNetRow([4]byte{10, 0, 0, 1}, []byte{2, 1, 2, 3, 4, 5}, 3)...))
	f.Fuzz(func(t *testing.T, data []byte) {
		got := ParseIPNetTable(data)
		if len(got) > maxNeighbors || len(got)*ipNetRowSize > len(data) {
			t.Fatalf("%d entries from %d bytes", len(got), len(data))
		}
	})
}
