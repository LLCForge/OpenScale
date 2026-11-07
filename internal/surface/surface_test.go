package surface

import (
	"encoding/binary"
	"net"
	"net/netip"
	"runtime"
	"testing"
)

const procTCP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 111 1 0000000000000000 100 0 0 10 0
   1: 0100007F:1F91 0200007F:C000 01 00000000:00000000 00:00000000 00000000     0        0 112 1 0000000000000000 100 0 0 10 0
   2: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 999 1 0000000000000000 100 0 0 10 0
   bozuk
`

func TestParseProcNetAndFilter(t *testing.T) {
	entries := ParseProcNet([]byte(procTCP))
	if len(entries) != 3 {
		t.Fatalf("entries %+v", entries)
	}
	got := FilterProc("tcp", entries, map[uint64]bool{111: true, 112: true})
	if len(got) != 1 || got[0].Addr != netip.MustParseAddr("127.0.0.1") || got[0].Port != 8080 {
		t.Fatalf("got %+v", got)
	}
	udp := FilterProc("udp", entries, map[uint64]bool{112: true})
	if len(udp) != 1 || udp[0].Port != 8081 {
		t.Fatalf("udp %+v", udp)
	}
}

func TestSocketInode(t *testing.T) {
	if n, ok := SocketInode("socket:[12345]"); !ok || n != 12345 {
		t.Fatal(n, ok)
	}
	for _, s := range []string{"pipe:[1]", "socket:[]", "socket:[0]", "socket:[x]", "socket:[1"} {
		if _, ok := SocketInode(s); ok {
			t.Fatalf("%q accepted", s)
		}
	}
}

func TestParseWindowsTables(t *testing.T) {
	tcp4 := binary.LittleEndian.AppendUint32(nil, 2)
	row := make([]byte, tcp4RowSize)
	binary.LittleEndian.PutUint32(row[0:], 2)
	copy(row[4:8], []byte{127, 0, 0, 1})
	row[8], row[9] = 0x1f, 0x90
	binary.LittleEndian.PutUint32(row[20:], 42)
	other := make([]byte, tcp4RowSize)
	copy(other, row)
	binary.LittleEndian.PutUint32(other[20:], 7)
	tcp4 = append(append(tcp4, row...), other...)
	got := ParseWindowsTable("tcp4", tcp4, 42)
	if len(got) != 1 || got[0].Port != 8080 || got[0].Addr != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("tcp4 %+v", got)
	}
	udp6 := binary.LittleEndian.AppendUint32(nil, 1)
	r6 := make([]byte, udp6RowSize)
	r6[15] = 1 // ::1
	r6[20], r6[21] = 0x00, 0x35
	binary.LittleEndian.PutUint32(r6[24:], 42)
	got = ParseWindowsTable("udp6", append(udp6, r6...), 42)
	if len(got) != 1 || got[0].Proto != "udp" || got[0].Port != 53 || got[0].Addr != netip.IPv6Loopback() {
		t.Fatalf("udp6 %+v", got)
	}
	if ParseWindowsTable("x", tcp4, 42) != nil || ParseWindowsTable("tcp6", []byte{1, 2}, 42) != nil {
		t.Fatal("bad input accepted")
	}
}

func TestOwnFindsListener(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("no socket table on this system")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	socks, ok := Own()
	if !ok {
		t.Fatal("tables not readable")
	}
	for _, s := range socks {
		if s.Proto == "tcp" && s.Port == port {
			return
		}
	}
	t.Fatalf("own listener %d not in %+v", port, socks)
}

func FuzzParseProcNet(f *testing.F) {
	f.Add([]byte(procTCP))
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, e := range ParseProcNet(data) {
			if !e.Addr.IsValid() || e.Inode == 0 {
				t.Fatalf("bad entry %+v", e)
			}
		}
	})
}

func FuzzParseWindowsTable(f *testing.F) {
	f.Add("tcp6", []byte{1, 0, 0, 0}, uint32(1))
	f.Fuzz(func(t *testing.T, kind string, data []byte, pid uint32) {
		got := ParseWindowsTable(kind, data, pid)
		if len(got)*udp4RowSize > len(data) {
			t.Fatalf("%d sockets from %d bytes", len(got), len(data))
		}
	})
}
