package filter

import (
	"net/netip"
	"sync"
	"testing"
	"time"
)

func drainAll(t *FlowTap) []TapRecord {
	var out []TapRecord
	t.Drain(0, func(r TapRecord) { out = append(out, r) })
	return out
}

func TestFlowTapSamplesNewConnectionsOnly(t *testing.T) {
	d := benchDoc()
	f := New(time.Now)
	f.Update(d, d.Devices[1])
	tap := NewFlowTap(64)
	f.SetFlowTap(tap)
	src, dst := d.Devices[0].IPv4, d.Devices[1].IPv4

	if !f.Inbound(tcp(src, dst, 40000, 443, tcpSYN)) {
		t.Fatal("allowed SYN dropped")
	}
	f.Inbound(tcp(src, dst, 40000, 443, 0x10))        // ACK: not sampled
	f.Inbound(tcp(src, dst, 40001, 8080, tcpSYN))     // refused SYN: sampled
	f.Inbound(tcp(src, dst, 40002, 443, tcpSYN|0x10)) // SYN-ACK: not sampled
	f.Inbound(udp(src, dst, 5000, 53))                // first UDP: sampled
	f.Inbound(udp(src, dst, 5000, 53))                // same flow: not sampled

	got := drainAll(tap)
	if len(got) != 3 {
		t.Fatalf("records = %d, want 3: %+v", len(got), got)
	}
	if got[0].Port != 443 || got[0].Dropped || !got[0].Inbound || got[0].Src != src || got[0].Dst != dst || got[0].Proto != 6 {
		t.Fatalf("first record wrong: %+v", got[0])
	}
	if got[1].Port != 8080 || !got[1].Dropped {
		t.Fatalf("refused record wrong: %+v", got[1])
	}
	if got[2].Proto != 17 || got[2].Port != 53 {
		t.Fatalf("udp record wrong: %+v", got[2])
	}
	f.SetFlowTap(nil)
	f.Inbound(tcp(src, dst, 40003, 443, tcpSYN))
	if n := len(drainAll(tap)); n != 0 {
		t.Fatalf("removed tap still sampled %d", n)
	}
}

func TestFlowTapIPv6AndOverflow(t *testing.T) {
	tap := NewFlowTap(4)
	src := netip.MustParseAddr("fd7a:115c:a1e0::1")
	dst := netip.MustParseAddr("fd7a:115c:a1e0::2")
	pkt := make([]byte, 60)
	pkt[0] = 0x60
	pkt[6] = 6
	s16, d16 := src.As16(), dst.As16()
	copy(pkt[8:24], s16[:])
	copy(pkt[24:40], d16[:])
	pkt[40+13] = 0x02
	for p := range 10 {
		pkt[42], pkt[43] = 0, byte(p+1)
		tap.sample(pkt, false, true)
	}
	got := drainAll(tap)
	if len(got) != 4 || tap.Lost() != 6 {
		t.Fatalf("records %d lost %d, want 4 and 6", len(got), tap.Lost())
	}
	if got[0].Src != src || got[0].Dst != dst || got[0].Port != 7 || got[3].Port != 10 || got[0].Inbound || !got[0].Dropped {
		t.Fatalf("records wrong: %+v", got)
	}
	// Short and payload-only packets are ignored without panicking.
	tap.sample(pkt[:30], true, false)
	tap.sample([]byte{0x45}, true, false)
	frag := tcp(netip.MustParseAddr("100.80.1.1"), netip.MustParseAddr("100.80.1.2"), 1, 2, tcpSYN)
	frag[7] = 1 // non-zero fragment offset
	tap.sample(frag, true, false)
	if n := len(drainAll(tap)); n != 0 {
		t.Fatalf("ignored packets sampled: %d", n)
	}
}

// TestFlowTapConcurrent runs writers against a reader under -race.
func TestFlowTapConcurrent(t *testing.T) {
	tap := NewFlowTap(256)
	src, dst := netip.MustParseAddr("100.80.1.1"), netip.MustParseAddr("100.80.1.2")
	var wg sync.WaitGroup
	for w := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 2000 {
				tap.sample(tcp(src, dst, uint16(w*5000+i), uint16(i%1000+1), tcpSYN), true, false)
			}
		}()
	}
	total := 0
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	for {
		tap.Drain(0, func(r TapRecord) {
			if r.Src != src || r.Dst != dst || r.Proto != 6 {
				t.Errorf("torn record: %+v", r)
			}
			total++
		})
		select {
		case <-done:
			tap.Drain(0, func(TapRecord) { total++ })
			if uint64(total)+tap.Lost() != 8000 {
				t.Fatalf("read %d + lost %d != 8000", total, tap.Lost())
			}
			return
		default:
		}
	}
}

func TestFlowTapNoAllocs(t *testing.T) {
	tap := NewFlowTap(1024)
	pkt := tcp(netip.MustParseAddr("100.80.1.1"), netip.MustParseAddr("100.80.1.2"), 1000, 22, tcpSYN)
	u := udp(netip.MustParseAddr("100.80.1.1"), netip.MustParseAddr("100.80.1.2"), 1000, 53)
	if n := testing.AllocsPerRun(1000, func() { tap.sample(pkt, true, false); tap.sample(u, true, false) }); n != 0 {
		t.Fatalf("sample allocates %v", n)
	}
}

// BenchmarkFlowTapTracked compares the tracked flow fast path without and
// with the tap (the ADR-0221 budget is under 3 percent).
func BenchmarkFlowTapTracked(b *testing.B) {
	for _, on := range []bool{false, true} {
		name := "off"
		if on {
			name = "on"
		}
		b.Run(name, func(b *testing.B) {
			d := benchDoc()
			f := New(time.Now)
			f.Update(d, d.Devices[1])
			if on {
				tap := NewFlowTap(0)
				f.SetFlowTap(tap)
			}
			if !f.Inbound(tcp(d.Devices[0].IPv4, d.Devices[1].IPv4, 40000, 443, tcpSYN)) {
				b.Fatal("dropped")
			}
			ack := tcp(d.Devices[0].IPv4, d.Devices[1].IPv4, 40000, 443, 0x10)
			b.ReportAllocs()
			for b.Loop() {
				if !f.Inbound(ack) {
					b.Fatal("dropped")
				}
			}
		})
	}
}

// BenchmarkFlowTapNewFlow is the same for packets that open a flow and so
// are written to the ring.
func BenchmarkFlowTapNewFlow(b *testing.B) {
	for _, on := range []bool{false, true} {
		name := "off"
		if on {
			name = "on"
		}
		b.Run(name, func(b *testing.B) {
			d := benchDoc()
			f := New(time.Now)
			f.Update(d, d.Devices[1])
			if on {
				f.SetFlowTap(NewFlowTap(0))
			}
			src, dst := d.Devices[0].IPv4, d.Devices[1].IPv4
			pkts := make([][]byte, 1024)
			for i := range pkts {
				pkts[i] = tcp(src, dst, uint16(20000+i), 443, tcpSYN)
			}
			b.ReportAllocs()
			i := 0
			for b.Loop() {
				if !f.Inbound(pkts[i%len(pkts)]) {
					b.Fatal("dropped")
				}
				i++
				if i%len(pkts) == 0 {
					f.Update(d, d.Devices[1])
				}
			}
		})
	}
}
