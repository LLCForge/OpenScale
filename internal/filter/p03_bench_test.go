package filter

import (
	"fmt"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/trust"
)

// Measurements behind the P03 decisions on the rule compiler (#390) and the
// sharded connection table (#391). They are not part of the #576 gate.

// benchDocRules is benchDoc with n rules, the last of which matches.
func benchDocRules(n int) *trust.Document {
	d := &trust.Document{}
	for i := range 64 {
		d.Devices = append(d.Devices, trust.Device{Name: fmt.Sprintf("d%d", i), IPv4: netip.AddrFrom4([4]byte{100, 80, 1, byte(i + 1)})})
	}
	for i := range n - 1 {
		d.Rules = append(d.Rules, trust.Rule{From: []string{fmt.Sprintf("d%d", i%63+1)}, To: []string{"d2"}, Protocol: trust.ProtocolTCP, Ports: []string{fmt.Sprint(1000 + i)}})
	}
	d.Rules = append(d.Rules, trust.Rule{From: []string{"d0"}, To: []string{"d1"}, Protocol: trust.ProtocolTCP, Ports: []string{"443"}})
	return d
}

// BenchmarkP03NewFlowRules measures rule evaluation as the rule count grows.
func BenchmarkP03NewFlowRules(b *testing.B) {
	for _, n := range []int{64, 256, 1024} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			d := benchDocRules(n)
			f := New(time.Now)
			f.Update(d, d.Devices[1])
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

// BenchmarkP03TrackedFlowParallel measures the connection table fast path
// with many goroutines on distinct flows (lock contention, #391).
func BenchmarkP03TrackedFlowParallel(b *testing.B) {
	d := benchDoc()
	f := New(time.Now)
	f.Update(d, d.Devices[1])
	const flows = 64
	acks := make([][]byte, flows)
	for i := range flows {
		port := uint16(40000 + i)
		if !f.Inbound(tcp(d.Devices[0].IPv4, d.Devices[1].IPv4, port, 443, tcpSYN)) {
			b.Fatal("dropped")
		}
		acks[i] = tcp(d.Devices[0].IPv4, d.Devices[1].IPv4, port, 443, 0x10)
	}
	var next atomic.Uint32
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		pkt := acks[next.Add(1)%flows]
		for pb.Next() {
			if !f.Inbound(pkt) {
				b.Fatal("dropped")
			}
		}
	})
}
