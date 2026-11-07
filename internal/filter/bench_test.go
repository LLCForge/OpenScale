package filter

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/trust"
)

// Benchmarks of the performance gate (#576, tools/benchgate). Names are
// part of the gate's baseline: rename only together with the CI step.

// benchDoc is a 64-device network with 64 rules, the last of which matches.
func benchDoc() *trust.Document {
	d := &trust.Document{}
	for i := range 64 {
		d.Devices = append(d.Devices, trust.Device{Name: fmt.Sprintf("d%d", i), IPv4: netip.AddrFrom4([4]byte{100, 80, 1, byte(i + 1)})})
	}
	for i := range 63 {
		d.Rules = append(d.Rules, trust.Rule{From: []string{fmt.Sprintf("d%d", i+1)}, To: []string{"d2"}, Protocol: trust.ProtocolTCP, Ports: []string{"22"}})
	}
	d.Rules = append(d.Rules, trust.Rule{From: []string{"d0"}, To: []string{"d1"}, Protocol: trust.ProtocolTCP, Ports: []string{"443"}})
	return d
}

// BenchmarkFilterNewFlow measures a full rule evaluation per packet.
func BenchmarkFilterNewFlow(b *testing.B) {
	d := benchDoc()
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
			f.Update(d, d.Devices[1]) // forget the flows so every packet is new
		}
	}
}

// BenchmarkFilterTrackedFlow measures the connection table fast path.
func BenchmarkFilterTrackedFlow(b *testing.B) {
	d := benchDoc()
	f := New(time.Now)
	f.Update(d, d.Devices[1])
	pkt := tcp(d.Devices[0].IPv4, d.Devices[1].IPv4, 40000, 443, tcpSYN)
	if !f.Inbound(pkt) {
		b.Fatal("dropped")
	}
	ack := tcp(d.Devices[0].IPv4, d.Devices[1].IPv4, 40000, 443, 0x10)
	b.ReportAllocs()
	for b.Loop() {
		if !f.Inbound(ack) {
			b.Fatal("dropped")
		}
	}
}
