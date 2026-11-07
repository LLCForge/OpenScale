package filter

import (
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/packet"
	"github.com/openscale/openscale/internal/trust"
)

// Differential test of the packet filter against the rule simulator (#572).
// Random documents and packets are fed to both: the filter sees the raw
// packet on the sending and on the receiving device, the simulator
// (Document.Explain, behind `openscale policy check` and the panel) sees
// the query a person would type. Any disagreement is a bug: a simulator
// that says "allowed" while the filter drops breaks trust in the tool, and
// the reverse hides an open path.

var diffNow = time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)

var diffIPs = []netip.Addr{
	netip.MustParseAddr("100.80.0.1"),
	netip.MustParseAddr("100.80.0.2"),
	netip.MustParseAddr("100.80.0.3"),
	netip.MustParseAddr("100.80.0.4"),
}

var diffNames = []string{"laptop", "masaustu", "telefon", "sunucu"}

// randomDoc builds a document whose rules stay inside the valid rule
// language: device, tag, group and wildcard entries; tcp, udp, icmp, any
// and numeric protocols; ports and ranges; deny, disabled, bidirectional
// and ICMP type limits.
func randomDoc(r *rand.Rand) *trust.Document {
	d := &trust.Document{}
	tags := []string{"is", "ev"}
	for i, n := range diffNames {
		dev := trust.Device{Name: n, IPv4: diffIPs[i]}
		if r.IntN(2) == 0 {
			dev.Tags = []string{tags[r.IntN(len(tags))]}
		}
		d.Devices = append(d.Devices, dev)
	}
	d.Groups = []trust.Group{{Name: "g1", Members: pickNames(r, 1+r.IntN(3))}}
	nrules := r.IntN(7)
	for range nrules {
		d.Rules = append(d.Rules, randomRule(r))
	}
	return d
}

func pickNames(r *rand.Rand, n int) []string {
	perm := r.Perm(len(diffNames))
	out := make([]string, 0, n)
	for _, i := range perm[:min(n, len(perm))] {
		out = append(out, diffNames[i])
	}
	return out
}

func randomEntries(r *rand.Rand) []string {
	pool := append(append([]string{}, diffNames...), "tag:is", "tag:ev", "group:g1", trust.RuleWildcard)
	perm := r.Perm(len(pool))
	n := 1 + r.IntN(2)
	out := make([]string, 0, n)
	for _, i := range perm[:n] {
		out = append(out, pool[i])
	}
	return out
}

func randomRule(r *rand.Rand) trust.Rule {
	rule := trust.Rule{From: randomEntries(r), To: randomEntries(r), Ports: []string{}}
	switch r.IntN(5) {
	case 0:
		rule.Protocol = trust.ProtocolTCP
	case 1:
		rule.Protocol = trust.ProtocolUDP
	case 2:
		rule.Protocol = trust.ProtocolICMP
		switch r.IntN(3) {
		case 0:
			rule.ICMPTypes = []string{"echo"}
		case 1:
			rule.ICMPTypes = []string{"v4:13"}
		}
	case 3:
		rule.Protocol = trust.ProtocolAny
	default:
		rule.Protocol = trust.Protocol("47")
	}
	if rule.Protocol == trust.ProtocolTCP || rule.Protocol == trust.ProtocolUDP {
		for range 1 + r.IntN(2) {
			lo := diffPorts[r.IntN(len(diffPorts))]
			if r.IntN(3) == 0 {
				rule.Ports = append(rule.Ports, strconv.Itoa(int(lo))+"-"+strconv.Itoa(int(lo)+r.IntN(100)))
			} else {
				rule.Ports = append(rule.Ports, strconv.Itoa(int(lo)))
			}
		}
	}
	if r.IntN(4) == 0 {
		rule.Action = trust.RuleDeny
	}
	rule.Disabled = r.IntN(8) == 0
	rule.Bidirectional = r.IntN(6) == 0
	return rule
}

// diffPorts keeps ports in a small set so rules and packets meet often.
var diffPorts = []uint16{22, 53, 80, 443, 3389, 8080}

// probe is one packet: its raw bytes and the simulator query for it.
type probe struct {
	src, dst int
	pkt      []byte
	proto    string
	port     uint16
}

func randomProbe(r *rand.Rand) probe {
	src := r.IntN(len(diffNames))
	dst := (src + 1 + r.IntN(len(diffNames)-1)) % len(diffNames)
	p := probe{src: src, dst: dst}
	s, d := diffIPs[src], diffIPs[dst]
	sport := uint16(40000 + r.IntN(20000))
	port := diffPorts[r.IntN(len(diffPorts))]
	if r.IntN(4) == 0 {
		port += uint16(r.IntN(100))
	}
	switch r.IntN(4) {
	case 0:
		p.pkt, p.proto, p.port = tcp(s, d, sport, port, tcpSYN), "tcp", port
	case 1:
		p.pkt, p.proto, p.port = udp(s, d, sport, port), "udp", port
	case 2:
		p.pkt, p.proto = icmpEcho(s, d, uint16(r.IntN(65536))), "icmp"
	default:
		p.pkt, p.proto = rawIP(s, d, 47), "47"
	}
	return p
}

// icmpEcho builds a minimal IPv4 ICMP echo request.
func icmpEcho(src, dst netip.Addr, id uint16) []byte {
	pkt := make([]byte, 28)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], 28)
	pkt[8] = 64
	pkt[9] = packet.ProtoICMPv4
	s, d := src.As4(), dst.As4()
	copy(pkt[12:16], s[:])
	copy(pkt[16:20], d[:])
	pkt[20] = 8 // echo request
	binary.BigEndian.PutUint16(pkt[24:26], id)
	return pkt
}

// simQuery builds the query the way the simulator's front ends do
// (internal/panel policy check, `openscale policy check`): protocol name,
// destination port, ICMP echo by default, a numeric protocol without port.
func simQuery(proto string, port uint16) trust.PacketQuery {
	q := trust.PacketQuery{ICMPType: -1, At: diffNow}
	switch proto {
	case "tcp":
		q.Proto, q.Port = 6, port
	case "udp":
		q.Proto, q.Port = 17, port
	case "icmp":
		q.Proto, q.ICMPType = 1, 8
	default:
		n, _ := strconv.Atoi(proto)
		q.Proto = n
	}
	return q
}

// compareOnce returns a description of the first disagreement, or "".
func compareOnce(d *trust.Document, p probe) string {
	src, dst := diffNames[p.src], diffNames[p.dst]
	want := d.Explain(src, dst, simQuery(p.proto, p.port))
	now := func() time.Time { return diffNow }
	for _, side := range []struct {
		name string
		self int
		run  func(*Filter, []byte) bool
	}{
		{"outbound@" + src, p.src, (*Filter).Outbound},
		{"inbound@" + dst, p.dst, (*Filter).Inbound},
	} {
		f := New(now)
		f.Update(d, d.Devices[side.self])
		if got := side.run(f, p.pkt); got != want.Allowed {
			return fmt.Sprintf("%s %s->%s %s/%d: filter=%v simulator=%v (%s, rule %d)\nrules=%+v",
				side.name, src, dst, p.proto, p.port, got, want.Allowed, want.Reason, want.Rule, d.Rules)
		}
	}
	return ""
}

func TestFilterMatchesSimulator(t *testing.T) {
	r := rand.New(rand.NewPCG(572, 2026))
	docs := 1500
	if testing.Short() {
		docs = 200
	}
	allowed, total := 0, 0
	for i := range docs {
		d := randomDoc(r)
		for range 16 {
			p := randomProbe(r)
			if msg := compareOnce(d, p); msg != "" {
				t.Fatalf("doc %d: %s", i, msg)
			}
			total++
			if d.Explain(diffNames[p.src], diffNames[p.dst], simQuery(p.proto, p.port)).Allowed {
				allowed++
			}
		}
	}
	// The generator must reach both verdicts often, or the comparison
	// proves nothing.
	if allowed < total/20 || allowed > total*19/20 {
		t.Fatalf("generator is lopsided: %d of %d probes allowed", allowed, total)
	}
	t.Logf("%d probes, %d allowed", total, allowed)
}

func FuzzFilterMatchesSimulator(f *testing.F) {
	f.Add(uint64(1), uint64(2))
	f.Add(uint64(572), uint64(0))
	f.Fuzz(func(t *testing.T, a, b uint64) {
		r := rand.New(rand.NewPCG(a, b))
		d := randomDoc(r)
		for range 8 {
			if msg := compareOnce(d, randomProbe(r)); msg != "" {
				t.Fatal(msg)
			}
		}
	})
}
