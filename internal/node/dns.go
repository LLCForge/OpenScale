package node

import (
	"net/netip"

	"github.com/openscale/openscale/internal/magicdns"
	"github.com/openscale/openscale/internal/packet"
	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/internal/wgconf"
)

// dnsPort is the standard DNS port.
const dnsPort = 53

// answerDNS answers MagicDNS queries the operating system sends to the
// reserved resolver address (ADR-0016). The query never leaves this
// computer: it is answered from the signed document and written back to
// the OS interface.
//
// While an exit node is in use, an OS that sends every query to the exit
// node (Linux: one DNS server per link) still gets MagicDNS names and
// in-network reverse names answered here, from this device's document.
//
// Other names the OS sends to the resolver are forwarded through the
// tunnel to the network's resolvers or the exit node (ADR-0034), and
// queries over TCP are answered too (F-066).
func (e *Engine) answerDNS(pkt []byte) ([]byte, bool) {
	in, err := packet.Parse(pkt)
	if err != nil || in.DstPort != dnsPort {
		return nil, false
	}
	doc := e.cfg.Store.Document()
	resolver := doc.DNSResolverIPv4()
	if in.Proto == packet.ProtoTCP && in.Dst == resolver {
		e.answerDNSTCP(pkt)
		return nil, true
	}
	if in.Proto != packet.ProtoUDP {
		return nil, false
	}
	if in.Dst != resolver {
		if in.Fragment || !e.isExitDNS(doc, in.Dst) {
			return nil, false
		}
		if !magicdns.Handles(doc, in.Payload) {
			// Split domains keep their own resolvers while an exit node
			// is in use; everything else goes on to the exit node.
			servers := e.exitSplitRoute(doc, in.Payload)
			if len(servers) == 0 {
				return nil, false
			}
			e.forwardUDP(in, in.Dst, servers)
			return nil, true
		}
		resolver = in.Dst
	}
	if in.Fragment {
		return nil, true
	}
	if !magicdns.Handles(doc, in.Payload) {
		if servers := e.networkRoute(doc, in.Payload); len(servers) > 0 {
			e.forwardUDP(in, resolver, servers)
			return nil, true
		}
	}
	answer := magicdns.Answer(e.dnsDocument(doc), in.Payload)
	if answer == nil {
		return nil, true
	}
	reply, err := packet.BuildUDP4(resolver, in.Src, dnsPort, in.SrcPort, answer)
	if err != nil {
		return nil, true
	}
	return reply, true
}

// dnsDocument returns the view MagicDNS answers from: the document as
// applied, limited to this device and its configured tunnel peers (F-069),
// so a name never resolves to a device this one cannot reach. Until the
// first apply the full document is used.
func (e *Engine) dnsDocument(doc *trust.Document) *trust.Document {
	e.mu.Lock()
	v := e.dnsView
	e.mu.Unlock()
	if v == nil || v.NetworkID != doc.NetworkID || v.Version != doc.Version {
		return doc
	}
	return v
}

// magicDNSView builds the MagicDNS view for doc: self plus the peers that
// got a WireGuard entry (want). Names of other devices then get NXDOMAIN,
// and reverse lookups of their addresses too.
func (e *Engine) magicDNSView(doc *trust.Document, self trust.Device, want map[trust.Key]wgconf.Peer) *trust.Document {
	if e.cfg.MagicDNSAllDevices {
		return doc
	}
	v := *doc
	v.Devices = make([]trust.Device, 0, len(want))
	for _, d := range doc.Devices {
		if _, ok := want[d.WireGuardKey]; ok || d.Name == self.Name {
			v.Devices = append(v.Devices, d)
		}
	}
	return &v
}

// isExitDNS reports whether dst is the overlay address of the exit node
// in use.
func (e *Engine) isExitDNS(doc *trust.Document, dst netip.Addr) bool {
	e.mu.Lock()
	active := e.exitActive
	e.mu.Unlock()
	if active == "" {
		return false
	}
	d, ok := doc.DeviceByName(active)
	return ok && d.IPv4 == dst
}

// DNSResolver returns the address the OS should send MagicDNS queries to
// and the network domain.
func (e *Engine) DNSResolver() (string, string) {
	doc := e.cfg.Store.Document()
	return doc.DNSResolverIPv4().String(), doc.DNSDomain
}
