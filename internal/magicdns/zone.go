package magicdns

import (
	"net/netip"
	"strings"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/openscale/openscale/internal/trust"
)

// Names under the network domain (ADR-0016, ADR-0034): devices and their
// aliases, the coordinator, the records of the magic_dns section, and
// optionally every name below a device (F-055).

// maxChase bounds how many in-zone CNAME links one answer follows.
const maxChase = 8

// rr is one record of an answer.
type rr struct {
	name   dnsmessage.Name
	typ    dnsmessage.Type
	addr   netip.Addr
	target string // CNAME, SRV and PTR target, absolute with the dot
	txt    string
	prio   uint16
	weight uint16
	port   uint16
}

// zone answers names under one document's domain.
type zone struct {
	doc *trust.Document
	// owners maps device names and aliases to their device.
	owners map[string]trust.Device
}

func newZone(doc *trust.Document) zone {
	z := zone{doc: doc, owners: make(map[string]trust.Device, 2*len(doc.Devices))}
	for _, d := range doc.Devices {
		z.owners[d.Name] = d
		for _, a := range d.Aliases {
			z.owners[a] = d
		}
	}
	return z
}

func (z zone) records() []trust.DNSRecord {
	if z.doc.MagicDNS == nil {
		return nil
	}
	return z.doc.MagicDNS.Records
}

// lookup answers rel (the name relative to the domain, "" for the apex)
// for qtype. found is false when the name does not exist (NXDOMAIN).
// extra holds the addresses of in-zone SRV targets.
func (z zone) lookup(rel string, owner dnsmessage.Name, qtype dnsmessage.Type, depth int) (found bool, answers, extra []rr) {
	if rel == "" {
		return true, nil, nil // the apex exists but has no data
	}
	var exact []trust.DNSRecord
	for _, r := range z.records() {
		if r.Name == rel {
			exact = append(exact, r)
		}
	}
	if len(exact) > 0 {
		for _, r := range exact {
			if r.Type == trust.RecordCNAME {
				return true, z.cname(r, owner, qtype, depth), nil
			}
		}
		for _, r := range exact {
			if out, ok := z.recordRR(r, owner, qtype); ok {
				answers = append(answers, out)
				if out.typ == dnsmessage.TypeSRV {
					extra = append(extra, z.targetAddrs(out.target, depth)...)
				}
			}
		}
		return true, answers, extra
	}
	if rel == CoordinatorLabel && z.doc.Coordinator != nil {
		return true, addrRRs(owner, qtype, z.doc.Coordinator.IPv4, z.doc.Coordinator.IPv6), nil
	}
	if ok, ans := z.panelAnswer(rel, owner, qtype); ok { // ADR-0191
		return true, ans, nil
	}
	if d, ok := z.owners[rel]; ok {
		return true, addrRRs(owner, qtype, d.IPv4, d.IPv6), nil
	}
	// An empty non-terminal ("_tcp.masaustu" when "_rdp._tcp.masaustu"
	// exists) exists without data.
	for _, r := range z.records() {
		if strings.HasSuffix(r.Name, "."+rel) && !strings.HasPrefix(r.Name, "*.") {
			return true, nil, nil
		}
	}
	if w, ok := z.wildcard(rel); ok {
		for _, r := range z.records() {
			if r.Name != w {
				continue
			}
			if out, ok := z.recordRR(r, owner, qtype); ok {
				answers = append(answers, out)
				if out.typ == dnsmessage.TypeSRV {
					extra = append(extra, z.targetAddrs(out.target, depth)...)
				}
			}
		}
		return true, answers, extra
	}
	if s := z.doc.MagicDNS; s != nil && s.DeviceSubdomains {
		if i := strings.LastIndexByte(rel, '.'); i >= 0 {
			if d, ok := z.owners[rel[i+1:]]; ok {
				return true, addrRRs(owner, qtype, d.IPv4, d.IPv6), nil
			}
		}
	}
	if d, ok := z.serviceOwner(rel); ok { // published services, ADR-0139
		return true, addrRRs(owner, qtype, d.IPv4, d.IPv6), nil
	}
	if ok, ans := z.shortAnswer(rel, owner, qtype); ok { // short names, #762
		return true, ans, nil
	}
	return false, nil, nil
}

// wildcard returns the closest "*.x" record name covering rel.
func (z zone) wildcard(rel string) (string, bool) {
	best := ""
	for _, r := range z.records() {
		base, ok := strings.CutPrefix(r.Name, "*.")
		if !ok || !strings.HasSuffix(rel, "."+base) {
			continue
		}
		if len(r.Name) > len(best) {
			best = r.Name
		}
	}
	return best, best != ""
}

// cname answers with the CNAME record and, for an in-zone target, the
// target's records of the asked type.
func (z zone) cname(r trust.DNSRecord, owner dnsmessage.Name, qtype dnsmessage.Type, depth int) []rr {
	out := []rr{{name: owner, typ: dnsmessage.TypeCNAME, target: r.Value + "."}}
	if qtype == dnsmessage.TypeCNAME || depth >= maxChase {
		return out
	}
	rel, inZone := z.relative(r.Value)
	if !inZone {
		return out // the client's resolver follows names outside the zone
	}
	target, err := dnsmessage.NewName(r.Value + ".")
	if err != nil {
		return out
	}
	_, more, _ := z.lookup(rel, target, qtype, depth+1)
	return append(out, more...)
}

// targetAddrs returns the addresses of an in-zone target for the
// additional section.
func (z zone) targetAddrs(target string, depth int) []rr {
	name := strings.TrimSuffix(target, ".")
	rel, inZone := z.relative(name)
	if !inZone || depth >= maxChase {
		return nil
	}
	owner, err := dnsmessage.NewName(target)
	if err != nil {
		return nil
	}
	var out []rr
	for _, t := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		_, ans, _ := z.lookup(rel, owner, t, depth+1)
		for _, a := range ans {
			if a.typ == t {
				out = append(out, a)
			}
		}
	}
	return out
}

// recordRR converts a record when it matches qtype. An address inside the
// network is answered only while it belongs to a device in this view, so
// a record never points at a device this one cannot reach.
func (z zone) recordRR(r trust.DNSRecord, owner dnsmessage.Name, qtype dnsmessage.Type) (rr, bool) {
	var typ dnsmessage.Type
	switch r.Type {
	case trust.RecordA:
		typ = dnsmessage.TypeA
	case trust.RecordAAAA:
		typ = dnsmessage.TypeAAAA
	case trust.RecordSRV:
		typ = dnsmessage.TypeSRV
	case trust.RecordTXT:
		typ = dnsmessage.TypeTXT
	default:
		return rr{}, false
	}
	if qtype != typ && qtype != dnsmessage.TypeALL {
		return rr{}, false
	}
	out := rr{name: owner, typ: typ}
	switch typ {
	case dnsmessage.TypeA, dnsmessage.TypeAAAA:
		a, err := netip.ParseAddr(r.Value)
		if err != nil {
			return rr{}, false
		}
		if inNetwork(z.doc, a) {
			if _, ok := nameOf(z.doc, a); !ok {
				return rr{}, false
			}
		}
		out.addr = a
	case dnsmessage.TypeSRV:
		out.target, out.prio, out.weight, out.port = r.Value+".", r.Priority, r.Weight, r.Port
	case dnsmessage.TypeTXT:
		out.txt = r.Value
	}
	return out, true
}

func (z zone) relative(name string) (string, bool) {
	if name == z.doc.DNSDomain {
		return "", true
	}
	return strings.CutSuffix(name, "."+z.doc.DNSDomain)
}

// addrRRs returns the A and AAAA records of a device for qtype.
func addrRRs(owner dnsmessage.Name, qtype dnsmessage.Type, v4, v6 netip.Addr) []rr {
	var out []rr
	if (qtype == dnsmessage.TypeA || qtype == dnsmessage.TypeALL) && v4.Is4() {
		out = append(out, rr{name: owner, typ: dnsmessage.TypeA, addr: v4})
	}
	if (qtype == dnsmessage.TypeAAAA || qtype == dnsmessage.TypeALL) && v6.Is6() {
		out = append(out, rr{name: owner, typ: dnsmessage.TypeAAAA, addr: v6})
	}
	return out
}

// write appends one record to the builder's current section.
func (r rr) write(b *dnsmessage.Builder) error {
	h := dnsmessage.ResourceHeader{Name: r.name, Class: dnsmessage.ClassINET, TTL: TTL}
	switch r.typ {
	case dnsmessage.TypeA:
		return b.AResource(h, dnsmessage.AResource{A: r.addr.As4()})
	case dnsmessage.TypeAAAA:
		return b.AAAAResource(h, dnsmessage.AAAAResource{AAAA: r.addr.As16()})
	case dnsmessage.TypeCNAME, dnsmessage.TypePTR, dnsmessage.TypeSRV:
		target, err := dnsmessage.NewName(r.target)
		if err != nil {
			return err
		}
		switch r.typ {
		case dnsmessage.TypeCNAME:
			return b.CNAMEResource(h, dnsmessage.CNAMEResource{CNAME: target})
		case dnsmessage.TypePTR:
			return b.PTRResource(h, dnsmessage.PTRResource{PTR: target})
		}
		return b.SRVResource(h, dnsmessage.SRVResource{Priority: r.prio, Weight: r.weight, Port: r.port, Target: target})
	case dnsmessage.TypeTXT:
		return b.TXTResource(h, dnsmessage.TXTResource{TXT: []string{r.txt}})
	}
	return nil
}
