package dnsguard

import (
	"errors"
	"fmt"
	"net/netip"

	"golang.org/x/net/dns/dnsmessage"
)

// Rebinding filter limits.
const MaxRebindNames = 1024

var (
	cgnatRange   = netip.MustParsePrefix("100.64.0.0/10")
	thisNetRange = netip.MustParsePrefix("0.0.0.0/8")
	nat64Range   = netip.MustParsePrefix("64:ff9b::/96")
	siteLocal6   = netip.MustParsePrefix("fec0::/10")
	// defaultInternal are names that are local by design (RFC 6761, RFC
	// 8375 and widespread private suffixes); their answers may be private.
	defaultInternal = []string{
		"lan.", "local.", "localhost.", "localdomain.", "home.arpa.", "internal.",
		"home.", "corp.", "intranet.", "private.", "in-addr.arpa.", "ip6.arpa.",
	}
)

// RebindAddr reports an address that an outside name must not return:
// private (RFC 1918, ULA), loopback, link-local, unspecified, multicast,
// CGNAT (which holds the tunnel's own addresses), "this network",
// deprecated site-local and NAT64 forms of any of these.
func RebindAddr(a netip.Addr) bool {
	a = a.Unmap()
	if a.Is6() && nat64Range.Contains(a) {
		b := a.As16()
		a = netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
	}
	return a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsUnspecified() || a.IsMulticast() || cgnatRange.Contains(a) || thisNetRange.Contains(a) ||
		siteLocal6.Contains(a)
}

// RebindFilter removes private answers of outside names (#739).
type RebindFilter struct {
	internal []string
	allow    []string
}

// NewRebindFilter builds a filter. internal are the network's own domains
// (the MagicDNS domain, the home domain) whose answers may be private;
// allow are the owner's exceptions (for example a public name that points
// at a home server on purpose). Both cover their names and below.
func NewRebindFilter(internal, allow []string) (*RebindFilter, error) {
	if len(internal)+len(allow) > MaxRebindNames {
		return nil, fmt.Errorf("en fazla %d istisna adı olabilir", MaxRebindNames)
	}
	f := &RebindFilter{internal: append([]string(nil), defaultInternal...)}
	for _, s := range internal {
		n, ok := normalizeName(s)
		if !ok {
			return nil, fmt.Errorf("geçersiz iç alan adı: %q", s)
		}
		f.internal = append(f.internal, n)
	}
	for _, s := range allow {
		n, ok := normalizeName(s)
		if !ok {
			return nil, fmt.Errorf("geçersiz istisna adı: %q", s)
		}
		f.allow = append(f.allow, n)
	}
	return f, nil
}

// Exempt reports whether name may be answered with private addresses:
// single labels, internal domains and the owner's exceptions.
func (f *RebindFilter) Exempt(name string) bool {
	n := absName(name)
	if len(n) < 2 || !containsDot(n[:len(n)-1]) {
		return true
	}
	for _, d := range f.internal {
		if under(n, d) {
			return true
		}
	}
	for _, d := range f.allow {
		if under(n, d) {
			return true
		}
	}
	return false
}

func containsDot(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			return true
		}
	}
	return false
}

// ErrNotResponse is returned for a message that is not a DNS response.
var ErrNotResponse = errors.New("DNS yanıtı değil")

// Filter checks a response. When the question's name is not exempt and
// an A or AAAA answer (under any owner name in a CNAME chain) holds a
// rebinding address, those records are removed; if no address answer of
// the asked type remains, the response becomes an empty NOERROR answer
// (NODATA). removed is the number of records taken out; out is msg itself
// when nothing changed.
func (f *RebindFilter) Filter(msg []byte) (out []byte, removed int, err error) {
	var m dnsmessage.Message
	if err := m.Unpack(msg); err != nil {
		return nil, 0, fmt.Errorf("DNS yanıtı okunamadı: %w", err)
	}
	if !m.Header.Response {
		return nil, 0, ErrNotResponse
	}
	if len(m.Questions) == 1 && f.Exempt(m.Questions[0].Name.String()) {
		return msg, 0, nil
	}
	kept := m.Answers[:0:0]
	for _, r := range m.Answers {
		if bad(r) {
			removed++
			continue
		}
		kept = append(kept, r)
	}
	// Additional records may carry glue with private addresses too.
	keptAdd := m.Additionals[:0:0]
	for _, r := range m.Additionals {
		if bad(r) {
			removed++
			continue
		}
		keptAdd = append(keptAdd, r)
	}
	if removed == 0 {
		return msg, 0, nil
	}
	m.Answers, m.Additionals = kept, keptAdd
	hasAddr := false
	for _, r := range kept {
		if len(m.Questions) == 1 && r.Header.Type == m.Questions[0].Type {
			hasAddr = true
		}
	}
	if !hasAddr {
		// NODATA: drop the CNAME chain as well so a client does not
		// follow it to another resolver path.
		m.Answers = nil
		m.Authorities = nil
	}
	out, err = m.Pack()
	if err != nil {
		return nil, 0, fmt.Errorf("DNS yanıtı yazılamadı: %w", err)
	}
	return out, removed, nil
}

func bad(r dnsmessage.Resource) bool {
	switch b := r.Body.(type) {
	case *dnsmessage.AResource:
		return RebindAddr(netip.AddrFrom4(b.A))
	case *dnsmessage.AAAAResource:
		return RebindAddr(netip.AddrFrom16(b.AAAA))
	}
	return false
}
