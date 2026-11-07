package trust

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// Network-wide DNS settings (ADR-0024, F-051, F-052).

// Limits of the dns section.
const (
	MaxNameservers  = 4
	MaxSplitDomains = 32
	maxSplitServers = 4
)

// DNSSettings is the optional dns section of the document. Every resolver
// address must be the tunnel address of a device in the document, so the
// network setting can never send queries to a third-party resolver
// (ADR-0008).
type DNSSettings struct {
	// Nameservers resolve every name that MagicDNS does not answer.
	Nameservers []netip.Addr `json:"nameservers,omitempty"`
	// Split sends names under a domain to specific resolvers.
	Split []SplitDNS `json:"split,omitempty"`
}

// SplitDNS maps one domain and its subdomains to resolvers.
type SplitDNS struct {
	Domain      string       `json:"domain"`
	Nameservers []netip.Addr `json:"nameservers"`
}

// SetDNS replaces the dns section; nil removes it. The settings are copied.
func (doc *Document) SetDNS(s *DNSSettings) error {
	var next *DNSSettings
	if s != nil {
		next = &DNSSettings{Nameservers: slices.Clone(s.Nameservers)}
		for _, e := range s.Split {
			next.Split = append(next.Split, SplitDNS{Domain: e.Domain, Nameservers: slices.Clone(e.Nameservers)})
		}
	}
	return doc.transact(func() error {
		doc.DNS = next
		// A split domain that is gone leaves the search list too (ADR-0034).
		doc.pruneSearch()
		return nil
	})
}

func (doc *Document) validateDNS() error {
	s := doc.DNS
	if s == nil {
		return nil
	}
	if len(s.Nameservers) == 0 && len(s.Split) == 0 {
		return errors.New("dns section is empty; remove it instead")
	}
	tunnel := make(map[netip.Addr]bool, 2*len(doc.Devices))
	for _, d := range doc.Devices {
		tunnel[d.IPv4], tunnel[d.IPv6] = true, true
	}
	if err := checkResolvers("dns nameservers", s.Nameservers, MaxNameservers, tunnel); err != nil {
		return err
	}
	if len(s.Split) > MaxSplitDomains {
		return fmt.Errorf("dns split allows at most %d domains", MaxSplitDomains)
	}
	seen := make(map[string]bool, len(s.Split))
	for i, e := range s.Split {
		if err := doc.checkSplitDomain(e.Domain); err != nil {
			return fmt.Errorf("dns split %d: %w", i, err)
		}
		if seen[e.Domain] {
			return fmt.Errorf("dns split %d: domain %q is listed twice", i, e.Domain)
		}
		seen[e.Domain] = true
		if len(e.Nameservers) == 0 {
			return fmt.Errorf("dns split %d (%s): needs at least one nameserver", i, e.Domain)
		}
		if err := checkResolvers("dns split "+e.Domain, e.Nameservers, maxSplitServers, tunnel); err != nil {
			return err
		}
	}
	return nil
}

func checkResolvers(field string, addrs []netip.Addr, limit int, tunnel map[netip.Addr]bool) error {
	if len(addrs) > limit {
		return fmt.Errorf("%s allows at most %d addresses", field, limit)
	}
	seen := make(map[netip.Addr]bool, len(addrs))
	for _, a := range addrs {
		if !a.IsValid() || a.Zone() != "" || a.Is4In6() || !tunnel[a] {
			return fmt.Errorf("%s: %v is not the tunnel address of a device in this network", field, a)
		}
		if seen[a] {
			return fmt.Errorf("%s lists %v twice", field, a)
		}
		seen[a] = true
	}
	return nil
}

// checkSplitDomain accepts a lowercase domain of one or more labels (for
// example "lan" or "ev.lan") that does not overlap the MagicDNS domain:
// neither equal to it, below it, nor above it.
func (doc *Document) checkSplitDomain(d string) error {
	if len(d) == 0 || len(d) > maxDomainLength {
		return errors.New("domain is empty or too long")
	}
	for _, l := range strings.Split(d, ".") {
		if !isValidLabel(l) {
			return fmt.Errorf("domain %q is not a lowercase domain name", d)
		}
	}
	for _, magic := range []string{doc.DNSDomain, DefaultDNSDomain} {
		if domainsOverlap(d, magic) {
			return fmt.Errorf("domain %q overlaps the MagicDNS domain %s", d, magic)
		}
	}
	return nil
}

// domainsOverlap reports whether a equals b or one is a subdomain of the
// other.
func domainsOverlap(a, b string) bool {
	return a == b || strings.HasSuffix(a, "."+b) || strings.HasSuffix(b, "."+a)
}

// dropDNSAddrs removes resolver addresses (of a revoked device) from the
// dns section. Split entries left without resolvers are dropped, and an
// empty section is removed.
func (doc *Document) dropDNSAddrs(addrs ...netip.Addr) {
	s := doc.DNS
	if s == nil {
		return
	}
	gone := func(a netip.Addr) bool { return slices.Contains(addrs, a) }
	s.Nameservers = slices.DeleteFunc(s.Nameservers, gone)
	if len(s.Nameservers) == 0 {
		s.Nameservers = nil
	}
	kept := s.Split[:0]
	for _, e := range s.Split {
		e.Nameservers = slices.DeleteFunc(e.Nameservers, gone)
		if len(e.Nameservers) > 0 {
			kept = append(kept, e)
		}
	}
	s.Split = kept
	if len(s.Split) == 0 {
		s.Split = nil
	}
	if len(s.Nameservers) == 0 && len(s.Split) == 0 {
		doc.DNS = nil
	}
	doc.pruneSearch()
}
