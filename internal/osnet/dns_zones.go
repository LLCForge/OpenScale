package osnet

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Reverse zones of the network ranges (ADR-0024, F-056), shared by the
// Linux DNS backends and tests on every system.

// maxReverseZones bounds how many reverse zones one prefix may expand to.
const maxReverseZones = 64

// linkDomains is the routing-domain list for the tunnel link: the network
// domain and the reverse zones of both ranges.
func linkDomains(domain string, v4, v6 netip.Prefix) []string {
	out := []string{"~" + domain}
	for _, z := range append(reverseZones(v4), reverseZones(v6)...) {
		out = append(out, "~"+z)
	}
	return out
}

// reverseZones returns the in-addr.arpa or ip6.arpa zones that exactly
// cover p. A prefix that is not on a label boundary expands to its
// sub-zones (100.64.0.0/10 is 64 /16 zones); if that would be too many,
// the enclosing zone is used.
func reverseZones(p netip.Prefix) []string {
	if !p.IsValid() {
		return nil
	}
	p = p.Masked()
	if p.Addr().Is4() {
		b := p.Addr().As4()
		full, rem := p.Bits()/8, p.Bits()%8
		labels := func(n int, last int) string {
			var parts []string
			if last >= 0 {
				parts = append(parts, strconv.Itoa(last))
			}
			for i := n - 1; i >= 0; i-- {
				parts = append(parts, strconv.Itoa(int(b[i])))
			}
			return strings.Join(append(parts, "in-addr.arpa"), ".")
		}
		if rem == 0 || 1<<(8-rem) > maxReverseZones || full == 4 {
			return []string{labels(full, -1)}
		}
		var out []string
		for v := int(b[full]); v < int(b[full])+1<<(8-rem); v++ {
			out = append(out, labels(full, v))
		}
		return out
	}
	b := p.Addr().As16()
	nibble := func(i int) int {
		if i%2 == 0 {
			return int(b[i/2] >> 4)
		}
		return int(b[i/2] & 0x0f)
	}
	full, rem := p.Bits()/4, p.Bits()%4
	labels := func(n int, last int) string {
		var parts []string
		if last >= 0 {
			parts = append(parts, fmt.Sprintf("%x", last))
		}
		for i := n - 1; i >= 0; i-- {
			parts = append(parts, fmt.Sprintf("%x", nibble(i)))
		}
		return strings.Join(append(parts, "ip6.arpa"), ".")
	}
	if rem == 0 || full == 32 {
		return []string{labels(full, -1)}
	}
	var out []string
	for v := nibble(full); v < nibble(full)+1<<(4-rem); v++ {
		out = append(out, labels(full, v))
	}
	return out
}
