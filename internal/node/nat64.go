package node

import (
	"context"
	"net/netip"
	"sync"
	"time"
)

// NAT64 on IPv6-only networks (#384, ADR-0152). Many mobile operators give
// phones and hotspots only IPv6 and translate to IPv4 with NAT64. A
// coordinator configured by IPv4 address (or by a name with only an A
// record when the resolver does not synthesize) is then unreachable. When
// this host has no usable IPv4 address but has global IPv6, the NAT64
// prefix is discovered from the local resolver as RFC 7050 describes
// (AAAA query for "ipv4only.arpa", RFC 8880) and the coordinator's IPv4
// address is embedded in it (RFC 6052). WireGuard still authenticates the
// coordinator, so a forged prefix can only cost reachability, never trust.

const (
	nat64Name = "ipv4only.arpa"
	// nat64TTL is how long a discovered prefix (or its absence) is kept;
	// a network change clears it earlier.
	nat64TTL = 30 * time.Minute
	// nat64Timeout bounds the discovery query.
	nat64Timeout = 3 * time.Second
)

// The well-known IPv4 addresses of ipv4only.arpa (RFC 7050 section 2.2).
var nat64WKA = [2][4]byte{{192, 0, 0, 170}, {192, 0, 0, 171}}

// nat64Lengths are the prefix lengths of RFC 6052, longest first as RFC
// 7050 section 3 searches them.
var nat64Lengths = [...]int{96, 64, 56, 48, 40, 32}

// nat64Positions returns the byte offsets that carry the IPv4 address for
// prefix length pl (RFC 6052 section 2.2; byte 8 is the zero "u" octet).
func nat64Positions(pl int) [4]int {
	switch pl {
	case 32:
		return [4]int{4, 5, 6, 7}
	case 40:
		return [4]int{5, 6, 7, 9}
	case 48:
		return [4]int{6, 7, 9, 10}
	case 56:
		return [4]int{7, 9, 10, 11}
	case 64:
		return [4]int{9, 10, 11, 12}
	default: // 96
		return [4]int{12, 13, 14, 15}
	}
}

// usableNAT64Prefix refuses prefixes that cannot be a NAT64 prefix.
func usableNAT64Prefix(p netip.Prefix) bool {
	a := p.Addr()
	if !p.IsValid() || !a.Is6() || a.Is4In6() || a.Zone() != "" {
		return false
	}
	return !a.IsUnspecified() && !a.IsLoopback() && !a.IsMulticast() && !a.IsLinkLocalUnicast() && !a.IsInterfaceLocalMulticast()
}

// nat64PrefixFrom finds the NAT64 prefix in the AAAA answers for
// ipv4only.arpa. ok is false when no answer embeds a well-known address.
func nat64PrefixFrom(answers []netip.Addr) (netip.Prefix, bool) {
	for _, a := range answers {
		if !a.Is6() || a.Is4In6() {
			continue
		}
		b := a.As16()
		for _, pl := range nat64Lengths {
			if pl < 96 && b[8] != 0 {
				continue
			}
			pos := nat64Positions(pl)
			for _, wka := range nat64WKA {
				if b[pos[0]] == wka[0] && b[pos[1]] == wka[1] && b[pos[2]] == wka[2] && b[pos[3]] == wka[3] {
					p, err := a.Prefix(pl)
					if err == nil && usableNAT64Prefix(p) {
						return p, true
					}
				}
			}
		}
	}
	return netip.Prefix{}, false
}

// synthesizeNAT64 embeds v4 in prefix (RFC 6052 section 2.2).
func synthesizeNAT64(prefix netip.Prefix, v4 netip.Addr) (netip.Addr, bool) {
	v4 = v4.Unmap()
	if !v4.Is4() || !usableNAT64Prefix(prefix) {
		return netip.Addr{}, false
	}
	pl := prefix.Bits()
	valid := false
	for _, l := range nat64Lengths {
		valid = valid || l == pl
	}
	if !valid {
		return netip.Addr{}, false
	}
	b := prefix.Masked().Addr().As16()
	if pl < 96 {
		b[8] = 0 // the "u" octet
	}
	v := v4.As4()
	pos := nat64Positions(pl)
	for i := range 4 {
		b[pos[i]] = v[i]
	}
	return netip.AddrFrom16(b), true
}

// nat64Translatable reports whether an IPv4 address may go through NAT64:
// only public addresses (the well-known prefix must not carry private
// ones, RFC 6052 section 3.1).
func nat64Translatable(a netip.Addr) bool {
	a = a.Unmap()
	if !a.Is4() || !a.IsGlobalUnicast() || a.IsPrivate() {
		return false
	}
	// 100.64.0.0/10 (shared address space) and 192.0.0.0/24 are not public.
	return !netip.MustParsePrefix("100.64.0.0/10").Contains(a) && !netip.MustParsePrefix("192.0.0.0/24").Contains(a)
}

// ipv6OnlyHost reports whether the host has global IPv6 but no usable IPv4
// address (the tunnel, overlay, loopback and link-local addresses do not
// count).
func ipv6OnlyHost(addrs []interfaceAddr, tunnel string, overlay []netip.Prefix) bool {
	has4, has6 := false, false
	for _, ia := range addrs {
		a := ia.addr.Unmap()
		if ia.iface == tunnel || inAny(overlay, a) || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsUnspecified() || a.IsMulticast() {
			continue
		}
		if a.Is4() {
			has4 = true
		} else if a.IsGlobalUnicast() {
			has6 = true
		}
	}
	return has6 && !has4
}

// nat64Cache keeps the discovered prefix.
type nat64Cache struct {
	mu      sync.Mutex
	prefix  netip.Prefix
	found   bool
	checked time.Time
}

func (c *nat64Cache) reset() {
	c.mu.Lock()
	c.checked = time.Time{}
	c.found = false
	c.mu.Unlock()
}

// get returns the cached prefix; fresh is false when it must be discovered.
func (c *nat64Cache) get(now time.Time) (netip.Prefix, bool, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.checked.IsZero() || now.Sub(c.checked) > nat64TTL || now.Before(c.checked) {
		return netip.Prefix{}, false, false
	}
	return c.prefix, c.found, true
}

func (c *nat64Cache) set(now time.Time, p netip.Prefix, found bool) {
	c.mu.Lock()
	c.prefix, c.found, c.checked = p, found, now
	c.mu.Unlock()
}

// nat64Prefix discovers (or recalls) the NAT64 prefix of this network.
func (e *Engine) nat64Prefix(ctx context.Context) (netip.Prefix, bool) {
	now := e.cfg.Now()
	if p, found, fresh := e.p03.nat64.get(now); fresh {
		return p, found
	}
	rctx, cancel := context.WithTimeout(ctx, nat64Timeout)
	defer cancel()
	addrs, err := e.cfg.Resolve(rctx, nat64Name)
	if err != nil {
		if ctx.Err() == nil {
			e.p03.nat64.set(now, netip.Prefix{}, false)
		}
		return netip.Prefix{}, false
	}
	p, found := nat64PrefixFrom(addrs)
	e.p03.nat64.set(now, p, found)
	if found {
		e.logger.Info("NAT64 prefix discovered", "prefix", p.String())
	}
	return p, found
}

// viaNAT64 returns ap unchanged unless it is a public IPv4 address, this
// host is IPv6-only and the network has a NAT64 prefix: then the
// synthesized IPv6 address is returned.
func (e *Engine) viaNAT64(ctx context.Context, ap netip.AddrPort) netip.AddrPort {
	if e.cfg.DisableNAT64 || !nat64Translatable(ap.Addr()) {
		return ap
	}
	addrs, err := listInterfaceAddrs()
	if err != nil {
		return ap
	}
	tunName := ""
	if e.cfg.TUN != nil {
		tunName, _ = e.cfg.TUN.Name()
	}
	var overlay []netip.Prefix
	if e.cfg.Store != nil {
		doc := e.cfg.Store.Document()
		overlay = []netip.Prefix{doc.IPv4Prefix, doc.IPv6Prefix}
	}
	if !ipv6OnlyHost(addrs, tunName, overlay) {
		return ap
	}
	p, ok := e.nat64Prefix(ctx)
	if !ok {
		return ap
	}
	a, ok := synthesizeNAT64(p, ap.Addr())
	if !ok {
		return ap
	}
	return netip.AddrPortFrom(a, ap.Port())
}
