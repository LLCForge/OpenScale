package trust

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// Network range change (F-185, #330, ADR-0136). The owner moves the overlay
// to a new IPv4 and/or IPv6 prefix; every device, invite and coordinator is
// given an address in the new range and the change is published as one
// ordinary root-signed version. Nothing else is rewritten automatically: a
// rule, named address, reserved range or DNS setting that still points into
// the old range is reported and the change is refused, so a stale address
// can never silently end up meaning a different device.

// AddressMove is one address changed by Readdress.
type AddressMove struct {
	// Kind is "device", "invite" or "coordinator".
	Kind string
	Name string
	From netip.Addr
	To   netip.Addr
}

// ErrReaddressStale lists references into the old range that Readdress
// cannot rewrite safely.
var ErrReaddressStale = errors.New("document still refers to the old range")

// Readdress moves the overlay to ipv4 and ipv6. An invalid (zero) prefix
// keeps the current one. Addresses that are already valid host addresses of
// the new range are kept (widening a range moves nothing); the others keep
// their host part when it fits and is free, else they get the lowest free
// address. The document is changed in place; callers work on the next
// version (admin.Network.Prepare), so a failure leaves nothing signed.
func (doc *Document) Readdress(ipv4, ipv6 netip.Prefix) ([]AddressMove, error) {
	oldV4, oldV6 := doc.IPv4Prefix, doc.IPv6Prefix
	if !ipv4.IsValid() {
		ipv4 = oldV4
	}
	if !ipv6.IsValid() {
		ipv6 = oldV6
	}
	if err := validateIPv4Prefix(ipv4); err != nil {
		return nil, err
	}
	if err := validateIPv6Prefix(ipv6); err != nil {
		return nil, err
	}
	if ipv4 == oldV4 && ipv6 == oldV6 {
		return nil, errors.New("the new range is the same as the current one")
	}
	doc.IPv4Prefix, doc.IPv6Prefix = ipv4, ipv6

	r := readdresser{doc: doc, used: map[netip.Addr]bool{doc.DNSResolverIPv4(): true, doc.DNSResolverIPv6(): true}}
	type slot struct {
		kind, name string
		addr       *netip.Addr
		oldP, newP netip.Prefix
	}
	var slots []slot
	add := func(kind, name string, a *netip.Addr) {
		if !a.IsValid() {
			return
		}
		if a.Is4() {
			slots = append(slots, slot{kind, name, a, oldV4, ipv4})
		} else {
			slots = append(slots, slot{kind, name, a, oldV6, ipv6})
		}
	}
	if c := doc.Coordinator; c != nil {
		add("coordinator", coordinatorLabel(*c), &c.IPv4)
		add("coordinator", coordinatorLabel(*c), &c.IPv6)
	}
	for i := range doc.Coordinators {
		c := &doc.Coordinators[i]
		add("coordinator", coordinatorLabel(*c), &c.IPv4)
		add("coordinator", coordinatorLabel(*c), &c.IPv6)
	}
	for i := range doc.Devices {
		d := &doc.Devices[i]
		add("device", d.Name, &d.IPv4)
		add("device", d.Name, &d.IPv6)
	}
	for i := range doc.Invites {
		inv := &doc.Invites[i]
		add("invite", inv.ID, &inv.IPv4)
	}

	// Pass 1: keep what is already a free host address of the new range.
	keep := make([]bool, len(slots))
	for i, s := range slots {
		if isHostAddr(s.newP, *s.addr) && !r.used[*s.addr] {
			r.used[*s.addr] = true
			keep[i] = true
		}
	}
	// Pass 2: move the rest, keeping the host part when possible.
	var moves []AddressMove
	for i, s := range slots {
		if keep[i] {
			continue
		}
		to, err := r.place(*s.addr, s.oldP, s.newP)
		if err != nil {
			return nil, fmt.Errorf("%s %s: %w", s.kind, s.name, err)
		}
		moves = append(moves, AddressMove{Kind: s.kind, Name: s.name, From: *s.addr, To: to})
		*s.addr = to
	}
	if stale := doc.staleReferences(oldV4, oldV6); len(stale) > 0 {
		return nil, fmt.Errorf("%w: %s", ErrReaddressStale, strings.Join(stale, ", "))
	}
	return moves, nil
}

func coordinatorLabel(c Coordinator) string {
	if c.Name != "" {
		return c.Name
	}
	return c.Endpoint
}

type readdresser struct {
	doc  *Document
	used map[netip.Addr]bool
}

func (r *readdresser) free(p netip.Prefix, a netip.Addr) bool {
	return isHostAddr(p, a) && !r.used[a] && !r.doc.reserved(a)
}

// place returns the new address for a, preferring the same host part.
func (r *readdresser) place(a netip.Addr, oldP, newP netip.Prefix) (netip.Addr, error) {
	if c, ok := sameHostPart(a, oldP, newP); ok && r.free(newP, c) {
		r.used[c] = true
		return c, nil
	}
	for c := newP.Addr(); c.IsValid() && newP.Contains(c); c = c.Next() {
		if r.free(newP, c) {
			r.used[c] = true
			return c, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("no free address left in %s", newP)
}

// sameHostPart maps a's host bits under oldP onto newP. It fails when a is
// outside oldP or its host part does not fit into newP.
func sameHostPart(a netip.Addr, oldP, newP netip.Prefix) (netip.Addr, bool) {
	if !oldP.Contains(a) || a.Is4() != newP.Addr().Is4() {
		return netip.Addr{}, false
	}
	b := a.AsSlice()
	base := newP.Masked().Addr().AsSlice()
	for i := range b {
		for bit := 0; bit < 8; bit++ {
			pos := i*8 + bit
			m := byte(0x80 >> bit)
			if pos < oldP.Bits() {
				b[i] &^= m
				continue
			}
			if pos < newP.Bits() && b[i]&m != 0 {
				return netip.Addr{}, false
			}
		}
		b[i] |= base[i]
	}
	out, ok := netip.AddrFromSlice(b)
	return out, ok
}

// staleReferences walks the encoded document and returns every address or
// range that lies in an old prefix but not in the new one. The field path
// is reported so the owner knows what to edit first.
func (doc *Document) staleReferences(oldV4, oldV6 netip.Prefix) []string {
	data, err := json.Marshal(doc)
	if err != nil {
		return []string{"document: " + err.Error()}
	}
	var tree any
	if err := json.Unmarshal(data, &tree); err != nil {
		return []string{"document: " + err.Error()}
	}
	olds := []netip.Prefix{oldV4, oldV6}
	news := []netip.Prefix{doc.IPv4Prefix, doc.IPv6Prefix}
	staleAddr := func(a netip.Addr) bool {
		for i, o := range olds {
			if o.IsValid() && o.Contains(a) && !news[i].Contains(a) {
				return true
			}
		}
		return false
	}
	stalePrefix := func(p netip.Prefix) bool {
		for i, o := range olds {
			if !o.IsValid() || p.Addr().Is4() != o.Addr().Is4() || !p.Overlaps(o) {
				continue
			}
			n := news[i]
			if !(n.Bits() <= p.Bits() && n.Contains(p.Addr())) {
				return true
			}
		}
		return false
	}
	var out []string
	var walk func(path string, v any)
	walk = func(path string, v any) {
		switch t := v.(type) {
		case map[string]any:
			keys := make([]string, 0, len(t))
			for k := range t {
				keys = append(keys, k)
			}
			slices.Sort(keys)
			for _, k := range keys {
				if path == "" && (k == "ipv4_prefix" || k == "ipv6_prefix") {
					continue
				}
				walk(joinPath(path, k), t[k])
			}
		case []any:
			for i, e := range t {
				walk(fmt.Sprintf("%s[%d]", path, i), e)
			}
		case string:
			if a, err := netip.ParseAddr(t); err == nil {
				if staleAddr(a.Unmap()) {
					out = append(out, path+"="+t)
				}
				return
			}
			if p, err := netip.ParsePrefix(t); err == nil {
				if stalePrefix(p.Masked()) {
					out = append(out, path+"="+t)
				}
			}
		}
	}
	walk("", tree)
	return out
}

func joinPath(path, k string) string {
	if path == "" {
		return k
	}
	return path + "." + k
}
