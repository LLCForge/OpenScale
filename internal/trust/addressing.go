package trust

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
)

// Address assignment strategy (ADR-0133, F-050, #267). Without the
// addressing field a new device, invite or coordinator gets the lowest free
// address, exactly as before.

// Address assignment strategies.
const (
	// AssignFirstFree takes the lowest free address (the default).
	AssignFirstFree = ""
	// AssignSequential continues after the highest assigned address and
	// wraps around only when the range is used up, so a freed address is
	// not handed to the next device right away.
	AssignSequential = "sequential"
	// AssignRandom takes a random free address.
	AssignRandom = "random"
)

// MaxReservedRanges bounds the reserved address ranges.
const MaxReservedRanges = 16

// randomAddrTries bounds random picks before falling back to a scan.
const randomAddrTries = 128

// addrRandom is the randomness of AssignRandom (tests replace it).
var addrRandom io.Reader = rand.Reader

// Addressing is the owner's address assignment setting.
type Addressing struct {
	Strategy string `json:"strategy,omitempty"`
	// Reserved ranges are never handed out automatically; the owner places
	// chosen devices there (SetDeviceAddress), which keeps a pool of
	// addresses for, for example, servers.
	Reserved []netip.Prefix `json:"reserved,omitempty"`
}

func (doc *Document) validateAddressing() error {
	a := doc.Addressing
	if a == nil {
		return nil
	}
	switch a.Strategy {
	case AssignFirstFree, AssignSequential, AssignRandom:
	default:
		return fmt.Errorf("unknown address strategy %q", a.Strategy)
	}
	if len(a.Reserved) > MaxReservedRanges {
		return fmt.Errorf("at most %d reserved ranges are allowed", MaxReservedRanges)
	}
	for i, p := range a.Reserved {
		if err := doc.validateOverlayPrefix("reserved range", p, p.String()); err != nil {
			return err
		}
		if !doc.insideOverlay(p) {
			return fmt.Errorf("reserved range %s must lie inside the network prefixes", p)
		}
		for _, o := range a.Reserved[:i] {
			if o.Overlaps(p) {
				return fmt.Errorf("reserved ranges %s and %s overlap", o, p)
			}
		}
	}
	return nil
}

func (doc *Document) reserved(a netip.Addr) bool {
	if doc.Addressing == nil {
		return false
	}
	for _, p := range doc.Addressing.Reserved {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// customAddressing reports whether freeAddr must use pickAddr.
func (doc *Document) customAddressing() bool {
	return doc.Addressing != nil && (doc.Addressing.Strategy != AssignFirstFree || len(doc.Addressing.Reserved) > 0)
}

// pickAddr chooses a free host address of p under the addressing setting.
// used holds every address already taken.
func (doc *Document) pickAddr(p netip.Prefix, used map[netip.Addr]bool) (netip.Addr, error) {
	free := func(a netip.Addr) bool { return isHostAddr(p, a) && !used[a] && !doc.reserved(a) }
	scan := func(from netip.Addr) (netip.Addr, bool) {
		for a := from; a.IsValid() && p.Contains(a); a = a.Next() {
			if free(a) {
				return a, true
			}
		}
		return netip.Addr{}, false
	}
	switch doc.Addressing.Strategy {
	case AssignSequential:
		var high netip.Addr
		mark := func(a netip.Addr) {
			if p.Contains(a) && (!high.IsValid() || a.Compare(high) > 0) {
				high = a
			}
		}
		for _, d := range doc.Devices {
			mark(d.IPv4)
			mark(d.IPv6)
		}
		for _, inv := range doc.Invites {
			mark(inv.IPv4)
		}
		if high.IsValid() {
			if a, ok := scan(high.Next()); ok {
				return a, nil
			}
		}
	case AssignRandom:
		bits := p.Addr().BitLen() - p.Bits()
		raw := p.Addr().AsSlice()
		buf := make([]byte, len(raw))
		for range randomAddrTries {
			if _, err := io.ReadFull(addrRandom, buf); err != nil {
				return netip.Addr{}, fmt.Errorf("random address: %w", err)
			}
			cand := slices.Clone(raw)
			for i := range cand {
				for bit := 0; bit < 8; bit++ {
					if i*8+bit >= len(raw)*8-bits {
						m := byte(0x80 >> bit)
						cand[i] = cand[i]&^m | buf[i]&m
					}
				}
			}
			a, _ := netip.AddrFromSlice(cand)
			if free(a) {
				return a, nil
			}
		}
	}
	if a, ok := scan(p.Addr().Next()); ok {
		return a, nil
	}
	return netip.Addr{}, ErrAddressSpaceFull
}

// SetAddressing changes the address assignment setting; nil restores the
// default.
func (doc *Document) SetAddressing(a *Addressing) error {
	if a != nil && a.Strategy == AssignFirstFree && len(a.Reserved) == 0 {
		a = nil
	}
	if a != nil {
		c := *a
		c.Reserved = slices.Clone(a.Reserved)
		a = &c
	}
	return doc.transact(func() error {
		doc.Addressing = a
		return nil
	})
}

// SetDeviceAddress moves a device to another IPv4 address of the network,
// for example into a reserved pool. Rules, DNS and peers follow the new
// address with the next document; open connections to the old address end.
func (doc *Document) SetDeviceAddress(name string, ipv4 netip.Addr) error {
	return doc.transact(func() error {
		idx := slices.IndexFunc(doc.Devices, func(d Device) bool { return d.Name == name })
		if idx < 0 {
			return ErrUnknownDevice
		}
		if !isHostAddr(doc.IPv4Prefix, ipv4) {
			return errors.New("address must be a host address inside ipv4_prefix")
		}
		for _, inv := range doc.Invites {
			if inv.IPv4 == ipv4 {
				return errors.New("address is held by an open invite")
			}
		}
		doc.Devices[idx].IPv4 = ipv4
		return nil
	})
}
