package testnet

import (
	"math/rand/v2"
	"net/netip"
	"sync"
)

// NAT simulation (#54, ADR-0231): an in-memory model of a home or carrier
// NAT, after RFC 4787's mapping and filtering behaviours, for tests of NAT
// traversal logic. No socket is opened; tests pass each datagram through
// Outbound on the sender's NAT and Inbound on the receiver's.

// NATMapping is how the NAT picks the public port of an outgoing flow.
type NATMapping int

const (
	// MapEndpointIndependent reuses one public port for every destination
	// ("easy" NAT, full or restricted cone).
	MapEndpointIndependent NATMapping = iota
	// MapSequential gives each new destination (address and port) the next
	// free public port.
	MapSequential
	// MapRandom gives each new destination a random free public port
	// (symmetric NAT with port randomisation).
	MapRandom
)

// NATFiltering is which incoming datagrams a mapping lets in.
type NATFiltering int

const (
	// FilterEndpointIndependent lets in anything sent to a mapped port.
	FilterEndpointIndependent NATFiltering = iota
	// FilterAddress lets in datagrams from an address the mapping sent to,
	// from any port of it.
	FilterAddress
	// FilterAddressPort lets in datagrams only from an address and port the
	// mapping sent to (like Linux conntrack).
	FilterAddressPort
)

// natFirstPort is the lowest public port the NAT hands out.
const natFirstPort = 1024

type natFlow struct {
	internal netip.AddrPort
	dst      netip.AddrPort // zero for endpoint-independent mapping
}

type natBinding struct {
	internal netip.AddrPort
	sentTo   map[netip.AddrPort]bool
}

// NAT is one simulated NAT with a single public address.
type NAT struct {
	mu        sync.Mutex
	public    netip.Addr
	mapping   NATMapping
	filtering NATFiltering
	rng       *rand.Rand
	next      int
	flows     map[natFlow]uint16
	ports     map[uint16]*natBinding

	dropped, passed int
}

// NewNAT returns a NAT for public with the given behaviour; seed fixes the
// random port choice.
func NewNAT(public netip.Addr, m NATMapping, f NATFiltering, seed uint64) *NAT {
	return &NAT{public: public, mapping: m, filtering: f, rng: rand.New(rand.NewPCG(seed, seed^0x5851f42d4c957f2d)), next: natFirstPort,
		flows: map[natFlow]uint16{}, ports: map[uint16]*natBinding{}}
}

// Public is the NAT's public address.
func (n *NAT) Public() netip.Addr { return n.public }

// Outbound returns the public source of a datagram from internal to dst,
// creating the mapping when needed. ok is false when the NAT has no free
// port left.
func (n *NAT) Outbound(internal, dst netip.AddrPort) (netip.AddrPort, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	flow := natFlow{internal: internal, dst: dst}
	if n.mapping == MapEndpointIndependent {
		flow.dst = netip.AddrPort{}
	}
	port, ok := n.flows[flow]
	if !ok {
		if port, ok = n.allocLocked(); !ok {
			return netip.AddrPort{}, false
		}
		n.flows[flow] = port
		n.ports[port] = &natBinding{internal: internal, sentTo: map[netip.AddrPort]bool{}}
	}
	n.ports[port].sentTo[dst] = true
	return netip.AddrPortFrom(n.public, port), true
}

func (n *NAT) allocLocked() (uint16, bool) {
	if len(n.ports) >= 65536-natFirstPort {
		return 0, false
	}
	switch n.mapping {
	case MapRandom:
		for {
			p := uint16(natFirstPort + n.rng.IntN(65536-natFirstPort)) //nolint:gosec // below 65536
			if n.ports[p] == nil {
				return p, true
			}
		}
	default:
		for n.ports[uint16(n.next)] != nil { //nolint:gosec // wraps below
			n.next++
			if n.next > 65535 {
				n.next = natFirstPort
			}
		}
		p := uint16(n.next) //nolint:gosec // at most 65535
		n.next++
		if n.next > 65535 {
			n.next = natFirstPort
		}
		return p, true
	}
}

// Inbound returns the internal destination of a datagram from from to the
// NAT's public port, or false when the NAT drops it.
func (n *NAT) Inbound(from netip.AddrPort, port uint16) (netip.AddrPort, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	b := n.ports[port]
	ok := b != nil
	if ok {
		switch n.filtering {
		case FilterAddressPort:
			ok = b.sentTo[from]
		case FilterAddress:
			ok = false
			for dst := range b.sentTo {
				if dst.Addr() == from.Addr() {
					ok = true
					break
				}
			}
		}
	}
	if !ok {
		n.dropped++
		return netip.AddrPort{}, false
	}
	n.passed++
	return b.internal, true
}

// Mappings is the number of public ports in use.
func (n *NAT) Mappings() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.ports)
}

// Stats returns how many incoming datagrams were dropped and passed.
func (n *NAT) Stats() (dropped, passed int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.dropped, n.passed
}

// NATNet routes datagrams between hosts behind simulated NATs by public
// address. Hosts without a NAT are not modelled.
type NATNet struct {
	mu   sync.Mutex
	nats map[netip.Addr]*NAT
	sent int
}

// NewNATNet connects the given NATs.
func NewNATNet(nats ...*NAT) *NATNet {
	w := &NATNet{nats: map[netip.Addr]*NAT{}}
	for _, n := range nats {
		w.nats[n.public] = n
	}
	return w
}

// Send passes one datagram from internal behind from's NAT to the public
// endpoint dst. It returns the source address the receiver sees and the
// receiver's internal address, or ok false when a NAT dropped it.
func (w *NATNet) Send(from *NAT, internal, dst netip.AddrPort) (src, to netip.AddrPort, ok bool) {
	w.mu.Lock()
	w.sent++
	rcv := w.nats[dst.Addr()]
	w.mu.Unlock()
	src, ok = from.Outbound(internal, dst)
	if !ok || rcv == nil {
		return netip.AddrPort{}, netip.AddrPort{}, false
	}
	to, ok = rcv.Inbound(src, dst.Port())
	return src, to, ok
}

// Sent is the number of datagrams handed to Send.
func (w *NATNet) Sent() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.sent
}
