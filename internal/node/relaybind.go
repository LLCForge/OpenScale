package node

import (
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/openscale/openscale/internal/control"
)

// relayEndpointPrefix marks a peer endpoint reached through the coordinator
// (ADR-0017), e.g. "relay-0123...": WireGuard stores and prints it like any
// endpoint, and relayBind sends to it through the coordinator tunnel.
const relayEndpointPrefix = "relay-"

const relayQueueLen = 1024

// relayEndpoint is a peer reached through the coordinator.
type relayEndpoint struct {
	id [control.RelayIDLen]byte
}

func (e *relayEndpoint) ClearSrc()           {}
func (e *relayEndpoint) SrcToString() string { return "" }
func (e *relayEndpoint) DstToString() string {
	return relayEndpointPrefix + hex.EncodeToString(e.id[:])
}
func (e *relayEndpoint) DstToBytes() []byte { return append([]byte("relay"), e.id[:]...) }
func (e *relayEndpoint) DstIP() netip.Addr  { return netip.Addr{} }
func (e *relayEndpoint) SrcIP() netip.Addr  { return netip.Addr{} }

// RelayEndpointString is the endpoint value that routes a peer through the
// coordinator.
func RelayEndpointString(deviceID string) (string, error) {
	raw, err := hex.DecodeString(deviceID)
	if err != nil || len(raw) != control.RelayIDLen {
		return "", errors.New("invalid device id")
	}
	return relayEndpointPrefix + deviceID, nil
}

type relayed struct {
	from [control.RelayIDLen]byte
	data []byte
}

// relayBind wraps the normal UDP bind. Relay endpoints are sent with send,
// which wraps them for the coordinator; relayed packets the engine receives
// from the coordinator come back through an extra receive function.
type relayBind struct {
	conn.Bind
	send func(dst [control.RelayIDLen]byte, pkt []byte) bool
	// forceRelay (F-022) keeps every peer on the relay: UDP is exchanged
	// with the coordinator only, so no direct path ever forms, not even by
	// WireGuard roaming after a peer sends to this device directly.
	forceRelay bool
	coordIP    atomic.Pointer[netip.Addr]
	// extraIPs are the additional coordinators' addresses (ADR-0111),
	// also allowed while relaying is forced.
	extraIPs atomic.Pointer[[]netip.Addr]
	// probes, when set, takes path probes (ADR-0025) out of every receive
	// function before WireGuard sees them.
	probes *prober

	mu     sync.Mutex
	in     chan relayed
	closed chan struct{}
}

func newRelayBind(base conn.Bind, send func([control.RelayIDLen]byte, []byte) bool, forceRelay bool) *relayBind {
	return &relayBind{Bind: base, send: send, forceRelay: forceRelay}
}

// setCoordinator records the coordinator's address, the only direct UDP
// peer allowed while relaying is forced.
func (b *relayBind) setCoordinator(a netip.Addr) {
	a = a.Unmap()
	b.coordIP.Store(&a)
}

// directAllowed reports whether UDP to or from ip may be used.
func (b *relayBind) directAllowed(ip netip.Addr) bool {
	if !b.forceRelay {
		return true
	}
	c := b.coordIP.Load()
	return c != nil && c.IsValid() && ip.Unmap() == *c || b.isExtraCoordinator(ip)
}

// onlyCoordinator wraps a receive function so packets from anyone but the
// coordinator are dropped. Kept packets are moved to the front by copying:
// WireGuard pairs each buffer with its own backing array, so the slices
// themselves must stay in place.
func (b *relayBind) onlyCoordinator(fn conn.ReceiveFunc) conn.ReceiveFunc {
	return func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		n, err := fn(packets, sizes, eps)
		kept := 0
		for i := 0; i < n; i++ {
			if eps[i] == nil || !b.directAllowed(eps[i].DstIP()) {
				continue
			}
			if kept != i {
				sizes[kept] = copy(packets[kept], packets[i][:sizes[i]])
				eps[kept] = eps[i]
			}
			kept++
		}
		return kept, err
	}
}

func (b *relayBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actual, err := b.Bind.Open(port)
	if err != nil {
		return nil, 0, err
	}
	if b.forceRelay {
		for i, fn := range fns {
			fns[i] = b.onlyCoordinator(fn)
		}
	}
	in, closed := make(chan relayed, relayQueueLen), make(chan struct{})
	b.mu.Lock()
	b.in, b.closed = in, closed
	b.mu.Unlock()
	var recv conn.ReceiveFunc = func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		select {
		case r := <-in:
			sizes[0] = copy(packets[0], r.data)
			eps[0] = &relayEndpoint{id: r.from}
			return 1, nil
		case <-closed:
			return 0, net.ErrClosed
		}
	}
	fns = append(fns, recv)
	if b.probes != nil {
		for i, fn := range fns {
			fns[i] = b.probes.intercept(fn)
		}
	}
	return fns, actual, nil
}

// sendTo sends one datagram from the WireGuard socket to a UDP address,
// outside WireGuard (path probes). It honours forced relaying.
func (b *relayBind) sendTo(pkt []byte, to netip.AddrPort) error {
	if !b.directAllowed(to.Addr()) {
		return errors.New("relaying is forced")
	}
	ep, err := b.Bind.ParseEndpoint(to.String())
	if err != nil {
		return err
	}
	return b.Bind.Send([][]byte{pkt}, ep)
}

func (b *relayBind) Close() error {
	b.mu.Lock()
	if b.closed != nil {
		close(b.closed)
		b.closed, b.in = nil, nil
	}
	b.mu.Unlock()
	return b.Bind.Close()
}

func (b *relayBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	re, ok := ep.(*relayEndpoint)
	if !ok {
		if !b.directAllowed(ep.DstIP()) {
			return nil // relaying is forced: never reveal this device directly
		}
		return b.Bind.Send(bufs, ep)
	}
	for _, buf := range bufs {
		// Dropped when the queue is full; WireGuard retransmits handshakes
		// and the transport above recovers data.
		b.send(re.id, buf)
	}
	return nil
}

func (b *relayBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	if rest, ok := strings.CutPrefix(s, relayEndpointPrefix); ok {
		raw, err := hex.DecodeString(rest)
		if err != nil || len(raw) != control.RelayIDLen {
			return nil, errors.New("invalid relay endpoint")
		}
		var e relayEndpoint
		copy(e.id[:], raw)
		return &e, nil
	}
	return b.Bind.ParseEndpoint(s)
}

// BindSocketToInterface4 and 6 pass interface binding (used while an exit
// node is in use) to the underlying bind when it supports it.
func (b *relayBind) BindSocketToInterface4(index uint32, blackhole bool) error {
	if x, ok := b.Bind.(conn.BindSocketToInterface); ok {
		return x.BindSocketToInterface4(index, blackhole)
	}
	return nil
}

func (b *relayBind) BindSocketToInterface6(index uint32, blackhole bool) error {
	if x, ok := b.Bind.(conn.BindSocketToInterface); ok {
		return x.BindSocketToInterface6(index, blackhole)
	}
	return nil
}

// markBind is the bind handed to the ExitRouter. Its SetMark goes through
// the WireGuard device, which stores the mark and applies it again every
// time it reopens its sockets (device up, port change). A mark set directly
// on the bind would be lost on the next reopen.
type markBind struct {
	*relayBind
	setMark func(mark uint32) error
}

func (b markBind) SetMark(mark uint32) error { return b.setMark(mark) }

// deliver hands a packet relayed by the coordinator to WireGuard.
func (b *relayBind) deliver(from [control.RelayIDLen]byte, data []byte) {
	b.mu.Lock()
	in := b.in
	b.mu.Unlock()
	if in == nil {
		return
	}
	select {
	case in <- relayed{from: from, data: append([]byte(nil), data...)}:
	default:
	}
}
