package evilcoord

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
)

// RelayMode is what the malicious relay does with WireGuard packets.
type RelayMode int32

// Relay modes.
const (
	// Pass forwards packets unchanged.
	Pass RelayMode = iota
	// FlipData flips one bit of every transport data message (type 4);
	// handshakes pass, so the tunnel comes up but carries altered data.
	FlipData
	// FlipAll flips one bit of every packet, handshakes included.
	FlipAll
)

// Relay is a UDP relay on 127.0.0.1 between two WireGuard endpoints, the
// way the coordinator relays traffic when no direct path exists. It can
// alter packets in flight. Only loopback addresses are used.
type Relay struct {
	conn    *net.UDPConn
	a, b    netip.AddrPort
	mode    atomic.Int32
	altered atomic.Uint64
	relayed atomic.Uint64
	wg      sync.WaitGroup
}

// NewRelay listens on a free loopback port and relays between a and b.
func NewRelay(a, b netip.AddrPort) (*Relay, error) {
	if !a.Addr().IsLoopback() || !b.Addr().IsLoopback() {
		return nil, errors.New("relay endpoints must be loopback addresses")
	}
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	r := &Relay{conn: c, a: a, b: b}
	r.wg.Add(1)
	go r.loop()
	return r, nil
}

// Addr is the relay's own address, to be given to both peers as the
// other's endpoint.
func (r *Relay) Addr() netip.AddrPort {
	return r.conn.LocalAddr().(*net.UDPAddr).AddrPort()
}

// SetMode changes what the relay does.
func (r *Relay) SetMode(m RelayMode) { r.mode.Store(int32(m)) }

// Stats returns how many packets were relayed and how many were altered.
func (r *Relay) Stats() (relayed, altered uint64) { return r.relayed.Load(), r.altered.Load() }

// Close stops the relay.
func (r *Relay) Close() error {
	err := r.conn.Close()
	r.wg.Wait()
	return err
}

func (r *Relay) loop() {
	defer r.wg.Done()
	buf := make([]byte, 65536)
	for {
		n, from, err := r.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		var to netip.AddrPort
		switch from {
		case r.a:
			to = r.b
		case r.b:
			to = r.a
		default:
			continue
		}
		pkt := buf[:n]
		if n > 0 {
			switch RelayMode(r.mode.Load()) {
			case FlipData:
				if pkt[0] == 4 && n > 32 {
					pkt[n-1] ^= 0x01
					r.altered.Add(1)
				}
			case FlipAll:
				pkt[n-1] ^= 0x01
				r.altered.Add(1)
			}
		}
		r.relayed.Add(1)
		_, _ = r.conn.WriteToUDPAddrPort(pkt, to)
	}
}
