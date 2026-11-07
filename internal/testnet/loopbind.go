// Package testnet holds helpers for tests that run real WireGuard engines.
//
// LoopbackBind listens only on 127.0.0.1. The default wireguard-go bind
// listens on every interface, which makes Windows Defender Firewall ask the
// user to allow each freshly built test binary. Tests never need traffic
// from other machines, so binding to loopback avoids the prompt entirely.
package testnet

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
)

var loopback = netip.AddrFrom4([4]byte{127, 0, 0, 1})

// LoopbackBind is a conn.Bind that sends and receives IPv4 UDP on 127.0.0.1.
type LoopbackBind struct {
	mu sync.Mutex
	c  *net.UDPConn
}

// NewLoopbackBind returns a closed LoopbackBind; it matches conn.NewDefaultBind.
func NewLoopbackBind() conn.Bind { return &LoopbackBind{} }

// Open listens on 127.0.0.1:port (port 0 picks a free port).
func (b *LoopbackBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.c != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	c, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(loopback, port)))
	if err != nil {
		return nil, 0, err
	}
	b.c = c
	recv := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		n, from, err := c.ReadFromUDPAddrPort(packets[0])
		if err != nil {
			return 0, err
		}
		sizes[0] = n
		eps[0] = &conn.StdNetEndpoint{AddrPort: netip.AddrPortFrom(from.Addr().Unmap(), from.Port())}
		return 1, nil
	}
	return []conn.ReceiveFunc{recv}, uint16(c.LocalAddr().(*net.UDPAddr).Port), nil
}

// Close stops the listener; receive functions return an error afterwards.
func (b *LoopbackBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.c == nil {
		return nil
	}
	err := b.c.Close()
	b.c = nil
	return err
}

// SetMark is a no-op: loopback traffic never needs routing marks.
func (b *LoopbackBind) SetMark(uint32) error { return nil }

// Send writes each buffer to the endpoint, which must be an IPv4 address.
func (b *LoopbackBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	b.mu.Lock()
	c := b.c
	b.mu.Unlock()
	if c == nil {
		return net.ErrClosed
	}
	dst, err := netip.ParseAddrPort(ep.DstToString())
	if err != nil {
		return fmt.Errorf("testnet: endpoint %q: %w", ep.DstToString(), err)
	}
	if !dst.Addr().Unmap().Is4() {
		return errors.New("testnet: loopback bind sends IPv4 only")
	}
	dst = netip.AddrPortFrom(dst.Addr().Unmap(), dst.Port())
	for _, buf := range bufs {
		if _, err := c.WriteToUDPAddrPort(buf, dst); err != nil {
			return err
		}
	}
	return nil
}

// ParseEndpoint parses "ip:port".
func (b *LoopbackBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &conn.StdNetEndpoint{AddrPort: ap}, nil
}

// BatchSize is 1: one packet per receive call is enough for tests.
func (b *LoopbackBind) BatchSize() int { return 1 }
