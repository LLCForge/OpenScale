package node

import (
	"errors"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"syscall"

	"golang.zx2c4.com/wireguard/conn"
)

// newBind returns the UDP bind for an engine without a configured one.
// With UDP offload disabled on Linux it is plainBind (F-024); otherwise
// wireguard-go's default bind, which uses UDP GSO/GRO when the kernel and
// the network card support it.
func newBind(disableOffload bool) conn.Bind {
	if disableOffload && runtime.GOOS == "linux" {
		return newPlainBind(netip.IPv4Unspecified(), netip.IPv6Unspecified())
	}
	return DefaultBind()
}

// plainBind is a minimal conn.Bind: one IPv4 and one IPv6 socket on the
// same port, one datagram per call, no segmentation offload and no sticky
// source addresses. It trades throughput for predictability.
type plainBind struct {
	addr4, addr6 netip.Addr

	mu   sync.Mutex
	v4   *net.UDPConn
	v6   *net.UDPConn
	mark uint32
}

func newPlainBind(addr4, addr6 netip.Addr) *plainBind {
	return &plainBind{addr4: addr4, addr6: addr6}
}

func (b *plainBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.v4 != nil || b.v6 != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	var fns []conn.ReceiveFunc
	if b.addr4.IsValid() {
		c, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(b.addr4, port)))
		if err != nil {
			return nil, 0, err
		}
		b.v4 = c
		port = uint16(c.LocalAddr().(*net.UDPAddr).Port) //nolint:gosec // a UDP port
		fns = append(fns, plainReceive(c))
	}
	if b.addr6.IsValid() {
		c, err := net.ListenUDP("udp6", net.UDPAddrFromAddrPort(netip.AddrPortFrom(b.addr6, port)))
		switch {
		case err == nil:
			b.v6 = c
			if b.v4 == nil {
				port = uint16(c.LocalAddr().(*net.UDPAddr).Port) //nolint:gosec // a UDP port
			}
			fns = append(fns, plainReceive(c))
		case b.v4 == nil || !errors.Is(err, syscall.EAFNOSUPPORT) && !isNoIPv6(err):
			b.closeLocked()
			return nil, 0, err
		}
	}
	if len(fns) == 0 {
		return nil, 0, syscall.EAFNOSUPPORT
	}
	if b.mark != 0 {
		if err := b.applyMarkLocked(); err != nil {
			b.closeLocked()
			return nil, 0, err
		}
	}
	return fns, port, nil
}

// isNoIPv6 reports errors of hosts with IPv6 turned off.
func isNoIPv6(err error) bool {
	var op *net.OpError
	return errors.As(err, &op) && errors.Is(op.Err, syscall.EADDRNOTAVAIL)
}

func plainReceive(c *net.UDPConn) conn.ReceiveFunc {
	return func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		n, from, err := c.ReadFromUDPAddrPort(packets[0])
		if err != nil {
			return 0, err
		}
		sizes[0] = n
		eps[0] = &conn.StdNetEndpoint{AddrPort: netip.AddrPortFrom(from.Addr().Unmap(), from.Port())}
		return 1, nil
	}
}

func (b *plainBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.closeLocked()
}

func (b *plainBind) closeLocked() error {
	var err error
	if b.v4 != nil {
		err = b.v4.Close()
		b.v4 = nil
	}
	if b.v6 != nil {
		err = errors.Join(err, b.v6.Close())
		b.v6 = nil
	}
	return err
}

// SetMark sets SO_MARK (Linux) on both sockets now and after every Open.
func (b *plainBind) SetMark(mark uint32) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.mark = mark
	return b.applyMarkLocked()
}

func (b *plainBind) applyMarkLocked() error {
	for _, c := range []*net.UDPConn{b.v4, b.v6} {
		if c == nil {
			continue
		}
		if err := setSocketMark(c, b.mark); err != nil {
			return err
		}
	}
	return nil
}

func (b *plainBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	dst, err := netip.ParseAddrPort(ep.DstToString())
	if err != nil {
		return err
	}
	dst = netip.AddrPortFrom(dst.Addr().Unmap(), dst.Port())
	b.mu.Lock()
	c := b.v4
	if dst.Addr().Is6() {
		c = b.v6
	}
	b.mu.Unlock()
	if c == nil {
		return net.ErrClosed
	}
	for _, buf := range bufs {
		if _, err := c.WriteToUDPAddrPort(buf, dst); err != nil {
			return err
		}
	}
	return nil
}

func (b *plainBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &conn.StdNetEndpoint{AddrPort: ap}, nil
}

// BatchSize is 1: no offload, one datagram at a time.
func (b *plainBind) BatchSize() int { return 1 }
