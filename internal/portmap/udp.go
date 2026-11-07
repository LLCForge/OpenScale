package portmap

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"
)

// defaultRetries is the retransmission schedule for one PCP or NAT-PMP
// request: RFC 6886 starts at 250 ms and doubles; we stop after four tries
// (about 3.75 s) and try again at the next round instead of blocking.
var defaultRetries = []time.Duration{250 * time.Millisecond, 500 * time.Millisecond, time.Second, 2 * time.Second}

// errNoReply means the gateway did not answer.
var errNoReply = errors.New("ağ geçidi yanıt vermedi")

// exchange sends req from the local address to the gateway's port and
// returns the first reply that comes from exactly that address and port
// and that accept takes. Replies from anywhere else are ignored.
func (c *Client) exchange(ctx context.Context, port int, req []byte, accept func([]byte) bool) ([]byte, error) {
	pc, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(c.local, 0)))
	if err != nil {
		return nil, err
	}
	defer pc.Close()
	stop := context.AfterFunc(ctx, func() { _ = pc.SetReadDeadline(time.Unix(1, 0)) })
	defer stop()
	dst := netip.AddrPortFrom(c.gw, uint16(port))
	buf := make([]byte, pcpMaxPacket+1)
	for _, wait := range c.opts.retries {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if _, err := pc.WriteToUDPAddrPort(req, dst); err != nil {
			return nil, err
		}
		deadline := time.Now().Add(wait)
		if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
		_ = pc.SetReadDeadline(deadline)
		for {
			n, from, err := pc.ReadFromUDPAddrPort(buf)
			if err != nil {
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					break
				}
				return nil, err
			}
			if from.Addr().Unmap() != c.gw || from.Port() != uint16(port) || n > pcpMaxPacket {
				continue
			}
			if accept(buf[:n]) {
				return append([]byte(nil), buf[:n]...), nil
			}
		}
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return nil, errNoReply
}
