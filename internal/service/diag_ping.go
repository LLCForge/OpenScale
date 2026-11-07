package service

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// icmpProtocol is the IANA number of ICMP for IPv4.
const icmpProtocol = 1

// PingICMPv4 sends one ICMP echo request from src (this device's overlay
// address, so the packet enters the tunnel) to dst and waits for the reply
// until ctx ends (F-014). It needs a raw socket (administrator/root); on
// Linux an unprivileged ICMP socket is tried as well.
func PingICMPv4(ctx context.Context, src, dst netip.Addr) (time.Duration, error) {
	if !src.Is4() || !dst.Is4() {
		return 0, errors.New("ICMP ping yalnızca IPv4 adresleriyle")
	}
	c, err := icmp.ListenPacket("ip4:icmp", src.String())
	privileged := err == nil
	if err != nil {
		c, err = icmp.ListenPacket("udp4", src.String())
		if err != nil {
			return 0, errors.New("ICMP soketi açılamadı (yönetici/root gerekir)")
		}
	}
	defer c.Close()
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(3 * time.Second)
	}
	if err := c.SetDeadline(deadline); err != nil {
		return 0, err
	}
	var idb [4]byte
	if _, err := rand.Read(idb[:]); err != nil {
		return 0, err
	}
	id, seq := int(binary.BigEndian.Uint16(idb[:2])), int(binary.BigEndian.Uint16(idb[2:]))
	payload := []byte("OpenScale-ping")
	msg := icmp.Message{Type: ipv4.ICMPTypeEcho, Code: 0, Body: &icmp.Echo{ID: id, Seq: seq, Data: payload}}
	wb, err := msg.Marshal(nil)
	if err != nil {
		return 0, err
	}
	var to net.Addr = &net.IPAddr{IP: dst.AsSlice()}
	if !privileged {
		to = &net.UDPAddr{IP: dst.AsSlice()}
	}
	// Closing the socket ends a read blocked past a cancelled context.
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	start := time.Now()
	if _, err := c.WriteTo(wb, to); err != nil {
		return 0, err
	}
	rb := make([]byte, 1500)
	for {
		n, peer, err := c.ReadFrom(rb)
		if err != nil {
			if ctx.Err() != nil {
				return 0, errors.New("zaman aşımı")
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return 0, errors.New("zaman aşımı")
			}
			return 0, err
		}
		if !sameIP(peer, dst) {
			continue
		}
		rm, err := icmp.ParseMessage(icmpProtocol, rb[:n])
		if err != nil || rm.Type != ipv4.ICMPTypeEchoReply {
			continue
		}
		echo, ok := rm.Body.(*icmp.Echo)
		// An unprivileged socket gets its ID rewritten by the kernel.
		if !ok || echo.Seq != seq || (privileged && echo.ID != id) {
			continue
		}
		return time.Since(start), nil
	}
}

func sameIP(a net.Addr, want netip.Addr) bool {
	var ip net.IP
	switch v := a.(type) {
	case *net.IPAddr:
		ip = v.IP
	case *net.UDPAddr:
		ip = v.IP
	default:
		return false
	}
	got, ok := netip.AddrFromSlice(ip)
	return ok && got.Unmap() == want
}
