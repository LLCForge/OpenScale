package leaktest

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/control"
)

const (
	probeTimeout = 2 * time.Second
	probeRetries = 3
	maxDNSName   = 253
)

// NetProber is the real Prober. Its sockets are ordinary ones (no mark, no
// interface binding), so they take the same path as every program's
// traffic: through the exit node when it works.
type NetProber struct{}

var _ Prober = NetProber{}

// WhoAmI sends the who-am-I request up to three times.
func (NetProber) WhoAmI(ctx context.Context, addr netip.AddrPort) (netip.AddrPort, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "udp", addr.String())
	if err != nil {
		return netip.AddrPort{}, err
	}
	defer c.Close()
	var nonce [control.WhoAmINonce]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return netip.AddrPort{}, err
	}
	req := control.NewWhoAmIRequest(nonce)
	buf := make([]byte, 512)
	for range probeRetries {
		if ctx.Err() != nil {
			return netip.AddrPort{}, ctx.Err()
		}
		if _, err := c.Write(req); err != nil {
			return netip.AddrPort{}, err
		}
		_ = c.SetReadDeadline(time.Now().Add(probeTimeout))
		for {
			n, err := c.Read(buf)
			if err != nil {
				break // timeout: send again
			}
			if seen, ok := control.ParseWhoAmIReply(buf[:n], nonce); ok {
				return seen, nil
			}
		}
	}
	return netip.AddrPort{}, errors.New("yanıt yok")
}

// Resolve uses the system resolver.
func (NetProber) Resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// Query asks server for the A record of name and accepts any well-formed
// answer with the same id (NXDOMAIN too: the resolver works).
func (NetProber) Query(ctx context.Context, server netip.Addr, name string) error {
	q, id, err := dnsQuery(name)
	if err != nil {
		return err
	}
	var d net.Dialer
	c, err := d.DialContext(ctx, "udp", netip.AddrPortFrom(server, 53).String())
	if err != nil {
		return err
	}
	defer c.Close()
	buf := make([]byte, 1500)
	for range probeRetries {
		if _, err := c.Write(q); err != nil {
			return err
		}
		_ = c.SetReadDeadline(time.Now().Add(probeTimeout))
		for {
			n, err := c.Read(buf)
			if err != nil {
				break
			}
			if dnsAnswerOK(buf[:n], id) == nil {
				return nil
			}
		}
	}
	return errors.New("yanıt yok")
}

// dnsQuery builds a recursive A query for name.
func dnsQuery(name string) ([]byte, uint16, error) {
	name = strings.TrimSuffix(name, ".")
	if name == "" || len(name) > maxDNSName {
		return nil, 0, fmt.Errorf("geçersiz ad %q", name)
	}
	var idb [2]byte
	if _, err := rand.Read(idb[:]); err != nil {
		return nil, 0, err
	}
	id := binary.BigEndian.Uint16(idb[:])
	b := make([]byte, 12, 12+len(name)+6)
	binary.BigEndian.PutUint16(b[0:], id)
	b[2] = 0x01 // recursion desired
	binary.BigEndian.PutUint16(b[4:], 1)
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return nil, 0, fmt.Errorf("geçersiz ad %q", name)
		}
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	b = append(b, 0, 0, 1, 0, 1) // root, type A, class IN
	return b, id, nil
}

// dnsAnswerOK checks a reply's header: same id, a response, and a code
// other than SERVFAIL or REFUSED.
func dnsAnswerOK(b []byte, id uint16) error {
	if len(b) < 12 || binary.BigEndian.Uint16(b) != id || b[2]&0x80 == 0 {
		return errors.New("geçersiz yanıt")
	}
	switch b[3] & 0x0f {
	case 2:
		return errors.New("SERVFAIL")
	case 5:
		return errors.New("REFUSED")
	}
	return nil
}

// LocalAddrs returns the addresses of the up, non-loopback interfaces
// except skip (the tunnel), without IPv6 link-local ones: what a browser
// could offer as WebRTC host candidates.
func LocalAddrs(skip string) []netip.Addr {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, ifi := range ifs {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 || ifi.Name == skip {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if p, err := netip.ParsePrefix(a.String()); err == nil && !p.Addr().IsLinkLocalUnicast() {
				out = append(out, p.Addr().Unmap())
			}
		}
	}
	return out
}
