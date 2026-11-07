package ddns

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"time"
)

// Update replaces the address records of one name.
type Update struct {
	// Zone is the zone the server is authoritative for.
	Zone string
	// Name is the host name inside the zone.
	Name string
	// TTL of the new records (60-86400 seconds; 0 means 300).
	TTL uint32
	// Addrs are the new addresses. For each family present (IPv4, IPv6)
	// the name's records of that family are replaced; a family with no
	// address is left as it is.
	Addrs []netip.Addr
}

const (
	minTTL         = 60
	maxTTL         = 86400
	defaultTTL     = 300
	maxAddrs       = 8
	defaultTimeout = 10 * time.Second
)

// Validate checks the update.
func (u Update) Validate() error {
	zone, name := canonical(u.Zone), canonical(u.Name)
	if _, err := nameWire(zone); err != nil {
		return fmt.Errorf("%w: bölge", ErrBadName)
	}
	if !ValidName(name) || !inZone(name, zone) {
		return fmt.Errorf("%w: ad bölgenin içinde bir ana makine adı olmalı", ErrBadName)
	}
	if u.TTL != 0 && (u.TTL < minTTL || u.TTL > maxTTL) {
		return fmt.Errorf("ddns: TTL %d ile %d saniye arasında olmalı", minTTL, maxTTL)
	}
	if len(u.Addrs) == 0 || len(u.Addrs) > maxAddrs {
		return fmt.Errorf("ddns: 1 ile %d arasında adres verilmeli", maxAddrs)
	}
	for _, a := range u.Addrs {
		if !a.IsValid() || a.Zone() != "" {
			return errors.New("ddns: geçersiz adres")
		}
	}
	return nil
}

// message builds the unsigned UPDATE message (RFC 2136 2.5).
func (u Update) message(id uint16) ([]byte, error) {
	if err := u.Validate(); err != nil {
		return nil, err
	}
	zone, _ := nameWire(canonical(u.Zone))
	name, _ := nameWire(canonical(u.Name))
	ttl := u.TTL
	if ttl == 0 {
		ttl = defaultTTL
	}
	var v4, v6 []netip.Addr
	for _, a := range u.Addrs {
		a = a.Unmap()
		if a.Is4() {
			if !slices.Contains(v4, a) {
				v4 = append(v4, a)
			}
		} else if !slices.Contains(v6, a) {
			v6 = append(v6, a)
		}
	}
	var upd []byte
	count := 0
	family := func(typ uint16, addrs []netip.Addr) {
		if len(addrs) == 0 {
			return
		}
		// Delete the RRset of this type (class ANY, TTL 0, no data).
		upd = append(upd, name...)
		upd = binary.BigEndian.AppendUint16(upd, typ)
		upd = binary.BigEndian.AppendUint16(upd, classANY)
		upd = binary.BigEndian.AppendUint32(upd, 0)
		upd = binary.BigEndian.AppendUint16(upd, 0)
		count++
		for _, a := range addrs {
			raw := a.AsSlice()
			upd = append(upd, name...)
			upd = binary.BigEndian.AppendUint16(upd, typ)
			upd = binary.BigEndian.AppendUint16(upd, classIN)
			upd = binary.BigEndian.AppendUint32(upd, ttl)
			upd = binary.BigEndian.AppendUint16(upd, uint16(len(raw)))
			upd = append(upd, raw...)
			count++
		}
	}
	family(typeA, v4)
	family(typeAAAA, v6)
	b := make([]byte, 12, 12+len(zone)+4+len(upd))
	binary.BigEndian.PutUint16(b[0:], id)
	binary.BigEndian.PutUint16(b[2:], opUpdate<<11)
	binary.BigEndian.PutUint16(b[4:], 1)
	binary.BigEndian.PutUint16(b[8:], uint16(count))
	b = append(b, zone...)
	b = binary.BigEndian.AppendUint16(b, typeSOA)
	b = binary.BigEndian.AppendUint16(b, classIN)
	return append(b, upd...), nil
}

// Client sends signed updates to one authoritative server.
type Client struct {
	// Server is the server's address and port (normally 53).
	Server netip.AddrPort
	Key    Key
	// Timeout bounds one exchange (default 10 s).
	Timeout time.Duration
	// Now is the clock for TSIG (default time.Now).
	Now func() time.Time
}

func randomID() uint16 {
	var b [2]byte
	_, _ = rand.Read(b[:])
	return binary.BigEndian.Uint16(b[:])
}

// Send applies the update. It returns nil only when the server answered
// NOERROR with a valid signature over the answer.
func (c *Client) Send(ctx context.Context, u Update) error {
	if !c.Server.IsValid() || c.Server.Port() == 0 {
		return errors.New("ddns: DNS sunucusunun adresi ve portu gerekli")
	}
	if len(c.Key.Secret) == 0 {
		return ErrBadKey
	}
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	id := randomID()
	msg, err := u.message(id)
	if err != nil {
		return err
	}
	signed, mac := c.Key.sign(msg, nil, tsigVars{time: uint64(now().Unix()), fudge: DefaultFudge})
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	resp, err := exchangeUDP(ctx, c.Server, signed, id)
	if err == nil {
		if h, herr := parseHeader(resp); herr == nil && h.truncated {
			resp, err = exchangeTCP(ctx, c.Server, signed, id)
		}
	}
	if err != nil {
		return fmt.Errorf("ddns: sunucuya ulaşılamadı: %w", err)
	}
	return c.checkResponse(resp, id, mac, uint64(now().Unix()))
}

func (c *Client) checkResponse(resp []byte, id uint16, mac []byte, now uint64) error {
	h, err := parseHeader(resp)
	if err != nil || !h.response || h.id != id || h.opcode != opUpdate {
		return ErrBadResponse
	}
	_, verr := c.Key.verify(resp, mac, now)
	if errors.Is(verr, ErrUnsigned) {
		// An unsigned refusal is reported, an unsigned success is not
		// trusted.
		if h.rcode != rcodeNoError {
			return fmt.Errorf("ddns: %s (yanıt imzasız)", rcodeText(h.rcode))
		}
		return ErrUnsigned
	}
	if verr != nil {
		return verr
	}
	if h.rcode != rcodeNoError {
		return fmt.Errorf("ddns: %s", rcodeText(h.rcode))
	}
	return nil
}

// exchangeUDP sends msg and waits for the answer with the same ID from
// the server's address.
func exchangeUDP(ctx context.Context, server netip.AddrPort, msg []byte, id uint16) ([]byte, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", server.String())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if _, err := conn.Write(msg); err != nil {
		return nil, err
	}
	buf := make([]byte, maxMessage)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, err
		}
		if n >= 12 && binary.BigEndian.Uint16(buf[0:2]) == id {
			return append([]byte{}, buf[:n]...), nil
		}
	}
}

// exchangeTCP is used when the UDP answer was truncated.
func exchangeTCP(ctx context.Context, server netip.AddrPort, msg []byte, id uint16) ([]byte, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", server.String())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	out := binary.BigEndian.AppendUint16(nil, uint16(len(msg)))
	if _, err := conn.Write(append(out, msg...)); err != nil {
		return nil, err
	}
	var l [2]byte
	if _, err := io.ReadFull(conn, l[:]); err != nil {
		return nil, err
	}
	resp := make([]byte, binary.BigEndian.Uint16(l[:]))
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, err
	}
	if len(resp) < 12 || binary.BigEndian.Uint16(resp[0:2]) != id {
		return nil, ErrBadResponse
	}
	return resp, nil
}
