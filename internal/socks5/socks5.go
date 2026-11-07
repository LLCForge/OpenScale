// Package socks5 is a minimal SOCKS5 client (RFC 1928) with optional
// username/password authentication (RFC 1929). It supports only CONNECT
// and hands host names to the proxy unresolved, as Tor needs (ADR-0044).
package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"time"
)

const (
	version       = 5
	cmdConnect    = 1
	atypIPv4      = 1
	atypDomain    = 3
	atypIPv6      = 4
	methodNone    = 0x00
	methodUserPwd = 0x02
	methodNoGood  = 0xff
	authVersion   = 1
	// handshakeTimeout bounds the exchange when ctx has no deadline.
	handshakeTimeout = 30 * time.Second
)

// Auth is a username and password (RFC 1929); each is 1 to 255 bytes. Tor
// isolates streams by them (IsolateSOCKSAuth).
type Auth struct {
	Username string
	Password string
}

// ReplyError is a SOCKS5 failure reply.
type ReplyError struct{ Code byte }

var replyNames = map[byte]string{
	1: "genel SOCKS sunucusu hatası", 2: "kurallarca izin verilmedi", 3: "ağa ulaşılamıyor", 4: "ana makineye ulaşılamıyor",
	5: "bağlantı reddedildi", 6: "TTL süresi doldu", 7: "komut desteklenmiyor", 8: "adres türü desteklenmiyor",
}

func (e *ReplyError) Error() string {
	name, ok := replyNames[e.Code]
	if !ok {
		name = "bilinmeyen"
	}
	return fmt.Sprintf("SOCKS5 hata kodu %d (%s)", e.Code, name)
}

// Errors.
var (
	ErrNoAcceptableMethod = errors.New("SOCKS5 vekili kimlik doğrulama yöntemlerimizi kabul etmedi")
	ErrAuthFailed         = errors.New("SOCKS5 kimlik doğrulaması başarısız")
	ErrMalformed          = errors.New("SOCKS5 yanıtı geçersiz")
)

// Dialer opens TCP connections to the proxy.
type Dialer func(ctx context.Context, network, addr string) (net.Conn, error)

// Dial connects to target ("host:port") through the SOCKS5 proxy at proxy.
// A host name in target is sent to the proxy as a name, never resolved
// here. dial opens the connection to the proxy; nil uses net.Dialer.
func Dial(ctx context.Context, proxy, target string, auth *Auth, dial Dialer) (net.Conn, error) {
	req, err := connectRequest(target)
	if err != nil {
		return nil, err
	}
	if auth != nil && (len(auth.Username) == 0 || len(auth.Username) > 255 || len(auth.Password) == 0 || len(auth.Password) > 255) {
		return nil, errors.New("SOCKS5 kullanıcı adı ve parolası 1-255 bayt olmalı")
	}
	if dial == nil {
		d := &net.Dialer{}
		dial = d.DialContext
	}
	c, err := dial(ctx, "tcp", proxy)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(handshakeTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = c.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = c.SetDeadline(time.Unix(1, 0)) })
	if err := handshake(c, req, auth); err != nil {
		stop()
		_ = c.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	if !stop() {
		_ = c.Close()
		return nil, ctx.Err()
	}
	_ = c.SetDeadline(time.Time{})
	return c, nil
}

// connectRequest builds the CONNECT request for target.
func connectRequest(target string) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("geçersiz port %q", portStr)
	}
	req := []byte{version, cmdConnect, 0}
	if a, err := netip.ParseAddr(host); err == nil {
		if a.Zone() != "" {
			return nil, errors.New("bölgeli IPv6 adresi desteklenmiyor")
		}
		a = a.Unmap()
		if a.Is4() {
			b := a.As4()
			req = append(append(req, atypIPv4), b[:]...)
		} else {
			b := a.As16()
			req = append(append(req, atypIPv6), b[:]...)
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return nil, errors.New("ana makine adı 1-255 bayt olmalı")
		}
		req = append(append(req, atypDomain, byte(len(host))), host...)
	}
	return binary.BigEndian.AppendUint16(req, uint16(port)), nil
}

func handshake(rw io.ReadWriter, req []byte, auth *Auth) error {
	greeting := []byte{version, 1, methodNone}
	if auth != nil {
		greeting = []byte{version, 1, methodUserPwd}
	}
	if _, err := rw.Write(greeting); err != nil {
		return err
	}
	var sel [2]byte
	if _, err := io.ReadFull(rw, sel[:]); err != nil {
		return err
	}
	if sel[0] != version {
		return ErrMalformed
	}
	switch {
	case sel[1] == methodNoGood:
		return ErrNoAcceptableMethod
	case auth == nil && sel[1] == methodNone:
	case auth != nil && sel[1] == methodUserPwd:
		msg := []byte{authVersion, byte(len(auth.Username))}
		msg = append(msg, auth.Username...)
		msg = append(msg, byte(len(auth.Password)))
		msg = append(msg, auth.Password...)
		if _, err := rw.Write(msg); err != nil {
			return err
		}
		var st [2]byte
		if _, err := io.ReadFull(rw, st[:]); err != nil {
			return err
		}
		if st[0] != authVersion || st[1] != 0 {
			return ErrAuthFailed
		}
	default:
		// A method we did not offer.
		return ErrNoAcceptableMethod
	}
	if _, err := rw.Write(req); err != nil {
		return err
	}
	_, err := ReadReply(rw)
	return err
}

// ReadReply reads a CONNECT reply and returns the bound address the proxy
// reports (zero for a domain name).
func ReadReply(r io.Reader) (netip.AddrPort, error) {
	var h [4]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return netip.AddrPort{}, err
	}
	if h[0] != version || h[2] != 0 {
		return netip.AddrPort{}, ErrMalformed
	}
	var addr netip.Addr
	switch h[3] {
	case atypIPv4:
		var b [4]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return netip.AddrPort{}, err
		}
		addr = netip.AddrFrom4(b)
	case atypIPv6:
		var b [16]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return netip.AddrPort{}, err
		}
		addr = netip.AddrFrom16(b)
	case atypDomain:
		var n [1]byte
		if _, err := io.ReadFull(r, n[:]); err != nil {
			return netip.AddrPort{}, err
		}
		if _, err := io.CopyN(io.Discard, r, int64(n[0])); err != nil {
			return netip.AddrPort{}, err
		}
	default:
		return netip.AddrPort{}, ErrMalformed
	}
	var p [2]byte
	if _, err := io.ReadFull(r, p[:]); err != nil {
		return netip.AddrPort{}, err
	}
	if h[1] != 0 {
		return netip.AddrPort{}, &ReplyError{Code: h[1]}
	}
	if !addr.IsValid() {
		return netip.AddrPort{}, nil
	}
	return netip.AddrPortFrom(addr, binary.BigEndian.Uint16(p[:])), nil
}
