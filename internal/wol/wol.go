// Package wol builds and sends Wake-on-LAN magic packets.
//
// The package only performs the local send: a device on the same LAN as a
// sleeping computer receives a "wake" request through the tunnel (authorized
// by the caller against the signed network document) and calls Send with the
// LAN broadcast address. Nothing here listens on the network.
package wol

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"
)

const (
	// PortDiscard is the conventional Wake-on-LAN UDP port (discard).
	PortDiscard = 9
	// PortEcho is the alternative Wake-on-LAN UDP port (echo).
	PortEcho = 7

	syncLen   = 6
	macRepeat = 16
	macLen    = 6

	defaultRepeat = 3
	maxRepeat     = 10
	repeatGap     = 50 * time.Millisecond
)

var (
	// ErrInvalidMAC is returned for malformed or non-unicast MAC addresses.
	ErrInvalidMAC = errors.New("geçersiz MAC adresi")
	// ErrInvalidPassword is returned for a SecureOn password that is not 4 or 6 bytes.
	ErrInvalidPassword = errors.New("SecureOn parolası 4 veya 6 bayt olmalı")
	// ErrInvalidTarget is returned for an unusable broadcast or source address.
	ErrInvalidTarget = errors.New("geçersiz hedef veya kaynak adresi")
	// ErrInvalidPort is returned for a port other than 7 or 9.
	ErrInvalidPort = errors.New("Wake-on-LAN portu 7 veya 9 olmalı")
)

// ParseMAC parses a 48-bit MAC address written as aa:bb:cc:dd:ee:ff,
// aa-bb-cc-dd-ee-ff, aabb.ccdd.eeff or aabbccddeeff. The zero address and
// group (multicast/broadcast) addresses are rejected because they never
// identify a single network card.
func ParseMAC(s string) (net.HardwareAddr, error) {
	s = strings.TrimSpace(s)
	if len(s) > 17 {
		return nil, ErrInvalidMAC
	}
	var mac net.HardwareAddr
	if len(s) == 12 {
		b, err := hex.DecodeString(s)
		if err != nil {
			return nil, ErrInvalidMAC
		}
		mac = net.HardwareAddr(b)
	} else {
		parsed, err := net.ParseMAC(s)
		if err != nil {
			return nil, ErrInvalidMAC
		}
		mac = parsed
	}
	if err := validateMAC(mac); err != nil {
		return nil, err
	}
	return mac, nil
}

func validateMAC(mac net.HardwareAddr) error {
	if len(mac) != macLen {
		return ErrInvalidMAC
	}
	zero := true
	for _, b := range mac {
		if b != 0 {
			zero = false
			break
		}
	}
	if zero {
		return ErrInvalidMAC
	}
	// The I/G bit marks group addresses (multicast and broadcast).
	if mac[0]&0x01 != 0 {
		return ErrInvalidMAC
	}
	return nil
}

// ParsePassword parses a SecureOn password written either as six hex
// octets (like a MAC address) or as a dotted IPv4-style four-byte value.
// An empty string returns a nil password.
func ParsePassword(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	if a, err := netip.ParseAddr(s); err == nil && a.Is4() {
		b := a.As4()
		return b[:], nil
	}
	if len(s) > 17 {
		return nil, ErrInvalidPassword
	}
	if len(s) == 12 {
		b, err := hex.DecodeString(s)
		if err != nil {
			return nil, ErrInvalidPassword
		}
		return b, nil
	}
	hw, err := net.ParseMAC(s)
	if err != nil || len(hw) != macLen {
		return nil, ErrInvalidPassword
	}
	return []byte(hw), nil
}

// MagicPacket returns the magic packet for mac: six 0xFF bytes, the MAC
// repeated sixteen times and the optional 4- or 6-byte SecureOn password.
func MagicPacket(mac net.HardwareAddr, password []byte) ([]byte, error) {
	if err := validateMAC(mac); err != nil {
		return nil, err
	}
	switch len(password) {
	case 0, 4, 6:
	default:
		return nil, ErrInvalidPassword
	}
	pkt := make([]byte, 0, syncLen+macRepeat*macLen+len(password))
	for range syncLen {
		pkt = append(pkt, 0xFF)
	}
	for range macRepeat {
		pkt = append(pkt, mac...)
	}
	pkt = append(pkt, password...)
	return pkt, nil
}

// Options describes one wake request.
type Options struct {
	// MAC is the hardware address of the computer to wake.
	MAC net.HardwareAddr
	// Password is the optional SecureOn password (4 or 6 bytes).
	Password []byte
	// Broadcast is the IPv4 destination: the LAN's directed broadcast
	// address (see BroadcastAddr) or 255.255.255.255.
	Broadcast netip.Addr
	// Source optionally binds the sending socket to a local IPv4 address so
	// the packet leaves through the LAN interface and never through the
	// tunnel. The zero value lets the operating system choose.
	Source netip.Addr
	// Port is 9 (default) or 7.
	Port int
	// Repeat is how many copies to send (default 3, maximum 10).
	Repeat int
}

// Send transmits the magic packet described by opts.
func Send(ctx context.Context, opts Options) error {
	if opts.Port == 0 {
		opts.Port = PortDiscard
	}
	if opts.Port != PortDiscard && opts.Port != PortEcho {
		return ErrInvalidPort
	}
	dst := opts.Broadcast.Unmap()
	if !dst.Is4() || dst.IsUnspecified() || dst.IsLoopback() || dst.IsMulticast() {
		return ErrInvalidTarget
	}
	return send(ctx, opts, netip.AddrPortFrom(dst, uint16(opts.Port)))
}

// send performs the transmission without destination policy checks so the
// tests can target a loopback receiver.
func send(ctx context.Context, opts Options, dst netip.AddrPort) error {
	pkt, err := MagicPacket(opts.MAC, opts.Password)
	if err != nil {
		return err
	}
	repeat := opts.Repeat
	if repeat <= 0 {
		repeat = defaultRepeat
	}
	if repeat > maxRepeat {
		repeat = maxRepeat
	}
	var laddr *net.UDPAddr
	if opts.Source.IsValid() {
		src := opts.Source.Unmap()
		if !src.Is4() || src.IsUnspecified() || src.IsMulticast() {
			return ErrInvalidTarget
		}
		laddr = net.UDPAddrFromAddrPort(netip.AddrPortFrom(src, 0))
	}
	// Go enables SO_BROADCAST on UDP sockets, so a directed or limited
	// broadcast destination works without extra socket options.
	conn, err := net.DialUDP("udp4", laddr, net.UDPAddrFromAddrPort(dst))
	if err != nil {
		return fmt.Errorf("UDP soketi açılamadı: %w", err)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetWriteDeadline(deadline)
	}
	for i := range repeat {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err := conn.Write(pkt); err != nil {
			return fmt.Errorf("sihirli paket gönderilemedi: %w", err)
		}
		if i < repeat-1 {
			t := time.NewTimer(repeatGap)
			select {
			case <-ctx.Done():
				t.Stop()
				return ctx.Err()
			case <-t.C:
			}
		}
	}
	return nil
}

// BroadcastAddr returns the directed broadcast address of an IPv4 prefix,
// for example 192.168.1.255 for 192.168.1.20/24. Prefixes longer than /30
// have no usable broadcast address.
func BroadcastAddr(p netip.Prefix) (netip.Addr, error) {
	p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits())
	if !p.IsValid() || !p.Addr().Is4() || p.Bits() > 30 {
		return netip.Addr{}, ErrInvalidTarget
	}
	b := p.Addr().As4()
	host := uint32(0xFFFFFFFF) >> uint(p.Bits())
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	v |= host
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}), nil
}

// Target is a local IPv4 LAN address together with its broadcast address.
type Target struct {
	Interface string
	Source    netip.Addr
	Broadcast netip.Addr
}

// Targets lists the up, broadcast-capable, non-loopback IPv4 interfaces.
// skip lets the caller exclude interfaces such as the OpenScale tunnel; it
// may be nil.
func Targets(skip func(name string) bool) ([]Target, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("ağ arayüzleri okunamadı: %w", err)
	}
	var out []Target
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 || ifc.Flags&net.FlagBroadcast == 0 {
			continue
		}
		if skip != nil && skip(ifc.Name) {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipn.IP)
			if !ok {
				continue
			}
			ip = ip.Unmap()
			ones, _ := ipn.Mask.Size()
			if !ip.Is4() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			bc, err := BroadcastAddr(netip.PrefixFrom(ip, ones))
			if err != nil {
				continue
			}
			out = append(out, Target{Interface: ifc.Name, Source: ip, Broadcast: bc})
		}
	}
	return out, nil
}
