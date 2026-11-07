package srvaudit

import (
	"encoding/binary"
	"encoding/hex"
	"io/fs"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// Listener is a socket waiting for traffic on an address other machines
// can reach.
type Listener struct {
	Proto string     `json:"proto"`
	Addr  netip.Addr `json:"addr"`
	Port  uint16     `json:"port"`
}

const (
	tcpListenState = "0A"
	udpBoundState  = "07"
	maxListeners   = 512
)

// ReadListeners reads /proc/net/{tcp,tcp6,udp,udp6} under fsys and returns
// the non-loopback listeners; nil when no table could be read.
func ReadListeners(fsys fs.FS) []Listener {
	var out []Listener
	read := false
	for _, t := range []struct{ file, proto string }{
		{"proc/net/tcp", "tcp"}, {"proc/net/tcp6", "tcp"}, {"proc/net/udp", "udp"}, {"proc/net/udp6", "udp"},
	} {
		data, err := readSmall(fsys, t.file)
		if err != nil {
			continue
		}
		read = true
		out = append(out, parseProcNet(data, t.proto)...)
	}
	if !read {
		return nil
	}
	if out == nil {
		out = []Listener{}
	}
	slices.SortFunc(out, func(a, b Listener) int {
		if a.Proto != b.Proto {
			return strings.Compare(a.Proto, b.Proto)
		}
		return int(a.Port) - int(b.Port)
	})
	return slices.CompactFunc(out, func(a, b Listener) bool { return a.Proto == b.Proto && a.Port == b.Port })
}

// parseProcNet parses one /proc/net table. TCP sockets count when they
// listen; UDP sockets when they are bound and not connected.
func parseProcNet(text, proto string) []Listener {
	var out []Listener
	for i, line := range strings.Split(text, "\n") {
		if i == 0 || len(out) >= maxListeners {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		local, remote, state := f[1], f[2], f[3]
		switch proto {
		case "tcp":
			if state != tcpListenState {
				continue
			}
		case "udp":
			if state != udpBoundState {
				continue
			}
			if _, rport, ok := parseHexAddr(remote); !ok || rport != 0 {
				continue
			}
		default:
			return nil
		}
		addr, port, ok := parseHexAddr(local)
		if !ok || port == 0 || addr.IsLoopback() {
			continue
		}
		out = append(out, Listener{Proto: proto, Addr: addr, Port: port})
	}
	return out
}

// parseHexAddr parses "0100007F:0016" (IPv4) or the 32-digit IPv6 form;
// each 32-bit word is in host (little-endian) order.
func parseHexAddr(s string) (netip.Addr, uint16, bool) {
	a, p, ok := strings.Cut(s, ":")
	if !ok || len(p) != 4 {
		return netip.Addr{}, 0, false
	}
	port, err := strconv.ParseUint(p, 16, 16)
	if err != nil {
		return netip.Addr{}, 0, false
	}
	raw, err := hex.DecodeString(a)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return netip.Addr{}, 0, false
	}
	var b [16]byte
	for w := 0; w < len(raw)/4; w++ {
		binary.BigEndian.PutUint32(b[4*w:], binary.LittleEndian.Uint32(raw[4*w:]))
	}
	if len(raw) == 4 {
		return netip.AddrFrom4([4]byte(b[:4])), uint16(port), true
	}
	return netip.AddrFrom16(b).Unmap(), uint16(port), true
}
