package sysinfo

import (
	"net/netip"
	"slices"
)

// Listening services (F-220, #340, ADR-0108).
//
// The report carries the TCP ports this computer listens on at an address
// other devices could reach (not loopback), so the owner's panel can say
// "RDP is open here and no rule allows it". Like the rest of the report it
// goes only to admin devices through the tunnel; the coordinator never
// receives it. Only port numbers are sent: no process names, no addresses.

// MaxListen bounds the listening ports of one report.
const MaxListen = 32

// maxListenCompact is what is kept when the full report does not fit one
// datagram.
const maxListenCompact = 12

// listenEntry is one listening socket read from the operating system.
type listenEntry struct {
	addr netip.Addr
	port uint16
}

// ListeningPorts returns the TCP ports listening on a non-loopback address,
// sorted and without duplicates, at most MaxListen. It returns nil when the
// table cannot be read; it never fails.
func ListeningPorts() []uint16 {
	return pickPorts(listeningSockets())
}

// pickPorts keeps the ports reachable from outside this computer.
func pickPorts(entries []listenEntry) []uint16 {
	var out []uint16
	for _, e := range entries {
		a := e.addr.Unmap()
		if e.port == 0 || !a.IsValid() || a.IsLoopback() {
			continue
		}
		out = append(out, e.port)
	}
	return normalizePorts(out)
}

// normalizePorts sorts, removes duplicates and zero, and caps the list.
// It is applied to reports from other computers too.
func normalizePorts(ports []uint16) []uint16 {
	if len(ports) == 0 {
		return nil
	}
	out := slices.Clone(ports)
	out = slices.DeleteFunc(out, func(p uint16) bool { return p == 0 })
	slices.Sort(out)
	out = slices.Compact(out)
	if len(out) > MaxListen {
		out = out[:MaxListen]
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
