package osnet

import (
	"encoding/hex"
	"net/netip"
	"strconv"
	"strings"
)

// Tor exit (ADR-0142, Tor appendix): the exit node sends members' internet
// TCP into the Tor client installed on the host (its TransPort) and their
// DNS to its DNSPort; every other member packet bound for the internet is
// dropped. OpenScale neither embeds nor configures Tor. Only Linux exit
// nodes support it.

// TorRoute is the packet filter state of a Tor exit.
type TorRoute struct {
	// Overlay is the OpenScale interface and its network prefixes.
	Overlay   string
	OverlayV4 netip.Prefix
	OverlayV6 netip.Prefix
	// Self4 is this exit node's own address on the OpenScale network: a
	// redirected connection arrives there, so Tor's TransPort must listen
	// on it. Invalid when unknown; only the health check uses it.
	Self4 netip.Addr
	// TransPort and DNSPort are Tor's transparent proxy and DNS ports.
	TransPort uint16
	DNSPort   uint16
}

// TorHealth is what the host shows about Tor's listeners. It cannot tell
// that the listener is Tor; it tells whether anything listens where the
// filter sends members.
type TorHealth struct {
	// Trans: a TCP listener on TransPort that redirected connections reach
	// (Self4, 0.0.0.0 or ::).
	Trans bool
	// TransLoopbackOnly: TransPort listens, but only on a loopback address,
	// which redirected connections never reach.
	TransLoopbackOnly bool
	// DNS: a UDP socket on 127.0.0.1:DNSPort (or 0.0.0.0/::).
	DNS bool
	// Err is why /proc could not be read; nil otherwise.
	Err error
}

// Up reports whether members' TCP and DNS can reach Tor.
func (h TorHealth) Up() bool { return h.Trans && h.DNS }

// procSocket is one line of /proc/net/{tcp,tcp6,udp,udp6}.
type procSocket struct {
	local netip.AddrPort
	state string
}

// parseProcNet reads /proc/net/tcp-style tables. Lines it cannot read are
// skipped: the health check then reports "not listening", which drops
// members' traffic rather than leaking it.
func parseProcNet(data []byte) []procSocket {
	var out []procSocket
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || !strings.HasSuffix(f[0], ":") {
			continue
		}
		hostHex, portHex, ok := strings.Cut(f[1], ":")
		if !ok || len(portHex) != 4 {
			continue
		}
		port, err := strconv.ParseUint(portHex, 16, 16)
		if err != nil {
			continue
		}
		raw, err := hex.DecodeString(hostHex)
		if err != nil || (len(raw) != 4 && len(raw) != 16) {
			continue
		}
		// The kernel prints each 32-bit word in host (little-endian) order.
		for i := 0; i+4 <= len(raw); i += 4 {
			raw[i], raw[i+1], raw[i+2], raw[i+3] = raw[i+3], raw[i+2], raw[i+1], raw[i]
		}
		a, _ := netip.AddrFromSlice(raw)
		out = append(out, procSocket{local: netip.AddrPortFrom(a.Unmap(), uint16(port)), state: strings.ToUpper(f[3])})
	}
	return out
}

// Socket states in /proc/net: TCP_LISTEN for TCP, TCP_CLOSE for an unbound
// (listening) UDP socket.
const (
	procTCPListen = "0A"
	procUDPClose  = "07"
)

// torHealthFrom judges Tor's listeners from the socket tables.
func torHealthFrom(r TorRoute, tcp, udp []procSocket) TorHealth {
	var h TorHealth
	for _, s := range tcp {
		if s.state != procTCPListen || s.local.Port() != r.TransPort {
			continue
		}
		a := s.local.Addr()
		switch {
		case a.IsUnspecified(), r.Self4.IsValid() && a == r.Self4:
			h.Trans = true
		case !r.Self4.IsValid() && !a.IsLoopback():
			// Own address unknown: any non-loopback listener may be it.
			h.Trans = true
		case a.IsLoopback():
			h.TransLoopbackOnly = true
		}
	}
	if h.Trans {
		h.TransLoopbackOnly = false
	}
	for _, s := range udp {
		if s.state != procUDPClose || s.local.Port() != r.DNSPort {
			continue
		}
		a := s.local.Addr()
		if a.IsUnspecified() || a == netip.AddrFrom4([4]byte{127, 0, 0, 1}) {
			h.DNS = true
		}
	}
	return h
}
