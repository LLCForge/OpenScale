package desktop

import "github.com/openscale/openscale/internal/panel"

// peerDetail is the right-hand text of a device in the tray menu: its
// address and whether the tunnel to it is post-quantum or classical
// (ADR-0033). Nothing is added while the state is unknown.
func peerDetail(p panel.PeerInfo) string {
	switch p.PostQuantum {
	case panel.PostQuantumActive:
		return p.IPv4 + "  ·  kuantum sonrası"
	case panel.PostQuantumClassical, panel.PostQuantumUnsupported, panel.PostQuantumOff:
		return p.IPv4 + "  ·  klasik"
	}
	return p.IPv4
}
