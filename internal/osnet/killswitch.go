package osnet

import (
	"errors"
	"net/netip"
)

// KillSwitchConfig describes the persistent kill switch (ADR-0023). While
// it is installed, the computer can only reach the internet through the
// OpenScale tunnel, even if the service crashes or the computer restarts.
type KillSwitchConfig struct {
	// Interface is the tunnel interface whose traffic is permitted. It is
	// empty before the tunnel exists: then everything except the fixed
	// exceptions (loopback, OpenScale itself, DHCP, DHCPv6, neighbor
	// discovery and optionally the local network) is blocked.
	Interface string
	// AppPath is the program allowed to talk outside the tunnel (WireGuard
	// UDP, coordinator and relay connections). Empty uses the running
	// executable.
	AppPath string
	// AllowLAN permits the local network ranges, except DNS (ADR-0006).
	AllowLAN bool
}

// ErrKillSwitchUnsupported is returned where no persistent kill switch
// exists yet.
var ErrKillSwitchUnsupported = errors.New("kalıcı kill switch bu işletim sisteminde henüz yok")

// ksMatchKind says what a kill switch rule matches.
type ksMatchKind uint8

const (
	// ksMatchAll matches every connection (the default block).
	ksMatchAll ksMatchKind = iota
	// ksMatchLoopback matches loopback traffic.
	ksMatchLoopback
	// ksMatchTunnel matches traffic on the tunnel interface.
	ksMatchTunnel
	// ksMatchApp matches connections of the OpenScale program.
	ksMatchApp
	// ksMatchUDPPorts matches UDP with LocalPort and RemotePort.
	ksMatchUDPPorts
	// ksMatchICMPTypes matches ICMP of Protocol with a type in
	// ICMPLow..ICMPHigh.
	ksMatchICMPTypes
	// ksMatchRemotePrefix matches a remote address in Prefix.
	ksMatchRemotePrefix
	// ksMatchRemotePrefixPort matches a remote address in Prefix and the
	// remote port RemotePort, for every protocol.
	ksMatchRemotePrefixPort
)

// ksRule is one filter of the kill switch plan, independent of the
// operating system API that installs it.
type ksRule struct {
	Name string
	// IPv6 selects the IPv6 layers; otherwise IPv4.
	IPv6 bool
	// Inbound selects the receive/accept layer; otherwise connect.
	Inbound bool
	Permit  bool
	// Weight orders filters inside the sublayer: the highest matching
	// weight decides.
	Weight     uint8
	Kind       ksMatchKind
	Protocol   uint8
	LocalPort  uint16
	RemotePort uint16
	ICMPLow    uint8
	ICMPHigh   uint8
	Prefix     netip.Prefix
}

// Filter weights inside the OpenScale sublayer (0..15). A block of DNS in
// the local ranges sits between the local network permit and the other
// permits, so DNS only ever leaves through the tunnel.
const (
	ksWeightLoopback = 15
	ksWeightTunnel   = 14
	ksWeightApp      = 13
	ksWeightSystem   = 12
	ksWeightLANDNS   = 11
	ksWeightLAN      = 10
	ksWeightBlock    = 0
)

// maxKillSwitchFilters bounds the plan; the fixed filter keys are derived
// from the rule index, so cleanup knows every key that may exist.
const maxKillSwitchFilters = 96

const (
	protoICMPv6      = 58
	protoUDP         = 17
	dnsPort          = 53
	dhcpv6ClientPort = 546
	dhcpv6ServerPort = 547
)

// lanPrefixes4 and lanPrefixes6 are the local ranges allowed when local
// network access is on (ADR-0023): private, link-local, multicast and
// broadcast for IPv4; link-local, unique local and multicast for IPv6.
var (
	lanPrefixes4 = []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("224.0.0.0/4"),
		netip.MustParsePrefix("255.255.255.255/32"),
	}
	lanPrefixes6 = []netip.Prefix{
		netip.MustParsePrefix("fe80::/10"),
		netip.MustParsePrefix("fc00::/7"),
		netip.MustParsePrefix("ff00::/8"),
	}
)

// killSwitchPlan returns the filters of the kill switch. tunnel says whether
// the tunnel interface is known and gets a permit; allowLAN adds the local
// ranges. The same set is installed on the connect and the receive/accept
// layers of IPv4 and IPv6.
func killSwitchPlan(tunnel, allowLAN bool) []ksRule {
	var plan []ksRule
	for _, v6 := range []bool{false, true} {
		for _, in := range []bool{false, true} {
			add := func(r ksRule) {
				r.IPv6, r.Inbound = v6, in
				plan = append(plan, r)
			}
			add(ksRule{Name: "loopback izni", Permit: true, Weight: ksWeightLoopback, Kind: ksMatchLoopback})
			if tunnel {
				add(ksRule{Name: "tünel arayüzü izni", Permit: true, Weight: ksWeightTunnel, Kind: ksMatchTunnel})
			}
			add(ksRule{Name: "OpenScale programı izni", Permit: true, Weight: ksWeightApp, Kind: ksMatchApp})
			if v6 {
				add(ksRule{Name: "IPv6 komşu keşfi izni", Permit: true, Weight: ksWeightSystem, Kind: ksMatchICMPTypes, Protocol: protoICMPv6, ICMPLow: 133, ICMPHigh: 137})
				// DHCPv6 (RFC 8415): networks that hand out IPv6 addresses
				// or DNS servers this way would otherwise drop the computer.
				add(ksRule{Name: "DHCPv6 izni", Permit: true, Weight: ksWeightSystem, Kind: ksMatchUDPPorts, Protocol: protoUDP, LocalPort: dhcpv6ClientPort, RemotePort: dhcpv6ServerPort})
			} else {
				add(ksRule{Name: "DHCP izni", Permit: true, Weight: ksWeightSystem, Kind: ksMatchUDPPorts, Protocol: protoUDP, LocalPort: 68, RemotePort: 67})
			}
			if allowLAN {
				prefixes := lanPrefixes4
				if v6 {
					prefixes = lanPrefixes6
				}
				for _, p := range prefixes {
					add(ksRule{Name: "yerel ağda DNS engeli", Weight: ksWeightLANDNS, Kind: ksMatchRemotePrefixPort, Prefix: p, RemotePort: dnsPort})
					// DNS over TLS (and QUIC) to a local resolver is DNS
					// outside the tunnel too (#93).
					add(ksRule{Name: "yerel ağda DNS-over-TLS engeli", Weight: ksWeightLANDNS, Kind: ksMatchRemotePrefixPort, Prefix: p, RemotePort: dotPort})
					add(ksRule{Name: "yerel ağ izni", Permit: true, Weight: ksWeightLAN, Kind: ksMatchRemotePrefix, Prefix: p})
				}
			}
			add(ksRule{Name: "varsayılan engel", Weight: ksWeightBlock, Kind: ksMatchAll})
		}
	}
	return plan
}
