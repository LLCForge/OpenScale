package osnet

import (
	"errors"
	"net/netip"
)

// ErrExitUnsupported is returned where a role is not implemented yet.
var ErrExitUnsupported = errors.New("bu işletim sisteminde henüz desteklenmiyor")

// ExitNAT describes this computer acting as an exit node (ADR-0018).
type ExitNAT struct {
	Interface string
	IPv4      netip.Prefix
	IPv6      netip.Prefix
	// RateLimit bounds each member's forwarded traffic in bytes per second
	// and direction (#83, ADR-0133); 0 is no limit.
	RateLimit uint64
	// BlockPorts are destination ports members may not reach (#402).
	BlockPorts []ExitPort
	// BlockDoH are the owner's DoH servers; TCP and UDP 443 to them is
	// dropped (#403).
	BlockDoH []netip.Prefix
	// Sources choose the public address members leave from (#408).
	Sources []ExitSource
	// Quota adds the data quota block sets (#401, ADR-0155); members are
	// added with SetExitQuotaBlocked.
	Quota bool
}

func (c ExitNAT) validate() error {
	if err := (DNSConfig{Interface: c.Interface, Server: netip.MustParseAddr("192.0.2.1"), Domain: "x.internal"}).validate(); err != nil {
		return err
	}
	if !c.IPv4.IsValid() || !c.IPv4.Addr().Is4() || !c.IPv6.IsValid() || !c.IPv6.Addr().Is6() {
		return errors.New("invalid overlay prefixes")
	}
	return c.validatePolicy() // P04, exit_policy.go
}
