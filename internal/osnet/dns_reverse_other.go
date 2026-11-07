//go:build !linux

package osnet

import (
	"context"
	"net/netip"
)

// ConfigureReverseDNS is Linux only for now: elsewhere reverse names of the
// network keep their normal resolver.
func ConfigureReverseDNS(context.Context, DNSConfig, netip.Prefix, netip.Prefix) error { return nil }
