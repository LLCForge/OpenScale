//go:build !linux && !windows

package peercred

import "net/netip"

// Lookup is not available here; the token alone decides (ADR-0050).
func Lookup(netip.AddrPort, netip.AddrPort) (Identity, error) { return Identity{}, ErrUnsupported }

func groupMember(string, []string) bool { return false }
