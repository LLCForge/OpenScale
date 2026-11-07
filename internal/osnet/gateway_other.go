//go:build !linux && !windows && !freebsd && !openbsd && !darwin

package osnet

import "net/netip"

func defaultGateways4() ([]netip.Addr, error) { return nil, ErrNoGateway }
