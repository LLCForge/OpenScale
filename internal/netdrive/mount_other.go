//go:build !windows

package netdrive

import "net/netip"

func mapWindows(Mount, netip.Addr) error { return ErrUnsupported }

func unmapWindows(Mount) error { return ErrUnsupported }
