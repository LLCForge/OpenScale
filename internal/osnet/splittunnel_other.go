//go:build !linux

package osnet

import "context"

// EnableSplitTunnel is not available here (ADR-0134).
func EnableSplitTunnel(context.Context) error { return ErrSplitTunnelUnsupported }

// DisableSplitTunnel is a no-op here.
func DisableSplitTunnel(context.Context) error { return nil }

// JoinBypassGroup is not available here.
func JoinBypassGroup(int) error { return ErrSplitTunnelUnsupported }

// SplitTunnelSupported reports whether this system has per-application
// split tunneling.
func SplitTunnelSupported() bool { return false }
