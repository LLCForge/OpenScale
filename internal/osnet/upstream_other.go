//go:build !linux

package osnet

import "context"

// UpstreamRouter is only implemented on Linux exit nodes (ADR-0142).
type UpstreamRouter struct{}

// NewUpstreamRouter returns a router that refuses every change.
func NewUpstreamRouter() *UpstreamRouter { return &UpstreamRouter{} }

// UpstreamSupported reports whether this OS can be an upstream exit.
func UpstreamSupported() bool { return false }

// Apply is not supported here.
func (*UpstreamRouter) Apply(context.Context, UpstreamRoute) error { return ErrExitUnsupported }

// SetDirect is not supported here.
func (*UpstreamRouter) SetDirect(context.Context, bool) error { return ErrExitUnsupported }

// Remove has nothing to remove here.
func (*UpstreamRouter) Remove(context.Context) error { return nil }

// RecoverUpstream has nothing to recover here.
func RecoverUpstream(context.Context) {}
