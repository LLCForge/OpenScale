//go:build !linux

package osnet

import "context"

// TorRouter is only implemented on Linux exit nodes (ADR-0142).
type TorRouter struct{}

// NewTorRouter returns a router that refuses every change.
func NewTorRouter() *TorRouter { return &TorRouter{} }

// TorSupported reports whether this OS can be a Tor exit.
func TorSupported() bool { return false }

// Apply is not supported here.
func (*TorRouter) Apply(context.Context, TorRoute) error { return ErrExitUnsupported }

// Remove has nothing to remove here.
func (*TorRouter) Remove(context.Context) error { return nil }

// Probe reports nothing listening here.
func (*TorRouter) Probe(TorRoute) TorHealth { return TorHealth{Err: ErrExitUnsupported} }
