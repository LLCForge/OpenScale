//go:build darwin

package osnet

import (
	"context"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/openscale/openscale/internal/trust"
)

// NewExitRouter returns the OS router for using an exit node (ADR-0100).
func NewExitRouter() interface {
	Enable(trust.Device, *trust.Document, string, conn.Bind) error
	Disable() error
} {
	return hostDarwinExit()
}

// EnableExitNAT: a Mac cannot be an exit node yet (forwarding and pf NAT
// are left for later; ADR-0100).
func EnableExitNAT(context.Context, ExitNAT) error { return ErrExitUnsupported }

// DisableExitNAT is a no-op on macOS.
func DisableExitNAT(context.Context) error { return nil }
