//go:build !linux && !windows && !darwin

package osnet

import (
	"context"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/openscale/openscale/internal/trust"
)

type otherExitRouter struct{}

// NewExitRouter returns the OS router for using an exit node.
func NewExitRouter() interface {
	Enable(trust.Device, *trust.Document, string, conn.Bind) error
	Disable() error
} {
	return otherExitRouter{}
}

func (otherExitRouter) Enable(trust.Device, *trust.Document, string, conn.Bind) error {
	return ErrExitUnsupported
}
func (otherExitRouter) Disable() error { return nil }

// EnableExitNAT is not implemented here.
func EnableExitNAT(context.Context, ExitNAT) error { return ErrExitUnsupported }

// DisableExitNAT is a no-op here.
func DisableExitNAT(context.Context) error { return nil }
