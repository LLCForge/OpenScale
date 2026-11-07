//go:build windows

package osnet

import (
	"context"
	"errors"
)

// RecoverExitClient removes the exit node routes and the catch-all NRPT
// rule a crashed run left on iface.
func RecoverExitClient(_ context.Context, iface string) error {
	if !validRecoverInterface(iface) {
		return errors.New("invalid interface name in the change journal")
	}
	(&windowsExitRouter{}).cleanup(iface, nil)
	return nil
}

// RecoverExitNAT does nothing: Windows has no exit node NAT (ADR-0018).
func RecoverExitNAT(context.Context) error { return nil }
