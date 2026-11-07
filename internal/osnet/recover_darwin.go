//go:build darwin

package osnet

import (
	"context"
	"fmt"
)

// RecoverExitClient removes the exit node routes of iface and restores the
// DNS servers networksetup changed, after a crash (ADR-0051, ADR-0100).
func RecoverExitClient(ctx context.Context, iface string) error {
	if !validRecoverInterface(iface) {
		return fmt.Errorf("geçersiz arayüz adı %q", iface)
	}
	return hostDarwinExit().recoverClient(ctx, iface)
}

// RecoverExitNAT does nothing: a Mac is never an exit node yet.
func RecoverExitNAT(context.Context) error { return nil }
