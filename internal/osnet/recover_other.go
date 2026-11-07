//go:build !linux && !windows && !darwin

package osnet

import "context"

// RecoverExitClient does nothing here: exit nodes are not supported.
func RecoverExitClient(context.Context, string) error { return nil }

// RecoverExitNAT does nothing here.
func RecoverExitNAT(context.Context) error { return nil }
