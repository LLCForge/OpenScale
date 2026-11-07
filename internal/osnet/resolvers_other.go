//go:build !linux

package osnet

// SystemResolvers is not read here; on Windows the kill switch holds the
// DNS client to the tunnel (ADR-0023).
func SystemResolvers() ([]SystemResolver, error) { return nil, nil }

// LeakGuardInstalled is false here: there is no separate leak guard.
func LeakGuardInstalled() (bool, error) { return false, nil }
