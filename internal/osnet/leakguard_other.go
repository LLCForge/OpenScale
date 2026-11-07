//go:build !linux

package osnet

// LeakGuardActive is false here: on Windows the kill switch itself holds
// DNS and IPv6 to the tunnel (ADR-0023).
func LeakGuardActive() bool { return false }
