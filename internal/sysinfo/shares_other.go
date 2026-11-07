//go:build !linux && !windows

package sysinfo

// listShares is not implemented on macOS and the BSDs yet: their shares
// are not reported (ADR-0226).
func listShares() []Share { return nil }
