//go:build !windows && !(darwin && cgo)

package rdesk

// NewSystemVerifier is available on Windows and on macOS builds with cgo
// (ADR-0198). Linux devices use SSH with their own accounts instead.
func NewSystemVerifier() (OSVerifier, error) { return nil, ErrOSLoginUnavailable }
