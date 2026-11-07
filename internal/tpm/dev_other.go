//go:build !windows && !linux

package tpm

// Detect is not implemented on this system.
func Detect() (Presence, error) { return Presence{}, ErrUnsupported }

// Open is not implemented on this system.
func Open() (Transport, error) { return nil, ErrUnsupported }
