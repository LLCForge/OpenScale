//go:build !linux && !windows

package sysinfo

// listeningSockets is not implemented here yet (macOS, BSD): the
// report simply has no listening ports.
func listeningSockets() []listenEntry { return nil }
