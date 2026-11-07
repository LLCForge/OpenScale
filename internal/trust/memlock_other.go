//go:build !linux && !windows

package trust

// Other platforms (macOS, BSD) do not lock memory yet: macOS needs libc
// calls and the daemon runs on Windows and Linux (ADR-0060).
const memlockSupported = false

func lockPage(addr, n uintptr) error { return nil }

func unlockPage(addr, n uintptr) error { return nil }
