//go:build !windows

package securefile

// Only Windows has a persistent operating system key store usable without
// a TPM; see protect.go and ADR-0060.
const protectionAvailable = false

func dpapiProtect([]byte, bool) ([]byte, error) { return nil, ErrProtectionUnavailable }

func dpapiUnprotect([]byte) ([]byte, error) { return nil, ErrProtectionUnavailable }
