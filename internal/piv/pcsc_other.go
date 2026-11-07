//go:build !windows && !(cgo && (linux || darwin))

package piv

// Without cgo there is no PC/SC client: Linux and macOS reach pcscd through
// libpcsclite or PCSC.framework (pcsc_unix.go, cgo), and other systems have
// none (ADR-0123, ADR-0171).

// Readers is not available in this build.
func Readers() ([]string, error) { return nil, ErrUnsupported }

// Card is a connected token (not available in this build).
type Card struct{}

// Open is not available in this build.
func Open(string) (*Card, error) { return nil, ErrUnsupported }

func openCard(string, bool) (*Card, error) { return nil, ErrUnsupported }

// Transmit is not available in this build.
func (*Card) Transmit([]byte) ([]byte, error) { return nil, ErrUnsupported }

// Close is a no-op.
func (*Card) Close() error { return nil }
