//go:build !windows

package winapp

import "github.com/openscale/openscale/internal/secmem"

// ReadSecretSecureDesktop has no counterpart here; the terminal prompt
// is used.
func ReadSecretSecureDesktop(string) (*secmem.Buffer, error) {
	return nil, ErrSecureInputUnavailable
}
