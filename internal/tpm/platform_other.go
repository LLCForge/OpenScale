//go:build !linux && !windows

package tpm

// PlatformSealer is not available here: the macOS Secure Enclave needs
// cgo and the Security framework, which the CGO_ENABLED=0 build lacks.
func PlatformSealer(bool) (Sealer, error) { return nil, ErrUnsupported }
