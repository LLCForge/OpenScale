//go:build !windows && !darwin

package updater

// PlatformSignature: Linux programs carry no operating system signature;
// the signed release manifest (and the package manager's signature,
// ADR-0091) are the checks there.
func PlatformSignature(string) (SignatureState, error) { return SignatureUnknown, nil }
