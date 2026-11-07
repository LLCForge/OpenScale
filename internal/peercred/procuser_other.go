//go:build !windows

package peercred

// ProcessUser is Windows only: elsewhere Identity.UID names the account.
func ProcessUser(int) (string, error) { return "", ErrUnsupported }
