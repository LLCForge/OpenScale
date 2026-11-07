//go:build openbsd

package osnet

// platformTUNName: OpenBSD tun units cannot be renamed (see openBSDTUNName).
func platformTUNName(name string) string { return openBSDTUNName(name) }
