//go:build !openbsd && !darwin

package osnet

// platformTUNName keeps the requested name: Linux, Windows, macOS and
// FreeBSD can name (or rename) the interface.
func platformTUNName(name string) string { return name }
