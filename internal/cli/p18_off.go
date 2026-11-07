//go:build openscale_noservices

package cli

// Built with the openscale_noservices tag (#300, ADR-0139): the internal
// CA, certificate, publishing, auth-server and connect commands are not in
// the binary.
func p18Commands() []command { return nil }
