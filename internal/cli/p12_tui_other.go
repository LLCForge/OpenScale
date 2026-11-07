//go:build !windows

package cli

// enableANSI is a no-op: Unix terminals process escape sequences.
func enableANSI(int) func() { return func() {} }
