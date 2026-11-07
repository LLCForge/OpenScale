//go:build windows

package cli

// checkConfigFilePerm: on Windows the long-running roles are the service,
// whose settings live in its protected data folder; --config files are
// read by a foreground "openscale up" with the caller's own rights.
func checkConfigFilePerm(string) error { return nil }
