//go:build !windows

package winapp

// IsServerCore is false outside Windows.
func IsServerCore() bool { return false }
