//go:build !windows

package wintunembed

// Ensure is a no-op outside Windows, where the kernel provides TUN.
func Ensure() error { return nil }
