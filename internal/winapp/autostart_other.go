//go:build !windows

package winapp

// SetRunEntry is Windows-only; other systems use XDG autostart or launch
// agents (internal/svcmgr).
func SetRunEntry(bool, string) error { return ErrUnsupported }

// DeleteRunEntry is Windows-only.
func DeleteRunEntry(bool) error { return ErrUnsupported }

// GetRunEntry is Windows-only.
func GetRunEntry(bool) (string, bool, error) { return "", false, ErrUnsupported }
