//go:build !linux

package autoupdate

// matchOwner has nothing to do here: the Windows service reads every file
// in its data directory.
func matchOwner(string, string) error { return nil }
