//go:build !windows && !linux

package autoupdate

// DefaultPaths: macOS and the rest have no installed service the updater
// can replace (Android updates through its own APK).
func DefaultPaths() Paths {
	return Paths{Reason: "Bu işletim sisteminde otomatik güncelleme desteklenmiyor; güncellemeyi elle kurun."}
}

// DefaultCoordinatorStateDir has no default here.
func DefaultCoordinatorStateDir() string { return "" }

// IsDeviceServiceDir is always false here.
func IsDeviceServiceDir(string) bool { return false }
