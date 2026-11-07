//go:build !windows

package winapp

// OnSessionLock is Windows only (#501).
func (t *Tray) OnSessionLock(fn func(locked bool)) {}

// OpenURLIsolated is Windows only (#520); elsewhere the default browser
// opens the panel.
func OpenURLIsolated(rawURL, profileDir string) error { return OpenURL(rawURL) }
