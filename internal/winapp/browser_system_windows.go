//go:build windows

package winapp

// OpenSystemBrowser opens a loopback panel URL in the default browser.
func OpenSystemBrowser(rawURL string) error { return OpenURL(rawURL) }
