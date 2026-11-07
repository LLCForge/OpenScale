//go:build !windows

package winapp

import "time"

// SetClipboardSecret is Windows-only.
func SetClipboardSecret(string, time.Duration) (func(), error) { return func() {}, ErrUnsupported }
