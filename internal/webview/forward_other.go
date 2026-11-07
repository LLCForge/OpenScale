//go:build !windows && !(darwin && cgo && !nowebview) && !(linux && cgo && !nowebview)

package webview

// ForwardToOpenWindow exists on Windows, macOS and Linux with cgo; elsewhere every open makes a new
// window (or uses the browser).
func ForwardToOpenWindow(string, TargetCheck) error { return ErrNoOpenWindow }
