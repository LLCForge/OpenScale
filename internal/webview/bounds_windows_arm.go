//go:build windows && arm

package webview

// putBounds: 32-bit ARM Windows has no WebView2 runtime.
func (p comPtr) putBounds(r winRect) error {
	return ErrUnsupported
}
