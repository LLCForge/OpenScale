//go:build windows && 386

package webview

// putBounds calls ICoreWebView2Controller.put_Bounds. stdcall on x86
// pushes the RECT by value as four 32-bit words.
func (p comPtr) putBounds(r winRect) error {
	return hrErr(p.call(idxControllerPutBounds, uintptr(r.left), uintptr(r.top), uintptr(r.right), uintptr(r.bottom)))
}
