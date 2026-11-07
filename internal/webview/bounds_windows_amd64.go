//go:build windows && amd64

package webview

import "unsafe"

// putBounds calls ICoreWebView2Controller.put_Bounds. The x64 calling
// convention passes a 16-byte RECT by reference to a copy.
func (p comPtr) putBounds(r winRect) error {
	return hrErr(p.call(idxControllerPutBounds, uintptr(unsafe.Pointer(&r))))
}
