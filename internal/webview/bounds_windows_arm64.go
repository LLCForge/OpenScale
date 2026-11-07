//go:build windows && arm64

package webview

// putBounds calls ICoreWebView2Controller.put_Bounds. ARM64 passes a
// 16-byte RECT by value in two registers: (left, top) and (right, bottom).
func (p comPtr) putBounds(r winRect) error {
	lo := uintptr(uint32(r.left)) | uintptr(uint32(r.top))<<32
	hi := uintptr(uint32(r.right)) | uintptr(uint32(r.bottom))<<32
	return hrErr(p.call(idxControllerPutBounds, lo, hi))
}
