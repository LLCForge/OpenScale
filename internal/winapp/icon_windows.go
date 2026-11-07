//go:build windows

package winapp

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modUser32 = windows.NewLazySystemDLL("user32.dll")
	modGdi32  = windows.NewLazySystemDLL("gdi32.dll")
	modShell  = windows.NewLazySystemDLL("shell32.dll")

	procGetDC              = modUser32.NewProc("GetDC")
	procReleaseDC          = modUser32.NewProc("ReleaseDC")
	procCreateIconIndirect = modUser32.NewProc("CreateIconIndirect")
	procDestroyIcon        = modUser32.NewProc("DestroyIcon")
	procGetSystemMetrics   = modUser32.NewProc("GetSystemMetrics")

	procCreateDIBSection = modGdi32.NewProc("CreateDIBSection")
	procCreateBitmap     = modGdi32.NewProc("CreateBitmap")
	procDeleteObject     = modGdi32.NewProc("DeleteObject")
)

const (
	smCxSmIcon   = 49
	biBitfields  = 3
	dibRGBColors = 0
)

// bitmapV5Header mirrors BITMAPV5HEADER. A V5 header with explicit channel
// masks is the documented way to hand an alpha channel to CreateIconIndirect.
type bitmapV5Header struct {
	Size          uint32
	Width         int32
	Height        int32
	Planes        uint16
	BitCount      uint16
	Compression   uint32
	SizeImage     uint32
	XPelsPerMeter int32
	YPelsPerMeter int32
	ClrUsed       uint32
	ClrImportant  uint32
	RedMask       uint32
	GreenMask     uint32
	BlueMask      uint32
	AlphaMask     uint32
	CSType        uint32
	Endpoints     [9]int32 // CIEXYZTRIPLE
	GammaRed      uint32
	GammaGreen    uint32
	GammaBlue     uint32
	Intent        uint32
	ProfileData   uint32
	ProfileSize   uint32
	Reserved      uint32
}

type iconInfo struct {
	FIcon    int32
	XHotspot uint32
	YHotspot uint32
	HbmMask  windows.Handle
	HbmColor windows.Handle
}

// smallIconSize returns the system small-icon size (16 at 100% scaling).
func smallIconSize() int {
	n, _, _ := procGetSystemMetrics.Call(smCxSmIcon)
	if int32(n) <= 0 {
		return 16
	}
	return min(int(int32(n)), maxIconSize)
}

// IconFromPNG decodes a PNG, fits it into a size x size square (size <= 0
// means the system small-icon size) and returns an HICON. The caller owns the
// handle and must release it with DestroyIcon.
func IconFromPNG(png []byte, size int) (windows.Handle, error) {
	img, err := decodePNG(png)
	if err != nil {
		return 0, err
	}
	if size <= 0 {
		size = smallIconSize()
	}
	size = min(size, maxIconSize)
	return createIconFromBGRA(scaleToBGRA(img, size), size)
}

// createIconFromBGRA builds an HICON from top-down BGRA pixels with straight
// alpha. The color bitmap is a 32-bit DIB section; the 1-bit mask is all zero
// because the alpha channel defines transparency.
func createIconFromBGRA(pix []byte, size int) (windows.Handle, error) {
	if size <= 0 || size > maxIconSize || len(pix) != size*size*4 {
		return 0, errors.New("simge verisi geçersiz")
	}
	hdr := bitmapV5Header{
		Width:       int32(size),
		Height:      -int32(size), // negative height: top-down rows
		Planes:      1,
		BitCount:    32,
		Compression: biBitfields,
		RedMask:     0x00FF0000,
		GreenMask:   0x0000FF00,
		BlueMask:    0x000000FF,
		AlphaMask:   0xFF000000,
	}
	hdr.Size = uint32(unsafe.Sizeof(hdr))

	hdc, _, _ := procGetDC.Call(0)
	if hdc == 0 {
		return 0, errors.New("simge oluşturulamadı: ekran bağlamı alınamadı")
	}
	var bits unsafe.Pointer
	color, _, callErr := procCreateDIBSection.Call(hdc, uintptr(unsafe.Pointer(&hdr)), dibRGBColors, uintptr(unsafe.Pointer(&bits)), 0, 0)
	procReleaseDC.Call(0, hdc)
	if color == 0 || bits == nil {
		return 0, fmt.Errorf("simge oluşturulamadı: %w", callErr)
	}
	defer procDeleteObject.Call(color)
	copy(unsafe.Slice((*byte)(bits), len(pix)), pix)

	// Monochrome rows are WORD aligned.
	stride := ((size + 15) / 16) * 2
	maskBits := make([]byte, stride*size)
	mask, _, callErr := procCreateBitmap.Call(uintptr(size), uintptr(size), 1, 1, uintptr(unsafe.Pointer(&maskBits[0])))
	if mask == 0 {
		return 0, fmt.Errorf("simge maskesi oluşturulamadı: %w", callErr)
	}
	defer procDeleteObject.Call(mask)

	ii := iconInfo{FIcon: 1, HbmMask: windows.Handle(mask), HbmColor: windows.Handle(color)}
	icon, _, callErr := procCreateIconIndirect.Call(uintptr(unsafe.Pointer(&ii)))
	if icon == 0 {
		return 0, fmt.Errorf("simge oluşturulamadı: %w", callErr)
	}
	return windows.Handle(icon), nil
}

func destroyIcon(h windows.Handle) {
	if h != 0 {
		procDestroyIcon.Call(uintptr(h))
	}
}
