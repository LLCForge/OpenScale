//go:build windows

package rdesk

import (
	"errors"
	"fmt"
	"image"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Screen capture with GDI BitBlt (ADR-0055). DXGI desktop duplication is
// faster but needs COM; it is a possible second step. BitBlt sees only the
// desktop of the calling process's session and window station: the
// OpenScale Windows service runs in session 0, so the server must run in
// the interactive user's session (see the ADR).

var (
	procGetDC               = modUser32.NewProc("GetDC")
	procReleaseDC           = modUser32.NewProc("ReleaseDC")
	procEnumDisplayMonitors = modUser32.NewProc("EnumDisplayMonitors")
	procGetMonitorInfoW     = modUser32.NewProc("GetMonitorInfoW")

	procCreateCompatibleDC = modGdi32.NewProc("CreateCompatibleDC")
	procCreateDIBSection   = modGdi32.NewProc("CreateDIBSection")
	procSelectObject       = modGdi32.NewProc("SelectObject")
	procBitBlt             = modGdi32.NewProc("BitBlt")
	procDeleteObject       = modGdi32.NewProc("DeleteObject")
	procDeleteDC           = modGdi32.NewProc("DeleteDC")
	procGdiFlush           = modGdi32.NewProc("GdiFlush")
)

const (
	srccopy             = 0x00CC0020
	captureblt          = 0x40000000
	dibRGBColors        = 0
	biRGB               = 0
	monitorInfoFPrimary = 1
)

type winRect struct {
	Left, Top, Right, Bottom int32
}

type monitorInfo struct {
	CbSize    uint32
	RcMonitor winRect
	RcWork    winRect
	DwFlags   uint32
}

type bitmapInfoHeader struct {
	BiSize          uint32
	BiWidth         int32
	BiHeight        int32
	BiPlanes        uint16
	BiBitCount      uint16
	BiCompression   uint32
	BiSizeImage     uint32
	BiXPelsPerMeter int32
	BiYPelsPerMeter int32
	BiClrUsed       uint32
	BiClrImportant  uint32
}

type bitmapInfo struct {
	Header bitmapInfoHeader
	Colors [1]uint32
}

type gdiCapturer struct {
	th       *winThread
	screenDC uintptr
	memDC    uintptr
	bitmap   uintptr
	oldObj   uintptr
	bits     unsafe.Pointer
	w, h     int
}

// NewScreenCapturer opens the interactive desktop with GDI.
func NewScreenCapturer() (Capturer, error) {
	c := &gdiCapturer{}
	th, err := startWinThread(c.init, c.release)
	if err != nil {
		return nil, err
	}
	c.th = th
	return c, nil
}

func (c *gdiCapturer) init() error {
	if err := procBitBlt.Find(); err != nil {
		return errors.Join(ErrUnsupported, err)
	}
	dc, _, err := procGetDC.Call(0)
	if dc == 0 {
		return fmt.Errorf("%w: GetDC: %v", ErrUnsupported, err)
	}
	mem, _, err := procCreateCompatibleDC.Call(dc)
	if mem == 0 {
		_, _, _ = procReleaseDC.Call(0, dc)
		return fmt.Errorf("%w: CreateCompatibleDC: %v", ErrUnsupported, err)
	}
	c.screenDC, c.memDC = dc, mem
	return nil
}

func (c *gdiCapturer) freeBitmap() {
	if c.bitmap != 0 {
		_, _, _ = procSelectObject.Call(c.memDC, c.oldObj)
		_, _, _ = procDeleteObject.Call(c.bitmap)
		c.bitmap, c.oldObj, c.bits, c.w, c.h = 0, 0, nil, 0, 0
	}
}

func (c *gdiCapturer) release() {
	c.freeBitmap()
	if c.memDC != 0 {
		_, _, _ = procDeleteDC.Call(c.memDC)
	}
	if c.screenDC != 0 {
		_, _, _ = procReleaseDC.Call(0, c.screenDC)
	}
}

func (c *gdiCapturer) Close() error {
	c.th.close()
	return nil
}

// monitor enumeration goes through one callback created once; NewCallback
// slots are never released.
var (
	enumOnce     sync.Once
	enumCallback uintptr
	enumMu       sync.Mutex
	enumResult   []Monitor
)

func monitorEnumProc(hmon, _ uintptr, _ uintptr, _ uintptr) uintptr {
	mi := monitorInfo{CbSize: uint32(unsafe.Sizeof(monitorInfo{}))}
	if r, _, _ := procGetMonitorInfoW.Call(hmon, uintptr(unsafe.Pointer(&mi))); r == 0 {
		return 1
	}
	b := image.Rect(int(mi.RcMonitor.Left), int(mi.RcMonitor.Top), int(mi.RcMonitor.Right), int(mi.RcMonitor.Bottom))
	if !b.Empty() && len(enumResult) < maxMonitors {
		enumResult = append(enumResult, Monitor{Bounds: b, Primary: mi.DwFlags&monitorInfoFPrimary != 0})
	}
	return 1
}

func (c *gdiCapturer) Monitors() ([]Monitor, error) {
	enumOnce.Do(func() { enumCallback = windows.NewCallback(monitorEnumProc) })
	var out []Monitor
	var callErr error
	err := c.th.run(func() {
		enumMu.Lock()
		defer enumMu.Unlock()
		enumResult = nil
		if r, _, e := procEnumDisplayMonitors.Call(0, 0, enumCallback, 0); r == 0 {
			callErr = fmt.Errorf("EnumDisplayMonitors: %v", e)
			return
		}
		out = enumResult
		enumResult = nil
	})
	if err != nil {
		return nil, err
	}
	if callErr != nil {
		return nil, callErr
	}
	if len(out) == 0 {
		return nil, errors.New("rdesk: monitör bulunamadı")
	}
	return out, nil
}

func (c *gdiCapturer) ensureBitmap(w, h int) error {
	if c.bitmap != 0 && c.w == w && c.h == h {
		return nil
	}
	c.freeBitmap()
	bi := bitmapInfo{Header: bitmapInfoHeader{
		BiWidth: int32(w), BiHeight: -int32(h), // negative: top-down rows
		BiPlanes: 1, BiBitCount: 32, BiCompression: biRGB,
	}}
	bi.Header.BiSize = uint32(unsafe.Sizeof(bi.Header))
	var bits unsafe.Pointer
	hbm, _, err := procCreateDIBSection.Call(c.memDC, uintptr(unsafe.Pointer(&bi)), dibRGBColors, uintptr(unsafe.Pointer(&bits)), 0, 0)
	if hbm == 0 || bits == nil {
		return fmt.Errorf("CreateDIBSection: %v", err)
	}
	old, _, _ := procSelectObject.Call(c.memDC, hbm)
	c.bitmap, c.oldObj, c.bits, c.w, c.h = hbm, old, bits, w, h
	return nil
}

func (c *gdiCapturer) Capture(r image.Rectangle, dst *image.RGBA) (*image.RGBA, error) {
	w, h := r.Dx(), r.Dy()
	if w <= 0 || h <= 0 || w > maxDim*4 || h > maxDim*4 {
		return nil, errors.New("rdesk: geçersiz yakalama alanı")
	}
	if dst == nil || dst.Rect.Dx() != w || dst.Rect.Dy() != h || dst.Rect.Min != (image.Point{}) {
		dst = image.NewRGBA(image.Rect(0, 0, w, h))
	}
	var capErr error
	err := c.th.run(func() {
		if err := c.ensureBitmap(w, h); err != nil {
			capErr = err
			return
		}
		ok, _, e := procBitBlt.Call(c.memDC, 0, 0, uintptr(w), uintptr(h), c.screenDC,
			uintptr(int32(r.Min.X)), uintptr(int32(r.Min.Y)), srccopy|captureblt)
		if ok == 0 {
			// The secure desktop (UAC prompt, lock screen) cannot be read
			// from the user's session.
			capErr = fmt.Errorf("%w: BitBlt: %v", ErrScreenUnavailable, e)
			return
		}
		_, _, _ = procGdiFlush.Call()
		src := unsafe.Slice((*byte)(c.bits), w*h*4)
		bgraToRGBA(dst.Pix, src)
	})
	if err != nil {
		return nil, err
	}
	if capErr != nil {
		return nil, capErr
	}
	return dst, nil
}

// bgraToRGBA converts GDI's BGRX pixels to opaque RGBA.
func bgraToRGBA(dst, src []byte) {
	for i := 0; i+3 < len(src) && i+3 < len(dst); i += 4 {
		dst[i], dst[i+1], dst[i+2], dst[i+3] = src[i+2], src[i+1], src[i], 0xff
	}
}
