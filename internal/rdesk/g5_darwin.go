//go:build darwin && cgo

package rdesk

/*
#cgo CFLAGS: -x objective-c -fobjc-arc -mmacosx-version-min=12.3
#cgo LDFLAGS: -framework CoreGraphics -framework CoreFoundation -framework Foundation -framework ApplicationServices -weak_framework ScreenCaptureKit
#include <CoreGraphics/CoreGraphics.h>
#include <ApplicationServices/ApplicationServices.h>
#include <Foundation/Foundation.h>
#include <ScreenCaptureKit/ScreenCaptureKit.h>
#include <dlfcn.h>
#include <stdint.h>
#include <string.h>

#define OS_MAX_DISPLAYS 16

// os_displays fills ids and rects (x, y, w, h in points, global display
// coordinates) and returns the count; the main display comes first.
static int os_displays(uint32_t *ids, double *rects) {
	CGDirectDisplayID list[OS_MAX_DISPLAYS];
	uint32_t n = 0;
	if (CGGetActiveDisplayList(OS_MAX_DISPLAYS, list, &n) != kCGErrorSuccess) {
		return -1;
	}
	CGDirectDisplayID main = CGMainDisplayID();
	int k = 0;
	for (int pass = 0; pass < 2; pass++) {
		for (uint32_t i = 0; i < n; i++) {
			if ((pass == 0) != (list[i] == main)) {
				continue;
			}
			CGRect b = CGDisplayBounds(list[i]);
			ids[k] = list[i];
			rects[4*k+0] = b.origin.x;
			rects[4*k+1] = b.origin.y;
			rects[4*k+2] = b.size.width;
			rects[4*k+3] = b.size.height;
			k++;
		}
	}
	return k;
}

static int os_screen_allowed(void) {
	if (@available(macOS 10.15, *)) {
		return CGPreflightScreenCaptureAccess() ? 1 : 0;
	}
	return 1;
}

static int os_input_allowed(void) {
	return AXIsProcessTrusted() ? 1 : 0;
}

// os_draw renders img into dst (w*h RGBA, opaque).
static void os_draw(CGImageRef img, uint8_t *dst, int w, int h) {
	CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
	CGContextRef ctx = CGBitmapContextCreate(dst, (size_t)w, (size_t)h, 8, (size_t)w * 4, cs,
		kCGImageAlphaNoneSkipLast | kCGBitmapByteOrder32Big);
	CGColorSpaceRelease(cs);
	if (ctx == NULL) {
		return;
	}
	CGContextSetInterpolationQuality(ctx, kCGInterpolationLow);
	CGContextDrawImage(ctx, CGRectMake(0, 0, w, h), img);
	CGContextRelease(ctx);
	for (size_t i = 3; i < (size_t)w * (size_t)h * 4; i += 4) {
		dst[i] = 0xff;
	}
}

typedef CGImageRef (*os_create_image_fn)(CGDirectDisplayID);

// os_capture_legacy uses CGDisplayCreateImage, looked up at run time
// because newer SDKs mark it unavailable.
static CGImageRef os_capture_legacy(uint32_t did) {
	static os_create_image_fn fn = NULL;
	static int looked = 0;
	if (!looked) {
		fn = (os_create_image_fn)dlsym(RTLD_DEFAULT, "CGDisplayCreateImage");
		looked = 1;
	}
	return fn != NULL ? fn(did) : NULL;
}

static CGImageRef os_capture_sck(uint32_t did, int w, int h) API_AVAILABLE(macos(14.0)) {
	__block SCShareableContent *content = nil;
	dispatch_semaphore_t sem = dispatch_semaphore_create(0);
	[SCShareableContent getShareableContentExcludingDesktopWindows:NO onScreenWindowsOnly:YES
		completionHandler:^(SCShareableContent *c, NSError *e) {
			content = c;
			dispatch_semaphore_signal(sem);
		}];
	if (dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 3 * NSEC_PER_SEC)) != 0 || content == nil) {
		return NULL;
	}
	SCDisplay *disp = nil;
	for (SCDisplay *d in content.displays) {
		if (d.displayID == did) {
			disp = d;
		}
	}
	if (disp == nil) {
		return NULL;
	}
	SCContentFilter *filter = [[SCContentFilter alloc] initWithDisplay:disp excludingWindows:@[]];
	SCStreamConfiguration *cfg = [[SCStreamConfiguration alloc] init];
	cfg.width = (size_t)w;
	cfg.height = (size_t)h;
	cfg.showsCursor = YES;
	__block CGImageRef out = NULL;
	__block int late = 0;
	NSLock *lock = [[NSLock alloc] init];
	[SCScreenshotManager captureImageWithFilter:filter configuration:cfg
		completionHandler:^(CGImageRef img, NSError *e) {
			[lock lock];
			if (!late && img != NULL) {
				out = CGImageRetain(img);
			}
			[lock unlock];
			dispatch_semaphore_signal(sem);
		}];
	if (dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC)) != 0) {
		[lock lock];
		late = 1;
		CGImageRef o = out;
		out = NULL;
		[lock unlock];
		if (o != NULL) {
			CGImageRelease(o);
		}
		return NULL;
	}
	return out;
}

// os_capture captures display did scaled to w*h points into dst. It
// returns 0, 1 without the Screen Recording permission, 2 when the screen
// cannot be read.
static int os_capture(uint32_t did, int w, int h, uint8_t *dst) {
	if (!os_screen_allowed()) {
		return 1;
	}
	CGImageRef img = NULL;
	@autoreleasepool {
		if (@available(macOS 14.0, *)) {
			img = os_capture_sck(did, w, h);
		}
		if (img == NULL) {
			img = os_capture_legacy(did);
		}
	}
	if (img == NULL) {
		return 2;
	}
	os_draw(img, dst, w, h);
	CGImageRelease(img);
	return 0;
}

static int os_post_mouse(CGEventType type, double x, double y, CGMouseButton b) {
	CGEventRef ev = CGEventCreateMouseEvent(NULL, type, CGPointMake(x, y), b);
	if (ev == NULL) {
		return -1;
	}
	CGEventPost(kCGHIDEventTap, ev);
	CFRelease(ev);
	return 0;
}

static int os_wheel(int dx, int dy) {
	CGEventRef ev = CGEventCreateScrollWheelEvent(NULL, kCGScrollEventUnitLine, 2, dy, dx);
	if (ev == NULL) {
		return -1;
	}
	CGEventPost(kCGHIDEventTap, ev);
	CFRelease(ev);
	return 0;
}

static int os_key(uint16_t code, int down, uint64_t flags) {
	CGEventRef ev = CGEventCreateKeyboardEvent(NULL, (CGKeyCode)code, down ? true : false);
	if (ev == NULL) {
		return -1;
	}
	CGEventSetFlags(ev, (CGEventFlags)flags);
	CGEventPost(kCGHIDEventTap, ev);
	CFRelease(ev);
	return 0;
}

static int os_text(const uint16_t *u, int n) {
	for (int down = 1; down >= 0; down--) {
		CGEventRef ev = CGEventCreateKeyboardEvent(NULL, 0, down ? true : false);
		if (ev == NULL) {
			return -1;
		}
		CGEventKeyboardSetUnicodeString(ev, (UniCharCount)n, (const UniChar *)u);
		CGEventPost(kCGHIDEventTap, ev);
		CFRelease(ev);
	}
	return 0;
}
*/
import "C"

import (
	"errors"
	"fmt"
	"image"
	"unicode/utf16"
	"unsafe"
)

// macOS screen capture (ScreenCaptureKit on macOS 14+, CGDisplayCreateImage
// before) and CGEvent input (ADR-0202). Coordinates are points in the
// global display space, the same space CGEvent uses, so Retina screens
// are sent at their point size. The process needs the "Screen Recording"
// and "Accessibility" permissions (docs/rehberler/macos-uzak-masaustu-izinleri.md).
// Not tried on a real Mac: this repository is built on Windows.

// ErrMacPermission is returned while a privacy permission is missing.
var ErrMacPermission = errors.New("rdesk: macOS izni eksik (Sistem Ayarları > Gizlilik ve Güvenlik: Ekran Kaydı ve Erişilebilirlik)")

// MacPermissions reports the Screen Recording and Accessibility
// permissions of this process (read only; nothing is requested).
func MacPermissions() (screen, input bool) {
	return C.os_screen_allowed() == 1, C.os_input_allowed() == 1
}

type macDisplay struct {
	id     uint32
	bounds image.Rectangle
}

func macDisplays() ([]macDisplay, error) {
	var ids [16]C.uint32_t
	var rects [64]C.double
	n := int(C.os_displays(&ids[0], &rects[0]))
	if n <= 0 {
		return nil, ErrScreenUnavailable
	}
	out := make([]macDisplay, 0, n)
	for i := range n {
		x, y := int(rects[4*i]), int(rects[4*i+1])
		w, h := int(rects[4*i+2]), int(rects[4*i+3])
		if w <= 0 || h <= 0 || w > maxDim || h > maxDim {
			continue
		}
		out = append(out, macDisplay{id: uint32(ids[i]), bounds: image.Rect(x, y, x+w, y+h)})
	}
	if len(out) == 0 {
		return nil, ErrScreenUnavailable
	}
	return out, nil
}

type macCapturer struct {
	tmp []byte
}

// NewScreenCapturer opens the screen.
func NewScreenCapturer() (Capturer, error) {
	if screen, _ := MacPermissions(); !screen {
		return nil, fmt.Errorf("%w: %w", ErrUnsupported, ErrMacPermission)
	}
	return &macCapturer{}, nil
}

func (c *macCapturer) Monitors() ([]Monitor, error) {
	ds, err := macDisplays()
	if err != nil {
		return nil, err
	}
	ms := make([]Monitor, len(ds))
	for i, d := range ds {
		ms[i] = Monitor{Bounds: d.bounds, Primary: i == 0}
	}
	return ms, nil
}

func (c *macCapturer) Capture(r image.Rectangle, dst *image.RGBA) (*image.RGBA, error) {
	if r.Empty() || r.Dx() > maxDim || r.Dy() > maxDim {
		return nil, ErrScreenUnavailable
	}
	if dst == nil || dst.Rect.Dx() != r.Dx() || dst.Rect.Dy() != r.Dy() {
		dst = image.NewRGBA(image.Rect(0, 0, r.Dx(), r.Dy()))
	} else {
		clear(dst.Pix)
	}
	ds, err := macDisplays()
	if err != nil {
		return nil, err
	}
	got := false
	for _, d := range ds {
		part := d.bounds.Intersect(r)
		if part.Empty() {
			continue
		}
		w, h := d.bounds.Dx(), d.bounds.Dy()
		need := w * h * 4
		if cap(c.tmp) < need {
			c.tmp = make([]byte, need)
		}
		buf := c.tmp[:need]
		switch C.os_capture(C.uint32_t(d.id), C.int(w), C.int(h), (*C.uint8_t)(unsafe.Pointer(&buf[0]))) {
		case 0:
		case 1:
			return nil, ErrMacPermission
		default:
			return nil, ErrScreenUnavailable
		}
		for y := part.Min.Y; y < part.Max.Y; y++ {
			so := ((y-d.bounds.Min.Y)*w + (part.Min.X - d.bounds.Min.X)) * 4
			do := dst.PixOffset(part.Min.X-r.Min.X, y-r.Min.Y)
			copy(dst.Pix[do:do+part.Dx()*4], buf[so:so+part.Dx()*4])
		}
		got = true
	}
	if !got {
		return nil, ErrScreenUnavailable
	}
	return dst, nil
}

func (c *macCapturer) Close() error { return nil }

type macInjector struct {
	x, y    float64
	buttons uint8
	flags   uint64
}

// NewInputInjector opens input injection.
func NewInputInjector() (Injector, error) {
	if _, input := MacPermissions(); !input {
		return nil, fmt.Errorf("%w: %w", ErrUnsupported, ErrMacPermission)
	}
	return &macInjector{}, nil
}

// CGEventType values (CGEventTypes.h).
const (
	cgLeftDown     = 1
	cgLeftUp       = 2
	cgRightDown    = 3
	cgRightUp      = 4
	cgMouseMoved   = 5
	cgLeftDragged  = 6
	cgRightDragged = 7
	cgOtherDown    = 25
	cgOtherUp      = 26
	cgOtherDragged = 27
)

func (in *macInjector) Pointer(x, y int, buttons uint8) error {
	fx, fy := float64(x), float64(y)
	moved := fx != in.x || fy != in.y
	if moved {
		t, b := C.CGEventType(cgMouseMoved), C.CGMouseButton(0)
		switch {
		case in.buttons&ButtonLeft != 0:
			t = cgLeftDragged
		case in.buttons&ButtonRight != 0:
			t, b = cgRightDragged, 1
		case in.buttons&ButtonMiddle != 0:
			t, b = cgOtherDragged, 2
		}
		if C.os_post_mouse(t, C.double(fx), C.double(fy), b) != 0 {
			return ErrUnsupported
		}
	}
	in.x, in.y = fx, fy
	for _, bt := range []struct {
		bit      uint8
		down, up C.CGEventType
		button   C.CGMouseButton
	}{
		{ButtonLeft, cgLeftDown, cgLeftUp, 0},
		{ButtonRight, cgRightDown, cgRightUp, 1},
		{ButtonMiddle, cgOtherDown, cgOtherUp, 2},
	} {
		was, now := in.buttons&bt.bit != 0, buttons&bt.bit != 0
		if was == now {
			continue
		}
		t := bt.up
		if now {
			t = bt.down
		}
		if C.os_post_mouse(t, C.double(fx), C.double(fy), bt.button) != 0 {
			return ErrUnsupported
		}
	}
	in.buttons = buttons
	return nil
}

func (in *macInjector) Wheel(dx, dy int) error {
	if C.os_wheel(C.int(dx), C.int(dy)) != 0 {
		return ErrUnsupported
	}
	return nil
}

func (in *macInjector) Key(usage uint16, down bool) error {
	code, ok := macKeyCodes[usage]
	if !ok {
		return nil
	}
	if f := macModifierFlag(usage); f != 0 {
		if down {
			in.flags |= f
		} else {
			in.flags &^= f
		}
	}
	d := C.int(0)
	if down {
		d = 1
	}
	if C.os_key(C.uint16_t(code), d, C.uint64_t(in.flags)) != 0 {
		return ErrUnsupported
	}
	return nil
}

func (in *macInjector) Text(s string) error {
	u := utf16.Encode([]rune(s))
	for len(u) > 0 {
		n := min(len(u), 20)
		if C.os_text((*C.uint16_t)(unsafe.Pointer(&u[0])), C.int(n)) != 0 {
			return ErrUnsupported
		}
		u = u[n:]
	}
	return nil
}

func (in *macInjector) Close() error {
	if in.buttons != 0 {
		_ = in.Pointer(int(in.x), int(in.y), 0)
	}
	return nil
}

// NewSystemClipboard is not implemented on macOS yet.
func NewSystemClipboard() (Clipboard, error) { return nil, ErrUnsupported }
