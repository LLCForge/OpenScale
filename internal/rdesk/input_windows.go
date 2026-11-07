//go:build windows

package rdesk

import (
	"errors"
	"fmt"
	"unicode/utf16"
	"unsafe"
)

// Input injection with SendInput. It reaches only windows of the same or
// lower integrity level (UIPI) and never the secure desktop; Ctrl+Alt+Del
// cannot be sent.

var (
	procSendInput        = modUser32.NewProc("SendInput")
	procGetSystemMetrics = modUser32.NewProc("GetSystemMetrics")
	procMapVirtualKeyW   = modUser32.NewProc("MapVirtualKeyW")
)

const (
	inputMouse    = 0
	inputKeyboard = 1

	mouseeventfMove        = 0x0001
	mouseeventfLeftDown    = 0x0002
	mouseeventfLeftUp      = 0x0004
	mouseeventfRightDown   = 0x0008
	mouseeventfRightUp     = 0x0010
	mouseeventfMiddleDown  = 0x0020
	mouseeventfMiddleUp    = 0x0040
	mouseeventfWheel       = 0x0800
	mouseeventfHWheel      = 0x1000
	mouseeventfVirtualDesk = 0x4000
	mouseeventfAbsolute    = 0x8000

	keyeventfExtendedKey = 0x0001
	keyeventfKeyUp       = 0x0002
	keyeventfUnicode     = 0x0004

	wheelDelta = 120

	smXVirtualScreen  = 76
	smYVirtualScreen  = 77
	smCXVirtualScreen = 78
	smCYVirtualScreen = 79

	mapvkVKToVSC = 0
)

// mouseInput is MOUSEINPUT; the INPUT union is as large as it.
type mouseInput struct {
	Dx, Dy    int32
	MouseData uint32
	Flags     uint32
	Time      uint32
	ExtraInfo uintptr
}

// keybdInput is KEYBDINPUT.
type keybdInput struct {
	Vk, Scan  uint16
	Flags     uint32
	Time      uint32
	ExtraInfo uintptr
}

// mouseInputEvent and keyInputEvent are INPUT with the matching union
// member; the padding makes both as large as INPUT (40 bytes on 64-bit,
// 28 on 32-bit Windows).
type mouseInputEvent struct {
	Type uint32
	Mi   mouseInput
}

type keyInputEvent struct {
	Type uint32
	Ki   keybdInput
	_    [8]byte
}

type sendInputInjector struct {
	th      *winThread
	buttons uint8
}

// NewInputInjector returns an injector for the interactive desktop.
func NewInputInjector() (Injector, error) {
	if err := procSendInput.Find(); err != nil {
		return nil, errors.Join(ErrUnsupported, err)
	}
	th, err := startWinThread(nil, nil)
	if err != nil {
		return nil, err
	}
	return &sendInputInjector{th: th}, nil
}

func (in *sendInputInjector) Close() error {
	in.th.close()
	return nil
}

func sendMouse(evs []mouseInputEvent) error {
	if len(evs) == 0 {
		return nil
	}
	n, _, err := procSendInput.Call(uintptr(len(evs)), uintptr(unsafe.Pointer(&evs[0])), unsafe.Sizeof(evs[0]))
	if int(n) != len(evs) {
		return fmt.Errorf("SendInput: %v", err)
	}
	return nil
}

func sendKeys(evs []keyInputEvent) error {
	if len(evs) == 0 {
		return nil
	}
	n, _, err := procSendInput.Call(uintptr(len(evs)), uintptr(unsafe.Pointer(&evs[0])), unsafe.Sizeof(evs[0]))
	if int(n) != len(evs) {
		return fmt.Errorf("SendInput: %v", err)
	}
	return nil
}

func metric(i uintptr) int {
	r, _, _ := procGetSystemMetrics.Call(i)
	return int(int32(r))
}

// absCoord maps a virtual desktop coordinate to SendInput's normalized
// 0..65535 range over the virtual desktop.
func absCoord(v, origin, size int) int32 {
	if size <= 1 {
		return 0
	}
	v = clampInt(v-origin, 0, size-1)
	return int32((v*65535 + (size-1)/2) / (size - 1))
}

// buttonEvents returns the SendInput flags that move the button state
// from old to cur.
func buttonEvents(old, cur uint8) []uint32 {
	var out []uint32
	pairs := []struct {
		bit      uint8
		down, up uint32
	}{
		{ButtonLeft, mouseeventfLeftDown, mouseeventfLeftUp},
		{ButtonRight, mouseeventfRightDown, mouseeventfRightUp},
		{ButtonMiddle, mouseeventfMiddleDown, mouseeventfMiddleUp},
	}
	for _, p := range pairs {
		switch {
		case old&p.bit == 0 && cur&p.bit != 0:
			out = append(out, p.down)
		case old&p.bit != 0 && cur&p.bit == 0:
			out = append(out, p.up)
		}
	}
	return out
}

func (in *sendInputInjector) Pointer(x, y int, buttons uint8) error {
	var err error
	if e := in.th.run(func() {
		vx, vy := metric(smXVirtualScreen), metric(smYVirtualScreen)
		vw, vh := metric(smCXVirtualScreen), metric(smCYVirtualScreen)
		abs := mouseInput{Dx: absCoord(x, vx, vw), Dy: absCoord(y, vy, vh)}
		flags := uint32(mouseeventfMove | mouseeventfAbsolute | mouseeventfVirtualDesk)
		evs := []mouseInputEvent{{Type: inputMouse, Mi: mouseInput{Dx: abs.Dx, Dy: abs.Dy, Flags: flags}}}
		for _, f := range buttonEvents(in.buttons, buttons) {
			evs = append(evs, mouseInputEvent{Type: inputMouse, Mi: mouseInput{Dx: abs.Dx, Dy: abs.Dy, Flags: f | mouseeventfAbsolute | mouseeventfVirtualDesk}})
		}
		if err = sendMouse(evs); err == nil {
			in.buttons = buttons
		}
	}); e != nil {
		return e
	}
	return err
}

func (in *sendInputInjector) Wheel(dx, dy int) error {
	var evs []mouseInputEvent
	if dy != 0 {
		evs = append(evs, mouseInputEvent{Type: inputMouse, Mi: mouseInput{MouseData: uint32(int32(dy * wheelDelta)), Flags: mouseeventfWheel}})
	}
	if dx != 0 {
		evs = append(evs, mouseInputEvent{Type: inputMouse, Mi: mouseInput{MouseData: uint32(int32(dx * wheelDelta)), Flags: mouseeventfHWheel}})
	}
	var err error
	if e := in.th.run(func() { err = sendMouse(evs) }); e != nil {
		return e
	}
	return err
}

// keyEvent builds the INPUT for a virtual key.
func keyEvent(k keyMap, down bool) keyInputEvent {
	var flags uint32
	if k.extended {
		flags |= keyeventfExtendedKey
	}
	if !down {
		flags |= keyeventfKeyUp
	}
	return keyInputEvent{Type: inputKeyboard, Ki: keybdInput{Vk: k.vk, Flags: flags}}
}

func (in *sendInputInjector) Key(usage uint16, down bool) error {
	k, ok := lookupKey(usage)
	if !ok {
		return fmt.Errorf("rdesk: bilinmeyen tuş %#x", usage)
	}
	var err error
	if e := in.th.run(func() {
		ev := keyEvent(k, down)
		if procMapVirtualKeyW.Find() == nil {
			sc, _, _ := procMapVirtualKeyW.Call(uintptr(k.vk), mapvkVKToVSC)
			ev.Ki.Scan = uint16(sc)
		}
		err = sendKeys([]keyInputEvent{ev})
	}); e != nil {
		return e
	}
	return err
}

// textEvents types s as Unicode characters; newline and tab become the
// Enter and Tab keys so applications see real key presses.
func textEvents(s string) []keyInputEvent {
	var evs []keyInputEvent
	for _, r := range s {
		switch r {
		case '\n':
			evs = append(evs, keyEvent(keyMap{vk: 0x0D}, true), keyEvent(keyMap{vk: 0x0D}, false))
			continue
		case '\t':
			evs = append(evs, keyEvent(keyMap{vk: 0x09}, true), keyEvent(keyMap{vk: 0x09}, false))
			continue
		}
		var units []uint16
		if r >= 0x10000 {
			a, b := utf16.EncodeRune(r)
			units = []uint16{uint16(a), uint16(b)}
		} else {
			units = []uint16{uint16(r)}
		}
		for _, u := range units {
			evs = append(evs,
				keyInputEvent{Type: inputKeyboard, Ki: keybdInput{Scan: u, Flags: keyeventfUnicode}},
				keyInputEvent{Type: inputKeyboard, Ki: keybdInput{Scan: u, Flags: keyeventfUnicode | keyeventfKeyUp}},
			)
		}
	}
	return evs
}

func (in *sendInputInjector) Text(s string) error {
	evs := textEvents(s)
	var err error
	if e := in.th.run(func() { err = sendKeys(evs) }); e != nil {
		return e
	}
	return err
}
