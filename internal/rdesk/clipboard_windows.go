//go:build windows

package rdesk

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"
	"unsafe"
)

var (
	procOpenClipboard              = modUser32.NewProc("OpenClipboard")
	procCloseClipboard             = modUser32.NewProc("CloseClipboard")
	procEmptyClipboard             = modUser32.NewProc("EmptyClipboard")
	procGetClipboardData           = modUser32.NewProc("GetClipboardData")
	procSetClipboardData           = modUser32.NewProc("SetClipboardData")
	procGetClipboardSequenceNumber = modUser32.NewProc("GetClipboardSequenceNumber")
	procIsClipboardFormatAvailable = modUser32.NewProc("IsClipboardFormatAvailable")
	procGlobalAlloc                = modKernel32.NewProc("GlobalAlloc")
	procGlobalFree                 = modKernel32.NewProc("GlobalFree")
	procGlobalLock                 = modKernel32.NewProc("GlobalLock")
	procGlobalUnlock               = modKernel32.NewProc("GlobalUnlock")
	procGlobalSize                 = modKernel32.NewProc("GlobalSize")

	errClipboardBusy = errors.New("rdesk: pano başka bir uygulamada açık")
)

const (
	clipboardOpenAttempts         = 10
	clipboardOpenDelay            = 20 * time.Millisecond
	cfUnicodeText         uintptr = 13
	gmemMoveable          uintptr = 0x0002
)

type winClipboard struct {
	th *winThread
}

// NewSystemClipboard opens the Windows text clipboard.
func NewSystemClipboard() (Clipboard, error) {
	if err := procGetClipboardSequenceNumber.Find(); err != nil {
		return nil, errors.Join(ErrUnsupported, err)
	}
	th, err := startWinThread(nil, nil)
	if err != nil {
		return nil, err
	}
	return &winClipboard{th: th}, nil
}

func (c *winClipboard) Close() error {
	c.th.close()
	return nil
}

func (c *winClipboard) Sequence() (uint64, error) {
	r, _, _ := procGetClipboardSequenceNumber.Call()
	return uint64(uint32(r)), nil
}

func openClipboard() error {
	for range clipboardOpenAttempts {
		if r, _, _ := procOpenClipboard.Call(0); r != 0 {
			return nil
		}
		time.Sleep(clipboardOpenDelay)
	}
	return errClipboardBusy
}

func (c *winClipboard) ReadText() (string, error) {
	var out string
	var err error
	if e := c.th.run(func() { out, err = readClipboardText() }); e != nil {
		return "", e
	}
	return out, err
}

func readClipboardText() (string, error) {
	if r, _, _ := procIsClipboardFormatAvailable.Call(cfUnicodeText); r == 0 {
		return "", nil
	}
	if err := openClipboard(); err != nil {
		return "", err
	}
	defer procCloseClipboard.Call()
	h, _, _ := procGetClipboardData.Call(cfUnicodeText)
	if h == 0 {
		return "", nil
	}
	size, _, _ := procGlobalSize.Call(h)
	p, _, err := procGlobalLock.Call(h)
	if p == 0 {
		return "", fmt.Errorf("GlobalLock: %v", err)
	}
	defer procGlobalUnlock.Call(h)
	n := min(int(size/2), maxClipboardBytes)
	units := unsafe.Slice((*uint16)(ptrFromHandle(p)), n)
	for i, u := range units {
		if u == 0 {
			units = units[:i]
			break
		}
	}
	return string(utf16.Decode(units)), nil
}

func (c *winClipboard) WriteText(s string) error {
	var err error
	if e := c.th.run(func() { err = writeClipboardText(s) }); e != nil {
		return e
	}
	return err
}

func writeClipboardText(s string) error {
	units := utf16.Encode([]rune(strings.ReplaceAll(s, "\x00", "")))
	units = append(units, 0)
	h, _, err := procGlobalAlloc.Call(gmemMoveable, uintptr(len(units)*2))
	if h == 0 {
		return fmt.Errorf("GlobalAlloc: %v", err)
	}
	p, _, err := procGlobalLock.Call(h)
	if p == 0 {
		_, _, _ = procGlobalFree.Call(h)
		return fmt.Errorf("GlobalLock: %v", err)
	}
	copy(unsafe.Slice((*uint16)(ptrFromHandle(p)), len(units)), units)
	_, _, _ = procGlobalUnlock.Call(h)
	if err := openClipboard(); err != nil {
		_, _, _ = procGlobalFree.Call(h)
		return err
	}
	defer procCloseClipboard.Call()
	_, _, _ = procEmptyClipboard.Call()
	if r, _, err := procSetClipboardData.Call(cfUnicodeText, h); r == 0 {
		// Ownership passes to the system only on success.
		_, _, _ = procGlobalFree.Call(h)
		return fmt.Errorf("SetClipboardData: %v", err)
	}
	return nil
}
