//go:build windows

package piv

import (
	"context"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Reader arrival and removal on Windows: SCardGetStatusChangeW with the
// special reader name \\?PnP?\Notification, whose current state carries the
// reader count in its high word, plus every known reader so a card change in
// a fixed reader is seen too (ADR-0171). Nothing is sent to a card.

var procSCardGetStatusChangeW = winscard.NewProc("SCardGetStatusChangeW")

const (
	scardStateUnaware   = 0x0000
	scardStateChanged   = 0x0002
	scardETimeout       = 0x8010000A
	scardECancelled     = 0x80100002
	pnpNotificationName = `\\?PnP?\Notification`
	waitStep            = 500 * time.Millisecond
	maxWatchedReaders   = 16
)

// scardReaderStateW mirrors SCARD_READERSTATEW (same layout on 386, amd64
// and arm64: pointer, pointer, three DWORDs, 36-byte ATR).
type scardReaderStateW struct {
	reader       *uint16
	userData     uintptr
	currentState uint32
	eventState   uint32
	atrLen       uint32
	atr          [36]byte
}

// WaitReaderChange blocks until a smart card reader (a YubiKey is its own
// reader) is added or removed, a card in a reader changes, timeout passes
// (false) or ctx ends. When no reader exists Windows stops the smart card
// service; the wait then falls back to listing readers every half second.
func WaitReaderChange(ctx context.Context, timeout time.Duration) (bool, error) {
	if err := loadWinscard(); err != nil {
		return false, err
	}
	if timeout <= 0 {
		return false, nil
	}
	deadline := time.Now().Add(timeout)
	for {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		left := time.Until(deadline)
		if left <= 0 {
			return false, nil
		}
		step := min(left, waitStep)
		changed, noService, err := waitStatusChangeOnce(step)
		switch {
		case err != nil:
			return false, err
		case changed:
			return true, nil
		case noService:
			t := time.NewTimer(step)
			select {
			case <-ctx.Done():
				t.Stop()
				return false, ctx.Err()
			case <-t.C:
			}
			if r, err := Readers(); err == nil && len(r) > 0 {
				return true, nil
			}
		}
	}
}

func isNoService(r uintptr) bool {
	code := uint32(r)
	return code == scardENoService || code == scardEServiceStopped
}

// waitStatusChangeOnce waits at most step for one change.
func waitStatusChangeOnce(step time.Duration) (changed, noService bool, err error) {
	var ctx uintptr
	if r, _, _ := procSCardEstablishContext.Call(scardScopeUser, 0, 0, uintptr(unsafe.Pointer(&ctx))); r != scardSuccess {
		if isNoService(r) {
			return false, true, nil
		}
		return false, false, scardErr("establish context", r)
	}
	defer procSCardReleaseContext.Call(ctx)
	readers, err := listReaders(ctx)
	if err != nil {
		return false, false, err
	}
	if len(readers) > maxWatchedReaders {
		readers = readers[:maxWatchedReaders]
	}
	names := make([]*uint16, 0, len(readers)+1)
	pnp, err := windows.UTF16PtrFromString(pnpNotificationName)
	if err != nil {
		return false, false, err
	}
	names = append(names, pnp)
	for _, r := range readers {
		p, err := windows.UTF16PtrFromString(r)
		if err != nil {
			return false, false, err
		}
		names = append(names, p)
	}
	states := make([]scardReaderStateW, len(names))
	for i, n := range names {
		states[i].reader = n
	}
	states[0].currentState = uint32(len(readers)) << 16
	// First call with a zero timeout learns the readers' current states.
	r, _, _ := procSCardGetStatusChangeW.Call(ctx, 0, uintptr(unsafe.Pointer(&states[0])), uintptr(len(states)))
	switch {
	case r == scardSuccess:
		if states[0].eventState&scardStateChanged != 0 {
			runtime.KeepAlive(names)
			return true, false, nil // the reader count moved between list and call
		}
	case uint32(r) == scardETimeout:
	case isNoService(r):
		return false, true, nil
	default:
		return false, false, scardErr("get status change", r)
	}
	for i := 1; i < len(states); i++ {
		states[i].currentState = states[i].eventState &^ scardStateChanged
	}
	states[0].currentState = uint32(len(readers)) << 16
	ms := uint32(step / time.Millisecond)
	r, _, _ = procSCardGetStatusChangeW.Call(ctx, uintptr(ms), uintptr(unsafe.Pointer(&states[0])), uintptr(len(states)))
	runtime.KeepAlive(names)
	switch {
	case r == scardSuccess:
		return true, false, nil
	case uint32(r) == scardETimeout, uint32(r) == scardECancelled:
		return false, false, nil
	case isNoService(r):
		// The last reader went away and Windows stopped the service.
		return true, false, nil
	}
	return false, false, scardErr("get status change", r)
}
