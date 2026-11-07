//go:build windows

package piv

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// PC/SC through winscard.dll (ADR-0123). The DLL is loaded only when a
// token is used, so machines without the smart card service are not
// affected.

var (
	winscard                  = windows.NewLazySystemDLL("winscard.dll")
	procSCardEstablishContext = winscard.NewProc("SCardEstablishContext")
	procSCardReleaseContext   = winscard.NewProc("SCardReleaseContext")
	procSCardListReadersW     = winscard.NewProc("SCardListReadersW")
	procSCardConnectW         = winscard.NewProc("SCardConnectW")
	procSCardDisconnect       = winscard.NewProc("SCardDisconnect")
	procSCardBeginTransaction = winscard.NewProc("SCardBeginTransaction")
	procSCardEndTransaction   = winscard.NewProc("SCardEndTransaction")
	procSCardTransmit         = winscard.NewProc("SCardTransmit")
)

const (
	scardScopeUser       = 0
	scardShareShared     = 2
	scardProtocolT0      = 1
	scardProtocolT1      = 2
	scardLeaveCard       = 0
	scardResetCard       = 1
	scardSuccess         = 0
	scardENoReaders      = 0x8010002E
	scardENoSmartcard    = 0x8010000C
	scardEServiceStopped = 0x8010001E
	scardENoService      = 0x8010001D
	maxReaderListChars   = 64 << 10
	maxResponseAPDU      = 258 // 256 data bytes + SW1 SW2 (short APDUs)
	scardIORequestSize   = 8
)

type scardIORequest struct {
	protocol  uint32
	pciLength uint32
}

func scardErr(op string, r uintptr) error {
	code := uint32(r)
	switch code {
	case scardSuccess:
		return nil
	case scardENoReaders:
		return fmt.Errorf("%s: no smart card reader found", op)
	case scardENoSmartcard:
		return fmt.Errorf("%s: no token in the reader", op)
	case scardEServiceStopped, scardENoService:
		return fmt.Errorf("%s: the smart card service is not running", op)
	}
	return fmt.Errorf("%s: PC/SC error 0x%08X", op, code)
}

func loadWinscard() error {
	if err := winscard.Load(); err != nil {
		return fmt.Errorf("%w: %w", ErrUnsupported, err)
	}
	return nil
}

// Readers lists the PC/SC readers.
func Readers() ([]string, error) {
	if err := loadWinscard(); err != nil {
		return nil, err
	}
	var ctx uintptr
	if r, _, _ := procSCardEstablishContext.Call(scardScopeUser, 0, 0, uintptr(unsafe.Pointer(&ctx))); r != scardSuccess {
		return nil, scardErr("establish context", r)
	}
	defer procSCardReleaseContext.Call(ctx)
	return listReaders(ctx)
}

func listReaders(ctx uintptr) ([]string, error) {
	var n uint32
	r, _, _ := procSCardListReadersW.Call(ctx, 0, 0, uintptr(unsafe.Pointer(&n)))
	if r != scardSuccess {
		if uint32(r) == scardENoReaders {
			return nil, nil
		}
		return nil, scardErr("list readers", r)
	}
	if n == 0 || n > maxReaderListChars {
		return nil, nil
	}
	buf := make([]uint16, n)
	if r, _, _ := procSCardListReadersW.Call(ctx, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n))); r != scardSuccess {
		return nil, scardErr("list readers", r)
	}
	if int(n) > len(buf) {
		return nil, errors.New("list readers: inconsistent length")
	}
	return splitMultiString(buf[:n]), nil
}

// splitMultiString splits a REG_MULTI_SZ-style UTF-16 list.
func splitMultiString(buf []uint16) []string {
	var out []string
	start := 0
	for i, c := range buf {
		if c == 0 {
			if i > start {
				out = append(out, windows.UTF16ToString(buf[start:i]))
			}
			start = i + 1
		}
	}
	return out
}

// Card is a connected token. Close resets the card, so a verified PIN does
// not outlive the session.
type Card struct {
	ctx      uintptr
	handle   uintptr
	protocol uint32
	reset    bool
}

// Open connects to the reader whose name contains reader (case-insensitive;
// empty picks the first Yubico reader) and starts an exclusive transaction.
func Open(reader string) (*Card, error) { return openCard(reader, true) }

// openCard is Open; reset false leaves the card as it is on Close, which
// Presence uses because it verifies no PIN and must not disturb another
// program's session on the same token every few seconds.
func openCard(reader string, reset bool) (*Card, error) {
	if err := loadWinscard(); err != nil {
		return nil, err
	}
	var ctx uintptr
	if r, _, _ := procSCardEstablishContext.Call(scardScopeUser, 0, 0, uintptr(unsafe.Pointer(&ctx))); r != scardSuccess {
		return nil, scardErr("establish context", r)
	}
	readers, err := listReaders(ctx)
	if err != nil {
		procSCardReleaseContext.Call(ctx)
		return nil, err
	}
	name, err := pickReader(readers, reader)
	if err != nil {
		procSCardReleaseContext.Call(ctx)
		return nil, err
	}
	name16, err := windows.UTF16PtrFromString(name)
	if err != nil {
		procSCardReleaseContext.Call(ctx)
		return nil, err
	}
	c := &Card{ctx: ctx, reset: reset}
	r, _, _ := procSCardConnectW.Call(ctx, uintptr(unsafe.Pointer(name16)), scardShareShared,
		scardProtocolT0|scardProtocolT1, uintptr(unsafe.Pointer(&c.handle)), uintptr(unsafe.Pointer(&c.protocol)))
	if r != scardSuccess {
		procSCardReleaseContext.Call(ctx)
		return nil, scardErr("connect", r)
	}
	if r, _, _ := procSCardBeginTransaction.Call(c.handle); r != scardSuccess {
		procSCardDisconnect.Call(c.handle, scardLeaveCard)
		procSCardReleaseContext.Call(ctx)
		return nil, scardErr("begin transaction", r)
	}
	return c, nil
}

// Transmit sends one APDU.
func (c *Card) Transmit(apdu []byte) ([]byte, error) {
	if c.handle == 0 {
		return nil, errors.New("card is closed")
	}
	if len(apdu) == 0 || len(apdu) > 261 {
		return nil, errors.New("invalid apdu length")
	}
	req := scardIORequest{protocol: c.protocol, pciLength: scardIORequestSize}
	out := make([]byte, maxResponseAPDU)
	n := uint32(len(out))
	r, _, _ := procSCardTransmit.Call(c.handle, uintptr(unsafe.Pointer(&req)),
		uintptr(unsafe.Pointer(&apdu[0])), uintptr(len(apdu)), 0,
		uintptr(unsafe.Pointer(&out[0])), uintptr(unsafe.Pointer(&n)))
	if r != scardSuccess {
		return nil, scardErr("transmit", r)
	}
	if int(n) > len(out) {
		return nil, errors.New("transmit: inconsistent length")
	}
	return out[:n], nil
}

// Close ends the transaction, resets the card and releases the context.
func (c *Card) Close() error {
	if c.handle == 0 {
		return nil
	}
	disp := uintptr(scardLeaveCard)
	if c.reset {
		disp = scardResetCard
	}
	procSCardEndTransaction.Call(c.handle, disp)
	r, _, _ := procSCardDisconnect.Call(c.handle, disp)
	procSCardReleaseContext.Call(c.ctx)
	c.handle, c.ctx = 0, 0
	return scardErr("disconnect", r)
}
