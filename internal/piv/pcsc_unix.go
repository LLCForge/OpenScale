//go:build cgo && (linux || darwin)

package piv

/*
#cgo linux CFLAGS: -I/usr/include/PCSC
#cgo linux LDFLAGS: -lpcsclite
#cgo darwin LDFLAGS: -framework PCSC

#include <stdlib.h>
#ifdef __APPLE__
#include <PCSC/wintypes.h>
#include <PCSC/winscard.h>
#else
#include <winscard.h>
#endif

// The wrappers keep the platform types (DWORD and LONG are unsigned long
// and long with pcsclite on 64-bit Linux, uint32_t and int32_t on macOS) and
// the SCARD_PCI_* macros on the C side.

static LONG osc_establish(SCARDCONTEXT *ctx) {
	return SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, ctx);
}

static LONG osc_release(SCARDCONTEXT ctx) {
	return SCardReleaseContext(ctx);
}

static LONG osc_list(SCARDCONTEXT ctx, char *buf, DWORD *n) {
	return SCardListReaders(ctx, NULL, buf, n);
}

static LONG osc_connect(SCARDCONTEXT ctx, const char *name, SCARDHANDLE *h, DWORD *proto) {
	return SCardConnect(ctx, name, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, h, proto);
}

static LONG osc_begin(SCARDHANDLE h) {
	return SCardBeginTransaction(h);
}

static LONG osc_end(SCARDHANDLE h, int reset) {
	return SCardEndTransaction(h, reset ? SCARD_RESET_CARD : SCARD_LEAVE_CARD);
}

static LONG osc_disconnect(SCARDHANDLE h, int reset) {
	return SCardDisconnect(h, reset ? SCARD_RESET_CARD : SCARD_LEAVE_CARD);
}

static LONG osc_transmit(SCARDHANDLE h, DWORD proto, const unsigned char *in, DWORD inLen,
		unsigned char *out, DWORD *outLen) {
	const SCARD_IO_REQUEST *pci = (proto == SCARD_PROTOCOL_T0) ? SCARD_PCI_T0 : SCARD_PCI_T1;
	return SCardTransmit(h, pci, in, inLen, NULL, out, outLen);
}
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"
)

// PC/SC through libpcsclite (Linux) or PCSC.framework (macOS), both talking
// to the system's pcscd (ADR-0171). Same calls and the same card handling as
// pcsc_windows.go: a shared connection, one transaction for the session and
// a reset on Close so a verified PIN does not outlive it.

const (
	pcscENoReaders      = 0x8010002E
	pcscENoSmartcard    = 0x8010000C
	pcscENoService      = 0x8010001D
	pcscEServiceStopped = 0x8010001E
	pcscEReaderUnavail  = 0x80100017
	pcscMaxReaderList   = 64 << 10
	pcscMaxResponse     = 258
)

func pcscErr(op string, rv C.LONG) error {
	code := uint32(rv)
	switch code {
	case 0:
		return nil
	case pcscENoReaders:
		return fmt.Errorf("%s: no smart card reader found", op)
	case pcscENoSmartcard:
		return fmt.Errorf("%s: no token in the reader", op)
	case pcscENoService, pcscEServiceStopped:
		return fmt.Errorf("%s: pcscd is not running", op)
	case pcscEReaderUnavail:
		return fmt.Errorf("%s: the reader went away", op)
	}
	return fmt.Errorf("%s: PC/SC error 0x%08X", op, code)
}

func establish() (C.SCARDCONTEXT, error) {
	var ctx C.SCARDCONTEXT
	if rv := C.osc_establish(&ctx); rv != 0 {
		return 0, pcscErr("establish context", rv)
	}
	return ctx, nil
}

// Readers lists the PC/SC readers. A system without pcscd running reports
// no readers rather than an error, as Windows does without the service.
func Readers() ([]string, error) {
	ctx, err := establish()
	if err != nil {
		return nil, err
	}
	defer C.osc_release(ctx)
	return listReadersUnix(ctx)
}

func listReadersUnix(ctx C.SCARDCONTEXT) ([]string, error) {
	var n C.DWORD
	rv := C.osc_list(ctx, nil, &n)
	if rv != 0 {
		if uint32(rv) == pcscENoReaders {
			return nil, nil
		}
		return nil, pcscErr("list readers", rv)
	}
	if n == 0 || uint64(n) > pcscMaxReaderList {
		return nil, nil
	}
	buf := make([]byte, int(n))
	rv = C.osc_list(ctx, (*C.char)(unsafe.Pointer(&buf[0])), &n)
	if rv != 0 {
		if uint32(rv) == pcscENoReaders {
			return nil, nil
		}
		return nil, pcscErr("list readers", rv)
	}
	if uint64(n) > uint64(len(buf)) {
		return nil, errors.New("list readers: inconsistent length")
	}
	return splitMultiStringBytes(buf[:int(n)]), nil
}

// splitMultiStringBytes splits a NUL-separated, double-NUL-terminated list.
func splitMultiStringBytes(buf []byte) []string {
	var out []string
	start := 0
	for i, c := range buf {
		if c == 0 {
			if i > start {
				out = append(out, string(buf[start:i]))
			}
			start = i + 1
		}
	}
	return out
}

// Card is a connected token. Close resets the card (unless it was opened
// for a presence probe), so a verified PIN does not outlive the session.
type Card struct {
	ctx      C.SCARDCONTEXT
	handle   C.SCARDHANDLE
	protocol C.DWORD
	open     bool
	reset    bool
}

// Open connects to the reader whose name contains reader (case-insensitive;
// empty picks the first Yubico reader) and starts an exclusive transaction.
func Open(reader string) (*Card, error) { return openCard(reader, true) }

func openCard(reader string, reset bool) (*Card, error) {
	ctx, err := establish()
	if err != nil {
		return nil, err
	}
	readers, err := listReadersUnix(ctx)
	if err != nil {
		C.osc_release(ctx)
		return nil, err
	}
	name, err := pickReader(readers, reader)
	if err != nil {
		C.osc_release(ctx)
		return nil, err
	}
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	c := &Card{ctx: ctx, reset: reset}
	if rv := C.osc_connect(ctx, cname, &c.handle, &c.protocol); rv != 0 {
		C.osc_release(ctx)
		return nil, pcscErr("connect", rv)
	}
	if rv := C.osc_begin(c.handle); rv != 0 {
		C.osc_disconnect(c.handle, 0)
		C.osc_release(ctx)
		return nil, pcscErr("begin transaction", rv)
	}
	c.open = true
	return c, nil
}

// Transmit sends one APDU.
func (c *Card) Transmit(apdu []byte) ([]byte, error) {
	if !c.open {
		return nil, errors.New("card is closed")
	}
	if len(apdu) == 0 || len(apdu) > 261 {
		return nil, errors.New("invalid apdu length")
	}
	out := make([]byte, pcscMaxResponse)
	n := C.DWORD(len(out))
	rv := C.osc_transmit(c.handle, c.protocol,
		(*C.uchar)(unsafe.Pointer(&apdu[0])), C.DWORD(len(apdu)),
		(*C.uchar)(unsafe.Pointer(&out[0])), &n)
	if rv != 0 {
		return nil, pcscErr("transmit", rv)
	}
	if uint64(n) > uint64(len(out)) {
		return nil, errors.New("transmit: inconsistent length")
	}
	return out[:int(n)], nil
}

// Close ends the transaction, resets the card (see Card) and releases the
// context.
func (c *Card) Close() error {
	if !c.open {
		return nil
	}
	reset := C.int(0)
	if c.reset {
		reset = 1
	}
	C.osc_end(c.handle, reset)
	rv := C.osc_disconnect(c.handle, reset)
	C.osc_release(c.ctx)
	c.open = false
	return pcscErr("disconnect", rv)
}
