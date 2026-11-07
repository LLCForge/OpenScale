//go:build windows

package tpm

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// TPM Base Services (tbs.dll), loaded lazily (ADR-0124).

var (
	tbs                    = windows.NewLazySystemDLL("tbs.dll")
	procTbsiGetDeviceInfo  = tbs.NewProc("Tbsi_GetDeviceInfo")
	procTbsiContextCreate  = tbs.NewProc("Tbsi_Context_Create")
	procTbsipSubmitCommand = tbs.NewProc("Tbsip_Submit_Command")
	procTbsipContextClose  = tbs.NewProc("Tbsip_Context_Close")
)

const (
	tbsSuccess            = 0
	tbsETPMNotFound       = 0x8028400F
	tbsEServiceNotRunning = 0x80284008
	tbsEServiceDisabled   = 0x80284010
	tbsContextVersionTwo  = 2
	tbsIncludeTPM20       = 1 << 2
	tbsLocalityZero       = 0
	tbsPriorityNormal     = 200
)

type tpmDeviceInfo struct {
	structVersion    uint32
	tpmVersion       uint32
	tpmInterfaceType uint32
	tpmImpRevision   uint32
}

type tbsContextParams2 struct {
	version uint32
	flags   uint32
}

var interfaceNames = map[uint32]string{
	1: "TIS (port I/O)",
	2: "TrustZone",
	3: "hardware (CRB)",
	4: "emulator",
	5: "SPB",
}

// Detect asks TBS whether a TPM is present. It sends no command to the TPM.
func Detect() (Presence, error) {
	if err := tbs.Load(); err != nil {
		return Presence{}, fmt.Errorf("%w: %w", ErrUnsupported, err)
	}
	var info tpmDeviceInfo
	r, _, _ := procTbsiGetDeviceInfo.Call(unsafe.Sizeof(info), uintptr(unsafe.Pointer(&info)))
	switch uint32(r) {
	case tbsSuccess:
	case tbsETPMNotFound:
		return Presence{}, nil
	case tbsEServiceNotRunning, tbsEServiceDisabled:
		return Presence{}, errors.New("TPM base services are not running")
	default:
		return Presence{}, fmt.Errorf("Tbsi_GetDeviceInfo: 0x%08X", uint32(r))
	}
	p := Presence{Present: true, Interface: interfaceNames[info.tpmInterfaceType]}
	switch info.tpmVersion {
	case 1:
		p.Version = "1.2"
	case 2:
		p.Version = "2.0"
	}
	return p, nil
}

type tbsTransport struct{ ctx uintptr }

// Open returns a read-only transport to the TPM 2.0 through TBS.
func Open() (Transport, error) {
	if err := tbs.Load(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnsupported, err)
	}
	params := tbsContextParams2{version: tbsContextVersionTwo, flags: tbsIncludeTPM20}
	var ctx uintptr
	r, _, _ := procTbsiContextCreate.Call(uintptr(unsafe.Pointer(&params)), uintptr(unsafe.Pointer(&ctx)))
	if uint32(r) == tbsETPMNotFound {
		return nil, ErrNotFound
	}
	if r != tbsSuccess {
		return nil, fmt.Errorf("Tbsi_Context_Create: 0x%08X", uint32(r))
	}
	return ReadOnly(&tbsTransport{ctx: ctx}), nil
}

func (t *tbsTransport) Submit(cmd []byte) ([]byte, error) {
	if t.ctx == 0 {
		return nil, errors.New("TPM context is closed")
	}
	if len(cmd) == 0 {
		return nil, errors.New("empty command")
	}
	out := make([]byte, MaxResponse)
	n := uint32(len(out))
	r, _, _ := procTbsipSubmitCommand.Call(t.ctx, tbsLocalityZero, tbsPriorityNormal,
		uintptr(unsafe.Pointer(&cmd[0])), uintptr(len(cmd)), uintptr(unsafe.Pointer(&out[0])), uintptr(unsafe.Pointer(&n)))
	if r != tbsSuccess {
		return nil, fmt.Errorf("Tbsip_Submit_Command: 0x%08X", uint32(r))
	}
	if int(n) > len(out) {
		return nil, errors.New("Tbsip_Submit_Command: inconsistent length")
	}
	return out[:n], nil
}

func (t *tbsTransport) Close() error {
	if t.ctx == 0 {
		return nil
	}
	r, _, _ := procTbsipContextClose.Call(t.ctx)
	t.ctx = 0
	if r != tbsSuccess {
		return fmt.Errorf("Tbsip_Context_Close: 0x%08X", uint32(r))
	}
	return nil
}
