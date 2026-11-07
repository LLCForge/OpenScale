//go:build windows && (amd64 || arm64)

package osnet

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/openscale/openscale/internal/dnsguard"
)

// The Windows applier of the #717 rules (dnsenforce.go). Unlike the kill
// switch, the session is dynamic (FWPM_SESSION_FLAG_DYNAMIC): the
// sublayer and the filters exist only while the service holds the
// session, so a crash or a kill never leaves DNS blocked. The objects
// carry no provider, so the kill switch's provider cleanup never touches
// them and they never touch the kill switch.

// dnsSublayerKey is OpenScale's DNS enforcement sublayer.
var dnsSublayerKey = windows.GUID{Data1: 0x7a1c0e55, Data2: 0x2f71, Data3: 0x4d0b, Data4: [8]byte{0x9a, 0x3e, 0x61, 0x0d, 0x5b, 0x17, 0x07, 0x17}}

const (
	fwpMatchNotEqual = 10
	// dnsSublayerWeight sits just below the kill switch sublayer.
	dnsSublayerWeight = 0xfffe
)

// NewDNSEnforcer returns the Windows applier.
func NewDNSEnforcer() dnsguard.Applier {
	return &wfpDNSEnforcer{ops: &wfpDNSHost{}, luidOf: interfaceLUID}
}

// DNSEnforceSupported reports true: WFP is part of every supported
// Windows.
func DNSEnforceSupported() bool { return true }

// wfpDNSHost is the real wfpDNSOps.
type wfpDNSHost struct {
	h         windows.Handle
	appID     *fwpByteBlob
	freeAppID func()
}

func (w *wfpDNSHost) open() error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("program yolu bulunamadı: %w", err)
	}
	appID, free, err := appIDFromFile(exe)
	if err != nil {
		return err
	}
	name, err := windows.UTF16PtrFromString("OpenScale DNS zorlama")
	if err != nil {
		free()
		return err
	}
	session := &fwpmSession0{
		displayData:          fwpmDisplayData0{name: name},
		flags:                fwpmSessionFlagDynamic,
		txnWaitTimeoutInMSec: ksTxnWaitMillis,
	}
	var h windows.Handle
	err = wfpCall(procFwpmEngineOpen0, 0, rpcCAuthnWinNT, 0, uintptr(unsafe.Pointer(session)), uintptr(unsafe.Pointer(&h)))
	runtime.KeepAlive(session)
	runtime.KeepAlive(name)
	if err != nil {
		free()
		return wfpError("Windows Filtering Platform açılamadı", err)
	}
	w.h, w.appID, w.freeAppID = h, appID, free
	return nil
}

func (w *wfpDNSHost) close() error {
	if w.h == 0 {
		return nil
	}
	err := wfpCall(procFwpmEngineClose0, uintptr(w.h))
	w.h = 0
	if w.freeAppID != nil {
		w.freeAppID()
		w.appID, w.freeAppID = nil, nil
	}
	if err != nil {
		return wfpError("DNS zorlama oturumu kapatılamadı", err)
	}
	return nil
}

func (w *wfpDNSHost) begin() error {
	if err := wfpCall(procFwpmTransactionBegin0, uintptr(w.h), 0); err != nil {
		return wfpError("WFP işlemi başlatılamadı", err)
	}
	return nil
}

func (w *wfpDNSHost) commit() error {
	if err := wfpCall(procFwpmTransactionCommit0, uintptr(w.h)); err != nil {
		return wfpError("WFP işlemi tamamlanamadı", err)
	}
	return nil
}

func (w *wfpDNSHost) abort() error { return wfpCall(procFwpmTransactionAbort0, uintptr(w.h)) }

func (w *wfpDNSHost) addSublayer() error {
	name, err := windows.UTF16PtrFromString("OpenScale DNS zorlama")
	if err != nil {
		return err
	}
	desc, err := windows.UTF16PtrFromString("OpenScale: DNS yalnızca tünelden (ADR-0224)")
	if err != nil {
		return err
	}
	sublayer := &fwpmSublayer0{
		subLayerKey: dnsSublayerKey,
		displayData: fwpmDisplayData0{name: name, description: desc},
		weight:      dnsSublayerWeight,
	}
	err = wfpCall(procFwpmSubLayerAdd0, uintptr(w.h), uintptr(unsafe.Pointer(sublayer)), 0)
	runtime.KeepAlive(sublayer)
	runtime.KeepAlive(name)
	runtime.KeepAlive(desc)
	if err != nil {
		return wfpError("DNS zorlama alt katmanı eklenemedi", err)
	}
	return nil
}

func (w *wfpDNSHost) deleteFilter(id uint64) error {
	if err := wfpCall(procFwpmFilterDeleteByID0, uintptr(w.h), uintptr(id)); err != nil && !errors.Is(err, errFwpFilterNotFound) {
		return wfpError("DNS zorlama kuralı silinemedi", err)
	}
	return nil
}

func (w *wfpDNSHost) addFilter(f dnsWFPFilter, luid uint64) (uint64, error) {
	b := &wfpBuilder{}
	cond := func(field windows.GUID, match uint32, v fwpValue0) fwpmFilterCondition0 {
		return fwpmFilterCondition0{fieldKey: field, matchType: match, conditionValue: v}
	}
	var conds []fwpmFilterCondition0
	if f.App {
		if w.appID == nil {
			return 0, errors.New("program kimliği yok")
		}
		conds = append(conds, cond(condALEAppID, fwpMatchEqual, fwpValue0{typ: fwpByteBlobType, value: uintptr(unsafe.Pointer(w.appID))}))
	} else {
		conds = append(conds,
			cond(condIPProtocol, fwpMatchEqual, fwpValue0{typ: fwpUint8, value: uintptr(f.Proto)}),
			cond(condIPRemotePort, fwpMatchEqual, b.uint16Value(f.Port)))
		if f.Prefix.IsValid() {
			v, err := b.prefixValue(ksRule{IPv6: f.IPv6, Prefix: f.Prefix})
			if err != nil {
				return 0, err
			}
			conds = append(conds, cond(condIPRemoteAddress, fwpMatchEqual, v))
		}
		switch f.Iface {
		case wfpIfaceEqual, wfpIfaceNotEqual:
			if luid == 0 {
				return 0, errors.New("tünel arayüzü bilinmiyor")
			}
			match := uint32(fwpMatchEqual)
			if f.Iface == wfpIfaceNotEqual {
				match = fwpMatchNotEqual
			}
			conds = append(conds, cond(condIPLocalInterface, match, b.uint64Value(luid)))
		}
	}
	name, err := windows.UTF16PtrFromString(f.Name)
	if err != nil {
		return 0, err
	}
	layer := layerALEAuthConnectV4
	if f.IPv6 {
		layer = layerALEAuthConnectV6
	}
	filter := &fwpmFilter0{
		displayData:         fwpmDisplayData0{name: name},
		layerKey:            layer,
		subLayerKey:         dnsSublayerKey,
		weight:              b.uint64Value(f.Weight),
		numFilterConditions: uint32(len(conds)), //nolint:gosec // at most a few
		filterCondition:     &conds[0],
		action:              fwpmAction0{typ: fwpActionBlock},
	}
	if f.Permit {
		filter.action.typ = fwpActionPermit
	} else {
		// A hard block: a lower sublayer cannot permit it again.
		filter.flags |= fwpmFilterFlagClearActionRight
	}
	var id uint64
	err = wfpCall(procFwpmFilterAdd0, uintptr(w.h), uintptr(unsafe.Pointer(filter)), 0, uintptr(unsafe.Pointer(&id)))
	runtime.KeepAlive(filter)
	runtime.KeepAlive(conds)
	runtime.KeepAlive(b)
	runtime.KeepAlive(name)
	runtime.KeepAlive(w.appID)
	if err != nil {
		return 0, wfpError("WFP", err)
	}
	return id, nil
}
