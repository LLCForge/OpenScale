//go:build windows && (amd64 || arm64)

package osnet

import (
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The kill switch is a set of persistent Windows Filtering Platform
// filters under OpenScale's own provider and sublayer (ADR-0023). The
// structure layouts below follow fwptypes.h and fwpmtypes.h for 64-bit
// Windows; killswitch_windows_test.go checks their sizes and offsets.

var (
	modfwpuclnt = windows.NewLazySystemDLL("fwpuclnt.dll")

	procFwpmEngineOpen0              = modfwpuclnt.NewProc("FwpmEngineOpen0")
	procFwpmEngineClose0             = modfwpuclnt.NewProc("FwpmEngineClose0")
	procFwpmTransactionBegin0        = modfwpuclnt.NewProc("FwpmTransactionBegin0")
	procFwpmTransactionCommit0       = modfwpuclnt.NewProc("FwpmTransactionCommit0")
	procFwpmTransactionAbort0        = modfwpuclnt.NewProc("FwpmTransactionAbort0")
	procFwpmProviderAdd0             = modfwpuclnt.NewProc("FwpmProviderAdd0")
	procFwpmProviderDeleteByKey0     = modfwpuclnt.NewProc("FwpmProviderDeleteByKey0")
	procFwpmProviderGetByKey0        = modfwpuclnt.NewProc("FwpmProviderGetByKey0")
	procFwpmSubLayerAdd0             = modfwpuclnt.NewProc("FwpmSubLayerAdd0")
	procFwpmSubLayerDeleteByKey0     = modfwpuclnt.NewProc("FwpmSubLayerDeleteByKey0")
	procFwpmFilterAdd0               = modfwpuclnt.NewProc("FwpmFilterAdd0")
	procFwpmFilterDeleteByKey0       = modfwpuclnt.NewProc("FwpmFilterDeleteByKey0")
	procFwpmFilterDeleteByID0        = modfwpuclnt.NewProc("FwpmFilterDeleteById0")
	procFwpmFilterCreateEnumHandle0  = modfwpuclnt.NewProc("FwpmFilterCreateEnumHandle0")
	procFwpmFilterEnum0              = modfwpuclnt.NewProc("FwpmFilterEnum0")
	procFwpmFilterDestroyEnumHandle0 = modfwpuclnt.NewProc("FwpmFilterDestroyEnumHandle0")
	procFwpmFreeMemory0              = modfwpuclnt.NewProc("FwpmFreeMemory0")
	procFwpmGetAppIDFromFileName0    = modfwpuclnt.NewProc("FwpmGetAppIdFromFileName0")
)

// OpenScale's fixed WFP identities. They never change, so every version
// finds and removes what an earlier one installed.
var (
	ksProviderKey = windows.GUID{Data1: 0x23ea0a49, Data2: 0xeb4d, Data3: 0x4480, Data4: [8]byte{0x84, 0xc7, 0x18, 0x43, 0x64, 0xee, 0xdc, 0xed}}
	ksSublayerKey = windows.GUID{Data1: 0x3f2f95e7, Data2: 0x16ee, Data3: 0x453d, Data4: [8]byte{0xb6, 0xd0, 0x44, 0xd5, 0xe2, 0x18, 0x3f, 0x94}}
	// ksFilterKeyBase: the last two bytes hold the rule index.
	ksFilterKeyBase = windows.GUID{Data1: 0x6553e551, Data2: 0x8f5f, Data3: 0x432b, Data4: [8]byte{0xae, 0xde, 0x2e, 0xb0, 0xee, 0xd8, 0x00, 0x00}}
)

// Layer and condition keys from fwpmu.h.
var (
	layerALEAuthConnectV4    = windows.GUID{Data1: 0xc38d57d1, Data2: 0x05a7, Data3: 0x4c33, Data4: [8]byte{0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82}}
	layerALEAuthConnectV6    = windows.GUID{Data1: 0x4a72393b, Data2: 0x319f, Data3: 0x44bc, Data4: [8]byte{0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4}}
	layerALEAuthRecvAcceptV4 = windows.GUID{Data1: 0xe1cd9fe7, Data2: 0xf4b5, Data3: 0x4273, Data4: [8]byte{0x96, 0xc0, 0x59, 0x2e, 0x48, 0x7b, 0x86, 0x50}}
	layerALEAuthRecvAcceptV6 = windows.GUID{Data1: 0xa3b42c97, Data2: 0x9f04, Data3: 0x4672, Data4: [8]byte{0xb8, 0x7e, 0xce, 0xe9, 0xc4, 0x83, 0x25, 0x7f}}

	condIPRemoteAddress  = windows.GUID{Data1: 0xb235ae9a, Data2: 0x1d64, Data3: 0x49b8, Data4: [8]byte{0xa4, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x45}}
	condIPProtocol       = windows.GUID{Data1: 0x3971ef2b, Data2: 0x623e, Data3: 0x4f9a, Data4: [8]byte{0x8c, 0xb1, 0x6e, 0x79, 0xb8, 0x06, 0xb9, 0xa7}}
	condIPLocalPort      = windows.GUID{Data1: 0x0c1ba1af, Data2: 0x5765, Data3: 0x453f, Data4: [8]byte{0xaf, 0x22, 0xa8, 0xf7, 0x91, 0xac, 0x77, 0x5b}}
	condIPRemotePort     = windows.GUID{Data1: 0xc35a604d, Data2: 0xd22b, Data3: 0x4e1a, Data4: [8]byte{0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b}}
	condIPLocalInterface = windows.GUID{Data1: 0x4cd62a49, Data2: 0x59c3, Data3: 0x4969, Data4: [8]byte{0xb7, 0xf3, 0xbd, 0xa5, 0xd3, 0x28, 0x90, 0xa4}}
	condALEAppID         = windows.GUID{Data1: 0xd78e1e87, Data2: 0x8644, Data3: 0x4ea5, Data4: [8]byte{0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71}}
	condFlags            = windows.GUID{Data1: 0x632ce23b, Data2: 0x5167, Data3: 0x435c, Data4: [8]byte{0x86, 0xd7, 0xe9, 0x03, 0x68, 0x4a, 0xa8, 0x0c}}
	// condICMPType is FWPM_CONDITION_ICMP_TYPE, an alias of the local port.
	condICMPType = condIPLocalPort
)

// fwptypes.h / fwpmtypes.h constants.
const (
	fwpUint8         = 1
	fwpUint16        = 2
	fwpUint32        = 3
	fwpUint64        = 4
	fwpByteBlobType  = 12
	fwpV4AddrMask    = 0x100
	fwpV6AddrMask    = 0x101
	fwpRangeType     = 0x102
	fwpMatchEqual    = 0
	fwpMatchRange    = 5
	fwpMatchFlagsAll = 6

	fwpActionBlock  = 0x1001
	fwpActionPermit = 0x1002

	fwpmProviderFlagPersistent     = 0x1
	fwpmSublayerFlagPersistent     = 0x1
	fwpmFilterFlagPersistent       = 0x1
	fwpmFilterFlagClearActionRight = 0x8
	fwpConditionFlagIsLoopback     = 0x1
	fwpFilterEnumOverlapping       = 1
	rpcCAuthnWinNT                 = 10
	ksSublayerWeight               = 0xffff
	ksTxnWaitMillis                = 30000
	ksEnumBatch                    = 64
	errFwpFilterNotFound           = windows.Errno(0x80320003)
	errFwpProviderNotFound         = windows.Errno(0x80320005)
	errFwpSublayerNotFound         = windows.Errno(0x80320007)
	errFwpAlreadyExists            = windows.Errno(0x80320009)
	errFwpInUse                    = windows.Errno(0x8032000a)
	errFwpNotFound                 = windows.Errno(0x80320008)
)

type fwpmDisplayData0 struct {
	name        *uint16
	description *uint16
}

type fwpByteBlob struct {
	size uint32
	data *byte
}

// fwpValue0 is FWP_VALUE0 and FWP_CONDITION_VALUE0: a type tag and an
// 8-byte union holding either a small integer or a pointer. Pointed-to
// values are kept alive by the wfpBuilder that made them.
type fwpValue0 struct {
	typ   uint32
	value uintptr
}

type fwpRange0 struct {
	valueLow  fwpValue0
	valueHigh fwpValue0
}

type fwpV4AddrAndMask struct {
	addr uint32
	mask uint32
}

type fwpV6AddrAndMask struct {
	addr         [16]byte
	prefixLength uint8
}

type fwpmFilterCondition0 struct {
	fieldKey       windows.GUID
	matchType      uint32
	conditionValue fwpValue0
}

type fwpmAction0 struct {
	typ        uint32
	filterType windows.GUID
}

type fwpmSession0 struct {
	sessionKey           windows.GUID
	displayData          fwpmDisplayData0
	flags                uint32
	txnWaitTimeoutInMSec uint32
	processID            uint32
	sid                  *windows.SID
	username             *uint16
	kernelMode           int32
}

type fwpmProvider0 struct {
	providerKey  windows.GUID
	displayData  fwpmDisplayData0
	flags        uint32
	providerData fwpByteBlob
	serviceName  *uint16
}

type fwpmSublayer0 struct {
	subLayerKey  windows.GUID
	displayData  fwpmDisplayData0
	flags        uint32
	providerKey  *windows.GUID
	providerData fwpByteBlob
	weight       uint16
}

type fwpmFilter0 struct {
	filterKey           windows.GUID
	displayData         fwpmDisplayData0
	flags               uint32
	providerKey         *windows.GUID
	providerData        fwpByteBlob
	layerKey            windows.GUID
	subLayerKey         windows.GUID
	weight              fwpValue0
	numFilterConditions uint32
	filterCondition     *fwpmFilterCondition0
	action              fwpmAction0
	// providerContext is the union of rawContext (UINT64) and
	// providerContextKey (GUID); [2]uint64 gives it the C alignment of 8.
	providerContext [2]uint64
	reserved        *windows.GUID
	filterID        uint64
	effectiveWeight fwpValue0
}

type fwpmFilterEnumTemplate0 struct {
	providerKey             *windows.GUID
	layerKey                windows.GUID
	enumType                uint32
	flags                   uint32
	providerContextTemplate uintptr
	numFilterConditions     uint32
	filterCondition         *fwpmFilterCondition0
	actionMask              uint32
	calloutKey              *windows.GUID
}

// ksLayers are the four layers the kill switch uses.
var ksLayers = []windows.GUID{layerALEAuthConnectV4, layerALEAuthRecvAcceptV4, layerALEAuthConnectV6, layerALEAuthRecvAcceptV6}

func ksLayer(r ksRule) windows.GUID {
	switch {
	case r.IPv6 && r.Inbound:
		return layerALEAuthRecvAcceptV6
	case r.IPv6:
		return layerALEAuthConnectV6
	case r.Inbound:
		return layerALEAuthRecvAcceptV4
	default:
		return layerALEAuthConnectV4
	}
}

func ksFilterKey(i int) windows.GUID {
	k := ksFilterKeyBase
	k.Data4[6], k.Data4[7] = byte(i>>8), byte(i)
	return k
}

// KillSwitchSupported reports whether this system has a persistent kill
// switch.
func KillSwitchSupported() bool { return true }

// InstallKillSwitch replaces any earlier OpenScale filters with the plan
// for cfg in one WFP transaction: either the whole new set is in place or
// the old state is kept. The filters are persistent and stay after a
// service crash or a restart until RemoveKillSwitch.
func InstallKillSwitch(cfg KillSwitchConfig) error {
	var luid uint64
	if cfg.Interface != "" {
		l, err := interfaceLUID(cfg.Interface)
		if err != nil {
			return err
		}
		luid = l
	}
	app := cfg.AppPath
	if app == "" {
		exe, err := os.Executable()
		if err != nil {
			return fmt.Errorf("program yolu bulunamadı: %w", err)
		}
		app = exe
	}
	appID, freeAppID, err := appIDFromFile(app)
	if err != nil {
		return err
	}
	defer freeAppID()

	plan := killSwitchPlan(luid != 0, cfg.AllowLAN)
	if len(plan) > maxKillSwitchFilters {
		return errors.New("kill switch kural sayısı sınırı aşıldı")
	}
	return withTransaction(func(h windows.Handle) error {
		if err := removeAllLocked(h); err != nil {
			return err
		}
		if err := addProviderAndSublayer(h); err != nil {
			return err
		}
		for i, r := range plan {
			if err := addRule(h, i, r, luid, appID); err != nil {
				return fmt.Errorf("kill switch kuralı eklenemedi (%s): %w", r.Name, err)
			}
		}
		return nil
	})
}

// RemoveKillSwitch deletes every filter, the sublayer and the provider
// that belong to OpenScale. Nothing installed is not an error.
func RemoveKillSwitch() error {
	return withTransaction(removeAllLocked)
}

// KillSwitchInstalled reports whether OpenScale's WFP provider exists.
func KillSwitchInstalled() (bool, error) {
	h, err := openEngine()
	if err != nil {
		return false, err
	}
	defer closeEngine(h)
	var p *fwpmProvider0
	err = wfpCall(procFwpmProviderGetByKey0, uintptr(h), uintptr(unsafe.Pointer(&ksProviderKey)), uintptr(unsafe.Pointer(&p)))
	if errors.Is(err, errFwpProviderNotFound) || errors.Is(err, errFwpNotFound) {
		return false, nil
	}
	if err != nil {
		return false, wfpError("kill switch durumu okunamadı", err)
	}
	freeWFP(unsafe.Pointer(&p))
	return true, nil
}

func wfpCall(p *windows.LazyProc, args ...uintptr) error {
	if err := p.Find(); err != nil {
		return fmt.Errorf("Windows Filtering Platform kullanılamıyor: %w", err)
	}
	r, _, _ := p.Call(args...)
	if r != 0 {
		return windows.Errno(r)
	}
	return nil
}

func wfpError(op string, err error) error {
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return fmt.Errorf("%s: yönetici izni gerekiyor: %w", op, err)
	}
	return fmt.Errorf("%s: %w", op, err)
}

func freeWFP(pp unsafe.Pointer) {
	if procFwpmFreeMemory0.Find() == nil {
		_, _, _ = procFwpmFreeMemory0.Call(uintptr(pp))
	}
}

func openEngine() (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString("OpenScale kill switch")
	if err != nil {
		return 0, err
	}
	// Not FWPM_SESSION_FLAG_DYNAMIC: objects must outlive the session.
	session := &fwpmSession0{
		displayData:          fwpmDisplayData0{name: name},
		txnWaitTimeoutInMSec: ksTxnWaitMillis,
	}
	var h windows.Handle
	err = wfpCall(procFwpmEngineOpen0, 0, rpcCAuthnWinNT, 0, uintptr(unsafe.Pointer(session)), uintptr(unsafe.Pointer(&h)))
	runtime.KeepAlive(session)
	runtime.KeepAlive(name)
	if err != nil {
		return 0, wfpError("Windows Filtering Platform açılamadı", err)
	}
	return h, nil
}

func closeEngine(h windows.Handle) {
	_ = wfpCall(procFwpmEngineClose0, uintptr(h))
}

// withTransaction runs fn inside one WFP transaction and commits it, or
// aborts on any error so the previous filters stay untouched.
func withTransaction(fn func(h windows.Handle) error) error {
	h, err := openEngine()
	if err != nil {
		return err
	}
	defer closeEngine(h)
	if err := wfpCall(procFwpmTransactionBegin0, uintptr(h), 0); err != nil {
		return wfpError("WFP işlemi başlatılamadı", err)
	}
	if err := fn(h); err != nil {
		_ = wfpCall(procFwpmTransactionAbort0, uintptr(h))
		return err
	}
	if err := wfpCall(procFwpmTransactionCommit0, uintptr(h)); err != nil {
		_ = wfpCall(procFwpmTransactionAbort0, uintptr(h))
		return wfpError("WFP işlemi tamamlanamadı", err)
	}
	return nil
}

// removeAllLocked deletes OpenScale's filters by their fixed keys, then any
// other filter of the provider found by enumeration, then the sublayer and
// the provider. Deleting the provider fails while anything still uses it,
// so success means nothing of OpenScale is left.
func removeAllLocked(h windows.Handle) error {
	for i := range maxKillSwitchFilters {
		key := ksFilterKey(i)
		err := wfpCall(procFwpmFilterDeleteByKey0, uintptr(h), uintptr(unsafe.Pointer(&key)))
		if err != nil && !errors.Is(err, errFwpFilterNotFound) {
			return wfpError("kill switch kuralı silinemedi", err)
		}
	}
	for _, layer := range ksLayers {
		ids, err := providerFilterIDs(h, layer)
		if err != nil {
			return wfpError("kill switch kuralları listelenemedi", err)
		}
		for _, id := range ids {
			if err := wfpCall(procFwpmFilterDeleteByID0, uintptr(h), uintptr(id)); err != nil && !errors.Is(err, errFwpFilterNotFound) {
				return wfpError("kill switch kuralı silinemedi", err)
			}
		}
	}
	if err := wfpCall(procFwpmSubLayerDeleteByKey0, uintptr(h), uintptr(unsafe.Pointer(&ksSublayerKey))); err != nil && !errors.Is(err, errFwpSublayerNotFound) {
		if errors.Is(err, errFwpInUse) {
			return errors.New("kill switch alt katmanı başka kurallarca kullanılıyor; silinemedi")
		}
		return wfpError("kill switch alt katmanı silinemedi", err)
	}
	if err := wfpCall(procFwpmProviderDeleteByKey0, uintptr(h), uintptr(unsafe.Pointer(&ksProviderKey))); err != nil &&
		!errors.Is(err, errFwpProviderNotFound) && !errors.Is(err, errFwpNotFound) {
		if errors.Is(err, errFwpInUse) {
			return errors.New("OpenScale WFP sağlayıcısı hâlâ kullanılıyor; silinemedi")
		}
		return wfpError("OpenScale WFP sağlayıcısı silinemedi", err)
	}
	return nil
}

// providerFilterIDs lists the ids of OpenScale's filters on one layer.
func providerFilterIDs(h windows.Handle, layer windows.GUID) ([]uint64, error) {
	tmpl := &fwpmFilterEnumTemplate0{
		providerKey: &ksProviderKey,
		layerKey:    layer,
		enumType:    fwpFilterEnumOverlapping,
		actionMask:  0xffffffff,
	}
	var eh windows.Handle
	err := wfpCall(procFwpmFilterCreateEnumHandle0, uintptr(h), uintptr(unsafe.Pointer(tmpl)), uintptr(unsafe.Pointer(&eh)))
	runtime.KeepAlive(tmpl)
	if err != nil {
		return nil, err
	}
	defer func() { _ = wfpCall(procFwpmFilterDestroyEnumHandle0, uintptr(h), uintptr(eh)) }()
	var ids []uint64
	for {
		var entries **fwpmFilter0
		var n uint32
		if err := wfpCall(procFwpmFilterEnum0, uintptr(h), uintptr(eh), ksEnumBatch, uintptr(unsafe.Pointer(&entries)), uintptr(unsafe.Pointer(&n))); err != nil {
			return nil, err
		}
		if n == 0 || entries == nil {
			return ids, nil
		}
		for _, f := range unsafe.Slice(entries, n) {
			if f != nil {
				ids = append(ids, f.filterID)
			}
		}
		freeWFP(unsafe.Pointer(&entries))
		if n < ksEnumBatch {
			return ids, nil
		}
	}
}

func addProviderAndSublayer(h windows.Handle) error {
	pname, err := windows.UTF16PtrFromString("OpenScale")
	if err != nil {
		return err
	}
	pdesc, err := windows.UTF16PtrFromString("OpenScale kalıcı kill switch (ADR-0023)")
	if err != nil {
		return err
	}
	provider := &fwpmProvider0{
		providerKey: ksProviderKey,
		displayData: fwpmDisplayData0{name: pname, description: pdesc},
		flags:       fwpmProviderFlagPersistent,
	}
	err = wfpCall(procFwpmProviderAdd0, uintptr(h), uintptr(unsafe.Pointer(provider)), 0)
	runtime.KeepAlive(provider)
	if err != nil && !errors.Is(err, errFwpAlreadyExists) {
		return wfpError("OpenScale WFP sağlayıcısı eklenemedi", err)
	}
	sname, err := windows.UTF16PtrFromString("OpenScale kill switch")
	if err != nil {
		return err
	}
	sublayer := &fwpmSublayer0{
		subLayerKey: ksSublayerKey,
		displayData: fwpmDisplayData0{name: sname, description: pdesc},
		flags:       fwpmSublayerFlagPersistent,
		providerKey: &ksProviderKey,
		weight:      ksSublayerWeight,
	}
	err = wfpCall(procFwpmSubLayerAdd0, uintptr(h), uintptr(unsafe.Pointer(sublayer)), 0)
	runtime.KeepAlive(sublayer)
	if err != nil && !errors.Is(err, errFwpAlreadyExists) {
		return wfpError("kill switch alt katmanı eklenemedi", err)
	}
	return nil
}

// wfpBuilder keeps every value a filter points to reachable until the
// filter has been added; the Go heap does not move objects.
type wfpBuilder struct {
	keep []any
}

func (b *wfpBuilder) uint16Value(v uint16) fwpValue0 {
	return fwpValue0{typ: fwpUint16, value: uintptr(v)}
}

func (b *wfpBuilder) uint64Value(v uint64) fwpValue0 {
	p := new(uint64)
	*p = v
	b.keep = append(b.keep, p)
	return fwpValue0{typ: fwpUint64, value: uintptr(unsafe.Pointer(p))}
}

func (b *wfpBuilder) rangeValue(lo, hi uint16) fwpValue0 {
	r := &fwpRange0{valueLow: b.uint16Value(lo), valueHigh: b.uint16Value(hi)}
	b.keep = append(b.keep, r)
	return fwpValue0{typ: fwpRangeType, value: uintptr(unsafe.Pointer(r))}
}

func (b *wfpBuilder) prefixValue(r ksRule) (fwpValue0, error) {
	p := r.Prefix.Masked()
	if r.IPv6 {
		if !p.Addr().Is6() {
			return fwpValue0{}, errors.New("IPv6 kuralında IPv4 adresi")
		}
		v := &fwpV6AddrAndMask{addr: p.Addr().As16(), prefixLength: uint8(p.Bits())} //nolint:gosec // 0..128
		b.keep = append(b.keep, v)
		return fwpValue0{typ: fwpV6AddrMask, value: uintptr(unsafe.Pointer(v))}, nil
	}
	if !p.Addr().Is4() {
		return fwpValue0{}, errors.New("IPv4 kuralında IPv6 adresi")
	}
	a := p.Addr().As4()
	// FWP_V4_ADDR_AND_MASK holds host-order integers.
	v := &fwpV4AddrAndMask{
		addr: uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3]),
		mask: ^uint32(0) << (32 - p.Bits()),
	}
	if p.Bits() == 0 {
		v.mask = 0
	}
	b.keep = append(b.keep, v)
	return fwpValue0{typ: fwpV4AddrMask, value: uintptr(unsafe.Pointer(v))}, nil
}

// conditions translates a rule's match into WFP filter conditions.
func (b *wfpBuilder) conditions(r ksRule, luid uint64, appID *fwpByteBlob) ([]fwpmFilterCondition0, error) {
	cond := func(field windows.GUID, match uint32, v fwpValue0) fwpmFilterCondition0 {
		return fwpmFilterCondition0{fieldKey: field, matchType: match, conditionValue: v}
	}
	proto := func(p uint8) fwpmFilterCondition0 {
		return cond(condIPProtocol, fwpMatchEqual, fwpValue0{typ: fwpUint8, value: uintptr(p)})
	}
	switch r.Kind {
	case ksMatchAll:
		return nil, nil
	case ksMatchLoopback:
		return []fwpmFilterCondition0{cond(condFlags, fwpMatchFlagsAll, fwpValue0{typ: fwpUint32, value: fwpConditionFlagIsLoopback})}, nil
	case ksMatchTunnel:
		if luid == 0 {
			return nil, errors.New("tünel arayüzü bilinmiyor")
		}
		return []fwpmFilterCondition0{cond(condIPLocalInterface, fwpMatchEqual, b.uint64Value(luid))}, nil
	case ksMatchApp:
		if appID == nil {
			return nil, errors.New("program kimliği yok")
		}
		return []fwpmFilterCondition0{cond(condALEAppID, fwpMatchEqual, fwpValue0{typ: fwpByteBlobType, value: uintptr(unsafe.Pointer(appID))})}, nil
	case ksMatchUDPPorts:
		return []fwpmFilterCondition0{
			proto(r.Protocol),
			cond(condIPLocalPort, fwpMatchEqual, b.uint16Value(r.LocalPort)),
			cond(condIPRemotePort, fwpMatchEqual, b.uint16Value(r.RemotePort)),
		}, nil
	case ksMatchICMPTypes:
		return []fwpmFilterCondition0{
			proto(r.Protocol),
			cond(condICMPType, fwpMatchRange, b.rangeValue(uint16(r.ICMPLow), uint16(r.ICMPHigh))),
		}, nil
	case ksMatchRemotePrefix, ksMatchRemotePrefixPort:
		v, err := b.prefixValue(r)
		if err != nil {
			return nil, err
		}
		out := []fwpmFilterCondition0{cond(condIPRemoteAddress, fwpMatchEqual, v)}
		if r.Kind == ksMatchRemotePrefixPort {
			out = append(out, cond(condIPRemotePort, fwpMatchEqual, b.uint16Value(r.RemotePort)))
		}
		return out, nil
	}
	return nil, fmt.Errorf("bilinmeyen kural türü %d", r.Kind)
}

func addRule(h windows.Handle, index int, r ksRule, luid uint64, appID *fwpByteBlob) error {
	b := &wfpBuilder{}
	conds, err := b.conditions(r, luid, appID)
	if err != nil {
		return err
	}
	name, err := windows.UTF16PtrFromString("OpenScale: " + r.Name)
	if err != nil {
		return err
	}
	f := &fwpmFilter0{
		filterKey:   ksFilterKey(index),
		displayData: fwpmDisplayData0{name: name},
		flags:       fwpmFilterFlagPersistent,
		providerKey: &ksProviderKey,
		layerKey:    ksLayer(r),
		subLayerKey: ksSublayerKey,
		weight:      fwpValue0{typ: fwpUint8, value: uintptr(r.Weight)},
		action:      fwpmAction0{typ: fwpActionBlock},
	}
	if r.Permit {
		f.action.typ = fwpActionPermit
	} else {
		// A hard block: lower sublayers cannot permit it again.
		f.flags |= fwpmFilterFlagClearActionRight
	}
	if len(conds) > 0 {
		f.numFilterConditions = uint32(len(conds)) //nolint:gosec // at most a few
		f.filterCondition = &conds[0]
	}
	var id uint64
	err = wfpCall(procFwpmFilterAdd0, uintptr(h), uintptr(unsafe.Pointer(f)), 0, uintptr(unsafe.Pointer(&id)))
	runtime.KeepAlive(f)
	runtime.KeepAlive(conds)
	runtime.KeepAlive(b)
	runtime.KeepAlive(name)
	runtime.KeepAlive(appID)
	if err != nil {
		return wfpError("WFP", err)
	}
	return nil
}

// appIDFromFile returns the WFP application id of path and its release
// function.
func appIDFromFile(path string) (*fwpByteBlob, func(), error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, nil, fmt.Errorf("program yolu geçersiz: %w", err)
	}
	var blob *fwpByteBlob
	err = wfpCall(procFwpmGetAppIDFromFileName0, uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&blob)))
	runtime.KeepAlive(p)
	if err != nil {
		return nil, nil, wfpError("program kimliği alınamadı", err)
	}
	if blob == nil {
		return nil, nil, errors.New("program kimliği alınamadı")
	}
	return blob, func() { freeWFP(unsafe.Pointer(&blob)) }, nil
}

// interfaceLUID returns the LUID of the named interface.
func interfaceLUID(name string) (uint64, error) {
	ifi, err := net.InterfaceByName(name)
	if err != nil || ifi.Index <= 0 {
		return 0, fmt.Errorf("tünel arayüzü bulunamadı: %s", name)
	}
	row := &windows.MibIfRow2{InterfaceIndex: uint32(ifi.Index)} //nolint:gosec // checked positive
	if err := windows.GetIfEntry2Ex(windows.MibIfEntryNormal, row); err != nil {
		return 0, fmt.Errorf("tünel arayüzü okunamadı: %w", err)
	}
	if row.InterfaceLuid == 0 {
		return 0, fmt.Errorf("tünel arayüzü bulunamadı: %s", name)
	}
	return row.InterfaceLuid, nil
}
