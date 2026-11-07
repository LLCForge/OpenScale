//go:build windows

package webview

import (
	"errors"
	"fmt"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Minimal COM plumbing for WebView2: calling methods of runtime objects by
// vtable index and implementing the completion and event handler
// interfaces the runtime calls back. Only the methods OpenScale uses are
// named; the indexes come from the published WebView2 interface order.

// comPtr is an interface pointer owned by the runtime (not Go memory).
type comPtr uintptr

const (
	sOK          = 0
	eNoInterface = 0x80004002
	ePointer     = 0x80004003
	eFail        = 0x80004005
)

// hresultError is a failed HRESULT.
type hresultError uint32

func (h hresultError) Error() string { return fmt.Sprintf("HRESULT 0x%08X", uint32(h)) }

func hrErr(hr uintptr) error {
	if int32(uint32(hr)) < 0 {
		return hresultError(uint32(hr))
	}
	return nil
}

// ptrFromUintptr turns a foreign address into an unsafe.Pointer without the
// uintptr-to-pointer conversion vet warns about; the address is never Go
// memory.
func ptrFromUintptr(p uintptr) unsafe.Pointer {
	return *(*unsafe.Pointer)(unsafe.Pointer(&p))
}

// call invokes method index (counted from QueryInterface = 0) of p.
// Pointer arguments must be converted with uintptr(unsafe.Pointer(x))
// inside the call expression; uintptrescapes then keeps them on the heap
// and alive for the duration of the call (as LazyProc.Call does).
//
//go:uintptrescapes
func (p comPtr) call(index int, args ...uintptr) uintptr {
	if p == 0 {
		return ePointer
	}
	vtbl := *(*uintptr)(ptrFromUintptr(uintptr(p)))
	fn := *(*uintptr)(ptrFromUintptr(vtbl + uintptr(index)*unsafe.Sizeof(uintptr(0))))
	all := make([]uintptr, 0, len(args)+1)
	all = append(all, uintptr(p))
	all = append(all, args...)
	r, _, _ := syscall.SyscallN(fn, all...)
	return r
}

// IUnknown.
const (
	idxQueryInterface = 0
	idxAddRef         = 1
	idxRelease        = 2
)

func (p comPtr) addRef() {
	if p != 0 {
		p.call(idxAddRef)
	}
}

func (p comPtr) release() {
	if p != 0 {
		p.call(idxRelease)
	}
}

func (p comPtr) queryInterface(iid *windows.GUID) (comPtr, error) {
	var out comPtr
	hr := p.call(idxQueryInterface, uintptr(unsafe.Pointer(iid)), uintptr(unsafe.Pointer(&out)))
	if err := hrErr(hr); err != nil {
		return 0, err
	}
	if out == 0 {
		return 0, errors.New("QueryInterface boş işaretçi döndürdü")
	}
	return out, nil
}

// getString calls a get_X(LPWSTR*) method and frees the string.
func (p comPtr) getString(index int) (string, error) {
	var s *uint16
	if err := hrErr(p.call(index, uintptr(unsafe.Pointer(&s)))); err != nil {
		return "", err
	}
	if s == nil {
		return "", nil
	}
	defer windows.CoTaskMemFree(unsafe.Pointer(s))
	return windows.UTF16PtrToString(s), nil
}

// getBool calls a get_X(BOOL*) method.
func (p comPtr) getBool(index int) (bool, error) {
	var b int32
	if err := hrErr(p.call(index, uintptr(unsafe.Pointer(&b)))); err != nil {
		return false, err
	}
	return b != 0, nil
}

// getInt calls a get_X(INT/ENUM*) method.
func (p comPtr) getInt(index int) (int32, error) {
	var v int32
	if err := hrErr(p.call(index, uintptr(unsafe.Pointer(&v)))); err != nil {
		return 0, err
	}
	return v, nil
}

// getPtr calls a get_X(IFoo**) method; the caller releases the result.
func (p comPtr) getPtr(index int) (comPtr, error) {
	var out comPtr
	if err := hrErr(p.call(index, uintptr(unsafe.Pointer(&out)))); err != nil {
		return 0, err
	}
	if out == 0 {
		return 0, errors.New("boş arayüz işaretçisi")
	}
	return out, nil
}

func (p comPtr) putBool(index int, v bool) error {
	b := uintptr(0)
	if v {
		b = 1
	}
	return hrErr(p.call(index, b))
}

func boolArg(v bool) uintptr {
	if v {
		return 1
	}
	return 0
}

// mustGUID parses a GUID constant.
func mustGUID(s string) windows.GUID {
	g, err := windows.GUIDFromString(s)
	if err != nil {
		panic("webview: bad GUID " + s)
	}
	return g
}

// iidIUnknown is IUnknown.
var iidIUnknown = mustGUID("{00000000-0000-0000-C000-000000000046}")

// ---- handler objects implemented in Go ----

// A handler object lives in LocalAlloc memory so the runtime may keep its
// address; the Go side is found through its id. Layout:
//
//	+0  vtable pointer (the shared handlerVtbl)
//	+8  reference count (int32, only touched on the UI thread)
//	+16 id
type handlerMem struct {
	vtbl uintptr
	refs int32
	_    int32
	id   uintptr
}

// handlerFunc is Invoke(this, a, b) without this.
type handlerFunc func(a, b uintptr) uintptr

type handlerEntry struct {
	iid windows.GUID
	fn  handlerFunc
	mem uintptr
	// text is the browser argument string of an options object.
	text string
}

var (
	handlersMu sync.Mutex
	handlers   = map[uintptr]*handlerEntry{}
	nextID     uintptr

	// handlerVtbl is shared by every handler: QueryInterface, AddRef,
	// Release, Invoke. A package variable never moves.
	handlerVtbl     [4]uintptr
	handlerVtblOnce sync.Once
)

func initHandlerVtbl() {
	handlerVtblOnce.Do(func() {
		handlerVtbl[0] = windows.NewCallback(handlerQueryInterface)
		handlerVtbl[1] = windows.NewCallback(handlerAddRef)
		handlerVtbl[2] = windows.NewCallback(handlerRelease)
		handlerVtbl[3] = windows.NewCallback(handlerInvoke)
	})
}

func memOf(this uintptr) *handlerMem { return (*handlerMem)(ptrFromUintptr(this)) }

func lookupHandler(this uintptr) *handlerEntry {
	if this == 0 {
		return nil
	}
	id := memOf(this).id
	handlersMu.Lock()
	defer handlersMu.Unlock()
	return handlers[id]
}

func handlerQueryInterface(this, riid, ppv uintptr) uintptr {
	if ppv == 0 {
		return ePointer
	}
	out := (*uintptr)(ptrFromUintptr(ppv))
	*out = 0
	h := lookupHandler(this)
	if h == nil || riid == 0 {
		return eNoInterface
	}
	iid := *(*windows.GUID)(ptrFromUintptr(riid))
	if iid != iidIUnknown && iid != h.iid {
		return eNoInterface
	}
	memOf(this).refs++
	*out = this
	return sOK
}

func handlerAddRef(this uintptr) uintptr {
	m := memOf(this)
	m.refs++
	return uintptr(m.refs)
}

func handlerRelease(this uintptr) uintptr {
	m := memOf(this)
	m.refs--
	n := m.refs
	if n <= 0 {
		handlersMu.Lock()
		delete(handlers, m.id)
		handlersMu.Unlock()
		_, _ = windows.LocalFree(windows.Handle(this))
		return 0
	}
	return uintptr(n)
}

func handlerInvoke(this, a, b uintptr) uintptr {
	h := lookupHandler(this)
	if h == nil {
		return eFail
	}
	return h.fn(a, b)
}

// newHandler creates a handler object with one reference owned by the
// caller, who releases it with comPtr.release.
func newHandler(iid windows.GUID, fn handlerFunc) (comPtr, error) {
	initHandlerVtbl()
	const lptr = 0x0040 // LMEM_FIXED | LMEM_ZEROINIT
	mem, err := windows.LocalAlloc(lptr, uint32(unsafe.Sizeof(handlerMem{})))
	if err != nil {
		return 0, err
	}
	handlersMu.Lock()
	nextID++
	id := nextID
	handlers[id] = &handlerEntry{iid: iid, fn: fn, mem: mem}
	handlersMu.Unlock()
	m := memOf(mem)
	m.vtbl = uintptr(unsafe.Pointer(&handlerVtbl[0]))
	m.refs = 1
	m.id = id
	return comPtr(mem), nil
}

// ---- ICoreWebView2EnvironmentOptions ----

// iidEnvironmentOptions is ICoreWebView2EnvironmentOptions; later
// versions of the interface are answered with E_NOINTERFACE, so the
// runtime uses its defaults for them.
var iidEnvironmentOptions = mustGUID("{2FDE08A8-1E9A-4766-8C05-95A9CEB9D1C5}")

// targetCompatibleVersion is the oldest runtime the bindings need.
const targetCompatibleVersion = "101.0.1210.39"

var (
	optionsVtbl        [11]uintptr
	optionsVtblOnce    sync.Once
	procCoTaskMemAlloc = windows.NewLazySystemDLL("ole32.dll").NewProc("CoTaskMemAlloc")
)

const eNotImpl = 0x80004001

func initOptionsVtbl() {
	initHandlerVtbl()
	optionsVtblOnce.Do(func() {
		optionsVtbl[0] = handlerVtbl[0]
		optionsVtbl[1] = handlerVtbl[1]
		optionsVtbl[2] = handlerVtbl[2]
		optionsVtbl[3] = windows.NewCallback(func(this, out uintptr) uintptr { // get_AdditionalBrowserArguments
			h := lookupHandler(this)
			if h == nil {
				return eFail
			}
			return coTaskString(h.text, out)
		})
		putNotImpl := windows.NewCallback(func(this, v uintptr) uintptr { return eNotImpl })
		optionsVtbl[4] = putNotImpl
		optionsVtbl[5] = windows.NewCallback(func(this, out uintptr) uintptr { return coTaskString("", out) }) // get_Language
		optionsVtbl[6] = putNotImpl
		optionsVtbl[7] = windows.NewCallback(func(this, out uintptr) uintptr { // get_TargetCompatibleBrowserVersion
			return coTaskString(targetCompatibleVersion, out)
		})
		optionsVtbl[8] = putNotImpl
		optionsVtbl[9] = windows.NewCallback(func(this, out uintptr) uintptr { // get_AllowSingleSignOnUsingOSPrimaryAccount
			if out == 0 {
				return ePointer
			}
			*(*int32)(ptrFromUintptr(out)) = 0
			return sOK
		})
		optionsVtbl[10] = putNotImpl
	})
}

// coTaskString writes a CoTaskMemAlloc'd UTF-16 copy of s to *out; the
// runtime frees it.
func coTaskString(s string, out uintptr) uintptr {
	if out == 0 {
		return ePointer
	}
	*(*uintptr)(ptrFromUintptr(out)) = 0
	u, err := windows.UTF16FromString(s)
	if err != nil {
		return eFail
	}
	n := uintptr(len(u)) * 2
	mem, _, _ := procCoTaskMemAlloc.Call(n)
	if mem == 0 {
		return 0x8007000E // E_OUTOFMEMORY
	}
	dst := unsafe.Slice((*uint16)(ptrFromUintptr(mem)), len(u))
	copy(dst, u)
	*(*uintptr)(ptrFromUintptr(out)) = mem
	return sOK
}

// newEnvironmentOptions returns an options object carrying the browser
// arguments, with one reference owned by the caller.
func newEnvironmentOptions(args string) (comPtr, error) {
	initOptionsVtbl()
	p, err := newHandler(iidEnvironmentOptions, nil)
	if err != nil {
		return 0, err
	}
	handlersMu.Lock()
	handlers[memOf(uintptr(p)).id].text = args
	handlersMu.Unlock()
	memOf(uintptr(p)).vtbl = uintptr(unsafe.Pointer(&optionsVtbl[0]))
	return p, nil
}
