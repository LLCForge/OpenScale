//go:build windows

package webview

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ---- WebView2 interface ids and vtable indexes (QueryInterface = 0) ----

var (
	iidEnvironmentCompleted   = mustGUID("{4E8A3389-C9D8-4BD2-B6B5-124FEE6CC14D}")
	iidControllerCompleted    = mustGUID("{6C4819F3-C9B7-4260-8127-C9F5BDE7F68C}")
	iidNavigationStarting     = mustGUID("{9ADBE429-F36D-432B-9DDC-F8881FBD76E3}")
	iidNavigationCompleted    = mustGUID("{D33A35BF-1C49-4F98-93AB-006E0533FE1C}")
	iidNewWindowRequested     = mustGUID("{D4C185FE-C81C-4989-97AF-2D3FA7AB5651}")
	iidPermissionRequested    = mustGUID("{15E1C6A3-C72A-4DF3-91D7-D097FBEC6BFD}")
	iidDownloadStarting       = mustGUID("{EFEDC989-C396-41CA-83F7-07F845A55724}")
	iidBasicAuthRequested     = mustGUID("{58B4D6C2-18D4-497E-B39B-9A96533FA278}")
	iidWebResourceRequested   = mustGUID("{AB00B74C-15F1-4646-80E8-E76341D25D71}")
	iidWindowCloseRequested   = mustGUID("{5C19E9E0-092F-486B-AFFA-CA8231913039}")
	iidProcessFailed          = mustGUID("{79E0AEA4-990B-42D9-AA1D-0FCC2E5BC7F1}")
	iidICoreWebView2_10       = mustGUID("{B1690564-6F5A-4983-8E48-31D1143FECDB}")
	iidICoreWebView2Settings4 = mustGUID("{CB56846C-4168-4D53-B04F-03B6D6796FF2}")
	iidICoreWebView2_22       = mustGUID("{DB75DFC7-A857-4632-A398-6969DDE26C0A}")
)

const (
	idxWV22AddFilterWithSourceKinds = 123
	sourceKindsAll                  = 0xffffffff
)

const (
	// ICoreWebView2Environment
	idxEnvCreateController     = 3
	idxEnvCreateResourceAnswer = 4

	// ICoreWebView2Controller
	idxControllerPutIsVisible     = 4
	idxControllerPutBounds        = 6
	idxControllerMoveFocus        = 12
	idxControllerNotifyParentMove = 23
	idxControllerClose            = 24
	idxControllerGetCoreWebView2  = 25

	// ICoreWebView2 ... ICoreWebView2_10 (one flat vtable)
	idxWVGetSettings                = 3
	idxWVNavigate                   = 5
	idxWVAddNavigationStarting      = 7
	idxWVAddNavigationCompleted     = 15
	idxWVAddFrameNavigationStarting = 17
	idxWVAddPermissionRequested     = 23
	idxWVAddProcessFailed           = 25
	idxWVReload                     = 31
	idxWVAddNewWindowRequested      = 44
	idxWVAddWebResourceRequested    = 55
	idxWVAddWebResourceFilter       = 57
	idxWVAddWindowCloseRequested    = 59
	idxWVAddDownloadStarting        = 75
	idxWVAddBasicAuthRequested      = 97

	// ICoreWebView2Settings ... Settings4 (one flat vtable)
	idxSetScriptEnabled          = 4
	idxSetWebMessageEnabled      = 6
	idxSetScriptDialogsEnabled   = 8
	idxSetStatusBarEnabled       = 10
	idxSetDevToolsEnabled        = 12
	idxSetContextMenusEnabled    = 14
	idxSetHostObjectsAllowed     = 16
	idxSetZoomControlEnabled     = 18
	idxSetBuiltInErrorPage       = 20
	idxSetBrowserAcceleratorKeys = 24
	idxSetPasswordAutosave       = 26
	idxSetGeneralAutofill        = 28

	// Event argument interfaces
	idxNavArgsGetURI           = 3
	idxNavArgsIsUserInitiated  = 4
	idxNavArgsPutCancel        = 8
	idxNewWinGetURI            = 3
	idxNewWinPutHandled        = 6
	idxNewWinIsUserInitiated   = 8
	idxPermGetURI              = 3
	idxPermPutState            = 7
	idxDownloadPutCancel       = 5
	idxDownloadPutHandled      = 9
	idxAuthGetURI              = 3
	idxAuthPutCancel           = 7
	idxResArgsGetRequest       = 3
	idxResArgsPutResponse      = 5
	idxRequestGetURI           = 3
	idxNavDoneIsSuccess        = 3
	idxProcessFailedGetKind    = 3
	permissionStateDeny        = 2
	resourceContextAll         = 0
	moveFocusProgrammatic      = 0
	processFailedBrowserExited = 0
	processFailedRenderExited  = 1
	processFailedFrameExited   = 3
	maxRenderReloads           = 3
)

// ---- Win32 ----

var (
	user32                       = windows.NewLazySystemDLL("user32.dll")
	procRegisterClassExW         = user32.NewProc("RegisterClassExW")
	procCreateWindowExW          = user32.NewProc("CreateWindowExW")
	procDefWindowProcW           = user32.NewProc("DefWindowProcW")
	procDestroyWindow            = user32.NewProc("DestroyWindow")
	procShowWindow               = user32.NewProc("ShowWindow")
	procSetForegroundWindow      = user32.NewProc("SetForegroundWindow")
	procGetMessageW              = user32.NewProc("GetMessageW")
	procTranslateMessage         = user32.NewProc("TranslateMessage")
	procDispatchMessageW         = user32.NewProc("DispatchMessageW")
	procPostMessageW             = user32.NewProc("PostMessageW")
	procPostQuitMessage          = user32.NewProc("PostQuitMessage")
	procGetClientRect            = user32.NewProc("GetClientRect")
	procSetWindowPos             = user32.NewProc("SetWindowPos")
	procGetDpiForWindow          = user32.NewProc("GetDpiForWindow")
	procSetThreadDpiAwarenessCtx = user32.NewProc("SetThreadDpiAwarenessContext")
	procMonitorFromWindow        = user32.NewProc("MonitorFromWindow")
	procGetMonitorInfoW          = user32.NewProc("GetMonitorInfoW")
	procLoadCursorW              = user32.NewProc("LoadCursorW")
	procSendMessageW             = user32.NewProc("SendMessageW")
	procCreateIconFromResourceEx = user32.NewProc("CreateIconFromResourceEx")
	procDestroyIcon              = user32.NewProc("DestroyIcon")
	procGetSystemMetricsForDpi   = user32.NewProc("GetSystemMetricsForDpi")
	procGetSystemMetrics         = user32.NewProc("GetSystemMetrics")
	kernel32                     = windows.NewLazySystemDLL("kernel32.dll")
	procGetModuleHandleW         = kernel32.NewProc("GetModuleHandleW")
	createEnvironmentProcMu      sync.Mutex
	createEnvironmentProcs       = map[string]*windows.Proc{}
	windowClassOnce              sync.Once
	windowClassErr               error
	windowClassName, _           = windows.UTF16PtrFromString("OpenScaleWebViewWindow")
	windowsByHandle              sync.Map // hwnd -> *win
	wndProcCallback              uintptr
	dpiAwarenessPerMonitorV2     = ^uintptr(3) // DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 (-4)
	loadLibrarySearchDLLLoadDir  = uint32(0x00000100)
	loadLibrarySearchSystem32    = uint32(0x00000800)
	createEnvironmentProcName    = "CreateWebViewEnvironmentWithOptionsInternal"
	webView2EnvironmentVariables = []string{"WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS", "WEBVIEW2_BROWSER_EXECUTABLE_FOLDER", "WEBVIEW2_USER_DATA_FOLDER", "WEBVIEW2_RELEASE_CHANNEL_PREFERENCE", "WEBVIEW2_PIPE_FOR_SCRIPT_DEBUGGER", "WEBVIEW2_WAIT_FOR_SCRIPT_DEBUGGER"}
	errBrowserProcessExited      = errors.New("webview: WebView2 tarayıcı süreci beklenmedik biçimde kapandı")
)

const (
	wmDestroy        = 0x0002
	wmMove           = 0x0003
	wmSize           = 0x0005
	wmSetFocus       = 0x0007
	wmClose          = 0x0010
	wmGetMinMaxInfo  = 0x0024
	wmSetIcon        = 0x0080
	wmDpiChanged     = 0x02E0
	wmAppNavigate    = 0x8000 + 1
	wmCopyData       = 0x004A
	wsOverlappedWin  = 0x00CF0000
	cwUseDefault     = 0x80000000
	swShow           = 5
	csHRedraw        = 0x0002
	csVRedraw        = 0x0001
	idcArrow         = 32512
	colorWindow      = 5
	swpNoZOrder      = 0x0004
	swpNoActivate    = 0x0010
	monitorNearest   = 2
	iconSmall        = 0
	iconBig          = 1
	smCxIcon         = 11
	smCxSmIcon       = 49
	lrDefaultColor   = 0
	iconResVersion   = 0x00030000
	defaultDPI       = 96
	maxPendingNavReq = 16
)

type winRect struct{ left, top, right, bottom int32 }

type winPoint struct{ x, y int32 }

type wndClassEx struct {
	size       uint32
	style      uint32
	wndProc    uintptr
	clsExtra   int32
	wndExtra   int32
	instance   uintptr
	icon       uintptr
	cursor     uintptr
	background uintptr
	menuName   *uint16
	className  *uint16
	iconSm     uintptr
}

type winMsg struct {
	hwnd    uintptr
	message uint32
	wParam  uintptr
	lParam  uintptr
	time    uint32
	pt      winPoint
	private uint32
}

type minMaxInfo struct {
	reserved     winPoint
	maxSize      winPoint
	maxPosition  winPoint
	minTrackSize winPoint
	maxTrackSize winPoint
}

type monitorInfo struct {
	size    uint32
	monitor winRect
	work    winRect
	flags   uint32
}

// win is the state of one open window. Every field is used only on the UI
// thread, except hwnd which is read by the cancel goroutine.
type win struct {
	cfg  config
	hwnd uintptr

	env        comPtr
	controller comPtr
	webview    comPtr // ICoreWebView2_10
	handlers   []comPtr
	icons      []uintptr

	err           error
	renderReloads int

	navMu   sync.Mutex
	navReqs []string
}

// open runs the window on a fresh OS thread that is discarded afterwards,
// so no COM apartment or DPI setting leaks into the Go scheduler.
func open(ctx context.Context, cfg config) error {
	rt, err := findRuntime()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	dataDir := cfg.dataDir
	if dataDir == "" {
		dataDir, err = defaultDataDir()
		if err != nil {
			return fmt.Errorf("%w: %v", ErrUnavailable, err)
		}
	}
	if err := ensurePrivateDir(dataDir); err != nil {
		return fmt.Errorf("%w: veri klasörü: %v", ErrUnavailable, err)
	}
	create, err := loadCreateEnvironment(rt.dll)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	// Arguments and folders injected through the environment of this
	// process (for example a remote debugging port) are not accepted.
	for _, name := range webView2EnvironmentVariables {
		_ = os.Unsetenv(name)
	}
	done := make(chan error, 1)
	go func() {
		// Never unlocked: the thread exits with the goroutine.
		runtime.LockOSThread()
		done <- runWindow(ctx, cfg, create, dataDir)
	}()
	return <-done
}

// defaultDataDir is %LOCALAPPDATA%\OpenScale\WebView2.
func defaultDataDir() (string, error) {
	local, err := windows.KnownFolderPath(windows.FOLDERID_LocalAppData, 0)
	if err != nil || local == "" {
		return "", errors.New("LOCALAPPDATA bulunamadı")
	}
	return filepath.Join(local, "OpenScale", "WebView2"), nil
}

// ensurePrivateDir creates dir so that only the current user and SYSTEM
// can open it. An existing folder must be a real directory, not a link.
func ensurePrivateDir(dir string) error {
	if fi, err := os.Lstat(dir); err == nil {
		if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
			return errors.New("klasör değil veya bağlantı")
		}
		attrs, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(dir))
		if err != nil {
			return err
		}
		if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return errors.New("klasör bir yeniden ayrıştırma noktası")
		}
		// A DataDir override may point into a shared folder: a profile
		// another account created in advance (preferences, cached pages
		// of the panel) is not used.
		return checkDirOwner(dir)
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + user.User.Sid.String() + ")(A;OICI;FA;;;SY)")
	if err != nil {
		return err
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	if err := windows.CreateDirectory(p, &sa); err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return err
	}
	return nil
}

// checkDirOwner accepts dir only when its owner is the current user, SYSTEM
// or the Administrators group (the owner of folders an elevated process
// creates).
func checkDirOwner(dir string) error {
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("klasör sahibi okunamadı: %w", err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return errors.New("klasör sahibi okunamadı")
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	if owner.Equals(user.User.Sid) || owner.IsWellKnown(windows.WinLocalSystemSid) ||
		owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		return nil
	}
	return errors.New("klasörün sahibi bu kullanıcı değil")
}

// loadCreateEnvironment loads the runtime DLL by absolute path, with its
// dependencies searched only in its own folder and System32.
func loadCreateEnvironment(dll string) (*windows.Proc, error) {
	createEnvironmentProcMu.Lock()
	defer createEnvironmentProcMu.Unlock()
	if p, ok := createEnvironmentProcs[dll]; ok {
		return p, nil
	}
	if !filepath.IsAbs(dll) {
		return nil, errors.New("WebView2 DLL yolu mutlak değil")
	}
	h, err := windows.LoadLibraryEx(dll, 0, uintptr(loadLibrarySearchDLLLoadDir|loadLibrarySearchSystem32))
	if err != nil {
		return nil, fmt.Errorf("WebView2 yüklenemedi: %w", err)
	}
	// The module stays loaded: runtime threads may outlive the window.
	d := &windows.DLL{Name: dll, Handle: windows.Handle(h)}
	p, err := d.FindProc(createEnvironmentProcName)
	if err != nil {
		return nil, fmt.Errorf("WebView2 giriş noktası yok: %w", err)
	}
	createEnvironmentProcs[dll] = p
	return p, nil
}

func registerWindowClass() error {
	windowClassOnce.Do(func() {
		wndProcCallback = windows.NewCallback(wndProc)
		inst, _, _ := procGetModuleHandleW.Call(0)
		cursor, _, _ := procLoadCursorW.Call(0, idcArrow)
		wc := wndClassEx{
			style:      csHRedraw | csVRedraw,
			wndProc:    wndProcCallback,
			instance:   inst,
			cursor:     cursor,
			background: colorWindow + 1,
			className:  windowClassName,
		}
		wc.size = uint32(unsafe.Sizeof(wc))
		if r, _, e := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc))); r == 0 {
			windowClassErr = fmt.Errorf("RegisterClassEx: %v", e)
		}
	})
	return windowClassErr
}

// runWindow runs on a locked OS thread.
func runWindow(ctx context.Context, cfg config, create *windows.Proc, dataDir string) error {
	if err := windows.CoInitializeEx(0, windows.COINIT_APARTMENTTHREADED); err != nil {
		return fmt.Errorf("%w: CoInitializeEx: %v", ErrUnavailable, err)
	}
	defer windows.CoUninitialize()
	if procSetThreadDpiAwarenessCtx.Find() == nil {
		_, _, _ = procSetThreadDpiAwarenessCtx.Call(dpiAwarenessPerMonitorV2)
	}
	if err := registerWindowClass(); err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	w := &win{cfg: cfg}
	title, err := windows.UTF16PtrFromString(cfg.title)
	if err != nil {
		return err
	}
	inst, _, _ := procGetModuleHandleW.Call(0)
	hwnd, _, e := procCreateWindowExW.Call(0,
		uintptr(unsafe.Pointer(windowClassName)), uintptr(unsafe.Pointer(title)),
		wsOverlappedWin, cwUseDefault, cwUseDefault, cwUseDefault, cwUseDefault,
		0, 0, inst, 0)
	if hwnd == 0 {
		return fmt.Errorf("%w: CreateWindowEx: %v", ErrUnavailable, e)
	}
	w.hwnd = hwnd
	windowsByHandle.Store(hwnd, w)
	defer windowsByHandle.Delete(hwnd)
	w.placeWindow()
	w.setIcons()
	w.initialTitleBar()
	if !cfg.hidden {
		_, _, _ = procShowWindow.Call(hwnd, swShow)
		_, _, _ = procSetForegroundWindow.Call(hwnd)
	}

	envHandler, err := newHandler(iidEnvironmentCompleted, w.onEnvironment)
	if err != nil {
		_, _, _ = procDestroyWindow.Call(hwnd)
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	w.handlers = append(w.handlers, envHandler)
	udf, err := windows.UTF16PtrFromString(dataDir)
	if err != nil {
		_, _, _ = procDestroyWindow.Call(hwnd)
		return err
	}
	opts, err := newEnvironmentOptions(browserArguments(cfg.origin))
	if err != nil {
		_, _, _ = procDestroyWindow.Call(hwnd)
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	w.handlers = append(w.handlers, opts)
	// checkRunningInstance = 1, runtime type = installed (0).
	hr, _, _ := create.Call(1, 0, uintptr(unsafe.Pointer(udf)), uintptr(opts), uintptr(envHandler))
	if err := hrErr(hr); err != nil {
		w.fail(fmt.Errorf("%w: WebView2 ortamı oluşturulamadı: %v", ErrUnavailable, err))
	}

	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_, _, _ = procPostMessageW.Call(hwnd, wmClose, 0, 0)
		case <-stop:
		}
	}()

	var m winMsg
	for {
		r, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		_, _, _ = procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		_, _, _ = procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
	w.releaseAll()
	if w.err != nil {
		return w.err
	}
	return ctx.Err()
}

// fail records the first error and closes the window.
func (w *win) fail(err error) {
	if w.err == nil {
		w.err = err
	}
	if w.hwnd != 0 {
		_, _, _ = procPostMessageW.Call(w.hwnd, wmClose, 0, 0)
	}
}

func (w *win) dpi() uint32 {
	if w.hwnd != 0 && procGetDpiForWindow.Find() == nil {
		if d, _, _ := procGetDpiForWindow.Call(w.hwnd); d != 0 {
			return uint32(d)
		}
	}
	return defaultDPI
}

func scale(v int, dpi uint32) int32 { return int32(int64(v) * int64(dpi) / defaultDPI) }

// placeWindow sizes the window for the monitor's DPI and centres it on
// the monitor's work area, never larger than the work area.
func (w *win) placeWindow() {
	dpi := w.dpi()
	width, height := scale(w.cfg.width, dpi), scale(w.cfg.height, dpi)
	mon, _, _ := procMonitorFromWindow.Call(w.hwnd, monitorNearest)
	mi := monitorInfo{}
	mi.size = uint32(unsafe.Sizeof(mi))
	x, y := int32(0), int32(0)
	if r, _, _ := procGetMonitorInfoW.Call(mon, uintptr(unsafe.Pointer(&mi))); r != 0 {
		ww := mi.work.right - mi.work.left
		wh := mi.work.bottom - mi.work.top
		width, height = min(width, ww), min(height, wh)
		x = mi.work.left + (ww-width)/2
		y = mi.work.top + (wh-height)/2
	}
	_, _, _ = procSetWindowPos.Call(w.hwnd, 0, uintptr(x), uintptr(y), uintptr(width), uintptr(height), swpNoZOrder|swpNoActivate)
}

// setIcons loads the big and small icon from the .ico data.
func (w *win) setIcons() {
	if len(w.cfg.iconICO) == 0 {
		return
	}
	images, err := parseICO(w.cfg.iconICO)
	if err != nil {
		return
	}
	dpi := w.dpi()
	for _, which := range []struct {
		metric int
		kind   uintptr
	}{{smCxIcon, iconBig}, {smCxSmIcon, iconSmall}} {
		size := metricForDPI(which.metric, dpi)
		im, ok := pickICO(images, size)
		if !ok {
			continue
		}
		h, _, _ := procCreateIconFromResourceEx.Call(uintptr(unsafe.Pointer(&im.data[0])), uintptr(len(im.data)), 1, iconResVersion, uintptr(size), uintptr(size), lrDefaultColor)
		if h == 0 {
			continue
		}
		w.icons = append(w.icons, h)
		_, _, _ = procSendMessageW.Call(w.hwnd, wmSetIcon, which.kind, h)
	}
}

func metricForDPI(index int, dpi uint32) int {
	if procGetSystemMetricsForDpi.Find() == nil {
		if v, _, _ := procGetSystemMetricsForDpi.Call(uintptr(index), uintptr(dpi)); v != 0 {
			return int(v)
		}
	}
	v, _, _ := procGetSystemMetrics.Call(uintptr(index))
	if v == 0 {
		return 32
	}
	return int(v)
}

func (w *win) releaseAll() {
	if w.webview != 0 {
		w.webview.release()
		w.webview = 0
	}
	if w.controller != 0 {
		w.controller.release()
		w.controller = 0
	}
	if w.env != 0 {
		w.env.release()
		w.env = 0
	}
	for _, h := range w.handlers {
		h.release()
	}
	w.handlers = nil
	for _, h := range w.icons {
		_, _, _ = procDestroyIcon.Call(h)
	}
	w.icons = nil
}

func wndProc(hwnd, msg, wParam, lParam uintptr) uintptr {
	v, ok := windowsByHandle.Load(hwnd)
	if !ok {
		r, _, _ := procDefWindowProcW.Call(hwnd, msg, wParam, lParam)
		return r
	}
	w := v.(*win)
	switch msg {
	case wmSize:
		w.resize()
		return 0
	case wmMove:
		if w.controller != 0 {
			w.controller.call(idxControllerNotifyParentMove)
		}
	case wmSetFocus:
		if w.controller != 0 {
			w.controller.call(idxControllerMoveFocus, moveFocusProgrammatic)
		}
	case wmGetMinMaxInfo:
		if lParam != 0 {
			mmi := (*minMaxInfo)(ptrFromUintptr(lParam))
			dpi := w.dpi()
			mmi.minTrackSize = winPoint{scale(w.cfg.minWidth, dpi), scale(w.cfg.minHeight, dpi)}
		}
		return 0
	case wmDpiChanged:
		if lParam != 0 {
			r := (*winRect)(ptrFromUintptr(lParam))
			_, _, _ = procSetWindowPos.Call(hwnd, 0, uintptr(r.left), uintptr(r.top),
				uintptr(r.right-r.left), uintptr(r.bottom-r.top), swpNoZOrder|swpNoActivate)
		}
		return 0
	case wmAppNavigate:
		w.drainNavigations()
		return 0
	case wmCopyData:
		return w.onForward(lParam) // forward.go
	case wmClose:
		_, _, _ = procDestroyWindow.Call(hwnd)
		return 0
	case wmDestroy:
		if w.controller != 0 {
			w.controller.call(idxControllerClose)
		}
		_, _, _ = procPostQuitMessage.Call(0)
		return 0
	}
	r, _, _ := procDefWindowProcW.Call(hwnd, msg, wParam, lParam)
	return r
}

func (w *win) resize() {
	if w.controller == 0 {
		return
	}
	var r winRect
	if ok, _, _ := procGetClientRect.Call(w.hwnd, uintptr(unsafe.Pointer(&r))); ok == 0 {
		return
	}
	_ = w.controller.putBounds(r)
}

// ---- WebView2 set-up ----

func (w *win) onEnvironment(hr, env uintptr) uintptr {
	if err := hrErr(hr); err != nil || env == 0 {
		w.fail(fmt.Errorf("%w: WebView2 ortamı oluşturulamadı: %v", ErrUnavailable, err))
		return sOK
	}
	w.env = comPtr(env)
	w.env.addRef()
	h, err := newHandler(iidControllerCompleted, w.onController)
	if err != nil {
		w.fail(fmt.Errorf("%w: %v", ErrUnavailable, err))
		return sOK
	}
	w.handlers = append(w.handlers, h)
	if err := hrErr(w.env.call(idxEnvCreateController, w.hwnd, uintptr(h))); err != nil {
		w.fail(fmt.Errorf("%w: WebView2 denetleyicisi oluşturulamadı: %v", ErrUnavailable, err))
	}
	return sOK
}

func (w *win) onController(hr, controller uintptr) uintptr {
	if err := hrErr(hr); err != nil || controller == 0 {
		w.fail(fmt.Errorf("%w: WebView2 denetleyicisi oluşturulamadı: %v", ErrUnavailable, err))
		return sOK
	}
	w.controller = comPtr(controller)
	w.controller.addRef()
	if err := w.setup(); err != nil {
		// Fail closed: a window without every guard is not shown.
		w.fail(fmt.Errorf("%w: %v", ErrUnavailable, err))
	}
	return sOK
}

func (w *win) setup() error {
	base, err := w.controller.getPtr(idxControllerGetCoreWebView2)
	if err != nil {
		return fmt.Errorf("ICoreWebView2 alınamadı: %v", err)
	}
	wv, err := base.queryInterface(&iidICoreWebView2_10)
	base.release()
	if err != nil {
		return fmt.Errorf("WebView2 çalışma zamanı çok eski (ICoreWebView2_10 yok): %v", err)
	}
	w.webview = wv
	if err := w.applySettings(); err != nil {
		return err
	}
	if err := w.addHandlers(); err != nil {
		return err
	}
	filter, _ := windows.UTF16PtrFromString("*")
	if err := hrErr(w.webview.call(idxWVAddWebResourceFilter, uintptr(unsafe.Pointer(filter)), resourceContextAll)); err != nil {
		return fmt.Errorf("istek süzgeci eklenemedi: %v", err)
	}
	// Newer runtimes also report worker requests with the source-kind
	// filter (ICoreWebView2_22); older ones lack it, which is not fatal:
	// the proxy rule of browserArguments is the network-level guard.
	if wv22, err := w.webview.queryInterface(&iidICoreWebView2_22); err == nil {
		_ = hrErr(wv22.call(idxWV22AddFilterWithSourceKinds, uintptr(unsafe.Pointer(filter)), resourceContextAll, sourceKindsAll))
		wv22.release()
	}
	w.resize()
	if err := hrErr(w.controller.call(idxControllerPutIsVisible, 1)); err != nil {
		return fmt.Errorf("görünürlük: %v", err)
	}
	if err := w.navigate(w.cfg.url); err != nil {
		return err
	}
	w.controller.call(idxControllerMoveFocus, moveFocusProgrammatic)
	if w.cfg.hooks != nil && w.cfg.hooks.ready != nil {
		w.cfg.hooks.ready(w.queueNavigation)
	}
	return nil
}

func (w *win) applySettings() error {
	base, err := w.webview.getPtr(idxWVGetSettings)
	if err != nil {
		return fmt.Errorf("ayarlar alınamadı: %v", err)
	}
	s, err := base.queryInterface(&iidICoreWebView2Settings4)
	base.release()
	if err != nil {
		return fmt.Errorf("WebView2 çalışma zamanı çok eski (Settings4 yok): %v", err)
	}
	defer s.release()
	for _, set := range []struct {
		idx  int
		on   bool
		name string
	}{
		{idxSetScriptEnabled, true, "IsScriptEnabled"},
		// Yalnızca tema iletisi kabul edilir (onWebMessage, parseThemeMessage).
		{idxSetWebMessageEnabled, true, "IsWebMessageEnabled"},
		{idxSetScriptDialogsEnabled, true, "AreDefaultScriptDialogsEnabled"},
		{idxSetStatusBarEnabled, false, "IsStatusBarEnabled"},
		{idxSetDevToolsEnabled, false, "AreDevToolsEnabled"},
		{idxSetContextMenusEnabled, false, "AreDefaultContextMenusEnabled"},
		{idxSetHostObjectsAllowed, false, "AreHostObjectsAllowed"},
		{idxSetZoomControlEnabled, true, "IsZoomControlEnabled"},
		{idxSetBuiltInErrorPage, true, "IsBuiltInErrorPageEnabled"},
		{idxSetBrowserAcceleratorKeys, false, "AreBrowserAcceleratorKeysEnabled"},
		{idxSetPasswordAutosave, false, "IsPasswordAutosaveEnabled"},
		{idxSetGeneralAutofill, false, "IsGeneralAutofillEnabled"},
	} {
		if err := s.putBool(set.idx, set.on); err != nil {
			return fmt.Errorf("ayar %s uygulanamadı: %v", set.name, err)
		}
	}
	return nil
}

func (w *win) addHandlers() error {
	for _, ev := range []struct {
		idx  int
		iid  windows.GUID
		fn   handlerFunc
		name string
	}{
		{idxWVAddNavigationStarting, iidNavigationStarting, w.onNavigationStarting, "NavigationStarting"},
		{idxWVAddFrameNavigationStarting, iidNavigationStarting, w.onFrameNavigationStarting, "FrameNavigationStarting"},
		{idxWVAddNavigationCompleted, iidNavigationCompleted, w.onNavigationCompleted, "NavigationCompleted"},
		{idxWVAddNewWindowRequested, iidNewWindowRequested, w.onNewWindow, "NewWindowRequested"},
		{idxWVAddPermissionRequested, iidPermissionRequested, w.onPermission, "PermissionRequested"},
		{idxWVAddWebResourceRequested, iidWebResourceRequested, w.onResource, "WebResourceRequested"},
		{idxWVAddDownloadStarting, iidDownloadStarting, w.onDownload, "DownloadStarting"},
		{idxWVAddBasicAuthRequested, iidBasicAuthRequested, w.onBasicAuth, "BasicAuthenticationRequested"},
		{idxWVAddWindowCloseRequested, iidWindowCloseRequested, w.onWindowClose, "WindowCloseRequested"},
		{idxWVAddProcessFailed, iidProcessFailed, w.onProcessFailed, "ProcessFailed"},
		{idxWVAddWebMessageReceived, iidWebMessageReceived, w.onWebMessage, "WebMessageReceived"},
	} {
		h, err := newHandler(ev.iid, ev.fn)
		if err != nil {
			return err
		}
		w.handlers = append(w.handlers, h)
		var token int64
		if err := hrErr(w.webview.call(ev.idx, uintptr(h), uintptr(unsafe.Pointer(&token)))); err != nil {
			return fmt.Errorf("%s işleyicisi eklenemedi: %v", ev.name, err)
		}
	}
	return nil
}

// navigate loads u after the same origin check as any other navigation.
func (w *win) navigate(u string) error {
	if w.cfg.origin.check(u) != actionAllow {
		w.cfg.emit("nav-block", u)
		return nil
	}
	p, err := windows.UTF16PtrFromString(u)
	if err != nil {
		return err
	}
	if err := hrErr(w.webview.call(idxWVNavigate, uintptr(unsafe.Pointer(p)))); err != nil {
		return fmt.Errorf("sayfa açılamadı: %v", err)
	}
	return nil
}

// queueNavigation may be called from any goroutine; the URL goes through
// NavigationStarting like every other navigation.
func (w *win) queueNavigation(u string) {
	w.navMu.Lock()
	if len(w.navReqs) < maxPendingNavReq {
		w.navReqs = append(w.navReqs, u)
	}
	w.navMu.Unlock()
	_, _, _ = procPostMessageW.Call(w.hwnd, wmAppNavigate, 0, 0)
}

func (w *win) drainNavigations() {
	w.navMu.Lock()
	reqs := w.navReqs
	w.navReqs = nil
	w.navMu.Unlock()
	if w.webview == 0 {
		return
	}
	for _, u := range reqs {
		p, err := windows.UTF16PtrFromString(u)
		if err != nil {
			continue
		}
		// Deliberately not pre-checked: tests use this to prove that
		// NavigationStarting blocks foreign URLs.
		w.webview.call(idxWVNavigate, uintptr(unsafe.Pointer(p)))
	}
}

// ---- event handlers (UI thread) ----

func (w *win) onNavigationStarting(_, args uintptr) uintptr {
	a := comPtr(args)
	uri, err := a.getString(idxNavArgsGetURI)
	if err != nil {
		_ = a.putBool(idxNavArgsPutCancel, true)
		return sOK
	}
	user, _ := a.getBool(idxNavArgsIsUserInitiated)
	switch w.cfg.origin.navigate(uri, user) {
	case actionAllow:
		w.cfg.emit("nav-allow", uri)
	case actionExternal:
		_ = a.putBool(idxNavArgsPutCancel, true)
		w.cfg.emit("nav-external", uri)
		openExternalAsync(uri)
	default:
		_ = a.putBool(idxNavArgsPutCancel, true)
		w.cfg.emit("nav-block", uri)
	}
	return sOK
}

func (w *win) onFrameNavigationStarting(_, args uintptr) uintptr {
	a := comPtr(args)
	uri, err := a.getString(idxNavArgsGetURI)
	if err != nil || w.cfg.origin.check(uri) != actionAllow {
		_ = a.putBool(idxNavArgsPutCancel, true)
		w.cfg.emit("frame-block", uri)
	}
	return sOK
}

func (w *win) onNavigationCompleted(_, args uintptr) uintptr {
	ok, _ := comPtr(args).getBool(idxNavDoneIsSuccess)
	if w.cfg.hooks != nil {
		uri := ""
		if w.webview != 0 {
			uri, _ = w.webview.getString(4) // get_Source
		}
		if ok {
			w.cfg.emit("nav-completed", uri)
		} else {
			w.cfg.emit("nav-failed", uri)
		}
	}
	return sOK
}

func (w *win) onNewWindow(_, args uintptr) uintptr {
	a := comPtr(args)
	// Handled without a new window: no window is ever created.
	_ = a.putBool(idxNewWinPutHandled, true)
	uri, err := a.getString(idxNewWinGetURI)
	if err != nil {
		return sOK
	}
	user, _ := a.getBool(idxNewWinIsUserInitiated)
	switch w.cfg.origin.navigate(uri, user) {
	case actionAllow:
		// A link to the panel itself opens in this window.
		w.cfg.emit("newwindow-same", uri)
		_ = w.navigate(uri)
	case actionExternal:
		w.cfg.emit("newwindow-external", uri)
		openExternalAsync(uri)
	default:
		w.cfg.emit("newwindow-block", uri)
	}
	return sOK
}

func (w *win) onPermission(_, args uintptr) uintptr {
	a := comPtr(args)
	_ = hrErr(a.call(idxPermPutState, permissionStateDeny))
	uri, _ := a.getString(idxPermGetURI)
	w.cfg.emit("permission-deny", uri)
	return sOK
}

func (w *win) onResource(_, args uintptr) uintptr {
	a := comPtr(args)
	req, err := a.getPtr(idxResArgsGetRequest)
	if err != nil {
		w.blockResource(a, "")
		return sOK
	}
	uri, err := req.getString(idxRequestGetURI)
	req.release()
	if err != nil || !w.cfg.origin.subresource(uri) {
		w.blockResource(a, uri)
	}
	return sOK
}

// blockResource answers a request with 403 and no body.
func (w *win) blockResource(args comPtr, uri string) {
	w.cfg.emit("resource-block", uri)
	if w.env == 0 {
		return
	}
	reason, _ := windows.UTF16PtrFromString("Forbidden")
	headers, _ := windows.UTF16PtrFromString("Content-Type: text/plain")
	var resp comPtr
	if err := hrErr(w.env.call(idxEnvCreateResourceAnswer, 0, 403, uintptr(unsafe.Pointer(reason)), uintptr(unsafe.Pointer(headers)), uintptr(unsafe.Pointer(&resp)))); err != nil || resp == 0 {
		return
	}
	_ = hrErr(args.call(idxResArgsPutResponse, uintptr(resp)))
	resp.release()
}

func (w *win) onDownload(_, args uintptr) uintptr {
	a := comPtr(args)
	_ = a.putBool(idxDownloadPutCancel, true)
	_ = a.putBool(idxDownloadPutHandled, true)
	w.cfg.emit("download-cancel", "")
	return sOK
}

func (w *win) onBasicAuth(_, args uintptr) uintptr {
	a := comPtr(args)
	_ = a.putBool(idxAuthPutCancel, true)
	uri, _ := a.getString(idxAuthGetURI)
	w.cfg.emit("auth-cancel", uri)
	return sOK
}

func (w *win) onWindowClose(_, _ uintptr) uintptr {
	_, _, _ = procPostMessageW.Call(w.hwnd, wmClose, 0, 0)
	return sOK
}

func (w *win) onProcessFailed(_, args uintptr) uintptr {
	kind, err := comPtr(args).getInt(idxProcessFailedGetKind)
	if err != nil {
		return sOK
	}
	switch kind {
	case processFailedBrowserExited:
		w.fail(errBrowserProcessExited)
	case processFailedRenderExited, processFailedFrameExited:
		if w.renderReloads < maxRenderReloads && w.webview != 0 {
			w.renderReloads++
			w.webview.call(idxWVReload)
		} else {
			w.fail(errors.New("webview: sayfa işlemi tekrar tekrar çöktü"))
		}
	}
	return sOK
}

// ---- system browser ----

var procShellExecuteW = windows.NewLazySystemDLL("shell32.dll").NewProc("ShellExecuteW")

// openExternal hands an https URL to the default browser. Tests replace it.
var openExternal = func(u string) error {
	u = externalURL(u)
	if u == "" || !strings.HasPrefix(u, "https://") {
		return errors.New("webview: dış adres reddedildi")
	}
	verb, _ := windows.UTF16PtrFromString("open")
	target, err := windows.UTF16PtrFromString(u)
	if err != nil {
		return err
	}
	r, _, _ := procShellExecuteW.Call(0, uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(target)), 0, 0, 1)
	if r <= 32 {
		return fmt.Errorf("webview: tarayıcı açılamadı (%d)", r)
	}
	return nil
}

func openExternalAsync(u string) {
	f := openExternal
	go func() { _ = f(u) }()
}
