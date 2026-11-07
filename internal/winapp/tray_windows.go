//go:build windows

package winapp

import (
	"context"
	"errors"
	"fmt"
	"image"
	"runtime"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procRegisterClassExW            = modUser32.NewProc("RegisterClassExW")
	procCreateWindowExW             = modUser32.NewProc("CreateWindowExW")
	procDefWindowProcW              = modUser32.NewProc("DefWindowProcW")
	procDestroyWindow               = modUser32.NewProc("DestroyWindow")
	procGetMessageW                 = modUser32.NewProc("GetMessageW")
	procTranslateMessage            = modUser32.NewProc("TranslateMessage")
	procDispatchMessageW            = modUser32.NewProc("DispatchMessageW")
	procPostMessageW                = modUser32.NewProc("PostMessageW")
	procPostQuitMessage             = modUser32.NewProc("PostQuitMessage")
	procRegisterWindowMessageW      = modUser32.NewProc("RegisterWindowMessageW")
	procCreatePopupMenu             = modUser32.NewProc("CreatePopupMenu")
	procAppendMenuW                 = modUser32.NewProc("AppendMenuW")
	procDestroyMenu                 = modUser32.NewProc("DestroyMenu")
	procTrackPopupMenuEx            = modUser32.NewProc("TrackPopupMenuEx")
	procSetMenuDefaultItem          = modUser32.NewProc("SetMenuDefaultItem")
	procGetCursorPos                = modUser32.NewProc("GetCursorPos")
	procSetForegroundWindow         = modUser32.NewProc("SetForegroundWindow")
	procChangeWindowMessageFilterEx = modUser32.NewProc("ChangeWindowMessageFilterEx")

	procShellNotifyIconW = modShell.NewProc("Shell_NotifyIconW")
)

const (
	wmNull        = 0x0000
	wmDestroy     = 0x0002
	wmClose       = 0x0010
	wmContextMenu = 0x007B
	wmApp         = 0x8000

	wmTrayCallback = wmApp + 1
	wmTrayUpdate   = wmApp + 2

	ninSelect    = 0x0400 // WM_USER + 0
	ninKeySelect = 0x0401 // WM_USER + 1

	nimAdd        = 0
	nimModify     = 1
	nimDelete     = 2
	nimSetVersion = 4

	nifMessage  = 0x01
	nifIcon     = 0x02
	nifTip      = 0x04
	nifInfo     = 0x10
	nifShowTip  = 0x80
	niifInfo    = 0x01
	niifQuiet   = 0x80 // NIIF_RESPECT_QUIET_TIME
	nifyVersion = 4    // NOTIFYICON_VERSION_4

	mfString     = 0x0000
	mfGrayed     = 0x0001
	mfChecked    = 0x0008
	mfPopup      = 0x0010
	mfSeparator  = 0x0800
	maxMenuDepth = 3

	tpmRightButton = 0x0002
	tpmNoNotify    = 0x0080
	tpmReturnCmd   = 0x0100

	msgfltAllow = 1

	trayIconID     = 1
	maxPendingNote = 8
	maxMenuID      = 0xFFFF
)

// notifyIconData mirrors NOTIFYICONDATAW (Vista+ layout). Go's natural
// alignment matches the C layout on both 32- and 64-bit Windows.
type notifyIconData struct {
	CbSize           uint32
	HWnd             uintptr
	UID              uint32
	UFlags           uint32
	UCallbackMessage uint32
	HIcon            windows.Handle
	SzTip            [128]uint16
	DwState          uint32
	DwStateMask      uint32
	SzInfo           [256]uint16
	UVersion         uint32 // union with uTimeout
	SzInfoTitle      [64]uint16
	DwInfoFlags      uint32
	GuidItem         windows.GUID
	HBalloonIcon     windows.Handle
}

type wndClassEx struct {
	Size       uint32
	Style      uint32
	WndProc    uintptr
	ClsExtra   int32
	WndExtra   int32
	Instance   windows.Handle
	Icon       windows.Handle
	Cursor     windows.Handle
	Background windows.Handle
	MenuName   *uint16
	ClassName  *uint16
	IconSm     windows.Handle
}

type point struct{ X, Y int32 }

type winMsg struct {
	HWnd    uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      point
	Private uint32
}

type balloon struct{ title, msg string }

// Tray is a notification-area icon with a popup menu. All setters are safe
// to call from any goroutine, before or after Run. Click callbacks run on
// their own goroutine so they may block or call back into the Tray.
type Tray struct {
	mu        sync.Mutex
	items     []MenuItem
	tooltip   string
	onClick   func(id int)
	onLeft    func()
	notes     []balloon
	custom    *image.RGBA
	iconDirty bool

	started atomic.Bool
	hwnd    atomic.Uintptr

	// Owned by the message-loop thread.
	icon  windows.Handle
	added bool
}

// NewTray creates a tray icon (not yet shown) with the given tooltip.
func NewTray(tooltip string) *Tray {
	return &Tray{tooltip: CurrentDiscreet().Neutralize(tooltip)} // #687
}

// SetItems replaces the popup menu; it is rebuilt on the next open.
func (t *Tray) SetItems(items []MenuItem) {
	cp := append([]MenuItem(nil), items...)
	t.mu.Lock()
	t.items = cp
	t.mu.Unlock()
}

// SetTooltip changes the hover text (truncated to 127 UTF-16 units).
func (t *Tray) SetTooltip(s string) {
	s = CurrentDiscreet().Neutralize(s) // #687, ADR-0196
	t.mu.Lock()
	t.tooltip = s
	t.mu.Unlock()
	t.post(wmTrayUpdate)
}

// OnClick sets the handler for menu selections; it receives MenuItem.ID.
func (t *Tray) OnClick(fn func(id int)) {
	t.mu.Lock()
	t.onClick = fn
	t.mu.Unlock()
}

// OnLeftClick sets the handler for a left click (or Enter) on the icon.
func (t *Tray) OnLeftClick(fn func()) {
	t.mu.Lock()
	t.onLeft = fn
	t.mu.Unlock()
}

// Notify shows a balloon / toast notification. Calls made before Run are
// queued (at most 8) and shown once the icon exists.
func (t *Tray) Notify(title, msg string) {
	if stealthSettings().QuietNotifications {
		return // ADR-0109 (#247): cosmetic only; events are still logged
	}
	if d := CurrentDiscreet(); d.Enabled { // #687, ADR-0196
		title, msg = d.Neutralize(title), d.Neutralize(msg)
	}
	t.mu.Lock()
	if len(t.notes) >= maxPendingNote {
		t.notes = t.notes[1:]
	}
	t.notes = append(t.notes, balloon{title: title, msg: msg})
	t.mu.Unlock()
	t.post(wmTrayUpdate)
}

// SetIconPNG replaces the generated icon with a PNG image, scaled to the
// system small-icon size. It can be called before or after Run.
func (t *Tray) SetIconPNG(png []byte) error {
	img, err := decodePNG(png)
	if err != nil {
		return err
	}
	t.mu.Lock()
	t.custom = img
	t.iconDirty = true
	t.mu.Unlock()
	t.post(wmTrayUpdate)
	return nil
}

func (t *Tray) post(msg uint32) {
	if h := t.hwnd.Load(); h != 0 {
		procPostMessageW.Call(h, uintptr(msg), 0, 0)
	}
}

var (
	trayWindows sync.Map // hwnd -> *Tray

	trayClassOnce sync.Once
	trayClassErr  error
	trayClassName *uint16
	taskbarMsg    uint32
)

const trayClassNameStr = "OpenScaleTrayWindow"

func registerTrayClass(hinst windows.Handle) error {
	trayClassOnce.Do(func() {
		name, err := windows.UTF16PtrFromString(trayClassNameStr)
		if err != nil {
			trayClassErr = err
			return
		}
		tbName, err := windows.UTF16PtrFromString("TaskbarCreated")
		if err != nil {
			trayClassErr = err
			return
		}
		r, _, _ := procRegisterWindowMessageW.Call(uintptr(unsafe.Pointer(tbName)))
		taskbarMsg = uint32(r)

		wc := wndClassEx{
			WndProc:   windows.NewCallback(trayWndProc),
			Instance:  hinst,
			ClassName: name,
		}
		wc.Size = uint32(unsafe.Sizeof(wc))
		atom, _, callErr := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
		if atom == 0 && !errors.Is(callErr, windows.ERROR_CLASS_ALREADY_EXISTS) {
			trayClassErr = fmt.Errorf("pencere sınıfı kaydedilemedi: %w", callErr)
			return
		}
		trayClassName = name
	})
	return trayClassErr
}

// Run shows the icon and runs the Win32 message loop on a locked OS thread
// until ctx is cancelled. It may be called only once per Tray.
func (t *Tray) Run(ctx context.Context) error {
	if !t.started.CompareAndSwap(false, true) {
		return errors.New("bildirim alanı simgesi zaten çalışıyor")
	}
	if IsServerCore() { // #493: no shell, no notification area
		return ErrNoDesktopShell
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var hinst windows.Handle
	if err := windows.GetModuleHandleEx(0, nil, &hinst); err != nil {
		return fmt.Errorf("modül tanıtıcısı alınamadı: %w", err)
	}
	if err := registerTrayClass(hinst); err != nil {
		return err
	}
	title, err := windows.UTF16PtrFromString("OpenScale")
	if err != nil {
		return err
	}
	// A hidden top-level window (never shown) rather than an HWND_MESSAGE
	// window: message-only windows do not receive the TaskbarCreated broadcast.
	hwnd, _, callErr := procCreateWindowExW.Call(0,
		uintptr(unsafe.Pointer(trayClassName)), uintptr(unsafe.Pointer(title)),
		0, 0, 0, 0, 0, 0, 0, uintptr(hinst), 0)
	if hwnd == 0 {
		return fmt.Errorf("simge penceresi oluşturulamadı: %w", callErr)
	}
	trayWindows.Store(hwnd, t)
	defer trayWindows.Delete(hwnd)
	destroyed := false
	defer func() {
		if !destroyed {
			procDestroyWindow.Call(hwnd)
		}
		destroyIcon(t.icon)
		t.icon = 0
	}()

	// An elevated process would otherwise not receive these from Explorer,
	// which runs at medium integrity (UIPI).
	if procChangeWindowMessageFilterEx.Find() == nil {
		procChangeWindowMessageFilterEx.Call(hwnd, uintptr(taskbarMsg), msgfltAllow, 0)
		procChangeWindowMessageFilterEx.Call(hwnd, wmTrayCallback, msgfltAllow, 0)
	}

	if err := t.rebuildIcon(); err != nil {
		return err
	}
	t.hwnd.Store(hwnd)
	defer t.hwnd.Store(0)
	// Screen lock reports (#501, tray_session_windows.go).
	defer registerSessionNotify(hwnd)()
	t.addIcon(hwnd) // failure is tolerated: Explorer may not be up yet; TaskbarCreated retries
	procPostMessageW.Call(hwnd, wmTrayUpdate, 0, 0)

	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			procPostMessageW.Call(hwnd, wmClose, 0, 0)
		case <-stop:
		}
	}()

	var m winMsg
	for {
		r, _, callErr := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		switch int32(r) {
		case -1:
			return fmt.Errorf("mesaj döngüsü hatası: %w", callErr)
		case 0: // WM_QUIT, posted from WM_DESTROY
			destroyed = true
			return nil
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
}

func trayWndProc(hwnd, msg, wParam, lParam uintptr) uintptr {
	v, ok := trayWindows.Load(hwnd)
	if !ok {
		r, _, _ := procDefWindowProcW.Call(hwnd, msg, wParam, lParam)
		return r
	}
	t := v.(*Tray)
	switch uint32(msg) {
	case wmTrayCallback:
		switch uint32(lParam & 0xFFFF) { // NOTIFYICON_VERSION_4: LOWORD(lParam) is the event
		case wmContextMenu:
			t.showMenu(hwnd)
		case ninSelect, ninKeySelect:
			t.mu.Lock()
			fn := t.onLeft
			t.mu.Unlock()
			if fn != nil {
				go fn()
			}
		case ninBalloonUserClick: // #813, f3_notify_windows.go
			t.balloonClicked()
		}
		return 0
	case wmTrayUpdate:
		t.applyPending(hwnd)
		return 0
	case wmWTSSessionChange:
		t.sessionChanged(wParam)
		return 0
	case wmClose:
		procDestroyWindow.Call(hwnd)
		return 0
	case wmDestroy:
		t.hwnd.Store(0)
		t.deleteIcon(hwnd)
		procPostQuitMessage.Call(0)
		return 0
	}
	if taskbarMsg != 0 && uint32(msg) == taskbarMsg {
		// Explorer restarted: the old icon is gone. Rebuild in case DPI changed.
		t.added = false
		_ = t.rebuildIcon()
		t.addIcon(hwnd)
		return 0
	}
	r, _, _ := procDefWindowProcW.Call(hwnd, msg, wParam, lParam)
	return r
}

func (t *Tray) baseNID(hwnd uintptr) notifyIconData {
	nid := notifyIconData{HWnd: hwnd, UID: trayIconID}
	nid.CbSize = uint32(unsafe.Sizeof(nid))
	return nid
}

func shellNotify(cmd uint32, nid *notifyIconData) bool {
	r, _, _ := procShellNotifyIconW.Call(uintptr(cmd), uintptr(unsafe.Pointer(nid)))
	return r != 0
}

// rebuildIcon recreates the HICON at the current small-icon size from the
// custom PNG (if any) or the generated default. Loop thread only.
func (t *Tray) rebuildIcon() error {
	t.mu.Lock()
	custom := t.custom
	t.iconDirty = false
	t.mu.Unlock()

	size := smallIconSize()
	var icon windows.Handle
	var err error
	if custom != nil {
		icon, err = createIconFromBGRA(scaleToBGRA(custom, size), size)
	}
	if custom == nil || err != nil {
		icon, err = createIconFromBGRA(renderDefaultIcon(size), size)
	}
	if err != nil {
		return err
	}
	old := t.icon
	t.icon = icon
	destroyIcon(old) // safe: the shell copies the icon on NIM_ADD/NIM_MODIFY
	return nil
}

func (t *Tray) addIcon(hwnd uintptr) {
	if stealthSettings().HideTray {
		return // ADR-0109 (#247): icon hidden; protections are untouched
	}
	t.mu.Lock()
	tip := t.tooltip
	t.mu.Unlock()

	nid := t.baseNID(hwnd)
	nid.UFlags = nifMessage | nifIcon | nifTip | nifShowTip
	nid.UCallbackMessage = wmTrayCallback
	nid.HIcon = t.icon
	copyUTF16(nid.SzTip[:], tip)
	if !shellNotify(nimAdd, &nid) {
		// A stale icon with the same ID may survive a crash; replace it.
		shellNotify(nimDelete, &nid)
		if !shellNotify(nimAdd, &nid) {
			return
		}
	}
	nid.UVersion = nifyVersion
	shellNotify(nimSetVersion, &nid)
	t.added = true
}

func (t *Tray) deleteIcon(hwnd uintptr) {
	if !t.added {
		return
	}
	nid := t.baseNID(hwnd)
	shellNotify(nimDelete, &nid)
	t.added = false
}

func (t *Tray) applyPending(hwnd uintptr) {
	t.mu.Lock()
	tip := t.tooltip
	dirty := t.iconDirty
	notes := t.notes
	t.notes = nil
	t.mu.Unlock()

	if dirty {
		_ = t.rebuildIcon()
	}
	if !t.added {
		t.addIcon(hwnd)
		if !t.added {
			return
		}
	}
	nid := t.baseNID(hwnd)
	nid.UFlags = nifIcon | nifTip | nifShowTip
	nid.HIcon = t.icon
	copyUTF16(nid.SzTip[:], tip)
	shellNotify(nimModify, &nid)

	for _, n := range notes {
		nb := t.baseNID(hwnd)
		nb.UFlags = nifInfo
		nb.DwInfoFlags = niifInfo | niifQuiet
		copyUTF16(nb.SzInfoTitle[:], n.title)
		copyUTF16(nb.SzInfo[:], n.msg)
		shellNotify(nimModify, &nb)
	}
}

func (t *Tray) showMenu(hwnd uintptr) {
	t.mu.Lock()
	items := t.items
	onClick := t.onClick
	t.mu.Unlock()
	if len(items) == 0 {
		return
	}

	menu := buildMenu(items, 0)
	if menu == 0 {
		return
	}
	// Destroying the top menu also destroys its submenus.
	defer procDestroyMenu.Call(menu)

	var pt point
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	// Required so the menu closes when the user clicks elsewhere.
	procSetForegroundWindow.Call(hwnd)
	r, _, _ := procTrackPopupMenuEx.Call(menu, tpmRightButton|tpmReturnCmd|tpmNoNotify,
		uintptr(pt.X), uintptr(pt.Y), hwnd, 0)
	procPostMessageW.Call(hwnd, wmNull, 0, 0)

	if id := int(int32(r)); id > 0 && onClick != nil {
		go onClick(id)
	}
}

// buildMenu creates a popup menu (and its submenus) from items.
func buildMenu(items []MenuItem, depth int) uintptr {
	menu, _, _ := procCreatePopupMenu.Call()
	if menu == 0 {
		return 0
	}
	for _, it := range items {
		if it.Separator {
			procAppendMenuW.Call(menu, mfSeparator, 0, 0)
			continue
		}
		text := menuLabel(it.Label)
		if it.Detail != "" {
			text += "\t" + menuLabel(it.Detail)
		}
		label, err := windows.UTF16PtrFromString(text)
		if err != nil {
			continue
		}
		if len(it.Children) > 0 && depth < maxMenuDepth {
			sub := buildMenu(it.Children, depth+1)
			if sub == 0 {
				continue
			}
			flags := uintptr(mfString | mfPopup)
			if it.Disabled {
				flags |= mfGrayed
			}
			procAppendMenuW.Call(menu, flags, sub, uintptr(unsafe.Pointer(label)))
			continue
		}
		flags := uintptr(mfString)
		id := 0
		if it.ID >= 1 && it.ID <= maxMenuID {
			id = it.ID
		}
		if it.Disabled || id == 0 {
			flags |= mfGrayed
		}
		if it.Checked {
			flags |= mfChecked
		}
		procAppendMenuW.Call(menu, flags, uintptr(id), uintptr(unsafe.Pointer(label)))
		if it.Default && id != 0 {
			procSetMenuDefaultItem.Call(menu, uintptr(id), 0)
		}
	}
	return menu
}
