//go:build windows

package winapp

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Start menu and desktop shortcuts for all users. They live in folders only
// administrators can change, so a standard user cannot point them elsewhere.
// The Start menu entry is refreshed on every install; the desktop one is made
// once, so a user who deletes it does not get it back on the next launch.

const (
	shortcutFileName = "OpenScale.lnk"
	shortcutComment  = "OpenScale paneli"
	shortcutArg      = "app"

	shortcutStateKey   = `SOFTWARE\OpenScale`
	shortcutStateValue = "DesktopShortcutCreated"

	coinitApartmentThreaded = 0x2
	clsctxInprocServer      = 0x1
	swShowMinNoActive       = 7

	// IShellLinkW
	idxSLGetPath             = 3
	idxSLSetDescription      = 7
	idxSLSetWorkingDirectory = 9
	idxSLGetArguments        = 10
	idxSLSetArguments        = 11
	idxSLSetShowCmd          = 15
	idxSLSetIconLocation     = 17
	idxSLSetPath             = 20
	// IPersistFile
	idxPFLoad = 5
	idxPFSave = 6
	// IUnknown
	idxQueryInterface = 0
	idxRelease        = 2
)

var (
	modOle32             = windows.NewLazySystemDLL("ole32.dll")
	procCoCreateInstance = modOle32.NewProc("CoCreateInstance")

	clsidShellLink  = windows.GUID{Data1: 0x00021401, Data4: [8]byte{0xC0, 0, 0, 0, 0, 0, 0, 0x46}}
	iidShellLinkW   = windows.GUID{Data1: 0x000214F9, Data4: [8]byte{0xC0, 0, 0, 0, 0, 0, 0, 0x46}}
	iidIPersistFile = windows.GUID{Data1: 0x0000010B, Data4: [8]byte{0xC0, 0, 0, 0, 0, 0, 0, 0x46}}
)

// comObject is the memory layout of a COM interface pointer.
type comObject struct {
	vtbl *[32]uintptr
}

func (o *comObject) call(idx int, args ...uintptr) error {
	all := append([]uintptr{uintptr(unsafe.Pointer(o))}, args...)
	r, _, _ := syscall.SyscallN(o.vtbl[idx], all...)
	if int32(r) < 0 {
		return fmt.Errorf("COM yöntemi %d: 0x%08X", idx, uint32(r))
	}
	return nil
}

func (o *comObject) callString(idx int, s string) error {
	p, err := windows.UTF16PtrFromString(s)
	if err != nil {
		return err
	}
	return o.call(idx, uintptr(unsafe.Pointer(p)))
}

func (o *comObject) release() { _ = o.call(idxRelease) }

// withShellLink runs fn on a thread with COM initialized, with a new shell
// link object and its IPersistFile.
func withShellLink(fn func(link, file *comObject) error) error {
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		done <- func() error {
			switch err := windows.CoInitializeEx(0, coinitApartmentThreaded); {
			case err == nil, errors.Is(err, syscall.Errno(1)): // S_FALSE: already initialized
				defer windows.CoUninitialize()
			case errors.Is(err, syscall.Errno(windows.RPC_E_CHANGED_MODE)):
				// COM is up on this thread in another mode; shell links work there too.
			default:
				return err
			}
			var link *comObject
			r, _, _ := procCoCreateInstance.Call(
				uintptr(unsafe.Pointer(&clsidShellLink)), 0, clsctxInprocServer,
				uintptr(unsafe.Pointer(&iidShellLinkW)), uintptr(unsafe.Pointer(&link)))
			if int32(r) < 0 || link == nil {
				return fmt.Errorf("kısayol nesnesi oluşturulamadı: 0x%08X", uint32(r))
			}
			defer link.release()
			var file *comObject
			if err := link.call(idxQueryInterface, uintptr(unsafe.Pointer(&iidIPersistFile)), uintptr(unsafe.Pointer(&file))); err != nil {
				return err
			}
			defer file.release()
			return fn(link, file)
		}()
	}()
	return <-done
}

// writeShortcut creates or replaces a shortcut that starts exe with the app
// command. The console the program briefly owns stays minimized.
func writeShortcut(path, exe string) error {
	return withShellLink(func(link, file *comObject) error {
		if err := link.callString(idxSLSetPath, exe); err != nil {
			return err
		}
		if err := link.callString(idxSLSetArguments, shortcutArg); err != nil {
			return err
		}
		if err := link.callString(idxSLSetWorkingDirectory, filepath.Dir(exe)); err != nil {
			return err
		}
		if err := link.callString(idxSLSetDescription, shortcutComment); err != nil {
			return err
		}
		icon, err := windows.UTF16PtrFromString(exe)
		if err != nil {
			return err
		}
		if err := link.call(idxSLSetIconLocation, uintptr(unsafe.Pointer(icon)), 0); err != nil {
			return err
		}
		if err := link.call(idxSLSetShowCmd, swShowMinNoActive); err != nil {
			return err
		}
		target, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return err
		}
		return file.call(idxPFSave, uintptr(unsafe.Pointer(target)), 1)
	})
}

func startMenuShortcutPath() (string, error) {
	dir, err := windows.KnownFolderPath(windows.FOLDERID_CommonPrograms, 0)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, shortcutFileName), nil
}

func desktopShortcutPath() (string, error) {
	dir, err := windows.KnownFolderPath(windows.FOLDERID_PublicDesktop, 0)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, shortcutFileName), nil
}

// installShortcuts needs an elevated process. Failure does not fail the
// install: the program works without shortcuts.
func installShortcuts(exe string) error {
	var errs []error
	if p, err := startMenuShortcutPath(); err != nil {
		errs = append(errs, err)
	} else if err := writeShortcut(p, exe); err != nil {
		errs = append(errs, fmt.Errorf("Başlat menüsü kısayolu: %w", err))
	}
	if err := installDesktopShortcutOnce(exe); err != nil {
		errs = append(errs, fmt.Errorf("masaüstü kısayolu: %w", err))
	}
	return errors.Join(errs...)
}

func installDesktopShortcutOnce(exe string) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, shortcutStateKey, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if _, _, err := k.GetIntegerValue(shortcutStateValue); err == nil {
		return nil
	}
	p, err := desktopShortcutPath()
	if err != nil {
		return err
	}
	if err := writeShortcut(p, exe); err != nil {
		return err
	}
	return k.SetDWordValue(shortcutStateValue, 1)
}

// removeShortcuts is best effort and leaves the service removal to go on.
func removeShortcuts() {
	if p, err := startMenuShortcutPath(); err == nil {
		_ = os.Remove(p)
	}
	if p, err := desktopShortcutPath(); err == nil {
		_ = os.Remove(p)
	}
	RemoveSendToShortcut() // #803: Gezgin > Gönder > OpenScale (f3_sendto_windows.go)
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, shortcutStateKey, registry.SET_VALUE); err == nil {
		_ = k.DeleteValue(shortcutStateValue)
		_ = k.Close()
	}
}
