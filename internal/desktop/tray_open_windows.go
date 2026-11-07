//go:build windows

package desktop

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/openscale/openscale/internal/winapp"
)

// The tray runs elevated, so opening a shortcut would ask for consent each
// time only to reach the tray that is already running. This event lets an
// unelevated launch of the installed program ask that tray to open the panel.
// The right it grants is limited to that: signed-in users can only set the
// event, and the session-local name keeps it within this desktop session.

const (
	trayOpenEventName = `Local\OpenScaleTrayOpen`
	// SYSTEM and Administrators full; Authenticated Users EVENT_MODIFY_STATE
	// and SYNCHRONIZE (0x100002) only.
	trayOpenEventSDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x100002;;;AU)"
)

func createTrayOpenEvent() (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(trayOpenEventName)
	if err != nil {
		return 0, err
	}
	sd, err := windows.SecurityDescriptorFromString(trayOpenEventSDDL)
	if err != nil {
		return 0, err
	}
	sa := windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(sa))
	h, err := windows.CreateEvent(&sa, 0, 0, name)
	if err != nil {
		// Someone else made it first, so its permissions are not ours: leave
		// this route unused rather than wait on an event another program owns.
		if h != 0 {
			_ = windows.CloseHandle(h)
		}
		return 0, err
	}
	return h, nil
}

// watchTrayOpen opens the panel each time the event is set, until ctx ends.
func watchTrayOpen(ctx context.Context, client *trayClient, ev windows.Handle) {
	go func() {
		<-ctx.Done()
		_ = windows.SetEvent(ev) // wakes the loop below
	}()
	for {
		r, err := windows.WaitForSingleObject(ev, windows.INFINITE)
		if err != nil || r != windows.WAIT_OBJECT_0 || ctx.Err() != nil {
			return
		}
		if err := openPanel(ctx, client); err != nil && !errors.Is(err, context.Canceled) {
			showError(err.Error())
		}
	}
}

// askRunningTrayToOpen reports whether a running tray took the request. Only
// the installed program may skip the elevated path: a newer copy opened from
// elsewhere must still go through it to upgrade the service.
func askRunningTrayToOpen() bool {
	exe, err := os.Executable()
	if err != nil || !strings.EqualFold(filepath.Clean(exe), filepath.Join(winapp.InstallDir(), "openscale.exe")) {
		return false
	}
	name, err := windows.UTF16PtrFromString(trayOpenEventName)
	if err != nil {
		return false
	}
	h, err := windows.OpenEvent(windows.EVENT_MODIFY_STATE, false, name)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	return windows.SetEvent(h) == nil
}
