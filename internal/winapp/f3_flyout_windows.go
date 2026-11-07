//go:build windows

package winapp

import (
	"context"
	"sync"
	"time"

	"golang.org/x/sys/windows/registry"
)

// Tray status flyout (#802): a left click on the icon opens a small
// read-only window above the notification area with the connection, the
// active exit node, the latest peers with their path and latency, the
// number of open alerts and an "Open panel" button. It changes nothing
// and needs no signature. It closes when it loses the focus, with Esc,
// or with a second click on the icon. The owner can make the left click
// open the panel directly, as before (SetTrayLeftClick, the tray's
// Preferences menu or "openscale tray left-click panel").

const (
	trayPrefsKey   = `Software\OpenScale\Tray`
	trayLeftClickV = "LeftClick"
)

// TrayLeftClick returns the saved left click choice (default: flyout).
func TrayLeftClick() string {
	k, err := registry.OpenKey(registry.CURRENT_USER, trayPrefsKey, registry.QUERY_VALUE)
	if err != nil {
		return LeftClickFlyout
	}
	defer k.Close()
	v, _, err := k.GetStringValue(trayLeftClickV)
	if err == nil && v == LeftClickPanel {
		return LeftClickPanel
	}
	return LeftClickFlyout
}

// SetTrayLeftClick saves the left click choice for this user.
func SetTrayLeftClick(choice string) error {
	if choice != LeftClickFlyout && choice != LeftClickPanel {
		return errUnknownLeftClick
	}
	k, _, err := registry.CreateKey(registry.CURRENT_USER, trayPrefsKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetStringValue(trayLeftClickV, choice)
}

var flyoutState struct {
	sync.Mutex
	cancel context.CancelFunc
	closed time.Time
}

// reopenGuard: the click on the icon that should close the flyout first
// takes the focus away, which already closes it; a click right after a
// close therefore does not open it again.
const reopenGuard = 500 * time.Millisecond

// ToggleFlyout closes an open flyout or opens a new one with the model
// from content, refreshed every two seconds while it is shown. onOpen
// runs when "Open panel" is pressed. It returns at once.
func ToggleFlyout(ctx context.Context, content func() UIModel, onOpen func()) {
	flyoutState.Lock()
	if flyoutState.cancel != nil {
		flyoutState.cancel()
		flyoutState.cancel = nil
		flyoutState.Unlock()
		return
	}
	if time.Since(flyoutState.closed) < reopenGuard {
		flyoutState.Unlock()
		return
	}
	fctx, cancel := context.WithCancel(ctx)
	flyoutState.cancel = cancel
	flyoutState.Unlock()
	go func() {
		defer func() {
			flyoutState.Lock()
			flyoutState.cancel = nil
			flyoutState.closed = time.Now()
			flyoutState.Unlock()
			cancel()
		}()
		res, err := ShowUI(fctx, UIFlyout, content(), func() (UIModel, bool) { return content(), true })
		if err == nil && res.Button == FlyoutOpenPanel && onOpen != nil {
			onOpen()
		}
	}()
}
