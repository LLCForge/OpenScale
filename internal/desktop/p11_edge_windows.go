//go:build windows

package desktop

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/winapp"
)

// Tray side of P11 (ADR-0154): screen lock reports for the lock shield
// (#501) and the panel in a separate browser profile (#520).

const (
	// lockReportAttempts: an unlock that cannot reach the service is
	// retried; a failed unlock only leaves the shield on (fail safe).
	lockReportAttempts = 3
	lockReportRetry    = 2 * time.Second
	// panelBrowserEnv set to "default" opens the panel in the default
	// browser instead of a separate profile.
	panelBrowserEnv = "OPENSCALE_PANEL_BROWSER"
)

// sessionLock tells the service that the screen was locked or unlocked.
func (c *trayClient) sessionLock(ctx context.Context, locked bool) error {
	var st panel.EdgeStatus
	return c.do(ctx, http.MethodPost, panel.LocalAPIPrefix+"/edge/lock", panel.EdgeLockRequest{Locked: locked}, &st)
}

// reportSessionLock is the tray's OnSessionLock callback.
func reportSessionLock(ctx context.Context, client *trayClient, locked bool) {
	for i := range lockReportAttempts {
		err := client.sessionLock(ctx, locked)
		if err == nil || ctx.Err() != nil {
			return
		}
		if i == lockReportAttempts-1 {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(lockReportRetry):
		}
	}
}

// panelProfileDir is the browser profile of the panel window, in the
// user's local application data (not roaming, not shared).
func panelProfileDir() (string, error) {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" || !filepath.IsAbs(base) {
		return "", errors.New("LOCALAPPDATA yok")
	}
	return filepath.Join(base, "OpenScale", "panel-browser"), nil
}

// openPanelURL opens the panel in a separate browser profile, falling back
// to the default browser.
func openPanelURL(link string) error {
	if strings.EqualFold(strings.TrimSpace(os.Getenv(panelBrowserEnv)), "default") {
		return winapp.OpenURL(link)
	}
	if dir, err := panelProfileDir(); err == nil {
		if err := winapp.OpenURLIsolated(link, dir); err == nil {
			return nil
		}
	}
	return winapp.OpenURL(link)
}
