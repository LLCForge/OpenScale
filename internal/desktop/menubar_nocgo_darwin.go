//go:build darwin && !cgo

package desktop

import (
	"context"
	"errors"
	"fmt"
	"os"
)

// Without cgo there is no AppKit: no menu bar icon and no native window.
// "openscale app" still installs or updates the service (password dialog)
// and opens the panel in the default browser with a one-time sign-in
// link (ADR-0227).

func runMacApp(ctx context.Context, quiet bool) error {
	if quiet {
		fmt.Fprintln(os.Stderr, "Bu derlemede menü çubuğu simgesi yok (cgo'suz derleme); paneli açmak için: openscale app")
		return nil
	}
	app, err := newMacApp()
	if err != nil {
		return err
	}
	if app.needsSetup() {
		if err := app.installService(ctx); err != nil {
			if errors.Is(err, errCancelled) {
				return nil
			}
			return fmt.Errorf("OpenScale servisi kurulamadı: %w", err)
		}
	} else if err := app.client.waitReady(ctx, macServiceWait); err != nil {
		return err
	}
	return app.openPanelBrowser(ctx)
}
