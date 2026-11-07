//go:build windows

package desktop

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"slices"
	"sync"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/piv"
	"github.com/openscale/openscale/internal/secmem"
	"github.com/openscale/openscale/internal/winapp"
)

// Tray wiring of the YubiKey administrator mode (ADR-0223).

// Menu ids of the token mode (below peerIDBase, above the iota ids).
const (
	idTokenModeOn  = 900
	idTokenModeOff = 901
)

// trayTokenMode is the tray's controller (nil until runTray starts it).
var trayTokenMode struct {
	mu sync.Mutex
	c  *winapp.TokenModeController
}

// startTokenMode builds the controller and runs it until ctx ends.
func startTokenMode(ctx context.Context, tray *winapp.Tray, dataDir string, refresh func()) {
	prober := &piv.Prober{}
	var keys []ed25519.PublicKey
	c := &winapp.TokenModeController{
		// Step is the only caller, so keys and the prober's options are
		// not shared.
		Probe: func(ctx context.Context, k []ed25519.PublicKey) (piv.PresenceResult, error) {
			if !slices.EqualFunc(keys, k, func(a, b ed25519.PublicKey) bool { return bytes.Equal(a, b) }) {
				keys = slices.Clone(k)
				prober.Options.Keys = keys
				prober.Invalidate()
			}
			return prober.Check(ctx)
		},
		Channel: newTokenModeChannel(dataDir),
		AskPIN: func(context.Context) (*secmem.Buffer, error) {
			return winapp.ReadSecretSecureDesktop("YubiKey PIN'i (yönetici kipi)")
		},
		OpenToken: func(ctx context.Context, reader string, pin func() ([]byte, error)) (admin.TokenSigner, error) {
			return piv.OpenToken(ctx, piv.TokenOptions{Reader: reader, PIN: pin})
		},
		Confirm:  confirm,
		Notify:   func(msg string) { tray.Notify("OpenScale", msg) },
		OnChange: func(winapp.TokenModeReport) { refresh() },
	}
	trayTokenMode.mu.Lock()
	trayTokenMode.c = c
	trayTokenMode.mu.Unlock()
	go func() { _ = c.Run(ctx, winapp.DefaultTokenPoll) }()
}

func currentTokenMode() *winapp.TokenModeController {
	trayTokenMode.mu.Lock()
	defer trayTokenMode.mu.Unlock()
	return trayTokenMode.c
}

// tokenModeItems are the menu items for the current state.
func tokenModeItems() []winapp.MenuItem {
	c := currentTokenMode()
	if c == nil {
		return nil
	}
	st := c.State()
	switch {
	case st.Open:
		detail := "kök anahtar"
		if st.Role == admin.SessionAdmin {
			detail = "yönetici: " + st.Name
		}
		return []winapp.MenuItem{{ID: idTokenModeOff, Label: "Yönetici kipini kapat", Detail: detail, Checked: true}}
	case st.Offer:
		return []winapp.MenuItem{{ID: idTokenModeOn, Label: "Yönetici kipini aç..."}}
	}
	return nil
}

// withTokenModeItems puts the token mode items before the panic item.
func withTokenModeItems(items []winapp.MenuItem) []winapp.MenuItem {
	extra := tokenModeItems()
	if len(extra) == 0 {
		return items
	}
	for i, it := range items {
		if it.ID == idPanic {
			return slices.Concat(items[:i:i], extra, items[i:])
		}
	}
	return append(items, extra...)
}

// tokenModeClick handles the token mode items; it reports whether id was
// one of them.
func tokenModeClick(ctx context.Context, tray *winapp.Tray, id int) bool {
	c := currentTokenMode()
	if c == nil || (id != idTokenModeOn && id != idTokenModeOff) {
		return false
	}
	if id == idTokenModeOff {
		c.Disable(ctx)
		return true
	}
	go func() {
		if err := c.Enable(ctx); err != nil {
			if errors.Is(err, winapp.ErrSecureInputCancelled) {
				return
			}
			tray.Notify("OpenScale", err.Error())
			return
		}
		tray.Notify("OpenScale", "Yönetici kipi açık. Panelde imza gereken işlemlerde \"YubiKey ile imzala\" seçeneği kullanılabilir.")
	}()
	return true
}
