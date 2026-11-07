//go:build windows

package desktop

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/peercred"
	"github.com/openscale/openscale/internal/winapp"
)

// W2 (desktop and tray): quiet start at sign-in, the local API limited to
// the OpenScale program (#645) and the tray's panic item.

// RunAppQuiet is the sign-in start ("openscale autostart run"): the
// service is installed and started as in RunApp and the tray icon shows,
// but no panel window opens.
func RunAppQuiet(ctx context.Context) error { return runAppMode(ctx, true) }

// localAPICheck is the service's check of the app token's callers: an
// elevated process (ADR-0050) that runs this OpenScale program (#645).
// When this program's file cannot be read the program check is left out
// (logged), so a broken install keeps its tray.
func localAPICheck(logger *slog.Logger) func(remote, local string) error {
	admins := peercred.Policy{Admins: true}
	programs, err := peercred.SelfProgramPolicy()
	if err != nil {
		logger.Warn("local API program check unavailable", "error", err.Error())
		return admins.Check
	}
	return func(remote, local string) error {
		if err := admins.Check(remote, local); err != nil {
			return err
		}
		return programs.CheckProgram(remote, local)
	}
}

// panicConfirm is the first question of the panic item.
const panicConfirm = "Panik: ağ kilitlensin mi?\n\nÖnceden hazırlanmış kilitleme belgesi yayımlanır. Cihazlar bir sonraki eşitlemede kilitli belgeyi alır ve bağlantılar kısıtlanır. Geri almak için kök anahtarla yeni bir belge imzalamanız gerekir.\n\nDevam ederseniz kök anahtar parolası ayrı, güvenli bir masaüstünde sorulur."

// trayPanic asks twice (dialog, then the passphrase on the secure
// desktop) and publishes the prepared lockdown document.
func trayPanic(ctx context.Context, client *trayClient, tray *winapp.Tray) {
	if !confirm(panicConfirm) {
		return
	}
	buf, err := winapp.ReadSecretSecureDesktop("Kök anahtar parolası (panik: kilitleme)")
	switch {
	case errors.Is(err, winapp.ErrSecureInputCancelled):
		return
	case err != nil:
		tray.Notify("OpenScale", "Parola sorulamadı: "+err.Error())
		return
	}
	defer buf.Destroy()
	// The passphrase leaves locked memory only for the request body.
	err = buf.Use(func(pass []byte) error { return client.publishPanic(ctx, string(pass)) })
	if err != nil {
		tray.Notify("OpenScale", "Panik uygulanamadı: "+err.Error())
		return
	}
	tray.Notify("OpenScale", "Kilitleme belgesi yayımlandı.")
}

// publishPanic publishes the prepared lockdown document.
func (c *trayClient) publishPanic(ctx context.Context, passphrase string) error {
	var out map[string]any
	return c.do(ctx, http.MethodPost, "/api/app/tray/panic", panel.TrayPanicRequest{Passphrase: passphrase}, &out)
}
