package rdesk

import (
	"context"
	"time"
)

// Wiring of the "remotely connected" frame and the kill shortcut into the
// running desktop server (W1, #671, #672, ADR-0200).

// KillShortcutBlock is how long new sessions are refused after the person
// at the device pressed the kill shortcut.
const KillShortcutBlock = 5 * time.Minute

// watchHotkey is WatchKillHotkey; tests replace it so no global shortcut
// is ever registered by a test run.
var watchHotkey = WatchKillHotkey

// WithSessionFrame turns on the frame of every session (#671). Where the
// platform cannot show one (NewSystemFrame returns ErrUnsupported) the
// session still starts unless RequireFrame is set.
func WithSessionFrame(cfg Config) Config {
	if cfg.NewFrame == nil {
		cfg.NewFrame = NewSystemFrame
	}
	return cfg
}

// WatchKillShortcut binds DefaultKillHotkey to srv.KillAll until ctx ends
// (#672). It runs in the interactive session (the desktop helper on
// Windows); onKill, when set, runs after every press with the number of
// sessions ended. The error is ErrUnsupported off Windows, or the
// registration error when another program owns the combination.
func WatchKillShortcut(ctx context.Context, srv *Server, onKill func(ended int)) error {
	return watchHotkey(ctx, DefaultKillHotkey, func() {
		n := srv.KillAll(KillShortcutBlock, "yerel kullanıcı kısayolla bağlantıyı kesti")
		if onKill != nil {
			onKill(n)
		}
	})
}
