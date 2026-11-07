package service

import (
	"errors"
	"fmt"
	"io/fs"
	"time"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/openscale/openscale/internal/autoupdate"
	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/node"
	"github.com/openscale/openscale/internal/osnet"
	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/internal/updater"
)

// errServiceStopping refuses to enable an exit node while the service
// stops.
var errServiceStopping = errors.New("servis duruyor")

// killSwitchState is what this process last did with the kill switch. Its
// mutex is a leaf: nothing else is locked while it is held.
type killSwitchState struct {
	installed bool
	allowLAN  bool
	err       string
	// tunIface is the running tunnel interface ("" while it is down).
	tunIface string
	// releaseUntil: a stop before this time removes the filters (the
	// owner's full exit from the tray).
	releaseUntil time.Time
}

// exitGuard wraps the OS exit router with the persistent kill switch
// (ADR-0023): the filters are installed before the routes, and removed
// after them. If installing fails, the exit node is not enabled.
type exitGuard struct {
	r     *Runtime
	inner node.ExitRouter
}

func (g *exitGuard) Enable(exit trust.Device, doc *trust.Document, iface string, bind conn.Bind) error {
	if err := g.r.syncKillSwitch(iface); err != nil {
		return err
	}
	// If the routes fail the filters stay: traffic stops instead of
	// leaking (fail closed, ADR-0006).
	return g.inner.Enable(exit, doc, iface, bind)
}

// Disable restores the normal routes. The kill switch goes with them,
// except while the service stops: a restart, an update or a shutdown keeps
// the filters so the computer stays protected until the service runs
// again (ADR-0023). Only the owner's explicit full exit releases them.
func (g *exitGuard) Disable() error {
	err := g.inner.Disable()
	if g.r.stopping() && !g.r.releaseRequested() {
		g.r.logger.Info("service stopping: kill switch stays installed")
		return err
	}
	return errors.Join(err, g.r.removeKillSwitch())
}

// releaseWindow is how long a release request waits for the stop it
// announces; an exit that never stops the service does not keep it armed.
const releaseWindow = 2 * time.Minute

// stopping reports whether the service is stopping, for any reason.
func (r *Runtime) stopping() bool {
	return r.ctx != nil && r.ctx.Err() != nil
}

// ReleaseKillSwitchOnStop implements panel.App: the owner chose to close
// OpenScale completely, so the stop that follows removes the kill switch
// instead of keeping it. The request expires after releaseWindow.
func (r *Runtime) ReleaseKillSwitchOnStop() {
	r.ksStateMu.Lock()
	r.ks.releaseUntil = r.cfg.Now().Add(releaseWindow)
	r.ksStateMu.Unlock()
	r.logger.Info("full exit requested: the kill switch is removed when the service stops")
}

// releaseRequested reports whether a full exit asked to remove the kill
// switch on this stop.
func (r *Runtime) releaseRequested() bool {
	r.ksStateMu.Lock()
	defer r.ksStateMu.Unlock()
	return !r.ks.releaseUntil.IsZero() && r.cfg.Now().Before(r.ks.releaseUntil)
}

func (r *Runtime) killSwitchAvailable() bool {
	return r.cfg.Hooks.InstallKillSwitch != nil && r.cfg.Hooks.RemoveKillSwitch != nil
}

// currentSettings loads the settings; a missing file gives the defaults.
func (r *Runtime) currentSettings() (settings, error) {
	r.settingsMu.Lock()
	defer r.settingsMu.Unlock()
	st, err := loadSettings(r.cfg.DataDir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return settings{}, err
	}
	return st, nil
}

// exitWanted reports whether the settings ask for an exit node on a
// connected tunnel, which is when the kill switch belongs in place.
func exitWanted(st settings) bool { return st.ExitNode != "" && !st.Disconnected }

// syncKillSwitch installs the kill switch for iface ("" before the tunnel
// exists) when the settings want it, and removes it otherwise.
func (r *Runtime) syncKillSwitch(iface string) error {
	if !r.killSwitchAvailable() {
		return nil
	}
	r.ksMu.Lock()
	defer r.ksMu.Unlock()
	if r.stopping() {
		// The service is stopping: never install now, and refuse new
		// routes. The filters stay unless the owner asked for a full exit.
		if r.releaseRequested() {
			if err := r.removeKillSwitchLocked(); err != nil {
				return err
			}
		}
		return errServiceStopping
	}
	st, err := r.currentSettings()
	if err != nil {
		return err
	}
	if !st.killSwitchOn() || !exitWanted(st) {
		return r.removeKillSwitchLocked()
	}
	return r.installKillSwitchLocked(iface, st.ExitAllowLAN)
}

// releaseKillSwitchOnStop removes the filters at the end of a stop that
// follows the owner's full exit, also when no exit node was active to take
// them down with its routes. Any other stop (restart, update, shutdown,
// crash) keeps them (ADR-0023).
func (r *Runtime) releaseKillSwitchOnStop() {
	if !r.stopping() || !r.releaseRequested() {
		return
	}
	// An update restarts the service: the kill switch stays across it, even
	// if the owner asked to close OpenScale just before (#203, ADR-0235).
	if updater.RestartForUpdate(autoupdate.DefaultPaths().UpdaterState, r.cfg.Now()) {
		r.logger.Info("kill switch kept: the service is restarted by an update")
		return
	}
	if err := r.removeKillSwitch(); err != nil {
		r.logger.Warn("kill switch on stop", "error", err.Error())
	}
}

// installKillSwitchLocked is called with r.ksMu held.
func (r *Runtime) installKillSwitchLocked(iface string, allowLAN bool) error {
	err := r.cfg.Hooks.InstallKillSwitch(osnet.KillSwitchConfig{Interface: iface, AllowLAN: allowLAN})
	r.ksStateMu.Lock()
	defer r.ksStateMu.Unlock()
	if err != nil {
		r.ks.err = "Kill switch kurulamadı: " + err.Error()
		r.logger.Warn("kill switch install", "error", err.Error())
		return fmt.Errorf("kill switch kurulamadı, çıkış düğümü etkinleştirilmedi: %w", err)
	}
	if !r.ks.installed || r.ks.allowLAN != allowLAN {
		r.logger.Info("kill switch installed", "tunnel", iface != "", "allow_lan", allowLAN)
	}
	r.ks.installed, r.ks.allowLAN, r.ks.err = true, allowLAN, ""
	return nil
}

func (r *Runtime) removeKillSwitch() error {
	if !r.killSwitchAvailable() {
		return nil
	}
	r.ksMu.Lock()
	defer r.ksMu.Unlock()
	return r.removeKillSwitchLocked()
}

// removeKillSwitchLocked is called with r.ksMu held. Removing what is not
// there is cheap and not an error, so it also cleans up after a crash.
func (r *Runtime) removeKillSwitchLocked() error {
	err := r.cfg.Hooks.RemoveKillSwitch()
	r.ksStateMu.Lock()
	defer r.ksStateMu.Unlock()
	if err != nil {
		r.ks.err = "Kill switch kaldırılamadı: " + err.Error()
		r.logger.Warn("kill switch removal", "error", err.Error())
		return fmt.Errorf("kill switch kaldırılamadı: %w", err)
	}
	if r.ks.installed {
		r.logger.Info("kill switch removed")
	}
	r.ks.installed, r.ks.err = false, ""
	return nil
}

func (r *Runtime) setTunnelInterface(name string) {
	r.ksStateMu.Lock()
	r.ks.tunIface = name
	r.ksStateMu.Unlock()
}

func (r *Runtime) tunnelInterface() string {
	r.ksStateMu.Lock()
	defer r.ksStateMu.Unlock()
	return r.ks.tunIface
}

func (r *Runtime) killSwitchSnapshot() killSwitchState {
	r.ksStateMu.Lock()
	defer r.ksStateMu.Unlock()
	return r.ks
}

// SetExitOptions implements panel.App: it saves the kill switch and the
// local network choice and applies them at once when an exit node is in
// use. The setting is kept unchanged if applying fails.
func (r *Runtime) SetExitOptions(killSwitch, allowLAN bool) error {
	if _, err := member.Open(r.path(DeviceDir)); err != nil {
		return errors.New("bu bilgisayar henüz bir ağa bağlı değil")
	}
	return r.applyExitOptions(killSwitch, allowLAN)
}

func (r *Runtime) applyExitOptions(killSwitch, allowLAN bool) error {
	if !r.killSwitchAvailable() && killSwitch {
		return errors.New("bu sistemde kalıcı kill switch yok")
	}
	r.ksMu.Lock()
	defer r.ksMu.Unlock()
	st, err := r.currentSettings()
	if err != nil {
		return err
	}
	if r.killSwitchAvailable() && exitWanted(st) {
		if killSwitch {
			err = r.installKillSwitchLocked(r.tunnelInterface(), allowLAN)
		} else {
			err = r.removeKillSwitchLocked()
		}
		if err != nil {
			return err
		}
	}
	r.settingsMu.Lock()
	defer r.settingsMu.Unlock()
	st, err = loadSettings(r.cfg.DataDir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	on := killSwitch
	st.KillSwitch, st.ExitAllowLAN = &on, allowLAN
	if err := saveSettings(r.cfg.DataDir, st); err != nil {
		return err
	}
	r.logger.Info("exit options", "kill_switch", killSwitch, "allow_lan", allowLAN)
	return nil
}
