package service

import (
	"errors"
	"io/fs"

	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/trust"
)

// SetExitNode implements panel.App: it remembers the choice and applies it
// to the running tunnel ("" turns exit node use off). With the kill switch
// on, its filters are installed before the choice is saved; if that fails
// the exit node is not enabled (ADR-0023).
func (r *Runtime) SetExitNode(name string) error {
	store, err := member.Open(r.path(DeviceDir))
	if err != nil {
		return errors.New("bu bilgisayar henüz bir ağa bağlı değil")
	}
	if name != "" {
		d, ok := store.Document().DeviceByName(name)
		if !ok || !d.HasRole(trust.RoleExitNode) {
			return errors.New("bu cihaz çıkış düğümü değil")
		}
	}
	if r.cfg.Hooks.ExitRouter == nil && name != "" {
		return errors.New("bu sistemde çıkış düğümü kullanılamıyor")
	}
	if err := r.saveExitChoice(name); err != nil {
		return err
	}
	r.mu.Lock()
	e := r.engine
	r.mu.Unlock()
	if e != nil {
		if err := e.SetExitNode(name); err != nil {
			return err
		}
	}
	if name == "" {
		// The engine removes the filters with the routes; this also covers
		// a tunnel that is not running (for example after a crash).
		if err := r.removeKillSwitch(); err != nil {
			return err
		}
	}
	r.logger.Info("exit node choice", "exit", name)
	return nil
}

// SetShields implements panel.App: it remembers the choice and applies it
// to the running tunnel at once (F-077).
func (r *Runtime) SetShields(on bool) error {
	if _, err := member.Open(r.path(DeviceDir)); err != nil {
		return errors.New("bu bilgisayar henüz bir ağa bağlı değil")
	}
	r.settingsMu.Lock()
	st, err := loadSettings(r.cfg.DataDir)
	if err == nil || errors.Is(err, fs.ErrNotExist) {
		st.Shields = on
		err = saveSettings(r.cfg.DataDir, st)
	}
	r.settingsMu.Unlock()
	if err != nil {
		return err
	}
	r.mu.Lock()
	e := r.engine
	r.mu.Unlock()
	if e != nil {
		e.SetShields(on)
	}
	r.logger.Info("shields", "on", on)
	return nil
}

// saveExitChoice installs the kill switch first when the new choice needs
// it, then saves the choice. Both happen under r.ksMu so a concurrent
// change of the options cannot interleave.
func (r *Runtime) saveExitChoice(name string) error {
	r.ksMu.Lock()
	defer r.ksMu.Unlock()
	r.settingsMu.Lock()
	st, err := loadSettings(r.cfg.DataDir)
	r.settingsMu.Unlock()
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	installed := false
	if name != "" && r.killSwitchAvailable() && st.killSwitchOn() && !st.Disconnected {
		if err := r.installKillSwitchLocked(r.tunnelInterface(), st.ExitAllowLAN); err != nil {
			return err
		}
		installed = !exitWanted(st)
	}
	r.settingsMu.Lock()
	st, err = loadSettings(r.cfg.DataDir)
	if err == nil || errors.Is(err, fs.ErrNotExist) {
		st.ExitNode = name
		if name != "" {
			st.LastExitNode = name
		}
		err = saveSettings(r.cfg.DataDir, st)
	}
	r.settingsMu.Unlock()
	if err != nil && installed {
		// Nothing asked for the filters before; do not leave them behind.
		return errors.Join(err, r.removeKillSwitchLocked())
	}
	return err
}
