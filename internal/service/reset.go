package service

import (
	"errors"
	"io/fs"
	"os"
)

// ErrResetAdmin is returned when the computer holding the root key asks to
// forget its membership; that would orphan the network on this computer.
var ErrResetAdmin = errors.New("bu bilgisayar ağın yöneticisi; sıfırlanamaz")

// ResetDevice implements panel.App: it stops the tunnel and forgets this
// computer's membership and device key, so it can join again with a new
// key and a new invite (for example after it was revoked by mistake).
func (r *Runtime) ResetDevice() error {
	r.mu.Lock()
	if r.network != nil {
		r.mu.Unlock()
		return ErrResetAdmin
	}
	if r.join != nil {
		r.join.cancel()
		r.join = nil
	}
	if r.stopDevice != nil {
		r.stopDevice()
		r.stopDevice = nil
	}
	r.engine, r.engineErr, r.lastJoinErr = nil, "", ""
	r.mu.Unlock()

	if err := os.RemoveAll(r.path(DeviceDir)); err != nil {
		return err
	}
	r.settingsMu.Lock()
	st, err := loadSettings(r.cfg.DataDir)
	if err == nil || errors.Is(err, fs.ErrNotExist) {
		st.ExitNode, st.Disconnected = "", false
		err = saveSettings(r.cfg.DataDir, st)
	}
	r.settingsMu.Unlock()
	r.setInventory(inventoryEmpty())
	// Without a membership no exit node can be used: the kill switch must
	// not keep this computer offline (ADR-0023). It goes after the setting
	// so a stopping tunnel cannot install it again.
	ksErr := r.removeKillSwitch()
	r.logger.Info("device membership reset")
	return errors.Join(err, ksErr)
}
