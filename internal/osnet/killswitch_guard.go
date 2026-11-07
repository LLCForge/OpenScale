package osnet

import (
	"errors"
	"fmt"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/openscale/openscale/internal/trust"
)

// ExitRouter is the OS router for using an exit node; NewExitRouter
// returns one and KillSwitchGuard wraps one.
type ExitRouter interface {
	Enable(exit trust.Device, doc *trust.Document, iface string, bind conn.Bind) error
	Disable() error
}

// KillSwitchGuard puts the persistent kill switch in front of an exit
// router (ADR-0023) for programs without the desktop service, such as
// "openscale up --kill-switch" on Linux: the kill switch is installed
// before the routes and removed after them. When installing fails the exit
// node is not enabled. A Disable while the program stops keeps the kill
// switch, so a crash, a restart or Ctrl+C never opens the computer; only
// leaving the exit node removes it.
type KillSwitchGuard struct {
	Inner    ExitRouter
	AllowLAN bool
	// Stopping reports whether the program is shutting down.
	Stopping func() bool
	// Install and Remove default to InstallKillSwitch and RemoveKillSwitch.
	Install func(KillSwitchConfig) error
	Remove  func() error
}

func (g *KillSwitchGuard) install(cfg KillSwitchConfig) error {
	if g.Install != nil {
		return g.Install(cfg)
	}
	return InstallKillSwitch(cfg)
}

func (g *KillSwitchGuard) remove() error {
	if g.Remove != nil {
		return g.Remove()
	}
	return RemoveKillSwitch()
}

// Prepare installs the kill switch for iface before the tunnel carries
// anything, so the start of the program is protected too (fail closed).
func (g *KillSwitchGuard) Prepare(iface string) error {
	if err := g.install(KillSwitchConfig{Interface: iface, AllowLAN: g.AllowLAN}); err != nil {
		return fmt.Errorf("kill switch kurulamadı: %w", err)
	}
	return nil
}

// Enable installs the kill switch for iface, then the exit node routes. If
// the routes fail the kill switch stays: traffic stops instead of leaking.
func (g *KillSwitchGuard) Enable(exit trust.Device, doc *trust.Document, iface string, bind conn.Bind) error {
	if err := g.install(KillSwitchConfig{Interface: iface, AllowLAN: g.AllowLAN}); err != nil {
		return fmt.Errorf("kill switch kurulamadı, çıkış düğümü etkinleştirilmedi: %w", err)
	}
	return g.Inner.Enable(exit, doc, iface, bind)
}

// Disable restores the routes and removes the kill switch, except while
// the program stops.
func (g *KillSwitchGuard) Disable() error {
	err := g.Inner.Disable()
	if g.Stopping != nil && g.Stopping() {
		return err
	}
	return errors.Join(err, g.remove())
}
