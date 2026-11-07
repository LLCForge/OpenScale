//go:build !linux && !darwin && (!windows || !(amd64 || arm64))

package osnet

import (
	"net/netip"
	"time"
)

// KillSwitchSupported reports whether this system has a persistent kill
// switch.
func KillSwitchSupported() bool { return false }

// InstallKillSwitch is not implemented here.
func InstallKillSwitch(KillSwitchConfig) error { return ErrKillSwitchUnsupported }

// RemoveKillSwitch has nothing to remove here.
func RemoveKillSwitch() error { return nil }

// KillSwitchInstalled is always false here.
func KillSwitchInstalled() (bool, error) { return false, nil }

// RestoreKillSwitch has nothing to restore here.
func RestoreKillSwitch() (bool, error) { return false, nil }

// KillSwitchBootSupported is false here.
func KillSwitchBootSupported() bool { return false }

// EnableKillSwitchBoot is not implemented here.
func EnableKillSwitchBoot(string) error { return ErrKillSwitchUnsupported }

// DisableKillSwitchBoot has nothing to remove here.
func DisableKillSwitchBoot() error { return nil }

// KillSwitchBootEnabled is always false here.
func KillSwitchBootEnabled() (bool, error) { return false, nil }

// AllowCaptivePortal is not implemented here.
func AllowCaptivePortal([]netip.Addr, time.Duration) error { return ErrKillSwitchUnsupported }

// RevokeCaptivePortal has nothing to revoke here.
func RevokeCaptivePortal() error { return nil }
