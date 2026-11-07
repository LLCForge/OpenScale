//go:build windows

package posture

import (
	"github.com/openscale/openscale/internal/tpm"
	"golang.org/x/sys/windows/registry"
)

func collectExtended() Extended {
	var x Extended
	x.SecureBoot = windowsSecureBoot()
	x.TPM = tpmState()
	policy := -1
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, registry.QUERY_VALUE); err == nil {
		if v, _, err := k.GetIntegerValue("InactivityTimeoutSecs"); err == nil && v < 1<<31 {
			policy = int(v)
		}
		k.Close()
	}
	var active, secure, timeout string
	if k, err := registry.OpenKey(registry.CURRENT_USER, `Control Panel\Desktop`, registry.QUERY_VALUE); err == nil {
		active, _, _ = k.GetStringValue("ScreenSaveActive")
		secure, _, _ = k.GetStringValue("ScreenSaverIsSecure")
		timeout, _, _ = k.GetStringValue("ScreenSaveTimeOut")
		k.Close()
	}
	x.ScreenLock, x.LockMinutes = WindowsScreenLock(policy, active, secure, timeout)
	return x
}

func windowsSecureBoot() State {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\SecureBoot\State`, registry.QUERY_VALUE)
	if err != nil {
		return Unknown
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue("UEFISecureBootEnabled")
	if err != nil {
		return Unknown
	}
	if v == 1 {
		return On
	}
	return Off
}

func tpmState() State {
	p, err := tpm.Detect()
	if err != nil {
		return Unknown
	}
	if p.Present && p.Version == "2.0" {
		return On
	}
	return Off
}
