//go:build windows

package usagehist

import (
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procGetSystemPowerStatus = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetSystemPowerStatus")

func filetime(ft windows.Filetime) time.Duration {
	return time.Duration(int64(ft.HighDateTime)<<32|int64(ft.LowDateTime)) * 100
}

// processCPU is the kernel and user time of this process.
func processCPU() (time.Duration, bool) {
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(windows.CurrentProcess(), &creation, &exit, &kernel, &user); err != nil {
		return 0, false
	}
	return filetime(kernel) + filetime(user), true
}

// systemPowerStatus is SYSTEM_POWER_STATUS.
type systemPowerStatus struct {
	ACLineStatus        byte
	BatteryFlag         byte
	BatteryLifePercent  byte
	SystemStatusFlag    byte
	BatteryLifeTime     uint32
	BatteryFullLifeTime uint32
}

func batteryState() Battery {
	var ps systemPowerStatus
	if r, _, _ := procGetSystemPowerStatus.Call(uintptr(unsafe.Pointer(&ps))); r == 0 {
		return Battery{}
	}
	// BatteryFlag 128: no system battery; 255: unknown.
	if ps.BatteryFlag == 128 || ps.BatteryFlag == 255 {
		return Battery{}
	}
	var b Battery
	switch ps.ACLineStatus {
	case 0:
		on := true
		b.OnBattery = &on
	case 1:
		on := false
		b.OnBattery = &on
	}
	if ps.BatteryLifePercent <= 100 {
		p := int(ps.BatteryLifePercent)
		b.Percent = &p
	}
	return b
}
