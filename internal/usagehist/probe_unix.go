//go:build unix

package usagehist

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// processCPU is the user and system time of this process.
func processCPU() (time.Duration, bool) {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0, false
	}
	return time.Duration(ru.Utime.Nano()) + time.Duration(ru.Stime.Nano()), true
}

// powerSupplyDir is where Linux lists power supplies.
var powerSupplyDir = "/sys/class/power_supply"

// batteryState reads the first battery of /sys/class/power_supply on
// Linux; other systems report an unknown state.
func batteryState() Battery {
	if runtime.GOOS != "linux" {
		return Battery{}
	}
	return linuxBattery(powerSupplyDir)
}

func readSmall(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	buf := make([]byte, 64)
	n, _ := f.Read(buf)
	return strings.TrimSpace(string(buf[:n]))
}

func linuxBattery(dir string) Battery {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return Battery{}
	}
	var b Battery
	for _, e := range entries {
		base := filepath.Join(dir, e.Name())
		switch readSmall(filepath.Join(base, "type")) {
		case "Battery":
			if b.Percent == nil {
				if n, err := strconv.Atoi(readSmall(filepath.Join(base, "capacity"))); err == nil && n >= 0 && n <= 100 {
					b.Percent = &n
				}
			}
			if b.OnBattery == nil {
				switch readSmall(filepath.Join(base, "status")) {
				case "Discharging":
					on := true
					b.OnBattery = &on
				case "Charging", "Full", "Not charging":
					on := false
					b.OnBattery = &on
				}
			}
		case "Mains":
			if readSmall(filepath.Join(base, "online")) == "1" {
				on := false
				b.OnBattery = &on
			}
		}
	}
	if b.Percent == nil {
		// No battery: a desktop or a server; the power state is moot.
		return Battery{}
	}
	return b
}
