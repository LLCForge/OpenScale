//go:build windows

package posture

import (
	"bytes"
	"context"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const createNoWindow = 0x08000000

func collect() Report {
	return Report{
		DiskEncryption: bitlocker(),
		Firewall:       firewall(),
		WindowsBuild:   int(windows.RtlGetVersion().BuildNumber),
	}
}

func isWireless(name string) bool { return wirelessByName(name) }

var profiles = [3]string{"DomainProfile", "StandardProfile", "PublicProfile"}

func firewall() State {
	var policy, local [3]int
	for i, p := range profiles {
		policy[i] = readDWORD(`SOFTWARE\Policies\Microsoft\WindowsFirewall\` + p)
		local[i] = readDWORD(`SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\` + p)
	}
	return windowsFirewall(policy, local)
}

// readDWORD returns EnableFirewall under HKLM\path, or -1 when absent.
func readDWORD(path string) int {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err != nil {
		return -1
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue("EnableFirewall")
	if err != nil {
		return -1
	}
	if v != 0 {
		return 1
	}
	return 0
}

// bitlocker asks the volume encryption WMI provider about every volume
// with a drive letter through the in-box PowerShell (no new dependency),
// keeps the answers for VolumeEncryption and returns the system drive's.
// It needs administrator rights; otherwise the answer is Unknown. The
// command line is fixed; nothing from the system is placed into it.
func bitlocker() State {
	drive := strings.ToUpper(os.Getenv("SystemDrive"))
	if len(drive) != 2 || drive[1] != ':' || !(drive[0] >= 'A' && drive[0] <= 'Z') {
		drive = "C:"
	}
	sysRoot, err := windows.GetSystemDirectory()
	if err != nil {
		return Unknown
	}
	ps := filepath.Join(sysRoot, "WindowsPowerShell", "v1.0", "powershell.exe")
	const script = `Get-CimInstance -Namespace root/CIMV2/Security/MicrosoftVolumeEncryption -ClassName Win32_EncryptableVolume -ErrorAction Stop | ForEach-Object { '' + $_.DriveLetter + '=' + $_.ProtectionStatus }`
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, ps, "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil || out.Len() > 4096 {
		return Unknown
	}
	vols := bitlockerVolumesFromOutput(out.String())
	volumes.Lock()
	volumes.m = vols
	volumes.Unlock()
	if st, ok := vols[drive]; ok {
		return st
	}
	return Unknown
}

var volumes struct {
	sync.Mutex
	m map[string]State
}

// VolumeEncryption returns the BitLocker protection of each drive letter
// ("C:") from the last posture collection (Cached refreshes it every 30
// minutes); it never starts a query itself. Empty until the first
// collection finished or when it failed.
func VolumeEncryption() map[string]State {
	volumes.Lock()
	defer volumes.Unlock()
	return maps.Clone(volumes.m)
}

// DeviceEncryption is the Linux block device check; volumes are reported
// by drive letter here.
func DeviceEncryption(string) State { return Unknown }

// DiskEncryption checks only the system drive's BitLocker protection.
func DiskEncryption() State { return bitlocker() }
