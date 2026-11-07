//go:build windows

package service

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/windows"
)

// bundleTool finds a tool in System32 (or its PowerShell folder) only.
func bundleTool(name string) (string, error) {
	sys, err := windows.GetSystemDirectory()
	if err != nil || sys == "" {
		return "", errors.New("System32 bulunamadı")
	}
	for _, dir := range []string{sys, filepath.Join(sys, "WindowsPowerShell", "v1.0")} {
		p := filepath.Join(dir, name+".exe")
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			return p, nil
		}
	}
	return "", errors.New("sistem aracı bulunamadı")
}

func prepareBundleCommand(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
}

// systemDumps are the routing table, interfaces and NRPT (DNS policy)
// rules, read only.
func systemDumps(ctx context.Context) map[string]string {
	ps := func(script string) string {
		return runForBundle(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command",
			"[Console]::OutputEncoding=[Text.Encoding]::UTF8; "+script)
	}
	return map[string]string{
		"route-print.txt":    runForBundle(ctx, "route", "print"),
		"interfaces-v4.txt":  runForBundle(ctx, "netsh", "interface", "ipv4", "show", "interfaces"),
		"interfaces-v6.txt":  runForBundle(ctx, "netsh", "interface", "ipv6", "show", "interfaces"),
		"dns-servers.txt":    ps("Get-DnsClientServerAddress | Format-Table -AutoSize | Out-String -Width 200"),
		"nrpt-rules.txt":     ps("Get-DnsClientNrptRule | Format-List * | Out-String -Width 200"),
		"nrpt-policy.txt":    ps("Get-DnsClientNrptPolicy | Format-List * | Out-String -Width 200"),
		"firewall-rules.txt": ps("Get-NetFirewallRule -DisplayName 'OpenScale*' -ErrorAction SilentlyContinue | Format-List DisplayName,Enabled,Direction,Action,Profile | Out-String -Width 200"),
	}
}
