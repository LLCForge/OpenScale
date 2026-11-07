//go:build windows

package winapp

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/windows"
)

// FirewallRulesPresent reports whether both OpenScale inbound rules exist
// (#498: feature updates of Windows can drop them). It only reads.
func FirewallRulesPresent() (bool, error) {
	sysDir, err := windows.GetSystemDirectory()
	if err != nil {
		return false, fmt.Errorf("sistem klasörü bulunamadı: %w", err)
	}
	for _, name := range []string{firewallRuleUDP, firewallRulePing} {
		ctx, cancel := context.WithTimeout(context.Background(), netshTimeout)
		cmd := exec.CommandContext(ctx, filepath.Join(sysDir, "netsh.exe"), "advfirewall", "firewall", "show", "rule", "name="+name)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
		err := cmd.Run()
		timedOut := ctx.Err() != nil
		cancel()
		if timedOut {
			return false, errors.New("netsh 15 saniye içinde yanıt vermedi")
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
			return false, nil
		}
		if err != nil {
			return false, fmt.Errorf("netsh başarısız oldu: %w", err)
		}
	}
	return true, nil
}
