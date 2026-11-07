//go:build windows

package winapp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

const (
	netshTimeout   = 15 * time.Second
	maxNetshOutput = 400
)

// EnsureFirewallRules (re)creates the inbound Windows Defender Firewall rules
// for OpenScale: UDP for exePath on all profiles, and ICMPv4 echo requests
// from the overlay network overlayIPv4 (e.g. "100.80.0.0/16"). Existing rules
// with the same names are deleted first, so the call is idempotent.
func EnsureFirewallRules(exePath string, overlayIPv4 string) error {
	if !IsElevated() {
		return errFirewallNeedsAdmin
	}
	exe, err := validateProgramPath(exePath)
	if err != nil {
		return fmt.Errorf("güvenlik duvarı kuralı eklenemedi: %w", err)
	}
	cidr, err := validateIPv4CIDR(overlayIPv4)
	if err != nil {
		return fmt.Errorf("güvenlik duvarı kuralı eklenemedi: %w", err)
	}
	removeRulesQuietly()
	for _, args := range firewallAddArgs(exe, cidr) {
		if err := runNetsh(args); err != nil {
			return fmt.Errorf("güvenlik duvarı kuralı eklenemedi: %w", err)
		}
	}
	return nil
}

// RemoveFirewallRules deletes the OpenScale firewall rules. Rules that do not
// exist are not an error.
func RemoveFirewallRules() error {
	if !IsElevated() {
		return errFirewallNeedsAdmin
	}
	var errs []error
	for _, args := range firewallDeleteArgs() {
		if err := runNetsh(args); err != nil && !errors.Is(err, errNetshNoMatch) {
			errs = append(errs, err)
		}
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("güvenlik duvarı kuralları kaldırılamadı: %w", err)
	}
	return nil
}

func removeRulesQuietly() {
	for _, args := range firewallDeleteArgs() {
		_ = runNetsh(args)
	}
}

var errNetshNoMatch = errors.New("eşleşen kural yok")

var errFirewallNeedsAdmin = errors.New("güvenlik duvarı kurallarını değiştirmek için yönetici izni gerekiyor")

// runNetsh executes %SystemRoot%\System32\netsh.exe directly (no shell, no
// PATH lookup) with a fixed argument list and a timeout.
func runNetsh(args []string) error {
	sysDir, err := windows.GetSystemDirectory()
	if err != nil {
		return fmt.Errorf("sistem klasörü bulunamadı: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), netshTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, filepath.Join(sysDir, "netsh.exe"), args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err = cmd.Run()
	if ctx.Err() != nil {
		return errors.New("netsh 15 saniye içinde yanıt vermedi")
	}
	if err == nil {
		return nil
	}
	text := strings.TrimSpace(out.String())
	// netsh prints a localized message, but the delete verb consistently
	// exits with code 1 when nothing matched. Callers check elevation first,
	// so an exit code of 1 here means "no rule".
	var exitErr *exec.ExitError
	if len(args) > 2 && args[2] == "delete" && errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
		return errNetshNoMatch
	}
	if len(text) > maxNetshOutput {
		text = text[:maxNetshOutput]
	}
	if text == "" {
		return fmt.Errorf("netsh başarısız oldu: %w", err)
	}
	return fmt.Errorf("netsh başarısız oldu (%v): %s", err, strings.ToValidUTF8(text, "?"))
}
