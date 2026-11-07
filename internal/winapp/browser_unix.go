//go:build !windows

package winapp

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
)

// browserOpeners are the absolute paths of the system URL openers; PATH
// is never searched, so a program planted earlier in PATH is not run.
func browserOpeners(goos string) []string {
	switch goos {
	case "darwin":
		return []string{"/usr/bin/open"}
	case "linux", "freebsd", "openbsd", "netbsd":
		return []string{"/usr/bin/xdg-open", "/usr/local/bin/xdg-open"}
	}
	return nil
}

// OpenSystemBrowser opens a loopback panel URL in the default browser
// (the fallback of the native window, ADR-0195).
func OpenSystemBrowser(rawURL string) error {
	u, err := validateLoopbackURL(rawURL)
	if err != nil {
		return err
	}
	for _, p := range browserOpeners(runtime.GOOS) {
		info, err := os.Stat(p)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		cmd := exec.Command(p, u)
		if err := cmd.Start(); err != nil {
			return fmt.Errorf("tarayıcı açılamadı: %w", err)
		}
		go func() { _ = cmd.Wait() }()
		return nil
	}
	return errors.New("sistem tarayıcısını açan program (xdg-open veya open) bulunamadı")
}
