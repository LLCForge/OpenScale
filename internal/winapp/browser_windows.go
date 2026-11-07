//go:build windows

package winapp

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Panel in a separate browser profile (#520, ADR-0154). The tray opens
// the one-time sign-in link in Microsoft Edge or Google Chrome with a
// profile of its own, no extensions and an app window, so an extension
// installed in the owner's everyday profile cannot read or drive the
// panel. No library is added (R-46 rejected WebView2); the browser is
// started by its absolute path from the usual install folders, never
// through PATH. When neither is found the caller falls back to the
// default browser.

// ErrNoIsolatedBrowser: no Chromium-based browser was found.
var ErrNoIsolatedBrowser = errors.New("Edge veya Chrome bulunamadı")

// isolatedBrowserArgs are the flags of the panel window.
func isolatedBrowserArgs(profileDir, u string) []string {
	return []string{
		"--user-data-dir=" + profileDir,
		"--app=" + u,
		"--no-first-run",
		"--no-default-browser-check",
		"--disable-extensions",
		"--disable-component-extensions-with-background-pages",
		"--disable-sync",
		"--disable-background-networking",
	}
}

// browserCandidates lists the absolute paths to try, Edge first.
func browserCandidates(getenv func(string) string) []string {
	var out []string
	for _, base := range []string{getenv("ProgramFiles(x86)"), getenv("ProgramFiles")} {
		if base != "" {
			out = append(out, filepath.Join(base, "Microsoft", "Edge", "Application", "msedge.exe"))
		}
	}
	for _, base := range []string{getenv("ProgramFiles"), getenv("ProgramFiles(x86)"), getenv("LOCALAPPDATA")} {
		if base != "" {
			out = append(out, filepath.Join(base, "Google", "Chrome", "Application", "chrome.exe"))
		}
	}
	return out
}

func findIsolatedBrowser() (string, error) {
	for _, p := range browserCandidates(os.Getenv) {
		if !filepath.IsAbs(p) {
			continue
		}
		if info, err := os.Stat(p); err == nil && info.Mode().IsRegular() {
			return p, nil
		}
	}
	return "", ErrNoIsolatedBrowser
}

// OpenURLIsolated opens a loopback panel URL in the native OpenScale
// window (WebView2, ADR-0170 and ADR-0195) in a separate non-elevated
// process; when no native window can be shown it falls back to an app
// window of Edge or Chrome with its own profile in profileDir and no
// extensions.
func OpenURLIsolated(rawURL, profileDir string) error {
	u, err := validateLoopbackURL(rawURL)
	if err != nil {
		return err
	}
	if !filepath.IsAbs(profileDir) || strings.ContainsAny(profileDir, "\"\x00\r\n") {
		return errors.New("tarayıcı profil klasörü geçersiz")
	}
	if err := openNativeWindowProcess(u); err == nil {
		return nil
	}
	if err := os.MkdirAll(profileDir, 0o700); err != nil {
		return fmt.Errorf("tarayıcı profil klasörü oluşturulamadı: %w", err)
	}
	exe, err := findIsolatedBrowser()
	if err != nil {
		return err
	}
	cmd := exec.Command(exe, isolatedBrowserArgs(profileDir, u)...)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("tarayıcı açılamadı: %w", err)
	}
	return cmd.Process.Release()
}
