package enrollkit

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/trust"
)

// Invite launcher (#360). The panel turns a short-lived invite code into a
// single file the new member double-clicks (Windows) or runs (Linux). The
// file only carries the invite code, which is already meant to be handed
// over; joining still needs the owner's approval with the 4-digit code, and
// the invite expires on its own (default one hour). The file never
// downloads anything: it uses an OpenScale that is already installed or the
// official installer placed next to it.

// shExt is kept apart so the file name is not read as a domain name.
const (
	shExt          = ".sh"
	linuxInstaller = "install-device" + shExt
)

// Launcher platforms.
const (
	PlatformWindows = "windows"
	PlatformLinux   = "linux"
)

// Launcher is a generated launcher file.
type Launcher struct {
	FileName string
	Content  []byte
}

// safeCode reports whether s only holds characters that cannot break out
// of a quoted shell or batch string. Invite codes are "osinv1." plus
// base64url, so this is a defence in depth check.
func safeCode(s string) bool {
	if s == "" || len(s) > 4096 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// NewLauncher returns the launcher for platform. code must be a valid
// single-part invite code; expires is printed for the user.
func NewLauncher(platform, code string, expires time.Time) (*Launcher, error) {
	code = strings.TrimSpace(code)
	if _, err := trust.DecodeInviteCode(code); err != nil {
		return nil, err
	}
	if trust.IsSplitInvite(code) || !safeCode(code) {
		return nil, errors.New("launcher needs a single-part invite code")
	}
	until := expires.UTC().Format("2006-01-02 15:04") + " UTC"
	switch platform {
	case PlatformWindows:
		return &Launcher{FileName: "openscale-davet.cmd", Content: []byte(windowsLauncher(code, until))}, nil
	case PlatformLinux:
		return &Launcher{FileName: "openscale-davet" + shExt, Content: []byte(linuxLauncher(code, until))}, nil
	}
	return nil, fmt.Errorf("unknown platform %q", platform)
}

// The Windows desktop joins through the app (the service owns the state),
// so the launcher installs or opens the app and puts the code on the
// clipboard for its "Katıl" screen. CRLF line ends for cmd.exe.
func windowsLauncher(code, until string) string {
	lines := []string{
		"@echo off",
		"chcp 65001 >nul",
		"setlocal",
		"rem OpenScale davet dosyası. Davet " + until + " tarihine kadar geçerlidir.",
		"rem Bu dosya hiçbir şey indirmez; yalnızca davet kodunu taşır.",
		`set "OS_EXE=%ProgramFiles%\OpenScale\openscale.exe"`,
		`set "OS_CODE=` + code + `"`,
		`if not exist "%OS_EXE%" (`,
		`  if exist "%~dp0install-windows.ps1" (`,
		`    echo OpenScale kuruluyor...`,
		`    powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install-windows.ps1"`,
		`  ) else (`,
		`    echo OpenScale bu bilgisayarda kurulu değil.`,
		`    echo Resmi kurulum dosyalarını bu dosyanın yanına koyup yeniden çalıştırın.`,
		`    pause`,
		`    exit /b 1`,
		`  )`,
		`)`,
		`if not exist "%OS_EXE%" (`,
		`  echo Kurulum tamamlanmadı.`,
		`  pause`,
		`  exit /b 1`,
		`)`,
		`echo %OS_CODE%| clip`,
		`start "" "%OS_EXE%" app`,
		`echo.`,
		`echo Davet kodu panoya kopyalandı. Açılan OpenScale penceresinde "Ağa katıl" ekranına yapıştırın.`,
		`echo Ekranda görünen 4 haneli kodu ağ sahibine söyleyin; o onaylayınca katılım tamamlanır.`,
		`pause`,
	}
	return strings.Join(lines, "\r\n") + "\r\n"
}

// Linux joins headless with "openscale invite-join" into the system
// service's state directory (deploy/linux/openscale-device.service).
func linuxLauncher(code, until string) string {
	lines := []string{
		"#!/bin/sh",
		"# OpenScale davet dosyası. Davet " + until + " tarihine kadar geçerlidir.",
		"# Bu dosya hiçbir şey indirmez; yalnızca davet kodunu taşır.",
		"set -eu",
		"OS_CODE='" + code + "'",
		`DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)`,
		`SUDO=""`,
		`[ "$(id -u)" -eq 0 ] || SUDO=sudo`,
		`if ! command -v openscale >/dev/null 2>&1; then`,
		`  if [ -x "$DIR/` + linuxInstaller + `" ]; then`,
		`    echo "OpenScale kuruluyor..."`,
		`    $SUDO "$DIR/` + linuxInstaller + `"`,
		`  else`,
		`    echo "OpenScale kurulu değil. Resmi kurulum dosyalarını bu dosyanın yanına koyup yeniden çalıştırın." >&2`,
		`    exit 1`,
		`  fi`,
		`fi`,
		`echo "Ağa katılım başlıyor. Ekranda görünen 4 haneli kodu ağ sahibine söyleyin."`,
		`$SUDO openscale invite-join --state-dir /var/lib/openscale/device --code "$OS_CODE"`,
		`$SUDO systemctl enable --now openscale-device.service`,
		`echo "Katılım tamamlandı."`,
	}
	return strings.Join(lines, "\n") + "\n"
}
