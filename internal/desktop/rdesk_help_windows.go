//go:build windows

package desktop

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/windows"

	"github.com/openscale/openscale/internal/winapp"
)

// The tray's "Yardım iste" item (#424, ADR-0146): it runs "openscale
// rdesk-help", which sends an end-to-end encrypted message to every device
// that may control this one. Nothing about the rules changes: whoever
// connects is still asked for on-screen approval unless a rule already
// grants unattended access.

const (
	helpPrompt = "Uzaktan yardım istensin mi?\n\nBu bilgisayarı uzaktan kontrol izni olan cihazlara bir bildirim gider. " +
		"Biri bağlanmak istediğinde yine onayınız sorulur; gözetimsiz erişim açılmaz."
	helpTimeout  = time.Minute
	helpCooldown = time.Minute
)

var helpState struct {
	mu   sync.Mutex
	last time.Time
}

func requestHelp(ctx context.Context, tray *winapp.Tray) {
	helpState.mu.Lock()
	if !helpState.last.IsZero() && time.Since(helpState.last) < helpCooldown {
		helpState.mu.Unlock()
		tray.Notify("OpenScale", "Yardım isteği az önce gönderildi; lütfen biraz bekleyin.")
		return
	}
	helpState.last = time.Now()
	helpState.mu.Unlock()
	exe, err := os.Executable()
	if err != nil {
		tray.Notify("OpenScale", "Yardım isteği gönderilemedi.")
		return
	}
	cctx, cancel := context.WithTimeout(ctx, helpTimeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, exe, "rdesk-help")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	out, err := cmd.CombinedOutput()
	if err != nil {
		tray.Notify("OpenScale", "Yardım isteği gönderilemedi: "+lastLine(string(out), 180))
		return
	}
	tray.Notify("OpenScale", "Yardım isteği gönderildi. Bağlanmak isteyen olursa onayınız sorulacak.")
}

// lastLine returns the last non-empty line, at most n bytes.
func lastLine(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	l := strings.TrimSpace(lines[len(lines)-1])
	if len(l) > n {
		l = l[:n]
		for len(l) > 0 && l[len(l)-1]&0xc0 == 0x80 {
			l = l[:len(l)-1]
		}
		if len(l) > 0 && l[len(l)-1] >= 0xc0 {
			l = l[:len(l)-1]
		}
	}
	return l
}
