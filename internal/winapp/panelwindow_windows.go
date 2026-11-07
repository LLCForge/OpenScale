//go:build windows

package winapp

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The tray runs elevated (desktop.RunApp relaunches with UAC), but the
// WebView2 window should not: a page bug in an elevated web engine is a
// privilege problem, and the runtime's per-user registration may only be
// trusted by a standard process (ADR-0170 section 2). The tray therefore
// starts "openscale panel-window" with the token of the desktop shell
// (explorer.exe), the same user without elevation. When that is not
// possible the browser path is used instead of an elevated window.

// windowStartGrace is how long the tray waits for the window process to
// report that no window can be shown.
const windowStartGrace = 4 * time.Second

var (
	procGetShellWindow  = modUser32.NewProc("GetShellWindow")
	modAdvapi32G4       = windows.NewLazySystemDLL("advapi32.dll")
	procCreateWithToken = modAdvapi32G4.NewProc("CreateProcessWithTokenW")
)

// openNativeWindowProcess shows the panel in a separate, non-elevated
// window process. It returns ErrWindowUnavailable when that process
// reports no window (or cannot start without elevation).
func openNativeWindowProcess(link string) error {
	if NativeWindowDisabled() {
		return ErrWindowUnavailable
	}
	if _, err := validateLoopbackURL(link); err != nil {
		return err
	}
	// Single window (W2): an open window takes the new link and comes to
	// the front instead of a second window opening.
	if ForwardToPanelWindow(link) == nil {
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	// Only the OpenScale program understands "panel-window"; another
	// program linking this package (a test binary, a tool) would run
	// itself again with unknown arguments.
	if !isOpenScaleProgram(exe) {
		return ErrWindowUnavailable
	}
	if !IsElevated() {
		return startWindowChild(exe, link)
	}
	return startWindowAsShellUser(exe, link)
}

// startWindowChild runs the window process as this (standard) user and
// gives it the one-time link on standard input, so it is not visible in
// the process list.
func startWindowChild(exe, link string) error {
	cmd := exec.Command(exe, "panel-window", "--title", DisplayName())
	cmd.Stdin = strings.NewReader(link + "\n")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("%w: %v", ErrWindowUnavailable, err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return windowExit(cmd.ProcessState.ExitCode(), err)
	case <-time.After(windowStartGrace):
		// The window is up; it keeps running on its own.
		go func() { <-done }()
		return nil
	}
}

func windowExit(code int, err error) error {
	switch code {
	case PanelWindowExitClosed:
		return nil
	case PanelWindowExitUnavailable:
		return ErrWindowUnavailable
	}
	return fmt.Errorf("%w: pencere süreci %d koduyla çıktı (%v)", ErrWindowUnavailable, code, err)
}

// shellToken returns a primary token of the desktop shell's user without
// elevation.
func shellToken() (windows.Token, error) {
	hwnd, _, _ := procGetShellWindow.Call()
	if hwnd == 0 {
		return 0, errors.New("masaüstü kabuğu bulunamadı")
	}
	var pid uint32
	if _, err := windows.GetWindowThreadProcessId(windows.HWND(hwnd), &pid); err != nil || pid == 0 {
		return 0, errors.New("masaüstü kabuğunun süreci bulunamadı")
	}
	proc, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(proc)
	var tok windows.Token
	if err := windows.OpenProcessToken(proc, windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY, &tok); err != nil {
		return 0, err
	}
	defer tok.Close()
	// The shell must itself be unelevated, or nothing is gained.
	if tok.IsElevated() {
		return 0, errors.New("masaüstü kabuğu yükseltilmiş çalışıyor")
	}
	var dup windows.Token
	access := uint32(windows.TOKEN_QUERY | windows.TOKEN_DUPLICATE | windows.TOKEN_ASSIGN_PRIMARY | windows.TOKEN_ADJUST_DEFAULT | windows.TOKEN_ADJUST_SESSIONID)
	if err := windows.DuplicateTokenEx(tok, access, nil, windows.SecurityImpersonation, windows.TokenPrimary, &dup); err != nil {
		return 0, err
	}
	return dup, nil
}

// startWindowAsShellUser starts the window process with the shell's
// token (CreateProcessWithTokenW).
//
// SECURITY FIX: CWE-214 Standard handles cannot be passed this way, and a
// command line is readable by other processes, which could redeem the
// one-time link before the window does. The link goes over a pipe, to the
// new process only (panelwindow_linkpipe_windows.go).
func startWindowAsShellUser(exe, link string) error {
	if err := procCreateWithToken.Find(); err != nil {
		return fmt.Errorf("%w: %v", ErrWindowUnavailable, err)
	}
	tok, err := shellToken()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrWindowUnavailable, err)
	}
	defer tok.Close()
	user, err := tok.GetTokenUser()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrWindowUnavailable, err)
	}
	pipe, cmdLine, err := prepareShellWindowStart(exe, link, user.User.Sid)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrWindowUnavailable, err)
	}
	defer pipe.close()
	app, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return err
	}
	line, err := windows.UTF16FromString(cmdLine)
	if err != nil {
		return err
	}
	var si windows.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi windows.ProcessInformation
	const createNoWindow = 0x08000000
	r, _, callErr := procCreateWithToken.Call(
		uintptr(tok), 0,
		uintptr(unsafe.Pointer(app)), uintptr(unsafe.Pointer(&line[0])),
		createNoWindow|windows.CREATE_UNICODE_ENVIRONMENT, 0, 0,
		uintptr(unsafe.Pointer(&si)), uintptr(unsafe.Pointer(&pi)))
	if r == 0 {
		return fmt.Errorf("%w: %v", ErrWindowUnavailable, callErr)
	}
	defer windows.CloseHandle(pi.Thread)
	defer windows.CloseHandle(pi.Process)
	// A process that exited first reports why through its exit code below.
	if err := pipe.serve(pi.ProcessId, link, pi.Process, windowStartGrace); err != nil && !errors.Is(err, errLinkPipeChildGone) {
		return fmt.Errorf("%w: %v", ErrWindowUnavailable, err)
	}
	ev, err := windows.WaitForSingleObject(pi.Process, uint32(windowStartGrace/time.Millisecond))
	if err != nil || ev != windows.WAIT_OBJECT_0 {
		return nil // still running: the window is up
	}
	var code uint32
	if err := windows.GetExitCodeProcess(pi.Process, &code); err != nil {
		return fmt.Errorf("%w: %v", ErrWindowUnavailable, err)
	}
	return windowExit(int(code), nil)
}
