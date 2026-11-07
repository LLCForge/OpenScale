//go:build windows

package winapp

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/openscale/openscale/internal/peercred"
)

// The tray hands a one-time sign-in ticket to the open panel window. The
// window is found by a class name any process can register, so the process
// behind it must be shown to be this OpenScale program before it gets
// anything: same desktop session, at least medium integrity (the window
// runs with the shell's token; a low-integrity sandboxed process does not
// qualify, not even when it runs a copy of the program), and the same
// program file (#645: path or SHA-256).
//
// Limits (same as #645): this stops other programs and sandboxed ones. A
// same-user process at medium integrity can still start a real copy of
// the program or write into the real window's memory; no check from
// outside the process can rule that out.

const (
	integrityMedium = 0x2000 // SECURITY_MANDATORY_MEDIUM_RID
	maxTokenLabel   = 256
)

// panelWindowFacts is what the system says about the window's process.
type panelWindowFacts struct {
	session   uint32
	integrity uint32
	image     string
}

// checkPanelWindowFacts applies the rules; allowed checks the program file.
func checkPanelWindowFacts(f panelWindowFacts, ownSession uint32, allowed func(string) error) error {
	if f.session != ownSession {
		return errors.New("pencere başka bir oturumda")
	}
	if f.integrity < integrityMedium {
		return errors.New("pencere süreci düşük bütünlük düzeyinde")
	}
	if f.image == "" {
		return errors.New("pencere sürecinin programı okunamadı")
	}
	if err := allowed(f.image); err != nil {
		return fmt.Errorf("pencere başka bir programa ait: %w", err)
	}
	return nil
}

// verifyPanelWindowProcess is the check of ForwardToPanelWindow. It fails
// closed: whatever cannot be read is refused, and the caller then opens a
// new window of its own.
func verifyPanelWindowProcess(pid uint32) error {
	if pid == 0 {
		return errors.New("pencere süreci yok")
	}
	facts, err := readPanelWindowFacts(pid)
	if err != nil {
		return err
	}
	var own uint32
	if err := windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &own); err != nil {
		return fmt.Errorf("oturum okunamadı: %w", err)
	}
	policy, err := peercred.SelfProgramPolicy()
	if err != nil {
		return fmt.Errorf("program kimliği okunamadı: %w", err)
	}
	return checkPanelWindowFacts(facts, own, policy.AllowsProgram)
}

func readPanelWindowFacts(pid uint32) (panelWindowFacts, error) {
	var f panelWindowFacts
	if err := windows.ProcessIdToSessionId(pid, &f.session); err != nil {
		return f, fmt.Errorf("pencere oturumu okunamadı: %w", err)
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return f, fmt.Errorf("pencere süreci açılamadı: %w", err)
	}
	defer windows.CloseHandle(h)
	var tok windows.Token
	if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &tok); err != nil {
		return f, fmt.Errorf("pencere belirteci açılamadı: %w", err)
	}
	defer tok.Close()
	if f.integrity, err = tokenIntegrity(tok); err != nil {
		return f, err
	}
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		return f, fmt.Errorf("pencere programı okunamadı: %w", err)
	}
	f.image = windows.UTF16ToString(buf[:n])
	return f, nil
}

// tokenIntegrity returns the integrity level RID of a token.
func tokenIntegrity(tok windows.Token) (uint32, error) {
	// Pointer-aligned: the buffer holds a TOKEN_MANDATORY_LABEL.
	var store [maxTokenLabel / unsafe.Sizeof(uintptr(0))]uintptr
	var size uint32
	if err := windows.GetTokenInformation(tok, windows.TokenIntegrityLevel, (*byte)(unsafe.Pointer(&store[0])), maxTokenLabel, &size); err != nil {
		return 0, fmt.Errorf("bütünlük düzeyi okunamadı: %w", err)
	}
	label := (*windows.Tokenmandatorylabel)(unsafe.Pointer(&store[0]))
	sid := label.Label.Sid
	if sid == nil || !sid.IsValid() || sid.SubAuthorityCount() == 0 {
		return 0, errors.New("bütünlük düzeyi okunamadı")
	}
	return sid.SubAuthority(uint32(sid.SubAuthorityCount()) - 1), nil
}
