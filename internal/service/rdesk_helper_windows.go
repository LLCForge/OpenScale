//go:build windows

package service

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/openscale/openscale/internal/peercred"
)

// noConsoleSession is what WTSGetActiveConsoleSessionId returns while no
// session is attached to the console.
const noConsoleSession = 0xFFFFFFFF

// winLauncher starts the helper with the console user's token. It is never
// run by tests: it needs a real user session.
type winLauncher struct{}

func (winLauncher) ConsoleSession() uint32 { return windows.WTSGetActiveConsoleSessionId() }

func (winLauncher) Launch(bootstrap []byte) (helperProc, error) {
	session := windows.WTSGetActiveConsoleSessionId()
	if session == noConsoleSession {
		return nil, errNoConsoleUser
	}
	var user windows.Token
	if err := windows.WTSQueryUserToken(session, &user); err != nil {
		return nil, errNoConsoleUser
	}
	defer user.Close()
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	exe, err = filepath.Abs(exe)
	if err != nil {
		return nil, err
	}
	var envBlock *uint16
	if err := windows.CreateEnvironmentBlock(&envBlock, user, false); err != nil {
		return nil, fmt.Errorf("kullanıcı ortamı alınamadı: %w", err)
	}
	defer windows.DestroyEnvironmentBlock(envBlock)

	// The read end of the pipe is the helper's stdin and the only handle
	// it inherits; the write end stays here.
	var rd, wr windows.Handle
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), InheritHandle: 1}
	if err := windows.CreatePipe(&rd, &wr, &sa, 0); err != nil {
		return nil, err
	}
	closeRd := func() { _ = windows.CloseHandle(rd) }
	if err := windows.SetHandleInformation(wr, windows.HANDLE_FLAG_INHERIT, 0); err != nil {
		closeRd()
		_ = windows.CloseHandle(wr)
		return nil, err
	}
	attrs, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		closeRd()
		_ = windows.CloseHandle(wr)
		return nil, err
	}
	defer attrs.Delete()
	handles := []windows.Handle{rd}
	if err := attrs.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&handles[0]), unsafe.Sizeof(handles[0])); err != nil {
		closeRd()
		_ = windows.CloseHandle(wr)
		return nil, err
	}
	desktop, _ := windows.UTF16PtrFromString(`winsta0\default`)
	si := windows.StartupInfoEx{
		StartupInfo: windows.StartupInfo{
			Cb:       uint32(unsafe.Sizeof(windows.StartupInfoEx{})),
			Desktop:  desktop,
			Flags:    windows.STARTF_USESTDHANDLES,
			StdInput: rd,
		},
		ProcThreadAttributeList: attrs.List(),
	}
	app, _ := windows.UTF16PtrFromString(exe)
	cmd, _ := windows.UTF16PtrFromString(windows.EscapeArg(exe) + " rdesk-helper")
	dir, _ := windows.UTF16PtrFromString(filepath.Dir(exe))
	var pi windows.ProcessInformation
	flags := uint32(windows.CREATE_UNICODE_ENVIRONMENT | windows.EXTENDED_STARTUPINFO_PRESENT | windows.CREATE_NO_WINDOW)
	err = windows.CreateProcessAsUser(user, app, cmd, nil, nil, true, flags, envBlock, dir, &si.StartupInfo, &pi)
	closeRd()
	if err != nil {
		_ = windows.CloseHandle(wr)
		return nil, fmt.Errorf("uzak masaüstü yardımcısı başlatılamadı: %w", err)
	}
	_ = windows.CloseHandle(pi.Thread)
	p := &winProc{h: pi.Process, pid: pi.ProcessId, stdin: wr, done: make(chan struct{})}
	var n uint32
	if err := windows.WriteFile(wr, bootstrap, &n, nil); err != nil || int(n) != len(bootstrap) {
		p.Stop(0)
		return nil, errors.New("yardımcıya başlangıç bilgisi gönderilemedi")
	}
	go p.wait()
	return p, nil
}

type winProc struct {
	h     windows.Handle
	pid   uint32
	once  sync.Once
	mu    sync.Mutex
	stdin windows.Handle
	done  chan struct{}
}

func (p *winProc) PID() uint32 { return p.pid }

func (p *winProc) Done() <-chan struct{} { return p.done }

func (p *winProc) wait() {
	_, _ = windows.WaitForSingleObject(p.h, windows.INFINITE)
	close(p.done)
}

func (p *winProc) closeStdin() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.stdin != 0 {
		_ = windows.CloseHandle(p.stdin)
		p.stdin = 0
	}
}

// Stop asks the helper to exit by closing its stdin, then ends it.
func (p *winProc) Stop(grace time.Duration) {
	p.once.Do(func() {
		p.closeStdin()
		select {
		case <-p.done:
		case <-time.After(grace):
			_ = windows.TerminateProcess(p.h, 1)
			select {
			case <-p.done:
			case <-time.After(2 * time.Second):
			}
		}
		_ = windows.CloseHandle(p.h)
	})
}

// lookupLoopbackPID returns the process behind a loopback connection.
func lookupLoopbackPID(remote, local string) (uint32, error) {
	c, err := netip.ParseAddrPort(remote)
	if err != nil {
		return 0, err
	}
	s, err := netip.ParseAddrPort(local)
	if err != nil {
		return 0, err
	}
	if !c.Addr().Unmap().IsLoopback() || !s.Addr().Unmap().IsLoopback() {
		return 0, errors.New("yalnızca yerel bağlantılar")
	}
	id, err := peercred.Lookup(netip.AddrPortFrom(c.Addr().Unmap(), c.Port()), netip.AddrPortFrom(s.Addr().Unmap(), s.Port()))
	if err != nil {
		return 0, err
	}
	if id.PID <= 0 {
		return 0, errors.New("süreç bulunamadı")
	}
	return uint32(id.PID), nil
}

// restartSystem schedules a restart in 10 seconds (LocalSystem holds the
// shutdown privilege; it is enabled for this call only).
func restartSystem(_ context.Context, peer string) error {
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &tok); err != nil {
		return err
	}
	defer tok.Close()
	var luid windows.LUID
	name, _ := windows.UTF16PtrFromString("SeShutdownPrivilege")
	if err := windows.LookupPrivilegeValue(nil, name, &luid); err != nil {
		return err
	}
	tp := windows.Tokenprivileges{PrivilegeCount: 1}
	tp.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}
	if err := windows.AdjustTokenPrivileges(tok, false, &tp, 0, nil, nil); err != nil {
		return err
	}
	msg, _ := windows.UTF16PtrFromString("OpenScale: " + peer + " cihazından uzak masaüstü oturumu bu bilgisayarı yeniden başlatıyor.")
	reason := uint32(windows.SHTDN_REASON_MAJOR_APPLICATION | windows.SHTDN_REASON_MINOR_MAINTENANCE | windows.SHTDN_REASON_FLAG_PLANNED)
	return windows.InitiateSystemShutdownEx(nil, msg, 10, true, true, reason)
}

// newRemoteDesktopHost returns the Windows service's helper host.
func (r *Runtime) newRemoteDesktopHost() RemoteDesktopHost {
	h := r.helperHost()
	return h
}

func (r *Runtime) helperHost() *helperHost {
	r.w2.once.Do(func() {
		r.w2.helper = &helperHost{
			launcher:  winLauncher{},
			apiAddr:   func() string { return fmt.Sprintf("127.0.0.1:%d", r.cfg.PanelPort) },
			lookupPID: lookupLoopbackPID,
			events: func(source string, ev rdeskEvent) {
				if a, err := r.appsOrErr(); err == nil {
					a.RDeskEvent(source, ev)
				}
			},
			endSource: func(source, reason string) {
				if a, err := r.appsOrErr(); err == nil {
					a.RDeskEndSource(source, reason)
				}
			},
			restart: restartSystem,
		}
	})
	return r.w2.helper
}
