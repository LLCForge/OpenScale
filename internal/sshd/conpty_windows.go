//go:build windows

package sshd

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// conPTYAvailable reports whether the pseudo console API (Windows 10 1809
// and later) exists; older systems fall back to sessions without a PTY.
func conPTYAvailable() bool {
	return windows.NewLazySystemDLL("kernel32.dll").NewProc("CreatePseudoConsole").Find() == nil
}

type conPTY struct {
	in  *os.File // writes go to the console input
	out *os.File // console output

	mu     sync.Mutex
	hpc    windows.Handle
	closed bool
}

func (t *conPTY) Read(p []byte) (int, error)  { return t.out.Read(p) }
func (t *conPTY) Write(p []byte) (int, error) { return t.in.Write(p) }

// ProcessExited closes the pseudo console. Its host flushes the remaining
// output and then closes the output pipe, which ends the reader. The call
// can block until the output is drained, so it runs in the background.
func (t *conPTY) ProcessExited() {
	go t.closeConsole()
}

func (t *conPTY) closeConsole() {
	t.mu.Lock()
	h := t.hpc
	t.hpc = 0
	t.mu.Unlock()
	if h != 0 {
		windows.ClosePseudoConsole(h)
	}
}

func (t *conPTY) Close() error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	t.closed = true
	t.mu.Unlock()
	// Closing the output side first unblocks a ClosePseudoConsole waiting
	// for the output to drain.
	_ = t.out.Close()
	t.closeConsole()
	return t.in.Close()
}

func (t *conPTY) resize(cols, rows uint32) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.hpc != 0 {
		_ = windows.ResizePseudoConsole(t.hpc, windows.Coord{X: int16(cols), Y: int16(rows)})
	}
}

type conPTYProcess struct {
	proc windows.Handle
	job  *jobHandle
	term *conPTY

	waitOnce sync.Once
	code     int
}

func (p *conPTYProcess) wait() int {
	p.waitOnce.Do(func() {
		p.code = exitCodeFail
		if _, err := windows.WaitForSingleObject(p.proc, windows.INFINITE); err == nil {
			var c uint32
			if windows.GetExitCodeProcess(p.proc, &c) == nil {
				p.code = int(c)
			}
		}
		_ = windows.CloseHandle(p.proc)
		p.job.close()
	})
	return p.code
}

func (p *conPTYProcess) kill() { p.job.terminate() }

func (p *conPTYProcess) resize(cols, rows uint32) { p.term.resize(cols, rows) }

// startPTY runs req attached to a Windows pseudo console. The process is
// created suspended and placed in a kill-on-close job before it runs, so
// every descendant ends with the session.
func startPTY(req procRequest, params ptyParams) (_ process, _ ptyTerminal, retErr error) {
	if !conPTYAvailable() {
		return nil, nil, errNoPTY
	}
	var inR, inW, outR, outW windows.Handle
	if err := windows.CreatePipe(&inR, &inW, nil, 0); err != nil {
		return nil, nil, fmt.Errorf("giriş borusu oluşturulamadı: %w", err)
	}
	if err := windows.CreatePipe(&outR, &outW, nil, 0); err != nil {
		_ = windows.CloseHandle(inR)
		_ = windows.CloseHandle(inW)
		return nil, nil, fmt.Errorf("çıkış borusu oluşturulamadı: %w", err)
	}
	term := &conPTY{in: os.NewFile(uintptr(inW), "conpty-in"), out: os.NewFile(uintptr(outR), "conpty-out")}
	var hpc windows.Handle
	err := windows.CreatePseudoConsole(windows.Coord{X: int16(params.cols), Y: int16(params.rows)}, inR, outW, 0, &hpc)
	// The console host duplicated its ends of the pipes.
	_ = windows.CloseHandle(inR)
	_ = windows.CloseHandle(outW)
	if err != nil {
		_ = term.in.Close()
		_ = term.out.Close()
		return nil, nil, fmt.Errorf("sözde konsol oluşturulamadı: %w", err)
	}
	term.hpc = hpc
	defer func() {
		if retErr != nil {
			_ = term.Close()
		}
	}()

	attrs, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		return nil, nil, err
	}
	defer attrs.Delete()
	// The attribute value is the HPCON itself, not a pointer to it.
	if err := attrs.Update(windows.PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, *(*unsafe.Pointer)(unsafe.Pointer(&hpc)), unsafe.Sizeof(hpc)); err != nil {
		return nil, nil, fmt.Errorf("süreç özniteliği ayarlanamadı: %w", err)
	}

	var si windows.StartupInfoEx
	si.Cb = uint32(unsafe.Sizeof(si))
	// Null standard handles keep the child from inheriting the server's.
	si.Flags = windows.STARTF_USESTDHANDLES
	si.ProcThreadAttributeList = attrs.List()

	reqTerm := req
	reqTerm.env = append(append([]string(nil), req.env...), "TERM="+sanitizeTerm(params.term))
	env, err := envBlock(sessionEnv(reqTerm))
	if err != nil {
		return nil, nil, err
	}
	cmdLine, err := windows.UTF16PtrFromString(commandLine(req))
	if err != nil {
		return nil, nil, err
	}
	appName, err := windows.UTF16PtrFromString(shellPath())
	if err != nil {
		return nil, nil, err
	}
	dir, err := windows.UTF16PtrFromString(sessionDir(req))
	if err != nil {
		return nil, nil, err
	}
	job, err := newKillJob()
	if err != nil {
		return nil, nil, fmt.Errorf("iş nesnesi oluşturulamadı: %w", err)
	}
	jh := &jobHandle{h: job}
	var pi windows.ProcessInformation
	flags := uint32(windows.EXTENDED_STARTUPINFO_PRESENT | windows.CREATE_UNICODE_ENVIRONMENT | windows.CREATE_SUSPENDED)
	if err := windows.CreateProcess(appName, cmdLine, nil, nil, false, flags, &env[0], dir, &si.StartupInfo, &pi); err != nil {
		jh.close()
		return nil, nil, fmt.Errorf("kabuk başlatılamadı: %w", err)
	}
	if err := windows.AssignProcessToJobObject(job, pi.Process); err != nil {
		_ = windows.TerminateProcess(pi.Process, 1)
		_ = windows.CloseHandle(pi.Thread)
		_ = windows.CloseHandle(pi.Process)
		jh.close()
		return nil, nil, fmt.Errorf("süreç iş nesnesine eklenemedi: %w", err)
	}
	if _, err := windows.ResumeThread(pi.Thread); err != nil {
		jh.terminate()
		_ = windows.CloseHandle(pi.Thread)
		_ = windows.CloseHandle(pi.Process)
		jh.close()
		return nil, nil, errors.New("kabuk sürdürülemedi")
	}
	_ = windows.CloseHandle(pi.Thread)
	return &conPTYProcess{proc: pi.Process, job: jh, term: term}, term, nil
}
