//go:build windows

package sshd

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// inheritedEnv lists the server environment variables a Windows session
// needs; everything else (including secrets) is withheld.
var inheritedEnv = []string{
	"SystemRoot", "SystemDrive", "windir", "ComSpec", "PATH", "PATHEXT",
	"TEMP", "TMP", "USERPROFILE", "USERNAME", "USERDOMAIN", "HOMEDRIVE",
	"HOMEPATH", "APPDATA", "LOCALAPPDATA", "ProgramData", "ProgramFiles",
	"ProgramFiles(x86)", "ProgramW6432", "CommonProgramFiles",
	"NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE", "OS", "PSModulePath",
	"ALLUSERSPROFILE", "PUBLIC", "COMPUTERNAME",
}

func systemRoot() string {
	if r := os.Getenv("SystemRoot"); r != "" && filepath.IsAbs(r) {
		return r
	}
	return `C:\Windows`
}

// shellPath is an absolute path so PATH or the working directory can never
// substitute a different cmd.exe.
func shellPath() string { return filepath.Join(systemRoot(), "System32", "cmd.exe") }

// commandLine builds the cmd.exe command line. /d skips AutoRun registry
// commands; /s /c "..." runs the client's command verbatim.
func commandLine(req procRequest) string {
	line := windows.EscapeArg(shellPath()) + " /d"
	if req.command != "" {
		line += ` /s /c "` + req.command + `"`
	}
	return line
}

func sessionEnv(req procRequest) []string {
	env := make([]string, 0, len(inheritedEnv)+len(req.env))
	for _, k := range inheritedEnv {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	return append(env, req.env...)
}

func sessionDir(req procRequest) string {
	if fi, err := os.Stat(req.acct.home); req.acct.home != "" && err == nil && fi.IsDir() {
		return req.acct.home
	}
	return systemRoot()
}

func buildCommand(req procRequest, _ bool) (*exec.Cmd, error) {
	sh := shellPath()
	cmd := &exec.Cmd{Path: sh, Args: []string{sh}}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CmdLine:       commandLine(req),
		HideWindow:    true,
		CreationFlags: windows.CREATE_NO_WINDOW,
	}
	cmd.Env = sessionEnv(req)
	cmd.Dir = sessionDir(req)
	return cmd, nil
}

// newKillJob creates a job object that terminates every process in it
// when the last handle closes, so a session cannot leave processes behind.
func newKillJob() (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, err
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
		},
	}
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		_ = windows.CloseHandle(job)
		return 0, err
	}
	return job, nil
}

// jobHandle guards a job object handle against use after close.
type jobHandle struct {
	mu sync.Mutex
	h  windows.Handle
}

func (j *jobHandle) terminate() {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.h != 0 {
		_ = windows.TerminateJobObject(j.h, 1)
	}
}

// close releases the handle; with KILL_ON_JOB_CLOSE this also ends any
// process the session left running.
func (j *jobHandle) close() {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.h != 0 {
		_ = windows.CloseHandle(j.h)
		j.h = 0
	}
}

// afterStart places the started process in a kill-on-close job. Processes
// it spawned in the short window before assignment are not covered.
func afterStart(cmd *exec.Cmd) (kill func(), onExit func()) {
	proc := cmd.Process
	job, err := newKillJob()
	if err != nil {
		return func() { _ = proc.Kill() }, nil
	}
	h, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(proc.Pid))
	if err == nil {
		err = windows.AssignProcessToJobObject(job, h)
		_ = windows.CloseHandle(h)
	}
	if err != nil {
		_ = windows.CloseHandle(job)
		return func() { _ = proc.Kill() }, nil
	}
	j := &jobHandle{h: job}
	return func() {
		j.terminate()
		_ = proc.Kill()
		j.close()
	}, j.close
}

// envBlock encodes env as a CreateProcess environment block.
func envBlock(env []string) ([]uint16, error) {
	var b []uint16
	for _, kv := range env {
		if strings.ContainsRune(kv, 0) {
			return nil, syscall.EINVAL
		}
		u, err := windows.UTF16FromString(kv)
		if err != nil {
			return nil, err
		}
		b = append(b, u...)
	}
	if len(b) == 0 {
		b = append(b, 0)
	}
	return append(b, 0), nil
}
