//go:build windows

package peercred

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ProcessImagePath returns the program file of a process.
func ProcessImagePath(pid int) (string, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return "", fmt.Errorf("open process %d: %w", pid, err)
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		return "", fmt.Errorf("image of process %d: %w", pid, err)
	}
	return windows.UTF16ToString(buf[:n]), nil
}

// parentProcess returns the parent process id, checking that the parent
// started before the child (process ids are reused).
func parentProcess(pid int) (int, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(snap)
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	if err := windows.Process32First(snap, &e); err != nil {
		return 0, err
	}
	parent := -1
	for {
		if int(e.ProcessID) == pid {
			parent = int(e.ParentProcessID)
			break
		}
		if err := windows.Process32Next(snap, &e); err != nil {
			break
		}
	}
	if parent <= 0 {
		return 0, nil
	}
	childStart, err1 := startTime(pid)
	parentStart, err2 := startTime(parent)
	if err1 != nil || err2 != nil || parentStart > childStart {
		return 0, nil
	}
	return parent, nil
}

func startTime(pid int) (int64, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(h)
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &created, &exited, &kernel, &user); err != nil {
		return 0, err
	}
	return created.Nanoseconds(), nil
}
