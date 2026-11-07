//go:build windows

package privacy

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// processNames lists running executables with CreateToolhelp32Snapshot.
// It reads names only; no process is opened.
func processNames() ([]string, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	if err := windows.Process32First(snap, &e); err != nil {
		return nil, err
	}
	var out []string
	for i := 0; i < maxProcesses; i++ {
		out = append(out, windows.UTF16ToString(e.ExeFile[:]))
		if err := windows.Process32Next(snap, &e); err != nil {
			break
		}
	}
	return out, nil
}
