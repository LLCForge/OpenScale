//go:build windows

package wintunembed

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows"
)

// Driver queries for the start-up repair after an operating system update
// (#498) and for the portable mode, which removes the driver it installed
// when it ends (#497, ADR-0163). Both go through the verified DLL that
// Ensure pinned in the process, never through a search by name.

// ErrDriverNotLoaded means no Wintun driver is running now.
var ErrDriverNotLoaded = errors.New("Wintun sürücüsü yüklü değil")

func wintunProc(name string) (uintptr, error) {
	if err := Ensure(); err != nil {
		return 0, err
	}
	path, err := dllPath()
	if err != nil {
		return 0, err
	}
	// Ensure loaded this exact file; this returns the same module.
	h, err := windows.LoadLibraryEx(path, 0, loadLibrarySearchDLLLoadDir|loadLibrarySearchSystem32)
	if err != nil {
		return 0, fmt.Errorf("load %s: %w", dllName, err)
	}
	p, err := windows.GetProcAddress(h, name)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}
	return p, nil
}

// DriverVersion returns the running Wintun driver version as "major.minor".
func DriverVersion() (string, error) {
	p, err := wintunProc("WintunGetRunningDriverVersion")
	if err != nil {
		return "", err
	}
	r, _, e := syscallN(p)
	if r == 0 {
		if errors.Is(e, windows.ERROR_FILE_NOT_FOUND) {
			return "", ErrDriverNotLoaded
		}
		return "", fmt.Errorf("WintunGetRunningDriverVersion: %w", e)
	}
	return fmt.Sprintf("%d.%d", (r>>16)&0xffff, r&0xffff), nil
}

// DeleteDriver removes the Wintun driver when no Wintun adapter is in use;
// Wintun refuses while one is.
func DeleteDriver() error {
	p, err := wintunProc("WintunDeleteDriver")
	if err != nil {
		return err
	}
	r, _, e := syscallN(p)
	if r == 0 {
		return fmt.Errorf("WintunDeleteDriver: %w", e)
	}
	return nil
}
