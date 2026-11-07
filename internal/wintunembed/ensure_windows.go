//go:build windows

package wintunembed

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"

	"github.com/openscale/openscale/internal/securefile"
)

const (
	dllName    = "wintun.dll"
	maxDLLSize = 4 << 20

	loadLibrarySearchDLLLoadDir = 0x00000100
	loadLibrarySearchSystem32   = 0x00000800
)

// Ensure installs (if needed), verifies and loads the embedded wintun.dll.
// It must run before the TUN device is created.
func Ensure() error {
	if len(embedded) == 0 {
		return ErrUnsupported
	}
	want := sha256.Sum256(embedded)
	path, err := dllPath()
	if err != nil {
		return err
	}
	for attempt := 0; attempt < 2; attempt++ {
		loaded, err := loadIfVerified(path, want)
		if err != nil {
			return err
		}
		if loaded {
			return nil
		}
		if err := securefile.Replace(path, embedded); err != nil {
			return fmt.Errorf("write %s next to openscale.exe: %w", dllName, err)
		}
	}
	return fmt.Errorf("%s could not be verified after rewriting it", dllName)
}

func dllPath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locate executable: %w", err)
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return "", fmt.Errorf("resolve executable path: %w", err)
	}
	return filepath.Join(filepath.Dir(exe), dllName), nil
}

// loadIfVerified opens the DLL denying write and delete sharing, checks its
// hash and, if it matches, loads it by full path while the lock is held.
// It returns false (and no error) when the file is missing or differs.
func loadIfVerified(path string, want [sha256.Size]byte) (bool, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil,
		windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			return false, nil
		}
		return false, fmt.Errorf("open %s: %w", dllName, err)
	}
	f := os.NewFile(uintptr(h), path)
	defer f.Close()

	hasher := sha256.New()
	n, err := io.Copy(hasher, io.LimitReader(f, maxDLLSize+1))
	if err != nil {
		return false, fmt.Errorf("read %s: %w", dllName, err)
	}
	if n > maxDLLSize || subtle.ConstantTimeCompare(hasher.Sum(nil), want[:]) != 1 {
		return false, nil
	}
	// The module stays loaded for the life of the process on purpose.
	if _, err := windows.LoadLibraryEx(path, 0, loadLibrarySearchDLLLoadDir|loadLibrarySearchSystem32); err != nil {
		return false, fmt.Errorf("load %s: %w", dllName, err)
	}
	return true, nil
}
