//go:build windows

package winapp

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The copy that becomes the LocalSystem service must be the program the
// administrator's consent started, not whatever sits at its path now: the
// source folder (Downloads) is writable by lower-trust processes, and a
// running image can be renamed and replaced. Hence a single handle:
// opened refusing other writers and renames, shown to be the image of this
// very process, and used for every hash and for the copy.

var procGetMappedFileNameW = windows.NewLazySystemDLL("kernel32.dll").NewProc("K32GetMappedFileNameW")

// getModuleHandleExUnchangedRefcount is GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT.
const getModuleHandleExUnchangedRefcount = 2

// errSourceNotRunningImage: the file at the source path is not this process's image.
var errSourceNotRunningImage = errors.New("kaynak program, onaylanıp çalıştırılan programla aynı dosya değil; dosya değiştirilmiş olabilir, kurulum durduruldu")

// openLockedSource opens path for reading; while the handle is open nobody
// can write, rename or delete the file.
func openLockedSource(path string) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, fmt.Errorf("kaynak program yolu geçersiz: %w", err)
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, fmt.Errorf("kaynak program açılamadı: %w", err)
	}
	return os.NewFile(uintptr(h), path), nil
}

type fileIdentity struct {
	volume, high, low uint32
}

func identityOf(h windows.Handle) (fileIdentity, error) {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return fileIdentity{}, err
	}
	return fileIdentity{info.VolumeSerialNumber, info.FileIndexHigh, info.FileIndexLow}, nil
}

// runningImageIdentity names the file mapped as this process's image. The
// mapping follows the file through a rename, unlike os.Executable, which
// repeats the path the process was started with.
func runningImageIdentity() (fileIdentity, error) {
	var module windows.Handle
	if err := windows.GetModuleHandleEx(getModuleHandleExUnchangedRefcount, nil, &module); err != nil {
		return fileIdentity{}, err
	}
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, _, callErr := procGetMappedFileNameW.Call(uintptr(windows.CurrentProcess()), uintptr(module), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if n == 0 {
		return fileIdentity{}, callErr
	}
	p, err := windows.UTF16PtrFromString(`\\?\GLOBALROOT` + windows.UTF16ToString(buf[:n]))
	if err != nil {
		return fileIdentity{}, err
	}
	h, err := windows.CreateFile(p, windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return fileIdentity{}, err
	}
	defer windows.CloseHandle(h)
	return identityOf(h)
}

// checkIsRunningImage reports whether f is the file this process runs from.
// It fails closed: when that cannot be shown nothing is installed.
func checkIsRunningImage(f *os.File) error {
	want, err := runningImageIdentity()
	if err != nil {
		return fmt.Errorf("çalışan programın kimliği okunamadı: %w", err)
	}
	got, err := identityOf(windows.Handle(f.Fd()))
	if err != nil {
		return fmt.Errorf("kaynak programın kimliği okunamadı: %w", err)
	}
	if got != want {
		return errSourceNotRunningImage
	}
	return nil
}

// hashHandle returns the SHA-256 of f from its start.
func hashHandle(f *os.File) ([sha256.Size]byte, error) {
	var sum [sha256.Size]byte
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return sum, fmt.Errorf("kaynak program okunamadı: %w", err)
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return sum, fmt.Errorf("kaynak program okunamadı: %w", err)
	}
	copy(sum[:], h.Sum(nil))
	return sum, nil
}
