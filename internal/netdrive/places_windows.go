//go:build windows

package netdrive

import (
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modShell32         = windows.NewLazySystemDLL("shell32.dll")
	procSHChangeNotify = modShell32.NewProc("SHChangeNotify")
)

const (
	shcneUpdateDir = 0x00001000
	shcnfPathW     = 0x0005
	// placeRecordName is the record of the locations OpenScale made,
	// under the user's local application data.
	placeRecordName = "netplaces.json"
)

// setPlaceAttrs gives the folder the read-only attribute and desktop.ini
// the hidden and system attributes: Explorer reads a folder's desktop.ini
// only then, which is how it recognises a network location.
func setPlaceAttrs(dir, ini string) error {
	d, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	i, err := windows.UTF16PtrFromString(ini)
	if err != nil {
		return err
	}
	if err := windows.SetFileAttributes(i, windows.FILE_ATTRIBUTE_HIDDEN|windows.FILE_ATTRIBUTE_SYSTEM); err != nil {
		return err
	}
	return windows.SetFileAttributes(d, windows.FILE_ATTRIBUTE_READONLY)
}

// clearPlaceAttrs removes the attributes again so the files and the
// folder can be deleted.
func clearPlaceAttrs(dir string) {
	for _, p := range []string{filepath.Join(dir, placeIni), filepath.Join(dir, placeLink), dir} {
		if u, err := windows.UTF16PtrFromString(p); err == nil {
			_ = windows.SetFileAttributes(u, windows.FILE_ATTRIBUTE_NORMAL)
		}
	}
}

// shellChanged asks open Explorer windows to read the folder again.
func shellChanged(dir string) {
	if procSHChangeNotify.Find() != nil {
		return
	}
	if u, err := windows.UTF16PtrFromString(dir); err == nil {
		_, _, _ = procSHChangeNotify.Call(shcneUpdateDir, shcnfPathW, uintptr(unsafe.Pointer(u)), 0)
	}
}

// DefaultPlaces returns the signed-in user's network locations: the
// Network Shortcuts folder (FOLDERID_NetHood) and the record under
// %LOCALAPPDATA%\OpenScale.
func DefaultPlaces(writeLink func(path, target, description string) error) (*Places, error) {
	nethood, err := windows.KnownFolderPath(windows.FOLDERID_NetHood, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return nil, err
	}
	local, err := windows.KnownFolderPath(windows.FOLDERID_LocalAppData, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return nil, err
	}
	return &Places{
		Dir:        nethood,
		RecordPath: filepath.Join(local, "OpenScale", placeRecordName),
		WriteLink:  writeLink,
	}, nil
}
