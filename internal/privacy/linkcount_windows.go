//go:build windows

package privacy

import (
	"io/fs"

	"golang.org/x/sys/windows"
)

// linkCount returns the number of hard links (NTFS) of the file at path;
// 1 when it cannot be read, so the caller falls back to overwriting only
// what it was given.
func linkCount(path string, _ fs.FileInfo) uint64 {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 1
	}
	h, err := windows.CreateFile(p, 0, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return 1
	}
	defer windows.CloseHandle(h)
	var fi windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &fi); err != nil {
		return 1
	}
	return uint64(fi.NumberOfLinks)
}
