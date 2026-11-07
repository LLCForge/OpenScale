//go:build windows

package winapp

import (
	"errors"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// WriteLink creates or replaces a shell link at path that opens target, a
// folder or a UNC path such as \\device.domain\share (the network
// locations of ADR-0226). Unlike writeShortcut it starts no program: the
// link only names the target, with description as its comment.
func WriteLink(path, target, description string) error {
	if path == "" || target == "" || strings.ContainsAny(target, "\x00\r\n\"") || strings.ContainsAny(description, "\x00") {
		return errors.New("kısayol bilgisi geçersiz")
	}
	return withShellLink(func(link, file *comObject) error {
		if err := link.callString(idxSLSetPath, target); err != nil {
			return err
		}
		if description != "" {
			if err := link.callString(idxSLSetDescription, description); err != nil {
				return err
			}
		}
		p, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return err
		}
		return file.call(idxPFSave, uintptr(unsafe.Pointer(p)), 1)
	})
}
