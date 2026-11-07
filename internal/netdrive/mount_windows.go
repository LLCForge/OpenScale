//go:build windows

package netdrive

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modMPR                    = windows.NewLazySystemDLL("mpr.dll")
	procWNetAddConnection2W   = modMPR.NewProc("WNetAddConnection2W")
	procWNetCancelConnection2 = modMPR.NewProc("WNetCancelConnection2W")
)

// netResource is NETRESOURCEW.
type netResource struct {
	scope       uint32
	typ         uint32
	displayType uint32
	usage       uint32
	localName   *uint16
	remoteName  *uint16
	comment     *uint16
	provider    *uint16
}

const (
	resourceTypeDisk     = 1
	connectUpdateProfile = 0x1
	connectTemporary     = 0x4
	errorAlreadyAssigned = 85
	errorNotConnected    = 2250
)

// mapWindows calls WNetAddConnection2W without a password, so Windows
// uses the Credential Manager entry for the server or the signed-in
// user's credentials; OpenScale never sees a password.
func mapWindows(m Mount, host netip.Addr) error {
	letter := strings.ToUpper(m.Letter)
	if drives, err := windows.GetLogicalDrives(); err == nil && drives&(1<<(letter[0]-'A')) != 0 {
		return fmt.Errorf("%s sürücü harfi kullanımda", letter)
	}
	local, err := syscall.UTF16PtrFromString(letter)
	if err != nil {
		return err
	}
	unc, err := UNC(host, m.Share)
	if err != nil {
		return err
	}
	remote, err := syscall.UTF16PtrFromString(unc)
	if err != nil {
		return err
	}
	var user *uint16
	if m.Username != "" {
		if user, err = syscall.UTF16PtrFromString(m.Username); err != nil {
			return err
		}
	}
	nr := netResource{typ: resourceTypeDisk, localName: local, remoteName: remote}
	flags := uintptr(connectTemporary)
	if m.Persistent {
		flags = connectUpdateProfile
	}
	if err := procWNetAddConnection2W.Find(); err != nil {
		return ErrUnsupported
	}
	r, _, _ := procWNetAddConnection2W.Call(uintptr(unsafe.Pointer(&nr)), 0, uintptr(unsafe.Pointer(user)), flags)
	switch r {
	case 0:
		return nil
	case errorAlreadyAssigned:
		return fmt.Errorf("%s sürücü harfi kullanımda", letter)
	default:
		return fmt.Errorf("ağ sürücüsü bağlanamadı: %w", syscall.Errno(r))
	}
}

func unmapWindows(m Mount) error {
	if err := procWNetCancelConnection2.Find(); err != nil {
		return ErrUnsupported
	}
	name, err := syscall.UTF16PtrFromString(strings.ToUpper(m.Letter))
	if err != nil {
		return err
	}
	flags := uintptr(0)
	if m.Persistent {
		flags = connectUpdateProfile
	}
	r, _, _ := procWNetCancelConnection2.Call(uintptr(unsafe.Pointer(name)), flags, 0)
	switch r {
	case 0:
		return nil
	case errorNotConnected:
		return errors.New("bu sürücü harfi bağlı değil")
	default:
		return fmt.Errorf("ağ sürücüsü kaldırılamadı: %w", syscall.Errno(r))
	}
}
