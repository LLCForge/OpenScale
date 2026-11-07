//go:build windows

package winapp

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// aceTypeDenied is ACCESS_DENIED_ACE_TYPE: it takes rights away, so it
// never opens a sub-object up.
const aceTypeDenied = 1

// maxInspectedObjects bounds the read-only check at service start.
const maxInspectedObjects = 20000

// createProtectedDir creates dir with the security descriptor already in
// place: there is no moment at which it carries the ACL of its parent.
// created is false when dir exists; the caller then inspects it.
func createProtectedDir(dir, sddl string) (created bool, err error) {
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return false, fmt.Errorf("veri klasörü yolu geçersiz: %w", err)
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return false, fmt.Errorf("güvenlik tanımı oluşturulamadı: %w", err)
	}
	sa := windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(sa))
	switch err := windows.CreateDirectory(p, &sa); {
	case err == nil:
		return true, nil
	case errors.Is(err, windows.ERROR_ALREADY_EXISTS):
		return false, nil
	case errors.Is(err, windows.ERROR_INVALID_OWNER):
		// Only an administrator can name Administrators as the owner.
		return false, fmt.Errorf("veri klasörü oluşturulamadı: yönetici izni gerekiyor: %w", err)
	default:
		return false, wrapWinErr("veri klasörü oluşturulamadı", err)
	}
}

// trustedDataOwner: SYSTEM, Administrators, or the administrator running
// this install.
func trustedDataOwner(s *windows.SID) bool {
	if s == nil {
		return false
	}
	if s.IsWellKnown(windows.WinLocalSystemSid) || s.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		return true
	}
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	return err == nil && s.Equals(u.User.Sid)
}

func aceSID(ace *windows.ACCESS_ALLOWED_ACE) *windows.SID {
	return (*windows.SID)(unsafe.Pointer(&ace.SidStart))
}

// auditDataTree checks everything below root; run it after root's own DACL
// is locked, so that no ordinary user can add an object behind the walk.
//   - An object owned by someone untrusted, or a reparse point, stops the
//     install: its owner can reopen it at any time, and what it left there
//     (a key-protection.off, a key file) cannot be trusted. Changing the
//     owner would hide this, not repair it.
//   - A grant to an untrusted account is removed and the object goes back
//     to inheriting from its parent.
func auditDataTree(root string, trusted func(*windows.SID) bool) error {
	return filepath.WalkDir(root, func(path string, _ fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if errors.Is(walkErr, fs.ErrNotExist) {
				return nil // the running service removed a temporary file
			}
			return wrapWinErr("veri klasörü taranamadı", walkErr)
		}
		if path == root {
			return nil
		}
		err := auditDataObject(path, trusted)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	})
}

func auditDataObject(path string, trusted func(*windows.SID) bool) error {
	open, err := inspectDataObject(path, trusted)
	if err != nil || !open {
		return err
	}
	return inheritOnly(path)
}

// DataDirProblem reports, without changing anything, what the install's
// audit would object to in the service data folder: the folder or an object
// in it that is a reparse point, has a foreign owner or grants access to an
// untrusted account. What this process may not read is not judged.
func DataDirProblem(dir string) error {
	self, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil
	}
	trusted := func(s *windows.SID) bool {
		return s != nil && (s.IsWellKnown(windows.WinLocalSystemSid) || s.IsWellKnown(windows.WinBuiltinAdministratorsSid) || s.Equals(self.User.Sid))
	}
	seen := 0
	return filepath.WalkDir(dir, func(path string, _ fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return skipUnreadable(walkErr)
		}
		if seen++; seen > maxInspectedObjects {
			return fs.SkipAll
		}
		open, err := inspectDataObject(path, trusted)
		if err != nil {
			return skipUnreadable(err)
		}
		if open {
			return fmt.Errorf("veri klasöründe başka hesaplara açık nesne var: %s", path)
		}
		return nil
	})
}

// skipUnreadable keeps real findings; an object that vanished or cannot be
// read says nothing either way.
func skipUnreadable(err error) error {
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, windows.ERROR_ACCESS_DENIED) || errors.Is(err, os.ErrPermission) {
		return nil
	}
	return err
}

// inspectDataObject returns an error for what cannot be repaired and true
// for an object that grants access to an untrusted account.
func inspectDataObject(path string, trusted func(*windows.SID) bool) (bool, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false, fmt.Errorf("veri klasöründe geçersiz yol: %w", err)
	}
	attrs, err := windows.GetFileAttributes(p)
	if err != nil {
		return false, wrapDataErr(path, err)
	}
	if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return false, fmt.Errorf("veri klasöründe bağlantı noktası var; güvenlik için silip yeniden deneyin: %s", path)
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false, wrapDataErr(path, err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return false, fmt.Errorf("veri klasöründeki nesnenin sahibi okunamadı: %s", path)
	}
	if !trusted(owner) {
		return false, fmt.Errorf("veri klasöründeki bir nesne başka bir kullanıcıya ait; güvenlik için silip yeniden deneyin: %s", path)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return false, fmt.Errorf("veri klasöründeki nesnenin izinleri okunamadı: %s", path)
	}
	open, err := grantsUntrusted(dacl, trusted)
	if err != nil {
		return false, fmt.Errorf("veri klasöründeki nesnenin izinleri okunamadı: %s: %w", path, err)
	}
	return open, nil
}

// grantsUntrusted reports a grant to an untrusted account. A missing DACL
// means full access to everyone.
//
// SECURITY FIX: CWE-732 An "inherited" entry is judged like any other: the
// flag can be written by whoever holds WRITE_DAC and survives the root's
// propagation on a DACL that does not inherit. What really came from a parent
// is clean by now, as parents are repaired before their children.
func grantsUntrusted(dacl *windows.ACL, trusted func(*windows.SID) bool) (bool, error) {
	if dacl == nil {
		return true, nil
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return false, err
		}
		if ace.Header.AceType == aceTypeDenied {
			continue
		}
		if !trusted(aceSID(ace)) {
			return true, nil
		}
	}
	return false, nil
}

// inheritOnly drops the explicit entries of path. The DACL passed is empty
// but present: a nil one would grant everyone full access.
func inheritOnly(path string) error {
	sd, err := windows.SecurityDescriptorFromString("D:")
	if err != nil {
		return fmt.Errorf("güvenlik tanımı oluşturulamadı: %w", err)
	}
	empty, _, err := sd.DACL()
	if err != nil || empty == nil {
		return errors.New("güvenlik tanımı oluşturulamadı")
	}
	info := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.UNPROTECTED_DACL_SECURITY_INFORMATION)
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, info, nil, nil, empty, nil); err != nil {
		return wrapWinErr("veri klasöründeki nesnenin izinleri düzeltilemedi", err)
	}
	return nil
}

// wrapDataErr keeps "it vanished" recognizable for the walk.
func wrapDataErr(path string, err error) error {
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) || errors.Is(err, os.ErrNotExist) {
		return fs.ErrNotExist
	}
	return wrapWinErr("veri klasöründeki nesne okunamadı: "+path, err)
}
