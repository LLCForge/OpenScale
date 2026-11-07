//go:build windows

package securefile

import (
	"fmt"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// ErrForeignDirectory: a privileged process was about to write private
// material into a directory that belongs to another account.
var ErrForeignDirectory = fmt.Errorf("directory belongs to another user")

// dirOwnerPolicy returns the owners a directory may have, nil when this
// process needs no check. Replaced in tests.
var dirOwnerPolicy = privilegedOwnerPolicy

// privilegedOwnerPolicy applies to SYSTEM and elevated processes only. New
// files take the ACL of their directory, and a directory's owner can always
// change that ACL, so such a directory would expose what SYSTEM writes
// there. An unprivileged process gains nothing from the check.
func privilegedOwnerPolicy() func(*windows.SID) bool {
	tok := windows.GetCurrentProcessToken()
	user, err := tok.GetTokenUser()
	if err != nil {
		return nil
	}
	if !tok.IsElevated() && !user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		return nil
	}
	self := user.User.Sid
	return func(s *windows.SID) bool {
		return s.IsWellKnown(windows.WinLocalSystemSid) || s.IsWellKnown(windows.WinBuiltinAdministratorsSid) || s.Equals(self)
	}
}

// checkDirOwner refuses a directory owned by an untrusted account. When
// the system reports no owner (a file system without ACLs) there is nothing
// to decide.
func checkDirOwner(dir string) error {
	trusted := dirOwnerPolicy()
	if trusted == nil {
		return nil
	}
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return nil
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return nil
	}
	if !trusted(owner) {
		return fmt.Errorf("%s: %w", filepath.Base(dir), ErrForeignDirectory)
	}
	return nil
}
