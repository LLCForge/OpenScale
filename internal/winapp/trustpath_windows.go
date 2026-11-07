//go:build windows

package winapp

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Pre-elevation trust check (F-124, #296). A program that runs as SYSTEM
// or elevated must not live where a standard user can change it: the file
// itself, its folder (where a planted DLL or a replaced file would be
// loaded) and every folder above it (which could be renamed away).

// trustedInstallerSID owns most of %ProgramFiles% and %SystemRoot%.
const trustedInstallerSID = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

// Access rights that let a principal change what runs from a path.
const (
	fileWriteData       = 0x0002 // FILE_WRITE_DATA / FILE_ADD_FILE
	fileAppendData      = 0x0004 // FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY
	fileWriteEA         = 0x0010
	fileDeleteChild     = 0x0040
	accessDelete        = 0x00010000
	accessWriteDAC      = 0x00040000
	accessWriteOwner    = 0x00080000
	accessGenericAll    = 0x10000000
	accessGenericWrite  = 0x40000000
	accessMaximumAllow  = 0x02000000
	ownershipChangeMask = accessWriteDAC | accessWriteOwner | accessGenericAll | accessMaximumAllow

	// fileMask: changing the program file.
	fileMask = fileWriteData | fileAppendData | fileWriteEA | accessDelete | accessGenericWrite | ownershipChangeMask
	// dirMask: the program's own folder; adding a file plants a DLL.
	dirMask = fileWriteData | fileAppendData | fileDeleteChild | accessDelete | accessGenericWrite | ownershipChangeMask
	// ancestorMask: folders above it; only replacing or renaming children
	// matters (C:\ lets users create folders, which is harmless here).
	ancestorMask = fileDeleteChild | accessDelete | ownershipChangeMask
)

// CheckTrustedPath reports an error when a principal other than SYSTEM,
// Administrators or TrustedInstaller may change the program file or add
// files to its folder. Only allow entries count; deny entries can only
// narrow access.
func CheckTrustedPath(path string) error {
	abs, err := cleanProgramPath(path)
	if err != nil {
		return err
	}
	if err := checkTrustedObject(abs, fileMask); err != nil {
		return err
	}
	return checkTrustedObject(filepath.Dir(abs), dirMask)
}

// CheckTrustedAncestors checks the folders above the program's folder for
// rights to rename or replace what is below them. Some computers grant
// Users full control of C:\ by hand; callers report this as a warning
// rather than refusing to install.
func CheckTrustedAncestors(path string) error {
	abs, err := cleanProgramPath(path)
	if err != nil {
		return err
	}
	for cur := filepath.Dir(abs); ; {
		parent := filepath.Dir(cur)
		if parent == cur || strings.TrimRight(parent, `\`) == strings.TrimRight(cur, `\`) {
			return nil
		}
		if err := checkTrustedObject(parent, ancestorMask); err != nil {
			return err
		}
		cur = parent
	}
}

func cleanProgramPath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		abs = resolved
	}
	return abs, nil
}

func checkTrustedObject(path string, mask uint32) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("%s: güvenlik bilgisi okunamadı: %w", path, err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return fmt.Errorf("%s: sahip okunamadı", path)
	}
	if !trustedSID(owner) {
		return fmt.Errorf("%s yöneticilere ait değil (sahip %s)", path, owner.String())
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		if errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND) {
			return fmt.Errorf("%s: erişim listesi yok (herkes yazabilir)", path)
		}
		return fmt.Errorf("%s: erişim listesi okunamadı: %w", path, err)
	}
	if dacl == nil {
		return fmt.Errorf("%s: erişim listesi yok (herkes yazabilir)", path)
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return fmt.Errorf("%s: erişim listesi okunamadı: %w", path, err)
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue // applies to children only
		}
		switch ace.Header.AceType {
		case windows.ACCESS_ALLOWED_ACE_TYPE:
		case 0x04, 0x05, 0x09, 0x0B:
			// Compound, object or conditional allow entries are not
			// expected on program folders; refuse instead of guessing
			// their layout.
			return fmt.Errorf("%s: tanınmayan izin girdisi (tür %d)", path, ace.Header.AceType)
		default:
			continue // deny and other entries only narrow access
		}
		if uint32(ace.Mask)&mask == 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !trustedSID(sid) {
			return fmt.Errorf("%s yönetici olmayan bir hesapça (%s) değiştirilebilir", path, sid.String())
		}
	}
	return nil
}

func trustedSID(sid *windows.SID) bool {
	if sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		return true
	}
	return sid.String() == trustedInstallerSID
}
