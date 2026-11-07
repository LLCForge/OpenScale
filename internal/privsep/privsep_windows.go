//go:build windows

package privsep

import (
	"errors"
	"fmt"
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modAdvapi32               = windows.NewLazySystemDLL("advapi32.dll")
	procCreateRestrictedToken = modAdvapi32.NewProc("CreateRestrictedToken")
)

const (
	disableMaxPrivilege = 0x1
	luaToken            = 0x4
)

// CurrentStatus reports the current process token's integrity level and
// elevation. It only reads the token.
func CurrentStatus() Status {
	tok := windows.GetCurrentProcessToken()
	rid, err := tokenIntegrity(tok)
	if err != nil {
		return Status{Summary: "bilinmiyor"}
	}
	st := Status{Integrity: integrityName(rid), Privileged: tok.IsElevated() || rid >= 0x3000}
	st.Summary = "bütünlük düzeyi " + st.Integrity
	if tok.IsElevated() {
		st.Summary += ", yükseltilmiş"
	}
	return st
}

func tokenIntegrity(tok windows.Token) (uint32, error) {
	var n uint32
	_ = windows.GetTokenInformation(tok, windows.TokenIntegrityLevel, nil, 0, &n)
	if n == 0 || n > 1024 {
		return 0, errors.New("integrity level unavailable")
	}
	buf := make([]byte, n)
	if err := windows.GetTokenInformation(tok, windows.TokenIntegrityLevel, &buf[0], n, &n); err != nil {
		return 0, err
	}
	tml := (*windows.Tokenmandatorylabel)(unsafe.Pointer(&buf[0]))
	sid := tml.Label.Sid
	if sid == nil || sid.SubAuthorityCount() == 0 {
		return 0, errors.New("integrity SID malformed")
	}
	return sid.SubAuthority(uint32(sid.SubAuthorityCount()) - 1), nil
}

// restrictedLowToken derives a primary token from the current process
// token with every privilege but SeChangeNotify removed, the
// Administrators group deny-only and the low integrity label. The caller
// closes it.
func restrictedLowToken() (windows.Token, error) {
	var cur windows.Token
	access := uint32(windows.TOKEN_DUPLICATE | windows.TOKEN_ASSIGN_PRIMARY | windows.TOKEN_QUERY | windows.TOKEN_ADJUST_DEFAULT)
	if err := windows.OpenProcessToken(windows.CurrentProcess(), access, &cur); err != nil {
		return 0, fmt.Errorf("süreç belirteci açılamadı: %w", err)
	}
	defer cur.Close()
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return 0, err
	}
	disable := []windows.SIDAndAttributes{{Sid: admins}}
	// Restricting SIDs (ADR-0233): every access check must also pass for
	// one of these, so objects granted only to the account itself, to
	// SYSTEM or to administrators (the service's state, keys, other
	// processes) are out of reach even though the token keeps the account.
	var restrict []windows.SIDAndAttributes
	for _, k := range []windows.WELL_KNOWN_SID_TYPE{windows.WinWorldSid, windows.WinBuiltinUsersSid, windows.WinRestrictedCodeSid} {
		sid, err := windows.CreateWellKnownSid(k)
		if err != nil {
			return 0, err
		}
		restrict = append(restrict, windows.SIDAndAttributes{Sid: sid})
	}
	var restricted windows.Token
	r, _, callErr := procCreateRestrictedToken.Call(uintptr(cur), disableMaxPrivilege|luaToken,
		uintptr(len(disable)), uintptr(unsafe.Pointer(&disable[0])), 0, 0,
		uintptr(len(restrict)), uintptr(unsafe.Pointer(&restrict[0])),
		uintptr(unsafe.Pointer(&restricted)))
	if r == 0 {
		return 0, fmt.Errorf("kısıtlı belirteç oluşturulamadı: %w", callErr)
	}
	low, err := windows.CreateWellKnownSid(windows.WinLowLabelSid)
	if err != nil {
		restricted.Close()
		return 0, err
	}
	tml := windows.Tokenmandatorylabel{Label: windows.SIDAndAttributes{Sid: low, Attributes: windows.SE_GROUP_INTEGRITY}}
	if err := windows.SetTokenInformation(restricted, windows.TokenIntegrityLevel, (*byte)(unsafe.Pointer(&tml)), tml.Size()); err != nil {
		restricted.Close()
		return 0, fmt.Errorf("düşük bütünlük düzeyi ayarlanamadı: %w", err)
	}
	if err := allowRestrictedSelf(cur, restricted); err != nil {
		restricted.Close()
		return 0, fmt.Errorf("kısıtlı belirteç izinleri ayarlanamadı: %w", err)
	}
	return restricted, nil
}

// tokenDefaultDacl is TOKEN_INFORMATION_CLASS TokenDefaultDacl.
const tokenDefaultDacl = 6

type tokenDefaultDACL struct {
	DefaultDacl *windows.ACL
}

// allowRestrictedSelf lets a process with the restricted token use the
// objects it creates, starting with its own process and thread: their
// access lists come from the token's default list, which names only the
// account and SYSTEM (no restricting SID matches), so RESTRICTED is added.
func allowRestrictedSelf(cur, tok windows.Token) error {
	tu, err := cur.GetTokenUser()
	if err != nil {
		return err
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return err
	}
	restrictedSID, err := windows.CreateWellKnownSid(windows.WinRestrictedCodeSid)
	if err != nil {
		return err
	}
	grant := func(sid *windows.SID) windows.EXPLICIT_ACCESS {
		return windows.EXPLICIT_ACCESS{AccessPermissions: windows.GENERIC_ALL, AccessMode: windows.GRANT_ACCESS, Inheritance: windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_UNKNOWN, TrusteeValue: windows.TrusteeValueFromSID(sid)}}
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{grant(tu.User.Sid), grant(system), grant(restrictedSID)}, nil)
	if err != nil {
		return err
	}
	dd := tokenDefaultDACL{DefaultDacl: acl}
	return windows.SetTokenInformation(tok, tokenDefaultDacl, (*byte)(unsafe.Pointer(&dd)), uint32(unsafe.Sizeof(dd)))
}

// Command prepares exe to run with a restricted, low integrity token.
// uid and gid are ignored on Windows. Call release after Start (or when
// the command is abandoned) to close the token handle.
func Command(exe string, args []string, _, _ uint32) (*exec.Cmd, func(), error) {
	tok, err := restrictedLowToken()
	if err != nil {
		return nil, func() {}, err
	}
	cmd := exec.Command(exe, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Token: syscall.Token(tok), HideWindow: true}
	return cmd, func() { tok.Close() }, nil
}

// Enter is called first thing in the helper process: it refuses to
// continue unless the process really runs at low integrity without
// elevation.
func Enter() error {
	tok := windows.GetCurrentProcessToken()
	rid, err := tokenIntegrity(tok)
	if err != nil {
		return err
	}
	if rid >= 0x2000 || tok.IsElevated() {
		return errors.New("yardımcı süreç düşük bütünlük düzeyinde değil; devam edilmez")
	}
	return nil
}
