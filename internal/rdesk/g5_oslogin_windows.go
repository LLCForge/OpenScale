//go:build windows

package rdesk

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows account check with LogonUserW (ADR-0198). A network logon
// (LOGON32_LOGON_NETWORK) checks the password without loading a profile
// or starting anything; the token is closed at once. "DOMAIN\user" and
// "user@domain" are accepted; a bare name means a local account.

var (
	modAdvapi32G5  = windows.NewLazySystemDLL("advapi32.dll")
	procLogonUserW = modAdvapi32G5.NewProc("LogonUserW")
)

const (
	logon32LogonNetwork    = 3
	logon32ProviderDefault = 0
)

// Account errors that mean "this account may not sign in"; they count as
// a wrong password so the answer does not tell which one it was.
var logonRefusals = map[windows.Errno]bool{
	1326: true, // ERROR_LOGON_FAILURE
	1327: true, // ERROR_ACCOUNT_RESTRICTION (blank password, logon hours)
	1328: true, // ERROR_INVALID_LOGON_HOURS
	1329: true, // ERROR_INVALID_WORKSTATION
	1330: true, // ERROR_PASSWORD_EXPIRED
	1331: true, // ERROR_ACCOUNT_DISABLED
	1385: true, // ERROR_LOGON_TYPE_NOT_GRANTED
	1907: true, // ERROR_PASSWORD_MUST_CHANGE
	1909: true, // ERROR_ACCOUNT_LOCKED_OUT
	1793: true, // ERROR_ACCOUNT_EXPIRED
}

// NewSystemVerifier returns the operating system's account check.
func NewSystemVerifier() (OSVerifier, error) {
	if err := procLogonUserW.Find(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrOSLoginUnavailable, err)
	}
	return OSVerifierFunc(verifyWindowsAccount), nil
}

// splitWindowsUser returns the user and domain arguments of LogonUserW.
func splitWindowsUser(user string) (string, string, bool) {
	if user == "" || len(user) > maxLoginUser || strings.ContainsAny(user, "\x00/") {
		return "", "", false
	}
	if i := strings.IndexByte(user, '\\'); i >= 0 {
		dom, name := user[:i], user[i+1:]
		if name == "" || strings.ContainsRune(name, '\\') {
			return "", "", false
		}
		if dom == "" {
			dom = "."
		}
		return name, dom, true
	}
	if strings.Contains(user, "@") {
		// A user principal name carries its own domain.
		return user, "", true
	}
	return user, ".", true
}

// utf16Secret converts the password to a NUL terminated UTF-16 buffer
// without making a string; the caller wipes it.
func utf16Secret(pw []byte) ([]uint16, bool) {
	out := make([]uint16, 0, len(pw)+1)
	for len(pw) > 0 {
		r, size := utf8.DecodeRune(pw)
		if r == utf8.RuneError && size <= 1 || r == 0 {
			wipe16(out)
			return nil, false
		}
		out = utf16.AppendRune(out, r)
		pw = pw[size:]
	}
	return append(out, 0), true
}

func wipe16(b []uint16) {
	for i := range b {
		b[i] = 0
	}
}

func verifyWindowsAccount(ctx context.Context, user string, password []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	name, dom, ok := splitWindowsUser(user)
	if !ok || len(password) == 0 {
		return ErrOSLoginFailed
	}
	pw, ok := utf16Secret(password)
	if !ok {
		return ErrOSLoginFailed
	}
	defer wipe16(pw)
	uName, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return ErrOSLoginFailed
	}
	var uDom *uint16
	if dom != "" {
		if uDom, err = windows.UTF16PtrFromString(dom); err != nil {
			return ErrOSLoginFailed
		}
	}
	var token windows.Token
	r, _, callErr := procLogonUserW.Call(uintptr(unsafe.Pointer(uName)), uintptr(unsafe.Pointer(uDom)), uintptr(unsafe.Pointer(&pw[0])),
		logon32LogonNetwork, logon32ProviderDefault, uintptr(unsafe.Pointer(&token)))
	if r != 0 {
		_ = token.Close()
		return nil
	}
	var errno windows.Errno
	if errors.As(callErr, &errno) && logonRefusals[errno] {
		return ErrOSLoginFailed
	}
	return fmt.Errorf("%w: %w", ErrOSLoginUnavailable, callErr)
}
