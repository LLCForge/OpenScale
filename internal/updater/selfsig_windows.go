//go:build windows

package updater

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// trustENoSignature is TRUST_E_NOSIGNATURE: the file carries no
// Authenticode signature.
const trustENoSignature = 0x800B0100

// PlatformSignature checks the file's Authenticode signature with
// WinVerifyTrust. No user interface, no revocation download (telemetry
// policy ADR-0008: the check never reaches the network).
func PlatformSignature(path string) (SignatureState, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return SignatureInvalid, err
	}
	file := windows.WinTrustFileInfo{
		Size:     uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})),
		FilePath: p,
	}
	data := windows.WinTrustData{
		Size:                            uint32(unsafe.Sizeof(windows.WinTrustData{})),
		UIChoice:                        windows.WTD_UI_NONE,
		RevocationChecks:                windows.WTD_REVOKE_NONE,
		UnionChoice:                     windows.WTD_CHOICE_FILE,
		StateAction:                     windows.WTD_STATEACTION_VERIFY,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(&file),
		ProvFlags:                       windows.WTD_CACHE_ONLY_URL_RETRIEVAL | windows.WTD_REVOCATION_CHECK_NONE,
	}
	verr := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, &data)
	data.StateAction = windows.WTD_STATEACTION_CLOSE
	_ = windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, &data)
	if verr == nil {
		return SignatureValid, nil
	}
	var en windows.Errno
	if errors.As(verr, &en) && uint32(en) == trustENoSignature {
		return SignatureAbsent, nil
	}
	return SignatureInvalid, fmt.Errorf("Authenticode: %w", verr)
}
