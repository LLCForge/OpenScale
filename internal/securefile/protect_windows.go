//go:build windows

package securefile

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

const protectionAvailable = true

// dpapiEntropy binds blobs to OpenScale: another program calling DPAPI on
// the same computer cannot decrypt them without it. It is not a secret.
var dpapiEntropy = []byte("openscale/protected-file/v1")

func blobOf(b []byte) *windows.DataBlob {
	if len(b) == 0 {
		return &windows.DataBlob{}
	}
	return &windows.DataBlob{Size: uint32(len(b)), Data: unsafe.SliceData(b)} //nolint:gosec // bounded by maxProtectedSize
}

// takeBlob copies and frees a buffer that DPAPI allocated, zeroing it first
// because it may hold plaintext.
func takeBlob(out *windows.DataBlob) []byte {
	if out.Data == nil {
		return []byte{}
	}
	buf := unsafe.Slice(out.Data, out.Size)
	result := append([]byte(nil), buf...)
	wipeBytes(buf)
	_, _ = windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return result
}

func dpapiProtect(data []byte, machine bool) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("nothing to protect")
	}
	name, err := windows.UTF16PtrFromString("OpenScale key")
	if err != nil {
		return nil, err
	}
	flags := uint32(windows.CRYPTPROTECT_UI_FORBIDDEN)
	if machine {
		flags |= windows.CRYPTPROTECT_LOCAL_MACHINE
	}
	var out windows.DataBlob
	if err := windows.CryptProtectData(blobOf(data), name, blobOf(dpapiEntropy), 0, nil, flags, &out); err != nil {
		return nil, err
	}
	return takeBlob(&out), nil
}

func dpapiUnprotect(blob []byte) ([]byte, error) {
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(blobOf(blob), nil, blobOf(dpapiEntropy), 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	return takeBlob(&out), nil
}
