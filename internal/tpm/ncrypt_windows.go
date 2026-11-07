//go:build windows

package tpm

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// NCrypt sealing through the Microsoft Platform Crypto Provider (#602,
// ADR-0208). The provider keeps the RSA key inside the TPM; only an
// opaque handle and the key name exist outside it. Not run on real
// hardware yet: creating a key writes to the TPM, which is forbidden on
// the development machine.

var (
	ncrypt                        = windows.NewLazySystemDLL("ncrypt.dll")
	procNCryptOpenStorageProvider = ncrypt.NewProc("NCryptOpenStorageProvider")
	procNCryptCreatePersistedKey  = ncrypt.NewProc("NCryptCreatePersistedKey")
	procNCryptOpenKey             = ncrypt.NewProc("NCryptOpenKey")
	procNCryptSetProperty         = ncrypt.NewProc("NCryptSetProperty")
	procNCryptFinalizeKey         = ncrypt.NewProc("NCryptFinalizeKey")
	procNCryptEncrypt             = ncrypt.NewProc("NCryptEncrypt")
	procNCryptDecrypt             = ncrypt.NewProc("NCryptDecrypt")
	procNCryptDeleteKey           = ncrypt.NewProc("NCryptDeleteKey")
	procNCryptFreeObject          = ncrypt.NewProc("NCryptFreeObject")
)

const (
	platformProvider     = "Microsoft Platform Crypto Provider"
	ncryptMachineKeyFlag = 0x00000020
	ncryptPadOAEPFlag    = 0x00000004
	keyNamePrefix        = "OpenScale-Device-"
	maxNCryptOut         = 512
)

type oaepPaddingInfo struct {
	algID  *uint16
	label  *byte
	labelN uint32
}

// NCryptSealer seals with a TPM-resident RSA-2048 key.
type NCryptSealer struct {
	// Machine selects machine scope (the service, LocalSystem); otherwise
	// the current user's scope.
	Machine bool
}

// Kind implements Sealer.
func (s *NCryptSealer) Kind() string { return "ncrypt" }

func ncryptErr(name string, r uintptr) error {
	if r == 0 {
		return nil
	}
	return fmt.Errorf("%s: 0x%08X", name, uint32(r))
}

func (s *NCryptSealer) flags() uintptr {
	if s.Machine {
		return ncryptMachineKeyFlag
	}
	return 0
}

func openProvider() (uintptr, error) {
	if err := procNCryptOpenStorageProvider.Find(); err != nil {
		return 0, ErrUnsupported
	}
	name, _ := windows.UTF16PtrFromString(platformProvider)
	var h uintptr
	r, _, _ := procNCryptOpenStorageProvider.Call(uintptr(unsafe.Pointer(&h)), uintptr(unsafe.Pointer(name)), 0)
	if r != 0 {
		return 0, fmt.Errorf("%w: platform provider 0x%08X", ErrNotFound, uint32(r))
	}
	return h, nil
}

func free(h uintptr) {
	if h != 0 {
		_, _, _ = procNCryptFreeObject.Call(h)
	}
}

func oaep() (*oaepPaddingInfo, error) {
	alg, err := windows.UTF16PtrFromString("SHA256")
	if err != nil {
		return nil, err
	}
	return &oaepPaddingInfo{algID: alg}, nil
}

// Seal implements Sealer: it creates a new TPM key for each seal and
// returns key name and ciphertext.
func (s *NCryptSealer) Seal(secret []byte) ([]byte, error) {
	if len(secret) == 0 || len(secret) > 128 {
		return nil, errors.New("sealed secret must be 1-128 bytes")
	}
	prov, err := openProvider()
	if err != nil {
		return nil, err
	}
	defer free(prov)
	var rnd [12]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return nil, err
	}
	keyName := keyNamePrefix + hex.EncodeToString(rnd[:])
	kn, _ := windows.UTF16PtrFromString(keyName)
	alg, _ := windows.UTF16PtrFromString("RSA")
	var key uintptr
	r, _, _ := procNCryptCreatePersistedKey.Call(prov, uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(alg)), uintptr(unsafe.Pointer(kn)), 0, s.flags())
	if err := ncryptErr("NCryptCreatePersistedKey", r); err != nil {
		return nil, err
	}
	defer free(key)
	length := uint32(2048)
	prop, _ := windows.UTF16PtrFromString("Length")
	r, _, _ = procNCryptSetProperty.Call(key, uintptr(unsafe.Pointer(prop)), uintptr(unsafe.Pointer(&length)), 4, 0)
	if err := ncryptErr("NCryptSetProperty", r); err != nil {
		return nil, err
	}
	r, _, _ = procNCryptFinalizeKey.Call(key, 0)
	if err := ncryptErr("NCryptFinalizeKey", r); err != nil {
		_, _, _ = procNCryptDeleteKey.Call(key, 0)
		return nil, err
	}
	pad, err := oaep()
	if err != nil {
		return nil, err
	}
	out := make([]byte, maxNCryptOut)
	var n uint32
	r, _, _ = procNCryptEncrypt.Call(key, uintptr(unsafe.Pointer(&secret[0])), uintptr(len(secret)), uintptr(unsafe.Pointer(pad)),
		uintptr(unsafe.Pointer(&out[0])), uintptr(len(out)), uintptr(unsafe.Pointer(&n)), ncryptPadOAEPFlag)
	if err := ncryptErr("NCryptEncrypt", r); err != nil {
		return nil, err
	}
	blob := binary.BigEndian.AppendUint16(nil, uint16(len(keyName)))
	blob = append(blob, keyName...)
	blob = binary.BigEndian.AppendUint16(blob, uint16(n))
	return append(blob, out[:n]...), nil
}

func splitNCryptBlob(blob []byte) (string, []byte, error) {
	if len(blob) < 2 {
		return "", nil, ErrEnvelope
	}
	n := int(binary.BigEndian.Uint16(blob))
	if n == 0 || n > 64 || len(blob) < 2+n+2 {
		return "", nil, ErrEnvelope
	}
	name := string(blob[2 : 2+n])
	rest := blob[2+n:]
	m := int(binary.BigEndian.Uint16(rest))
	if m == 0 || m > maxNCryptOut || len(rest) != 2+m || len(name) <= len(keyNamePrefix) || name[:len(keyNamePrefix)] != keyNamePrefix {
		return "", nil, ErrEnvelope
	}
	return name, rest[2:], nil
}

func (s *NCryptSealer) openKey(name string) (uintptr, uintptr, error) {
	prov, err := openProvider()
	if err != nil {
		return 0, 0, err
	}
	kn, _ := windows.UTF16PtrFromString(name)
	var key uintptr
	r, _, _ := procNCryptOpenKey.Call(prov, uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(kn)), 0, s.flags())
	if err := ncryptErr("NCryptOpenKey", r); err != nil {
		free(prov)
		return 0, 0, err
	}
	return prov, key, nil
}

// Unseal implements Sealer.
func (s *NCryptSealer) Unseal(blob []byte) ([]byte, error) {
	name, ct, err := splitNCryptBlob(blob)
	if err != nil {
		return nil, err
	}
	prov, key, err := s.openKey(name)
	if err != nil {
		return nil, err
	}
	defer free(prov)
	defer free(key)
	pad, err := oaep()
	if err != nil {
		return nil, err
	}
	out := make([]byte, maxNCryptOut)
	var n uint32
	r, _, _ := procNCryptDecrypt.Call(key, uintptr(unsafe.Pointer(&ct[0])), uintptr(len(ct)), uintptr(unsafe.Pointer(pad)),
		uintptr(unsafe.Pointer(&out[0])), uintptr(len(out)), uintptr(unsafe.Pointer(&n)), ncryptPadOAEPFlag)
	if err := ncryptErr("NCryptDecrypt", r); err != nil {
		return nil, err
	}
	secret := append([]byte(nil), out[:n]...)
	clear(out)
	return secret, nil
}

// DeleteSealedKey removes the TPM key named in blob (after re-sealing or
// leaving the network).
func (s *NCryptSealer) DeleteSealedKey(blob []byte) error {
	name, _, err := splitNCryptBlob(blob)
	if err != nil {
		return err
	}
	prov, key, err := s.openKey(name)
	if err != nil {
		return err
	}
	defer free(prov)
	r, _, _ := procNCryptDeleteKey.Call(key, 0) // frees the key handle
	return ncryptErr("NCryptDeleteKey", r)
}

// PlatformSealer returns the platform's sealer: NCrypt on Windows.
func PlatformSealer(machine bool) (Sealer, error) {
	if err := procNCryptOpenStorageProvider.Find(); err != nil {
		return nil, ErrUnsupported
	}
	return &NCryptSealer{Machine: machine}, nil
}
