package securefile

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
)

// Operating system key protection (#9, ADR-0060). On Windows the device and
// coordinator key files are encrypted with DPAPI in machine scope, so the
// service (LocalSystem) and the owner's CLI both open them on this computer
// while a copy of the file (a backup, a synced folder, another disk) is
// useless elsewhere. The protection is transparent:
//
//   - ReadPrivate recognises a protected file and returns the plaintext.
//   - With protection enabled (the openscale binary enables it; tests and
//     other programs do not), WriteNew and Replace protect those key files,
//     and ReadPrivate migrates an old plaintext key file in place on first
//     read. A failed protection keeps the plaintext file, never loses it.
//   - A key-protection.off file next to the keys turns automatic protection
//     off for that directory; UnprotectFile creates it, ProtectFile removes
//     it. Older versions cannot read protected files, so a downgrade starts
//     with "openscale key unprotect".
//
// DPAPI machine scope protects against copying the file, not against an
// administrator or LocalSystem on the same computer, and not against an
// attacker who has the whole disk including the registry hives. Linux has
// no persistent equivalent without a TPM: kernel keyrings are emptied at
// reboot, which would lose the device identity, so Linux keeps the 0600
// file in the 0700 directory (ADR-0060).

// Scheme names how a protected file is encrypted.
type Scheme string

// Protection schemes.
const (
	SchemeNone         Scheme = "none"
	SchemeDPAPIMachine Scheme = "dpapi-machine"
	SchemeDPAPIUser    Scheme = "dpapi-user"
)

// ErrProtectionUnavailable is returned when this platform cannot open or
// create a protected file.
var ErrProtectionUnavailable = errors.New("operating system key protection is not available on this platform")

// ErrBadProtectedFile is returned for a damaged protected file.
var ErrBadProtectedFile = errors.New("protected key file is damaged")

// OptOutFile in a key directory turns automatic protection off there.
const OptOutFile = "key-protection.off"

const (
	protectedMagic = "openscale-protected-v1"
	// maxProtectedSize bounds a protected file before it is decoded.
	maxProtectedSize = 1 << 20
)

// protectedNames are the key files that are protected automatically.
var protectedNames = []string{"device.key", "device.key.next", "coordinator.key"}

// writeScheme is the scheme new protected files use; tests switch it to
// user scope.
var writeScheme = SchemeDPAPIMachine

var autoProtect atomic.Bool

// EnableKeyProtection turns automatic protection of key files on or off
// for this process.
func EnableKeyProtection(on bool) { autoProtect.Store(on) }

// KeyProtectionEnabled reports whether automatic protection is on.
func KeyProtectionEnabled() bool { return autoProtect.Load() }

// ProtectionAvailable reports whether this platform can protect files.
func ProtectionAvailable() bool { return protectionAvailable }

// IsKeyFileName reports whether name is a key file that is protected
// automatically, including kept old device keys.
func IsKeyFileName(name string) bool {
	for _, n := range protectedNames {
		if name == n {
			return true
		}
	}
	return strings.HasPrefix(name, "device.key.old-")
}

// IsProtected reports whether data is a protected file.
func IsProtected(data []byte) bool {
	return bytes.HasPrefix(data, []byte(protectedMagic+" "))
}

// ProtectedScheme returns the scheme of protected data, or SchemeNone.
func ProtectedScheme(data []byte) Scheme {
	if !IsProtected(data) {
		return SchemeNone
	}
	header, _, _ := bytes.Cut(data, []byte("\n"))
	return Scheme(strings.TrimSpace(strings.TrimPrefix(string(header), protectedMagic+" ")))
}

// Protect encrypts data with the default scheme.
func Protect(data []byte) ([]byte, error) { return protectWith(data, writeScheme) }

func protectWith(data []byte, scheme Scheme) ([]byte, error) {
	if !protectionAvailable {
		return nil, ErrProtectionUnavailable
	}
	var blob []byte
	var err error
	switch scheme {
	case SchemeDPAPIMachine:
		blob, err = dpapiProtect(data, true)
	case SchemeDPAPIUser:
		blob, err = dpapiProtect(data, false)
	default:
		return nil, fmt.Errorf("unknown protection scheme %q", scheme)
	}
	if err != nil {
		return nil, fmt.Errorf("protect: %w", err)
	}
	var out bytes.Buffer
	out.WriteString(protectedMagic + " " + string(scheme) + "\n")
	out.WriteString(base64.StdEncoding.EncodeToString(blob))
	out.WriteByte('\n')
	return out.Bytes(), nil
}

// Unprotect decrypts a protected file's contents.
func Unprotect(data []byte) ([]byte, error) {
	if len(data) > maxProtectedSize {
		return nil, ErrTooLarge
	}
	header, body, ok := bytes.Cut(data, []byte("\n"))
	if !ok || !IsProtected(data) {
		return nil, ErrBadProtectedFile
	}
	scheme := Scheme(strings.TrimPrefix(string(header), protectedMagic+" "))
	if scheme != SchemeDPAPIMachine && scheme != SchemeDPAPIUser {
		return nil, fmt.Errorf("%w: unknown scheme", ErrBadProtectedFile)
	}
	blob, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(string(body)))
	if err != nil || len(blob) == 0 {
		return nil, ErrBadProtectedFile
	}
	if !protectionAvailable {
		return nil, ErrProtectionUnavailable
	}
	plain, err := dpapiUnprotect(blob)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadProtectedFile, err)
	}
	return plain, nil
}

// shouldProtect reports whether a write to path is protected automatically.
func shouldProtect(path string) bool {
	if !autoProtect.Load() || !protectionAvailable || !IsKeyFileName(filepath.Base(path)) {
		return false
	}
	_, err := os.Lstat(filepath.Join(filepath.Dir(path), OptOutFile))
	return errors.Is(err, fs.ErrNotExist)
}

// protectForPath returns the bytes to write to path: protected when
// automatic protection applies and a round trip succeeds, otherwise data
// unchanged, so a protection failure never loses a key.
func protectForPath(path string, data []byte) []byte {
	if IsProtected(data) || !shouldProtect(path) {
		return data
	}
	return protectVerified(data)
}

func protectVerified(data []byte) []byte {
	p, err := Protect(data)
	if err != nil {
		return data
	}
	back, err := Unprotect(p)
	if err != nil || !bytes.Equal(back, data) {
		wipeBytes(back)
		return data
	}
	wipeBytes(back)
	return p
}

// unprotectRead turns protected file contents into plaintext and migrates
// a plaintext key file when automatic protection applies.
func unprotectRead(path string, data []byte, limit int64) ([]byte, error) {
	if IsProtected(data) {
		plain, err := Unprotect(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Base(path), err)
		}
		if int64(len(plain)) > limit {
			wipeBytes(plain)
			return nil, fmt.Errorf("%s: %w", filepath.Base(path), ErrTooLarge)
		}
		return plain, nil
	}
	if shouldProtect(path) {
		if p := protectVerified(data); IsProtected(p) {
			// Best effort: the plaintext stays if the replace fails.
			_ = Replace(path, p)
		}
	}
	return data, nil
}

// ProtectFile protects an existing key file in place and turns automatic
// protection back on for its directory. It reports whether the file
// changed.
func ProtectFile(path string) (bool, error) {
	if !protectionAvailable {
		return false, ErrProtectionUnavailable
	}
	_ = os.Remove(filepath.Join(filepath.Dir(path), OptOutFile))
	data, err := readRaw(path)
	if err != nil {
		return false, err
	}
	defer wipeBytes(data)
	if IsProtected(data) {
		return false, nil
	}
	p := protectVerified(data)
	if !IsProtected(p) {
		return false, errors.New("protection round trip failed; the key file was left unchanged")
	}
	if err := Replace(path, p); err != nil {
		return false, err
	}
	return true, nil
}

// UnprotectFile writes the plaintext back, for a downgrade to a version
// without protection, and turns automatic protection off for the file's
// directory so the next read does not protect it again.
func UnprotectFile(path string) (bool, error) {
	if err := WriteOptOut(filepath.Dir(path)); err != nil {
		return false, err
	}
	data, err := readRaw(path)
	if err != nil {
		return false, err
	}
	if !IsProtected(data) {
		wipeBytes(data)
		return false, nil
	}
	plain, err := Unprotect(data)
	if err != nil {
		return false, err
	}
	defer wipeBytes(plain)
	if err := Replace(path, plain); err != nil {
		return false, err
	}
	return true, nil
}

// WriteOptOut turns automatic protection off for dir.
func WriteOptOut(dir string) error {
	err := WriteNew(filepath.Join(dir, OptOutFile), []byte("OpenScale: key files in this folder are not protected automatically (ADR-0060).\n"))
	if errors.Is(err, fs.ErrExist) {
		return nil
	}
	return err
}

// FileScheme returns how the file at path is stored.
func FileScheme(path string) (Scheme, error) {
	data, err := readRaw(path)
	if err != nil {
		return SchemeNone, err
	}
	defer wipeBytes(data)
	return ProtectedScheme(data), nil
}

func readRaw(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", filepath.Base(path))
	}
	if info.Size() > maxProtectedSize {
		return nil, fmt.Errorf("%s: %w", filepath.Base(path), ErrTooLarge)
	}
	buf := make([]byte, 0, info.Size())
	var tmp [4096]byte
	for {
		n, err := f.Read(tmp[:])
		buf = append(buf, tmp[:n]...)
		if len(buf) > maxProtectedSize {
			return nil, fmt.Errorf("%s: %w", filepath.Base(path), ErrTooLarge)
		}
		if err != nil {
			wipeBytes(tmp[:])
			if errors.Is(err, io.EOF) {
				return buf, nil
			}
			return nil, err
		}
	}
}

func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
