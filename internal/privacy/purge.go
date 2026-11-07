package privacy

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Purge removes an OpenScale data directory without leaving its contents
// readable in the file system (#52): every regular file is overwritten
// with random bytes, flushed, truncated, renamed to a random name and only
// then deleted.
//
// Limits (documented for the owner): on SSDs, flash cards and copy-on-
// write or journaling file systems (APFS, Btrfs, ZFS, NTFS with shadow
// copies) the controller or the file system may write the new bytes to
// another place, so old blocks can survive until they are reused. Full-
// disk encryption (BitLocker, LUKS, FileVault) is the dependable
// protection there; Purge still removes every name and every byte that is
// reachable through the file system.

var (
	// ErrNotDataDir is returned for a directory that does not look like an
	// OpenScale data directory; nothing is removed.
	ErrNotDataDir = errors.New("klasör bir OpenScale veri klasörüne benzemiyor")
	// ErrUnsafePath is returned for a file system root, a home or system
	// directory, or a symbolic link given as the directory.
	ErrUnsafePath = errors.New("bu klasör güvenle silinemez")
	// ErrRootKeyPresent is returned when the directory holds the network's
	// root key and the caller did not allow destroying it.
	ErrRootKeyPresent = errors.New("klasörde ağın kök anahtarı var")
	// ErrTooManyFiles stops a purge of a directory far larger than any
	// OpenScale data directory.
	ErrTooManyFiles = errors.New("klasörde beklenenden çok dosya var")
)

const (
	// maxPurgeFiles bounds the entries of one data directory.
	maxPurgeFiles = 20000
	// maxOverwrite bounds the bytes overwritten in one file; larger files
	// (received files, for example) are removed without overwriting.
	maxOverwrite = 256 << 20
	wipeChunk    = 32 << 10
	rootKeyName  = "root.key"
)

// dataMarkers are names that only an OpenScale data directory has, at the
// top level or one level below (device/, network/, coordinator/).
var dataMarkers = []string{
	"device.key", "coordinator.key", rootKeyName, "anchor.json", "app.token",
	"settings.json", "endpoints.json", "device.key.next",
}

// PurgeOptions changes what Purge accepts.
type PurgeOptions struct {
	// AllowRootKey permits destroying network/root.key: without a backup
	// the network itself is gone.
	AllowRootKey bool
	// Random is the overwrite source; nil uses crypto/rand.
	Random io.Reader
}

// PurgeResult summarises one purge.
type PurgeResult struct {
	Dir         string `json:"dir"`
	Files       int    `json:"files"`
	Overwritten int    `json:"overwritten"`
	Bytes       int64  `json:"bytes"`
	// NotOverwritten lists files only unlinked: hard links, files over the
	// overwrite limit, links and special files.
	NotOverwritten []string `json:"not_overwritten,omitempty"`
}

// CheckPurgeTarget validates dir without changing anything. It returns the
// cleaned absolute path.
func CheckPurgeTarget(dir string, allowRootKey bool) (string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	abs = filepath.Clean(abs)
	if unsafeDir(abs) {
		return "", fmt.Errorf("%s: %w", abs, ErrUnsafePath)
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return "", err
	}
	if info.Mode()&fs.ModeSymlink != 0 || !info.IsDir() {
		return "", fmt.Errorf("%s: %w", abs, ErrUnsafePath)
	}
	if !looksLikeDataDir(abs) {
		return "", fmt.Errorf("%s: %w", abs, ErrNotDataDir)
	}
	count := 0
	hasRoot := false
	err = filepath.WalkDir(abs, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		count++
		if count > maxPurgeFiles {
			return ErrTooManyFiles
		}
		if !d.IsDir() && d.Name() == rootKeyName {
			hasRoot = true
		}
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("%s: %w", abs, err)
	}
	if hasRoot && !allowRootKey {
		return "", fmt.Errorf("%s: %w", abs, ErrRootKeyPresent)
	}
	return abs, nil
}

// Purge overwrites and removes dir after CheckPurgeTarget accepts it. It
// keeps going after an error so as much as possible is removed, and
// returns every error joined.
func Purge(dir string, opts PurgeOptions) (PurgeResult, error) {
	abs, err := CheckPurgeTarget(dir, opts.AllowRootKey)
	if err != nil {
		return PurgeResult{Dir: dir}, err
	}
	random := opts.Random
	if random == nil {
		random = rand.Reader
	}
	res := PurgeResult{Dir: abs}
	var errs []error
	walkErr := filepath.WalkDir(abs, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			errs = append(errs, err)
			return nil
		}
		if d.IsDir() {
			return nil
		}
		res.Files++
		n, overwritten, err := WipeFile(p, random)
		if err != nil {
			errs = append(errs, err)
			return nil
		}
		if overwritten {
			res.Overwritten++
			res.Bytes += n
		} else {
			rel, _ := filepath.Rel(abs, p)
			res.NotOverwritten = append(res.NotOverwritten, rel)
		}
		return nil
	})
	if walkErr != nil {
		errs = append(errs, walkErr)
	}
	if err := os.RemoveAll(abs); err != nil {
		errs = append(errs, err)
	}
	return res, errors.Join(errs...)
}

// WipeFile overwrites a regular file with bytes from random, truncates it,
// renames it to a random name and removes it. Links, special files, hard-
// linked files and files over the overwrite limit are only removed, so
// another name or the link target is never damaged. It returns the bytes
// overwritten and whether the content was overwritten.
func WipeFile(path string, random io.Reader) (int64, bool, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return 0, false, err
	}
	if !info.Mode().IsRegular() || linkCount(path, info) > 1 || info.Size() > maxOverwrite {
		return 0, false, removeFile(path)
	}
	n, err := overwrite(path, info, random)
	if err != nil {
		// The content stays; the name must still go.
		return 0, false, errors.Join(err, removeFile(path))
	}
	return n, true, removeRenamed(path)
}

func overwrite(path string, before fs.FileInfo, random io.Reader) (int64, error) {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil && runtime.GOOS == "windows" {
		// A read-only attribute blocks writing; clear it and retry.
		if os.Chmod(path, 0o600) == nil {
			f, err = os.OpenFile(path, os.O_WRONLY, 0)
		}
	}
	if err != nil {
		return 0, fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil {
		return 0, err
	}
	// The file opened must be the one inspected (no swap in between).
	if !os.SameFile(before, after) {
		return 0, fmt.Errorf("%s: dosya incelendikten sonra değişti", filepath.Base(path))
	}
	size := after.Size()
	buf := make([]byte, wipeChunk)
	var done int64
	for done < size {
		chunk := buf[:min(int64(len(buf)), size-done)]
		if _, err := io.ReadFull(random, chunk); err != nil {
			return done, err
		}
		n, err := f.WriteAt(chunk, done)
		done += int64(n)
		if err != nil {
			return done, err
		}
	}
	if err := f.Sync(); err != nil {
		return done, err
	}
	if err := f.Truncate(0); err != nil {
		return done, err
	}
	return done, f.Sync()
}

// removeRenamed hides the original name before unlinking.
func removeRenamed(path string) error {
	var b [8]byte
	target := path
	if _, err := rand.Read(b[:]); err == nil {
		candidate := filepath.Join(filepath.Dir(path), "."+hex.EncodeToString(b[:]))
		if os.Rename(path, candidate) == nil {
			target = candidate
		}
	}
	return removeFile(target)
}

func removeFile(path string) error {
	err := os.Remove(path)
	if err != nil && runtime.GOOS == "windows" && os.Chmod(path, 0o600) == nil {
		err = os.Remove(path)
	}
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

func looksLikeDataDir(dir string) bool {
	if hasMarker(dir) {
		return true
	}
	for _, sub := range []string{"device", "network", "coordinator"} {
		if hasMarker(filepath.Join(dir, sub)) {
			return true
		}
	}
	return false
}

func hasMarker(dir string) bool {
	for _, m := range dataMarkers {
		if info, err := os.Lstat(filepath.Join(dir, m)); err == nil && info.Mode().IsRegular() {
			return true
		}
	}
	return false
}

// unsafeDir refuses roots, home directories and well-known system
// directories, whatever they contain.
func unsafeDir(abs string) bool {
	if filepath.Dir(abs) == abs || abs == filepath.VolumeName(abs)+string(filepath.Separator) {
		return true
	}
	deny := []string{}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		deny = append(deny, home)
	}
	if cfg, err := os.UserConfigDir(); err == nil && cfg != "" {
		deny = append(deny, cfg)
	}
	for _, env := range []string{"ProgramData", "ProgramFiles", "ProgramFiles(x86)", "SystemRoot", "windir", "APPDATA", "LOCALAPPDATA", "USERPROFILE"} {
		if v := os.Getenv(env); v != "" {
			deny = append(deny, v)
		}
	}
	if runtime.GOOS != "windows" {
		deny = append(deny, "/etc", "/var", "/var/lib", "/usr", "/usr/local", "/home", "/root", "/opt", "/tmp", "/boot", "/srv")
	}
	for _, d := range deny {
		c, err := filepath.Abs(d)
		if err != nil {
			continue
		}
		if sameDirName(filepath.Clean(c), abs) {
			return true
		}
	}
	return false
}

func sameDirName(a, b string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}
