// Package securefile reads and writes files that hold private material:
// owner-only permissions, size limits, and atomic replacement.
package securefile

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

// ErrInsecurePermissions is returned when a private file is accessible by
// group or others on a platform with POSIX permissions.
var ErrInsecurePermissions = errors.New("file permissions are too open, expected 0600")

// ErrTooLarge is returned when a file exceeds the caller's size limit.
var ErrTooLarge = errors.New("file is too large")

const (
	fileMode = 0o600
	dirMode  = 0o700
)

// WriteNew creates path with 0600 permissions and fails with fs.ErrExist if
// it already exists, so key files are never silently overwritten.
func WriteNew(path string, data []byte) (retErr error) {
	data = protectForPath(path, data) // #9, protect.go
	if err := os.MkdirAll(filepath.Dir(path), dirMode); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}
	// SECURITY FIX: CWE-732 Never into a directory another account owns.
	if err := checkDirOwner(filepath.Dir(path)); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fileMode)
	if err != nil {
		return err
	}
	defer func() {
		if retErr != nil {
			_ = f.Close()
			_ = os.Remove(path)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync %s: %w", filepath.Base(path), err)
	}
	return f.Close()
}

// Replace atomically replaces path with data via a temporary file in the
// same directory, so readers never observe a partially written file.
func Replace(path string, data []byte) (retErr error) {
	data = protectForPath(path, data) // #9, protect.go
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}
	// SECURITY FIX: CWE-732 Never into a directory another account owns.
	if err := checkDirOwner(dir); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		if retErr != nil {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(fileMode); err != nil && runtime.GOOS != "windows" {
		return fmt.Errorf("chmod temporary file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("write temporary file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync temporary file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename temporary file: %w", err)
	}
	syncDir(dir)
	return nil
}

// ReadPrivate reads a private file, refusing non-regular files, files that
// other users can read, and files larger than limit bytes.
func ReadPrivate(path string, limit int64) ([]byte, error) {
	return read(path, limit, true)
}

// ReadLimited reads a non-secret file with a size limit.
func ReadLimited(path string, limit int64) ([]byte, error) {
	return read(path, limit, false)
}

func read(path string, limit int64, private bool) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", filepath.Base(path), err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", filepath.Base(path))
	}
	// SECURITY FIX: CWE-732 Refuse private material other local users can read.
	if private && runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s: %w", filepath.Base(path), ErrInsecurePermissions)
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("%s: %w", filepath.Base(path), ErrTooLarge)
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", filepath.Base(path), err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s: %w", filepath.Base(path), ErrTooLarge)
	}
	if !private {
		return data, nil
	}
	// Protected key files (#9, protect.go). Close first: a plaintext key
	// file may be replaced by its protected form.
	_ = f.Close()
	return unprotectRead(path, data, limit)
}

// syncDir flushes the directory entry after a rename. Windows does not
// support opening directories for sync, so it is skipped there.
func syncDir(dir string) {
	if runtime.GOOS == "windows" {
		return
	}
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	_ = d.Sync()
	_ = d.Close()
}
