package securefile

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Temporary files (#46). OpenScale never writes to the system temporary
// directory: Replace creates its temporary file next to the target, inside
// the owner-only (0700) data directory, with 0600 permissions, and removes
// it on every error path. A crash or power loss between create and rename
// can still leave one behind; RemoveStaleTemps deletes those at start-up.

// staleAfter keeps a temporary file that another process may be writing
// right now.
const staleAfter = time.Minute

// maxTempDepth bounds how deep RemoveStaleTemps looks (data directory,
// device/, network/, network/history/).
const maxTempDepth = 3

// IsTempName reports whether name is a temporary file name made by
// Replace (".<name>.tmp-<random>") or by the Windows installer copy
// (".openscale-<random>.tmp").
func IsTempName(name string) bool {
	if !strings.HasPrefix(name, ".") {
		return false
	}
	return strings.Contains(name, ".tmp-") || (strings.HasPrefix(name, ".openscale-") && strings.HasSuffix(name, ".tmp"))
}

// RemoveStaleTemps removes leftover temporary files under dir that are
// older than a minute. It never follows links and never removes anything
// else. It returns how many files were removed.
func RemoveStaleTemps(dir string, now time.Time) (int, error) {
	root := filepath.Clean(dir)
	removed := 0
	var errs []error
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if p == root {
				return err
			}
			return nil
		}
		if d.IsDir() {
			rel, _ := filepath.Rel(root, p)
			if rel != "." && strings.Count(filepath.ToSlash(rel), "/")+1 > maxTempDepth {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || !IsTempName(d.Name()) {
			return nil
		}
		info, err := d.Info()
		if err != nil || now.Sub(info.ModTime()) < staleAfter {
			return nil
		}
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, err)
			return nil
		}
		removed++
		return nil
	})
	if errors.Is(err, fs.ErrNotExist) {
		err = nil
	}
	return removed, errors.Join(append(errs, err)...)
}
