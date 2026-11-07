package service

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/openscale/openscale/internal/securefile"
)

// readOnlyFile marks the panel read-only (F-180). It is a file of its own,
// not a field of settings.json, so the command line can switch it while the
// service runs without racing the service's own settings writes. The data
// directory is writable only by SYSTEM and administrators, so only they
// can create or delete it.
const readOnlyFile = "panel-readonly"

// readOnlyMarker is the file's content; only its presence counts.
var readOnlyMarker = []byte("Bu dosya varken OpenScale paneli salt okunurdur. Kapatmak için: openscale panel readonly off\n")

// PanelReadOnly reports whether the panel refuses every change. An error
// other than a missing file counts as read-only: the switch fails closed.
func PanelReadOnly(dataDir string) bool {
	if dataDir == "" {
		return false
	}
	_, err := os.Lstat(filepath.Join(dataDir, readOnlyFile))
	return !errors.Is(err, fs.ErrNotExist)
}

// SetPanelReadOnly turns the read-only panel on or off. It needs write
// access to the data directory (an administrator on Windows).
func SetPanelReadOnly(dataDir string, on bool) error {
	if dataDir == "" {
		return errors.New("veri klasörü bilinmiyor")
	}
	path := filepath.Join(dataDir, readOnlyFile)
	if on {
		return securefile.Replace(path, readOnlyMarker)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}
