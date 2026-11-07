package winapp

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// "Send with OpenScale" from Explorer's Send to menu (#803, ADR-0204).
//
// Explorer starts "openscale.exe send-to <files>" without elevation. The
// command checks its arguments, then hands the list to the running tray
// over a named pipe that only this user (and administrators) can open,
// after checking that the pipe belongs to the installed OpenScale
// program. The elevated tray opens every file while impersonating the
// caller, so it reads exactly what the person could read, checks the open
// handle once more (a normal file on a disk, not a link, a device or a
// file with several hard links) and asks for the recipient in its own
// window. The files then go to the service's private staging folder and
// on to the end-to-end transfer.

const (
	// MaxSendToFiles bounds one Send to request.
	MaxSendToFiles = 20
	// MaxSendToFile bounds one file (the staging limit of the panel).
	MaxSendToFile int64 = 2 << 30
	// MaxSendToTotal bounds all files of one request.
	MaxSendToTotal int64 = 8 << 30
	maxSendToPath        = 4096
)

// SendToFileInfo is a checked argument.
type SendToFileInfo struct {
	Path string
	Name string
	Size int64
}

// Errors of the argument check.
var (
	ErrSendToNone     = errors.New("gönderilecek dosya verilmedi")
	ErrSendToTooMany  = fmt.Errorf("en çok %d dosya birlikte gönderilebilir", MaxSendToFiles)
	ErrSendToTooLarge = errors.New("dosyalar gönderilemeyecek kadar büyük (dosya başına en çok 2 GiB, toplam 8 GiB)")
	// ErrSendToTrayMissing means no tray of this session listens.
	ErrSendToTrayMissing = errors.New("OpenScale tepsi uygulaması çalışmıyor")
)

// SendToArgError names the argument that failed.
type SendToArgError struct {
	Path   string
	Reason string
}

func (e *SendToArgError) Error() string { return e.Path + ": " + e.Reason }

// devicePath reports Win32 device and namespace paths (\\.\, \\?\,
// \??\) and reserved device names, which never name a normal file here.
func devicePath(p string) bool {
	for _, pre := range []string{`\\.\`, `\\?\`, `\??\`, `//./`, `//?/`} {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	base := strings.ToUpper(filepath.Base(p))
	if i := strings.IndexByte(base, '.'); i >= 0 {
		base = base[:i]
	}
	switch base {
	case "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$":
		return true
	}
	if len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '0' && base[3] <= '9' {
		return true
	}
	return false
}

// CheckSendToArgs checks the paths Explorer passed: 1 to MaxSendToFiles
// absolute paths of existing normal files (not links, folders or
// devices) within the size limits. lstat is os.Lstat outside tests.
func CheckSendToArgs(paths []string, lstat func(string) (fs.FileInfo, error)) ([]SendToFileInfo, error) {
	if len(paths) == 0 {
		return nil, ErrSendToNone
	}
	if len(paths) > MaxSendToFiles {
		return nil, ErrSendToTooMany
	}
	out := make([]SendToFileInfo, 0, len(paths))
	seen := map[string]bool{}
	var total int64
	for _, p := range paths {
		if p == "" || len(p) > maxSendToPath || !utf8.ValidString(p) || strings.ContainsRune(p, 0) {
			return nil, &SendToArgError{Path: p, Reason: "yol geçersiz"}
		}
		if devicePath(p) {
			return nil, &SendToArgError{Path: p, Reason: "aygıt yolları gönderilemez"}
		}
		if !filepath.IsAbs(p) {
			return nil, &SendToArgError{Path: p, Reason: "tam yol olmalı"}
		}
		clean := filepath.Clean(p)
		key := strings.ToLower(clean)
		if seen[key] {
			continue
		}
		seen[key] = true
		fi, err := lstat(clean)
		if err != nil {
			return nil, &SendToArgError{Path: p, Reason: "dosya bulunamadı veya okunamıyor"}
		}
		switch {
		case fi.Mode()&fs.ModeSymlink != 0:
			return nil, &SendToArgError{Path: p, Reason: "kısayol veya bağlantılar gönderilemez"}
		case fi.IsDir():
			return nil, &SendToArgError{Path: p, Reason: "klasörler gönderilemez; dosyaları seçin"}
		case !fi.Mode().IsRegular():
			return nil, &SendToArgError{Path: p, Reason: "yalnızca normal dosyalar gönderilebilir"}
		case fi.Size() > MaxSendToFile:
			return nil, &SendToArgError{Path: p, Reason: "dosya 2 GiB sınırını aşıyor"}
		}
		total += fi.Size()
		if total > MaxSendToTotal {
			return nil, ErrSendToTooLarge
		}
		out = append(out, SendToFileInfo{Path: clean, Name: filepath.Base(clean), Size: fi.Size()})
	}
	return out, nil
}
