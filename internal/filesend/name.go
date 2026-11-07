package filesend

import (
	"errors"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	maxRawNameLen   = 1024
	maxCleanNameLen = 200
	maxExtLen       = 20
)

// ErrBadName is returned for file names that cannot be stored safely.
var ErrBadName = errors.New("dosya adı güvenli değil")

// SanitizeName turns a file name offered by a peer into a safe base name for
// the inbox. Names that try to escape the inbox (path separators, "..",
// absolute or drive paths), contain control characters or Unicode
// bidirectional overrides, or are not valid UTF-8 are rejected. Characters
// Windows cannot store are replaced, invisible format characters are
// dropped, trailing dots and spaces are trimmed, reserved device names get a
// "_" prefix and overly long names are shortened.
func SanitizeName(name string) (string, error) {
	if name == "" || len(name) > maxRawNameLen || !utf8.ValidString(name) {
		return "", ErrBadName
	}
	if strings.ContainsAny(name, "/\\\x00") {
		return "", ErrBadName
	}
	if len(name) >= 2 && name[1] == ':' && isASCIILetter(name[0]) {
		return "", ErrBadName
	}
	var b strings.Builder
	for _, r := range name {
		switch {
		case isBidiControl(r):
			return "", ErrBadName
		case unicode.IsControl(r):
			return "", ErrBadName
		case unicode.Is(unicode.Cf, r):
			// Zero-width and other invisible format characters hide the real name.
			continue
		case strings.ContainsRune(`<>:"|?*`, r):
			b.WriteByte('_')
		default:
			b.WriteRune(r)
		}
	}
	clean := strings.TrimSpace(b.String())
	clean = strings.TrimRight(clean, ". ")
	if clean == "" || clean == "." || clean == ".." {
		return "", ErrBadName
	}
	if isReservedWindowsName(clean) {
		clean = "_" + clean
	}
	clean = shorten(clean)
	if filepath.Base(clean) != clean || !filepath.IsLocal(clean) {
		return "", ErrBadName
	}
	return clean, nil
}

func isASCIILetter(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

// isBidiControl reports Unicode bidirectional formatting characters, which
// can make "gpj.exe" display as "exe.jpg".
func isBidiControl(r rune) bool {
	switch {
	case r == 0x061C, r == 0x200E, r == 0x200F:
		return true
	case r >= 0x202A && r <= 0x202E:
		return true
	case r >= 0x2066 && r <= 0x2069:
		return true
	}
	return false
}

func isReservedWindowsName(name string) bool {
	stem := name
	if i := strings.IndexByte(stem, '.'); i >= 0 {
		stem = stem[:i]
	}
	stem = strings.ToUpper(strings.TrimRight(stem, " "))
	switch stem {
	case "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "CLOCK$":
		return true
	}
	if len(stem) >= 4 && (strings.HasPrefix(stem, "COM") || strings.HasPrefix(stem, "LPT")) {
		suffix := stem[3:]
		switch suffix {
		case "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "¹", "²", "³":
			return true
		}
	}
	return false
}

// shorten limits name to maxCleanNameLen bytes, keeping a short extension
// and never splitting a UTF-8 sequence.
func shorten(name string) string {
	if len(name) <= maxCleanNameLen {
		return name
	}
	ext := filepath.Ext(name)
	if len(ext) > maxExtLen || ext == name {
		ext = ""
	}
	stem := name[:len(name)-len(ext)]
	limit := maxCleanNameLen - len(ext)
	for limit > 0 && !utf8.RuneStart(stem[limit]) {
		limit--
	}
	return strings.TrimRight(stem[:limit], ". ") + ext
}

// executableExts lists extensions that run code when opened on common
// desktop systems; matching files are flagged for the user (#133).
var executableExts = map[string]bool{
	".exe": true, ".com": true, ".bat": true, ".cmd": true, ".msi": true, ".msp": true,
	".scr": true, ".pif": true, ".cpl": true, ".dll": true, ".sys": true, ".ps1": true,
	".psm1": true, ".vbs": true, ".vbe": true, ".js": true, ".jse": true, ".wsf": true,
	".wsh": true, ".hta": true, ".lnk": true, ".url": true, ".reg": true, ".jar": true,
	".appx": true, ".msix": true, ".appinstaller": true, ".sh": true, ".bash": true,
	".zsh": true, ".run": true, ".bin": true, ".elf": true, ".deb": true, ".rpm": true,
	".apk": true, ".app": true, ".pkg": true, ".dmg": true, ".command": true,
	".py": true, ".pl": true, ".rb": true, ".desktop": true, ".iso": true, ".img": true,
	".vhd": true, ".vhdx": true, ".docm": true, ".xlsm": true, ".pptm": true,
}

// IsExecutable reports whether name has an extension that may run code when
// opened, so the user interface can warn before opening it.
func IsExecutable(name string) bool {
	return executableExts[strings.ToLower(filepath.Ext(name))]
}
