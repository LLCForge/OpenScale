package filesend

import (
	"errors"
	"time"
)

// Quarantine marking of received files (#659, ADR-0205). A file that came
// from another device is labelled the way the operating system labels a
// download, so the shell, Office, Gatekeeper or the file manager warns
// before it is opened:
//
//   - Windows: the Zone.Identifier stream with ZoneId=3 (Mark-of-the-Web).
//   - macOS: the com.apple.quarantine extended attribute.
//   - Linux: user.xdg.origin.url and user.openscale.quarantine extended
//     attributes (no desktop enforces them, the panel shows the warning).
//
// Marking is best effort: file systems without streams or extended
// attributes (FAT, some network shares, tmpfs without user xattrs) return
// an error and the file stays unmarked; the caller reports it.

// ErrQuarantineUnsupported is returned where marking is not possible.
var ErrQuarantineUnsupported = errors.New("bu sistemde veya dosya sisteminde karantina işareti konamıyor")

// MarkQuarantine labels path as received from origin (a short text such
// as "openscale:<device>"; it is not a URL that anything fetches).
func MarkQuarantine(path, origin string) error {
	return markQuarantine(path, cleanOrigin(origin), time.Now())
}

// IsQuarantined reports whether path carries the mark.
func IsQuarantined(path string) bool { return isQuarantined(path) }

// cleanOrigin keeps printable ASCII without separators used by the
// formats above.
func cleanOrigin(s string) string {
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s) && len(b) < 128; i++ {
		c := s[i]
		if c < 0x21 || c > 0x7e || c == ';' || c == 0x5c || c == '"' {
			continue
		}
		b = append(b, c)
	}
	return string(b)
}
