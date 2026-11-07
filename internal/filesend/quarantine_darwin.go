//go:build darwin

package filesend

import (
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

const appleQuarantine = "com.apple.quarantine"

// markQuarantine writes the attribute in the form Gatekeeper reads:
// flags;hex time;agent;event id. 0083 is "downloaded, not yet approved".
func markQuarantine(path, origin string, now time.Time) error {
	v := fmt.Sprintf("0083;%08x;OpenScale;%s", now.Unix(), origin)
	if err := unix.Setxattr(path, appleQuarantine, []byte(v), 0); err != nil {
		return ErrQuarantineUnsupported
	}
	return nil
}

func isQuarantined(path string) bool {
	buf := make([]byte, 256)
	n, err := unix.Getxattr(path, appleQuarantine, buf)
	return err == nil && n > 0
}
