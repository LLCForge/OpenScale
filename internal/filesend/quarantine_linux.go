//go:build linux

package filesend

import (
	"time"

	"golang.org/x/sys/unix"
)

const (
	xattrOrigin     = "user.xdg.origin.url"
	xattrQuarantine = "user.openscale.quarantine"
)

func markQuarantine(path, origin string, now time.Time) error {
	if err := unix.Setxattr(path, xattrQuarantine, []byte(now.UTC().Format(time.RFC3339)), 0); err != nil {
		return ErrQuarantineUnsupported
	}
	if origin != "" {
		_ = unix.Setxattr(path, xattrOrigin, []byte(origin), 0)
	}
	return nil
}

func isQuarantined(path string) bool {
	buf := make([]byte, 64)
	n, err := unix.Getxattr(path, xattrQuarantine, buf)
	return err == nil && n > 0
}
