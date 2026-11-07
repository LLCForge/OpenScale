//go:build !linux && !windows

package privsep

import (
	"errors"
	"os/exec"
)

// ErrUnsupported is returned where no helper isolation exists yet.
var ErrUnsupported = errors.New("ayrıcalık ayrımı bu sistemde desteklenmiyor")

// CurrentStatus is unknown on this system.
func CurrentStatus() Status { return Status{Summary: "bilinmiyor"} }

// Command is unsupported on this system.
func Command(string, []string, uint32, uint32) (*exec.Cmd, func(), error) {
	return nil, func() {}, ErrUnsupported
}

// Enter is unsupported on this system: the helper must not start
// believing it is isolated.
func Enter() error { return ErrUnsupported }
