//go:build !windows

package piv

import (
	"context"
	"time"
)

// WaitReaderChange blocks until the reader list changes, timeout passes
// (false) or ctx ends. Outside Windows it lists the readers every half
// second: pcsclite's \\?PnP?\Notification is not available on macOS, and
// listing readers is cheap and sends nothing to a card (ADR-0171).
func WaitReaderChange(ctx context.Context, timeout time.Duration) (bool, error) {
	if timeout <= 0 {
		return false, nil
	}
	return pollReaderChange(ctx, timeout, 500*time.Millisecond)
}
