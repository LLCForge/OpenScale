//go:build windows

package updater

import (
	"errors"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

// busyWait bounds how long a rename or remove waits on Windows. A program
// that was just written or run stays open for a moment: a virus scanner
// reads it and the system lets go of its image late. The service is
// already stopped when this waits, so the bound is also added downtime.
const busyWait = 5 * time.Second

func isBusy(err error) bool {
	return errors.Is(err, windows.ERROR_SHARING_VIOLATION) ||
		errors.Is(err, windows.ERROR_LOCK_VIOLATION) ||
		errors.Is(err, windows.ERROR_ACCESS_DENIED)
}

func retryBusy(op func() error) error {
	deadline := time.Now().Add(busyWait)
	delay := 20 * time.Millisecond
	for {
		err := op()
		if err == nil || !isBusy(err) || time.Now().After(deadline) {
			return err
		}
		time.Sleep(delay)
		if delay < 500*time.Millisecond {
			delay *= 2
		}
	}
}

func renameBusy(from, to string) error {
	return retryBusy(func() error { return os.Rename(from, to) })
}

func removeBusy(path string) error {
	return retryBusy(func() error { return os.Remove(path) })
}
