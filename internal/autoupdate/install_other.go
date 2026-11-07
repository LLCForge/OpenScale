//go:build !windows && !linux

package autoupdate

import (
	"context"
	"errors"

	"github.com/openscale/openscale/internal/updater"
)

func packageOptions() (updater.PackageOptions, error) {
	return updater.PackageOptions{}, errors.New("bu işletim sisteminde otomatik güncelleme desteklenmiyor")
}

// Trigger is nil: nothing is installed here.
func Trigger(string) func(context.Context) error { return nil }
