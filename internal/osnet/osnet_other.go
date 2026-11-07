//go:build !linux && !windows && !freebsd && !openbsd && !darwin

package osnet

import (
	"context"
	"errors"
)

func configure(context.Context, Config) error {
	return errors.New("interface configuration is only implemented for Linux and Windows")
}
