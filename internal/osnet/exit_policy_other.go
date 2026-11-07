//go:build !linux

package osnet

import (
	"context"
	"errors"
	"net/netip"
)

// ErrExitNotActive is returned by SetExitQuotaBlocked while this host is
// not an exit node.
var ErrExitNotActive = errors.New("çıkış düğümü kuralları kurulu değil")

// SetExitQuotaBlocked is Linux only (#401).
func SetExitQuotaBlocked(context.Context, []netip.Addr) error { return ErrExitUnsupported }
