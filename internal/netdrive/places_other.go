//go:build !windows

package netdrive

import "errors"

// Network locations exist only in Windows Explorer (ADR-0226); elsewhere
// the attributes and the shell notification are no-ops so the logic can
// be tested on every system.

func setPlaceAttrs(string, string) error { return nil }

func clearPlaceAttrs(string) {}

func shellChanged(string) {}

// DefaultPlaces is available on Windows only.
func DefaultPlaces(func(path, target, description string) error) (*Places, error) {
	return nil, errors.Join(ErrUnsupported, errors.New("ağ konumları yalnızca Windows'ta var"))
}
