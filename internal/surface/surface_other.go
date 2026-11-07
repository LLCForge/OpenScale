//go:build !linux && !windows

package surface

func own() ([]Socket, bool) { return nil, false }
