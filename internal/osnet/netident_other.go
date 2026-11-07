//go:build !linux && !windows

package osnet

import "errors"

// CurrentNetworks is not implemented here; callers treat the error as an
// untrusted network (the exit node stays on).
func CurrentNetworks() ([]CurrentNetwork, error) {
	return nil, errors.New("ağ adı bu işletim sisteminde okunamıyor")
}
