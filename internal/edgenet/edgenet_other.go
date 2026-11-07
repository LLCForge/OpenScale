//go:build !linux && !windows

package edgenet

func neighbors() []Neighbor { return nil }

func meteredHint() (bool, bool) { return false, false }
