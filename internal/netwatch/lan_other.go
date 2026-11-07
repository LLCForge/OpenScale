//go:build !linux && !windows && !darwin

package netwatch

func readNeighbors() []Neighbor { return nil }
