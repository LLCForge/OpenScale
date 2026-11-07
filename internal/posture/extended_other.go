//go:build !windows && !linux && !darwin

package posture

func collectExtended() Extended { return Extended{} }
