//go:build !windows

package filesend

// defenderCloud: Defender's command line tool exists only on Windows.
func defenderCloud() (on, known bool) { return false, false }
