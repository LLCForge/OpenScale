//go:build !windows

package winapp

// DataDirProblem is Windows only; elsewhere file modes are checked.
func DataDirProblem(string) error { return nil }
