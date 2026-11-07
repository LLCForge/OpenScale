//go:build !linux && !windows

package osnet

// DetectWSL finds nothing outside Windows and Linux.
func DetectWSL(string) WSLInfo { return WSLInfo{} }
