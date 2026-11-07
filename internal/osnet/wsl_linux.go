//go:build linux

package osnet

// DetectWSL reports whether this Linux runs inside WSL. home is unused on
// Linux (the .wslconfig file lives on the Windows side).
func DetectWSL(string) WSLInfo {
	var w WSLInfo
	w.Inside, w.Version = ParseWSLKernel(string(readSmall("/proc/sys/kernel/osrelease")))
	w.Notes = WSLNotes(w)
	return w
}
