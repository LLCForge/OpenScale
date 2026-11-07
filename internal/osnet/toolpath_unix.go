//go:build !windows

package osnet

import "io/fs"

// toolDirs are root-owned system folders; /run/current-system/sw/bin is
// NixOS's read-only profile.
func toolDirs() []string {
	return []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin", "/run/current-system/sw/bin", "/usr/local/sbin", "/usr/local/bin"}
}

func toolFileNames(name string) []string { return []string{name} }

func executableMode(m fs.FileMode) bool { return m&0o111 != 0 }

// toolEnv is a fixed environment: a system PATH for the tools' own
// helpers, the C locale so output is parsed in English, and nothing the
// caller's shell or an installer left behind.
func toolEnv() []string {
	return []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
}
