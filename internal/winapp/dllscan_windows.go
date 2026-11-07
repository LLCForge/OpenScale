//go:build windows

package winapp

// checkFolderTrusted: only SYSTEM, Administrators and TrustedInstaller
// may change the program or add files to its folder (F-124).
func checkFolderTrusted(exe string) error { return CheckTrustedPath(exe) }

// systemOwnedFile: on Windows every unexpected DLL blocks, whoever wrote
// it; the program folder is OpenScale's alone.
func systemOwnedFile(string) bool { return false }

// InstalledProgramDirs are the folders of an installed program.
func InstalledProgramDirs() []string { return []string{InstallDir()} }
