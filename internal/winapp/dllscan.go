package winapp

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// DLL and dylib planting check (#644, ADR-0195 section 5). Windows loads
// a DLL that a program imports by name from the program's own folder
// first; macOS and Linux can be steered the same way through
// @rpath/@loader_path or a writable library folder. The installed program
// folder must therefore hold only what OpenScale put there, and only an
// administrator (root) may write to it.
//
// The check runs at start for the service and the tray, and only for the
// installed copy (a program run from Downloads shares its folder with
// whatever else was downloaded; the per-process DLL search hardening of
// #518 covers that case).

// ErrPlantedLibrary: an unexpected library is in the program folder.
var ErrPlantedLibrary = errors.New("program klasöründe beklenmeyen kitaplık dosyası var")

// libraryExts are the shared library extensions.
var libraryExts = []string{".dll", ".dylib", ".so", ".ocx", ".cpl", ".drv"}

// expectedLibraries are the libraries OpenScale itself places next to the
// program (lower case).
var expectedLibraries = []string{"wintun.dll"}

// isLibrary reports whether name looks like a shared library.
func isLibrary(name string) bool {
	low := strings.ToLower(name)
	for _, ext := range libraryExts {
		if strings.HasSuffix(low, ext) || strings.Contains(low, ".so.") {
			return true
		}
	}
	return false
}

// UnexpectedLibraries lists the library files in dir that are not in the
// allow list (names compared case-insensitively, as Windows does).
func UnexpectedLibraries(dir string, allowed []string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	allow := make([]string, 0, len(allowed))
	for _, a := range allowed {
		allow = append(allow, strings.ToLower(a))
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || !isLibrary(e.Name()) {
			continue
		}
		if slices.Contains(allow, strings.ToLower(e.Name())) {
			continue
		}
		out = append(out, e.Name())
	}
	slices.Sort(out)
	return out, nil
}

// ownerTrusted: owned by root and not writable by group or others.
func ownerTrusted(uid uint32, perm os.FileMode) bool { return uid == 0 && perm&0o022 == 0 }

// PlantingReport is the start-up result.
type PlantingReport struct {
	Dir        string
	Installed  bool     // the program runs from its installed folder
	Unexpected []string // library files that should not be there
	PermErr    string   // the folder is writable by non-administrators
}

// Block reports whether the start must be refused.
func (r PlantingReport) Block() bool {
	return r.Installed && (len(r.Unexpected) > 0 || r.PermErr != "")
}

// Err describes a blocking report.
func (r PlantingReport) Err() error {
	if !r.Block() {
		return nil
	}
	var parts []string
	if len(r.Unexpected) > 0 {
		parts = append(parts, ErrPlantedLibrary.Error()+": "+strings.Join(r.Unexpected, ", "))
	}
	if r.PermErr != "" {
		parts = append(parts, "program klasörünün izinleri fazla geniş: "+r.PermErr)
	}
	if len(r.Unexpected) > 0 {
		return fmt.Errorf("%w: %s (%s); programı yeniden kurun veya dosyaları kaldırın", ErrPlantedLibrary, strings.Join(parts, "; "), r.Dir)
	}
	return fmt.Errorf("%s (%s); programı yeniden kurun", strings.Join(parts, "; "), r.Dir)
}

// CheckProgramFolder checks the folder of exe. installedDirs are the
// folders an installation uses (Windows InstallDir, /usr/local/bin,
// /usr/bin); outside them only a note is returned.
func CheckProgramFolder(exe string, installedDirs []string) PlantingReport {
	dir := filepath.Dir(exe)
	r := PlantingReport{Dir: dir}
	for _, d := range installedDirs {
		if d != "" && strings.EqualFold(filepath.Clean(d), filepath.Clean(dir)) {
			r.Installed = true
		}
	}
	if !r.Installed {
		return r
	}
	// /usr/bin and /usr/local/bin hold other programs, not libraries; any
	// library there is still unexpected for OpenScale's start.
	if list, err := UnexpectedLibraries(dir, expectedLibraries); err == nil {
		for _, name := range list {
			// Linux: the system's own files in /usr/bin (Ubuntu ships
			// /usr/bin/ld.so) are root's, as trusted as this program. A
			// static Go program loads no library from here anyway; what
			// still blocks is a library someone else could have written.
			if systemOwnedFile(filepath.Join(dir, name)) {
				continue
			}
			r.Unexpected = append(r.Unexpected, name)
		}
	}
	if err := checkFolderTrusted(exe); err != nil {
		r.PermErr = err.Error()
	}
	return r
}
