// Package autoupdate keeps a device on the newest release its owner
// published on the coordinator (ADR-0225).
//
// The coordinator is untrusted. It is only a mirror: it announces the
// version it holds and serves the files inside the tunnel. The device
// decides: it fetches the signed manifest, verifies it with the release
// root key, the revocation list, the beta channel and the rollback rule
// (internal/updater), waits a random delay so that devices do not restart
// together, fetches its program or package, checks it against the manifest
// and hands it to a privileged installer that verifies everything again
// and runs the existing update with rollback. Nothing is installed that does
// not verify, and with no release root key nothing is installed at all.
package autoupdate

import (
	"fmt"
	"strings"

	"github.com/openscale/openscale/internal/updater"
)

// Install modes.
const (
	// ModeBinary replaces the installed program (updater.Apply).
	ModeBinary = "binary"
	// ModeDeb installs the Debian package with dpkg (updater.ApplyPackage).
	ModeDeb = "deb"
)

// Files.
const (
	// SettingsFile is the per-device switch, in the administrator-only
	// update folder.
	SettingsFile = "autoupdate.json"
	// StatusFile, RequestFile, TakenFile and ResultFile live in Paths.Work.
	StatusFile  = "status.json"
	RequestFile = "request.json"
	TakenFile   = "request.taken"
	ResultFile  = "result.json"
	// CacheDir holds the downloaded release in Paths.Work.
	CacheDir = "cache"
)

// Paths are where this installation keeps its settings and work files.
type Paths struct {
	// Supported is false where automatic updates cannot run; Reason says why.
	Supported bool
	Reason    string
	// Mode is ModeBinary or ModeDeb; Exe the installed program.
	Mode string
	Exe  string
	// UpdaterState is the updater's folder (journal, channel, revocations).
	UpdaterState string
	// Settings is the switch file.
	Settings string
	// Work is writable by the device process: status, cache, request.
	Work string
}

// ArtifactFor returns the manifest name of what this installation needs for
// version and the name the coordinator's mirror serves it under; compressed
// tells that the mirror file is gzip.
func ArtifactFor(mode, goos, goarch, version string) (artifact, mirror string, compressed bool, err error) {
	switch mode {
	case ModeBinary:
		a, err := updater.ArtifactName(goos, goarch)
		if err != nil {
			return "", "", false, err
		}
		return a, a + ".gz", true, nil
	case ModeDeb:
		arch := ""
		switch {
		case goos == "linux" && (goarch == "amd64" || goarch == "arm64"):
			arch = goarch
		case goos == "linux" && goarch == "arm":
			arch = "armhf"
		default:
			return "", "", false, fmt.Errorf("%s/%s için Debian paketi yayımlanmıyor", goos, goarch)
		}
		// scripts/release.sh: dpkg sorts "~" before the release.
		name := "openscale_" + strings.ReplaceAll(version, "-", "~") + "_" + arch + ".deb"
		return name, name, false, nil
	}
	return "", "", false, fmt.Errorf("bilinmeyen kurulum biçimi %q", mode)
}
