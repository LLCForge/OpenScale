package cli

import "github.com/openscale/openscale/internal/version"

// versionText is what "openscale version" prints: the version with the
// beta label (ADR-0193), e.g. "1.0.0-beta.1 (Beta 1, önsürüm) [20261030.0412]".
// "version --json" keeps the plain version for the updater.
func versionText() string {
	if Version != version.String() {
		// Tests and builds that set cli.Version directly.
		return version.Label(Version)
	}
	return version.Display()
}
