// Package version holds the program version. scripts/release.sh sets both
// values from the VERSION file at build time with -ldflags "-X ...".
package version

// Version is the OpenScale release, e.g. "0.8.0".
var Version = "0.0.0-dev"

// Build identifies the exact build (UTC date and time), e.g. "20261030.0412".
var Build = ""

// String returns "0.8.0 (20261030.0412)" or just the version.
func String() string {
	if Build == "" {
		return Version
	}
	return Version + " (" + Build + ")"
}
