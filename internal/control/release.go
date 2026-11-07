package control

import "strings"

// Release mirror (ADR-0225): the coordinator serves the owner's signed
// release files inside the tunnel and announces the newest version it holds.
// It is only a mirror; every device verifies the signed manifest itself
// (internal/updater) and installs nothing it cannot verify.
//
// Compatibility. Decode refuses unknown fields, so an old device would drop
// any message carrying File or Release. Both fields appear only in requests
// and replies of TypeRelease and TypeReleaseFile, which only new devices
// send; old devices never receive them, and they are never pushed. An old
// coordinator answers TypeRelease with "unknown message type" (its request
// carries no new field); a device sends TypeReleaseFile, whose request does
// carry File, only after a TypeRelease reply, so an old coordinator never
// sees it.
const (
	// TypeRelease asks for the announcement. The reply carries the version
	// in Release, the manifest's file name in File and its SHA-256 (hex) and
	// size in Digest and Size. An empty Release means nothing is published.
	TypeRelease = "rel"
	// TypeReleaseFile fetches one chunk of a mirrored file: the request
	// carries File, the announced manifest Digest (which binds the chunk to
	// one publication) and Offset; the reply carries the chunk in Data and
	// the file size in Total.
	TypeReleaseFile = "relf"
	// FeatureRelease is listed in a TypeCaps reply by coordinators that
	// understand both types.
	FeatureRelease = "rel"
)

// Limits of the release fields.
const (
	// MaxReleaseFileName bounds File.
	MaxReleaseFileName = 96
	// MaxReleaseVersion bounds Release.
	MaxReleaseVersion = 64
	// MaxReleaseSource bounds Source.
	MaxReleaseSource = 160
)

// ValidReleaseFileName accepts the base names a mirror may serve: letters,
// digits and "._~-", no path separator, no leading dot or dash.
func ValidReleaseFileName(name string) bool {
	if name == "" || len(name) > MaxReleaseFileName || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "-") || strings.Contains(name, "..") {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '~', r == '-':
		default:
			return false
		}
	}
	return true
}

func validReleaseFields(m Message) bool {
	if m.File != "" && !ValidReleaseFileName(m.File) {
		return false
	}
	if len(m.Release) > MaxReleaseVersion || len(m.Source) > MaxReleaseSource || m.Checked < 0 {
		return false
	}
	for _, r := range m.Release + m.Source {
		if r < '!' || r > '~' {
			return false
		}
	}
	return true
}
