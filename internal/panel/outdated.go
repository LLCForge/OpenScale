package panel

import (
	"strconv"
	"strings"

	"github.com/openscale/openscale/internal/version"
)

// Outdated device warning (F-153, #310): every device reports its
// OpenScale version with its system report; the panel compares it with
// the version of the computer it runs on (the owner's) and marks devices
// that are behind.

// referenceVersion is this program's release; tests replace it.
var referenceVersion = func() string { return version.Version }

// parseRelease reads "1.2.3", "v1.2.3" or "1.2.3-rc1" (the suffix is
// ignored). ok is false for anything else, such as development builds.
func parseRelease(s string) ([3]int, bool) {
	var out [3]int
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	if i := strings.IndexAny(s, "-+ "); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 1_000_000 {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

// olderRelease reports whether device is an older release than ref. Dev
// builds and unreadable versions are never called outdated.
func olderRelease(device, ref string) bool {
	d, ok1 := parseRelease(device)
	r, ok2 := parseRelease(ref)
	if !ok1 || !ok2 || strings.Contains(ref, "dev") || strings.Contains(device, "dev") {
		return false
	}
	for i := range d {
		if d[i] != r[i] {
			return d[i] < r[i]
		}
	}
	return false
}

// markOutdated fills systemView.Outdated.
func markOutdated(v *systemView) {
	if v == nil {
		return
	}
	ref := referenceVersion()
	if olderRelease(v.Version, ref) {
		v.Outdated, v.Latest = true, ref
	}
}
