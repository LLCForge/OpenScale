package osnet

import (
	"bufio"
	"bytes"
	"strings"
)

// Operating system build tracking (#498). Feature updates of Windows are
// known to reset firewall rules, NRPT entries and WFP filters without a
// word; a kernel or distribution upgrade on Linux can change nftables and
// the resolver. The service remembers the build it last ran on and, when
// it changes, checks and repairs what OpenScale put in place
// (internal/service/platform_p10.go).

// OSBuild identifies the running operating system build.
type OSBuild struct {
	// Family is "windows", "linux", "darwin" and so on.
	Family string `json:"family"`
	// Version is the release: "10.0" on Windows, "debian 12" on Linux.
	Version string `json:"version,omitempty"`
	// Build is the build number on Windows and the kernel release on Linux.
	Build string `json:"build,omitempty"`
	// Patch is the update revision (Windows UBR); a change here alone is a
	// monthly update, not a feature update.
	Patch string `json:"patch,omitempty"`
	// Edition is "Server Core", "Server" or "Client" on Windows (#493).
	Edition string `json:"edition,omitempty"`
}

// Known reports whether anything identifying was read.
func (b OSBuild) Known() bool { return b.Family != "" && (b.Version != "" || b.Build != "") }

// Key is what a major update changes: family, version and build, not the
// patch level.
func (b OSBuild) Key() string { return b.Family + "|" + b.Version + "|" + b.Build }

// String is a short human readable form.
func (b OSBuild) String() string {
	parts := []string{b.Family}
	if b.Version != "" {
		parts = append(parts, b.Version)
	}
	if b.Build != "" {
		parts = append(parts, b.Build)
	}
	s := strings.Join(parts, " ")
	if b.Patch != "" {
		s += "." + b.Patch
	}
	return s
}

// MajorChange reports whether going from prev to b is a feature update or
// an upgrade that warrants the full repair. An unknown previous build is
// not a change (first start).
func (b OSBuild) MajorChange(prev OSBuild) bool {
	return prev.Known() && b.Known() && prev.Key() != b.Key()
}

// parseOSRelease returns ID and VERSION_ID from an os-release file.
func parseOSRelease(data []byte) (id, version string) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		switch k {
		case "ID":
			id = cleanBuildField(v)
		case "VERSION_ID":
			version = cleanBuildField(v)
		}
	}
	return id, version
}

// cleanBuildField keeps printable ASCII and bounds the length, so a
// strange file cannot put control characters into logs or JSON.
func cleanBuildField(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r > 0x7e {
			continue
		}
		b.WriteRune(r)
		if b.Len() >= 64 {
			break
		}
	}
	return strings.TrimSpace(b.String())
}
