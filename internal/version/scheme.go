package version

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Version scheme (ADR-0193). Releases are MAJOR.MINOR.PATCH with an
// optional "-beta.N" pre-release:
//
//   - MINOR runs from 0 to 9; the minor release after x.9 is (x+1).0.0
//     (0.9 -> 1.0, 1.9 -> 2.0).
//   - PATCH counts fixes on a minor line.
//   - beta.N marks a pre-release; the updater installs one only when the
//     user chose the beta channel.

// MaxMinor is the last minor number of a major line.
const MaxMinor = 9

// Channel names.
const (
	ChannelStable = "stable"
	ChannelBeta   = "beta"
	ChannelDev    = "dev"
)

// Bump kinds.
const (
	BumpMinor   = "minor"
	BumpPatch   = "patch"
	BumpBeta    = "beta"
	BumpRelease = "release"
)

// ErrScheme is returned for versions outside the scheme.
var ErrScheme = errors.New("sürüm şemaya uymuyor (MAJOR.MINOR.PATCH, MINOR 0-9, isteğe bağlı -beta.N)")

// Semver is a parsed version of the scheme.
type Semver struct {
	Major, Minor, Patch int
	// Beta is N of "-beta.N"; zero means a final release.
	Beta int
	// Dev marks the "-dev" build of an unreleased tree.
	Dev bool
}

const maxComponent = 1_000_000

// Parse reads a version of the scheme; build metadata after "+" or a
// space ("1.0.0 (20261030.0412)") is ignored.
func Parse(s string) (Semver, error) {
	var v Semver
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "+ "); i >= 0 {
		s = s[:i]
	}
	if s == "" || len(s) > 64 {
		return v, ErrScheme
	}
	core, pre, hasPre := strings.Cut(s, "-")
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return v, ErrScheme
	}
	nums := [3]*int{&v.Major, &v.Minor, &v.Patch}
	for i, p := range parts {
		n, err := number(p)
		if err != nil {
			return Semver{}, ErrScheme
		}
		*nums[i] = n
	}
	if v.Minor > MaxMinor {
		return Semver{}, fmt.Errorf("%w: ara sürüm %d, en çok %d", ErrScheme, v.Minor, MaxMinor)
	}
	if hasPre {
		switch {
		case pre == "dev":
			v.Dev = true
		case strings.HasPrefix(pre, "beta."):
			n, err := number(strings.TrimPrefix(pre, "beta."))
			if err != nil || n == 0 {
				return Semver{}, ErrScheme
			}
			v.Beta = n
		default:
			return Semver{}, ErrScheme
		}
	}
	return v, nil
}

func number(p string) (int, error) {
	if p == "" || len(p) > 7 || (len(p) > 1 && p[0] == '0') {
		return 0, ErrScheme
	}
	for _, c := range p {
		if c < '0' || c > '9' {
			return 0, ErrScheme
		}
	}
	n, err := strconv.Atoi(p)
	if err != nil || n >= maxComponent {
		return 0, ErrScheme
	}
	return n, nil
}

// String formats the version.
func (v Semver) String() string {
	s := fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
	switch {
	case v.Dev:
		s += "-dev"
	case v.Beta > 0:
		s += fmt.Sprintf("-beta.%d", v.Beta)
	}
	return s
}

// Channel is stable, beta or dev.
func (v Semver) Channel() string {
	switch {
	case v.Dev:
		return ChannelDev
	case v.Beta > 0:
		return ChannelBeta
	}
	return ChannelStable
}

// nextMinor applies the 0-9 rule.
func (v Semver) nextMinor() Semver {
	if v.Minor >= MaxMinor {
		return Semver{Major: v.Major + 1}
	}
	return Semver{Major: v.Major, Minor: v.Minor + 1}
}

// Bump returns the next version of the given kind:
//
//	minor:   1.3.2 -> 1.4.0, 1.9.4 -> 2.0.0, 1.0.0-beta.2 -> 1.1.0
//	patch:   1.3.2 -> 1.3.3, 1.0.0-beta.2 -> 1.0.1
//	beta:    1.0.0-beta.1 -> 1.0.0-beta.2, 1.3.2 -> 1.4.0-beta.1,
//	         1.9.0 -> 2.0.0-beta.1
//	release: 1.0.0-beta.3 -> 1.0.0 (only from a beta)
func Bump(current, kind string) (string, error) {
	v, err := Parse(current)
	if err != nil {
		return "", err
	}
	if v.Major >= maxComponent-1 || v.Patch >= maxComponent-1 || v.Beta >= maxComponent-1 {
		return "", ErrScheme
	}
	var n Semver
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case BumpMinor:
		n = v.nextMinor()
	case BumpPatch:
		n = Semver{Major: v.Major, Minor: v.Minor, Patch: v.Patch + 1}
	case BumpBeta:
		if v.Beta > 0 {
			n = v
			n.Beta++
		} else {
			n = v.nextMinor()
			n.Beta = 1
		}
	case BumpRelease:
		if v.Beta == 0 && !v.Dev {
			return "", fmt.Errorf("%s zaten kararlı bir sürüm", current)
		}
		n = Semver{Major: v.Major, Minor: v.Minor, Patch: v.Patch}
	default:
		return "", fmt.Errorf("bilinmeyen artırma türü %q (minor, patch, beta, release)", kind)
	}
	return n.String(), nil
}

// Channel returns the channel of the running program.
func Channel() string {
	v, err := Parse(Version)
	if err != nil {
		return ChannelDev
	}
	return v.Channel()
}

// Label is the version with a Turkish channel note for people:
// "1.0.0-beta.1 (Beta 1, önsürüm)", "1.0.0", "0.0.0-dev (geliştirme)".
func Label(s string) string {
	v, err := Parse(s)
	if err != nil {
		return s
	}
	switch {
	case v.Dev:
		return v.String() + " (geliştirme)"
	case v.Beta > 0:
		return fmt.Sprintf("%s (Beta %d, önsürüm)", v.String(), v.Beta)
	}
	return v.String()
}

// Display is the running program's Label with the build, for the
// application window, the tray and "openscale version".
func Display() string {
	l := Label(Version)
	if Build == "" {
		return l
	}
	return l + " [" + Build + "]"
}
