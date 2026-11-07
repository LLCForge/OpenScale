package release

import (
	"cmp"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ErrRollback is returned when a release is older than the installed one.
var ErrRollback = errors.New("release is older than the installed version")

const maxVersionLength = 64

// Version is a Semantic Versioning 2.0.0 version. Build metadata ("+...")
// is accepted and ignored for ordering.
type Version struct {
	Major, Minor, Patch uint64
	Pre                 []string
}

// ParseVersion parses MAJOR.MINOR.PATCH[-PRERELEASE][+BUILD].
func ParseVersion(s string) (Version, error) {
	var v Version
	if s == "" || len(s) > maxVersionLength {
		return v, fmt.Errorf("invalid version %q", s)
	}
	core := s
	if i := strings.IndexByte(core, '+'); i >= 0 {
		if !validIdentifiers(core[i+1:], false) {
			return v, fmt.Errorf("invalid build metadata in version %q", s)
		}
		core = core[:i]
	}
	if i := strings.IndexByte(core, '-'); i >= 0 {
		pre := core[i+1:]
		if !validIdentifiers(pre, true) {
			return v, fmt.Errorf("invalid pre-release in version %q", s)
		}
		v.Pre = strings.Split(pre, ".")
		core = core[:i]
	}
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return Version{}, fmt.Errorf("version %q must look like 1.2.3", s)
	}
	nums := [3]*uint64{&v.Major, &v.Minor, &v.Patch}
	for i, p := range parts {
		if !isNumeric(p) || (len(p) > 1 && p[0] == '0') {
			return Version{}, fmt.Errorf("version %q must look like 1.2.3", s)
		}
		n, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			return Version{}, fmt.Errorf("version %q: %w", s, err)
		}
		*nums[i] = n
	}
	return v, nil
}

// Compare orders versions by SemVer precedence: -1, 0 or +1.
func (v Version) Compare(o Version) int {
	if c := cmp.Compare(v.Major, o.Major); c != 0 {
		return c
	}
	if c := cmp.Compare(v.Minor, o.Minor); c != 0 {
		return c
	}
	if c := cmp.Compare(v.Patch, o.Patch); c != 0 {
		return c
	}
	// A version without pre-release has higher precedence.
	switch {
	case len(v.Pre) == 0 && len(o.Pre) == 0:
		return 0
	case len(v.Pre) == 0:
		return 1
	case len(o.Pre) == 0:
		return -1
	}
	for i := 0; i < len(v.Pre) && i < len(o.Pre); i++ {
		a, b := v.Pre[i], o.Pre[i]
		an, bn := isNumeric(a), isNumeric(b)
		switch {
		case an && bn:
			if c := cmp.Compare(len(a), len(b)); c != 0 { // no leading zeros, so longer is larger
				return c
			}
			if c := strings.Compare(a, b); c != 0 {
				return c
			}
		case an:
			return -1
		case bn:
			return 1
		default:
			if c := strings.Compare(a, b); c != 0 {
				return c
			}
		}
	}
	return cmp.Compare(len(v.Pre), len(o.Pre))
}

// CompareVersions parses and compares two version strings.
func CompareVersions(a, b string) (int, error) {
	va, err := ParseVersion(a)
	if err != nil {
		return 0, err
	}
	vb, err := ParseVersion(b)
	if err != nil {
		return 0, err
	}
	return va.Compare(vb), nil
}

// CheckUpgrade is the rollback protection: it refuses a candidate release
// older than the installed version unless allowDowngrade is set. Installing
// the same version again is allowed.
func CheckUpgrade(installed, candidate string, allowDowngrade bool) error {
	c, err := CompareVersions(candidate, installed)
	if err != nil {
		return err
	}
	if c < 0 && !allowDowngrade {
		return fmt.Errorf("%w: %s < %s", ErrRollback, candidate, installed)
	}
	return nil
}

func validIdentifiers(s string, noLeadingZero bool) bool {
	if s == "" {
		return false
	}
	for _, id := range strings.Split(s, ".") {
		if id == "" {
			return false
		}
		for _, r := range id {
			if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r == '-') {
				return false
			}
		}
		if noLeadingZero && isNumeric(id) && len(id) > 1 && id[0] == '0' {
			return false
		}
	}
	return true
}

func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
