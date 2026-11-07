package release

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// Signed security advisories (#582, ADR-0149). The release root key signs a
// list that says which versions carry which known vulnerability. There is
// no automatic check (R-29, ADR-0008): the owner downloads the file by hand
// and imports it, and the verifier only compares it with versions it
// already knows. Like the revocation list, a higher Sequence replaces an
// older list, so a stale list cannot be replayed to hide a newer advisory.

// ContextAdvisories is the signature context of an advisory list.
const ContextAdvisories = "openscale/release-advisories/v1"

const (
	advisoriesFormat = "openscale-security-advisories-v1"
	// MaxAdvisories bounds the advisory list.
	MaxAdvisories = 1024
	// MaxAdvisoriesSize bounds a signed advisory file.
	MaxAdvisoriesSize = 2 << 20
	maxAdvisoryID     = 32
	maxSummaryLength  = 2000
)

// Advisory severities.
const (
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// Advisory is one known vulnerability.
type Advisory struct {
	// ID is the owner's identifier, for example OSA-2026-0001.
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Summary  string `json:"summary,omitempty"`
	// Introduced is the first affected version; Fixed the first version
	// without the problem, or empty when there is no fix yet.
	Introduced string    `json:"introduced"`
	Fixed      string    `json:"fixed,omitempty"`
	Published  time.Time `json:"published"`
}

// Advisories is a root-signed advisory list.
type Advisories struct {
	Format     string     `json:"format"`
	RootKey    PublicKey  `json:"root_key"`
	Sequence   uint64     `json:"sequence"`
	Issued     time.Time  `json:"issued"`
	Advisories []Advisory `json:"advisories"`
}

// ErrStaleAdvisories is returned for a list older than one already seen.
var ErrStaleAdvisories = errors.New("advisory list is older than the one already imported")

// SignAdvisories signs a list with the release root key. Format, RootKey
// and Issued are filled in.
func SignAdvisories(rootPriv ed25519.PrivateKey, a Advisories, now time.Time) ([]byte, error) {
	if len(rootPriv) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid root private key")
	}
	root, err := PublicKeyFrom(rootPriv.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, err
	}
	a.Format = advisoriesFormat
	a.RootKey = root
	a.Issued = now.UTC().Truncate(time.Second)
	if a.Advisories == nil {
		a.Advisories = []Advisory{}
	}
	for i := range a.Advisories {
		a.Advisories[i].Published = a.Advisories[i].Published.UTC().Truncate(time.Second)
	}
	if err := a.validate(); err != nil {
		return nil, err
	}
	payload, err := marshalIndent(a)
	if err != nil {
		return nil, fmt.Errorf("encode advisories: %w", err)
	}
	env, err := sign(rootPriv, ContextAdvisories, payload)
	if err != nil {
		return nil, err
	}
	out, err := marshalIndent(env)
	if err != nil {
		return nil, err
	}
	if len(out) > MaxAdvisoriesSize {
		return nil, errors.New("advisory list is too large")
	}
	return out, nil
}

// VerifyAdvisories checks a signed advisory list against the root key.
// minSequence is the sequence of the list imported before (0 for none).
func VerifyAdvisories(root PublicKey, data []byte, minSequence uint64) (*Advisories, error) {
	if len(data) > MaxAdvisoriesSize {
		return nil, errors.New("advisory list is too large")
	}
	var env Envelope
	if err := decodeStrict(data, &env); err != nil {
		return nil, fmt.Errorf("decode advisory list: %w", err)
	}
	payload, err := env.verify(root, ContextAdvisories)
	if err != nil {
		return nil, fmt.Errorf("advisory list: %w", err)
	}
	var a Advisories
	if err := decodeStrict(payload, &a); err != nil {
		return nil, fmt.Errorf("decode advisory list: %w", err)
	}
	if err := a.validate(); err != nil {
		return nil, err
	}
	if !a.RootKey.Equal(root) {
		return nil, errors.New("advisory list names a different root key")
	}
	if a.Sequence < minSequence {
		return nil, ErrStaleAdvisories
	}
	return &a, nil
}

// Affecting returns the advisories that apply to version. An unparsable
// version is an error, never "not affected".
func (a *Advisories) Affecting(version string) ([]Advisory, error) {
	v, err := ParseVersion(version)
	if err != nil {
		return nil, err
	}
	var out []Advisory
	for _, adv := range a.Advisories {
		intro, _ := ParseVersion(adv.Introduced) // validated
		if v.Compare(intro) < 0 {
			continue
		}
		if adv.Fixed != "" {
			fixed, _ := ParseVersion(adv.Fixed)
			if v.Compare(fixed) >= 0 {
				continue
			}
		}
		out = append(out, adv)
	}
	return out, nil
}

func (a *Advisories) validate() error {
	switch {
	case a.Format != advisoriesFormat:
		return fmt.Errorf("unsupported advisory list format %q", a.Format)
	case a.RootKey.IsZero():
		return errors.New("advisory list root key is missing")
	case a.Sequence == 0:
		return errors.New("advisory list sequence must start at 1")
	case a.Issued.IsZero():
		return errors.New("advisory list has no issue time")
	case len(a.Advisories) > MaxAdvisories:
		return fmt.Errorf("advisory list exceeds %d entries", MaxAdvisories)
	}
	seen := map[string]bool{}
	for i, adv := range a.Advisories {
		if err := adv.validate(); err != nil {
			return fmt.Errorf("advisory %d: %w", i, err)
		}
		if seen[adv.ID] {
			return fmt.Errorf("advisory %s is listed twice", adv.ID)
		}
		seen[adv.ID] = true
	}
	return nil
}

func (adv *Advisory) validate() error {
	if adv.ID == "" || len(adv.ID) > maxAdvisoryID {
		return errors.New("id is empty or too long")
	}
	for _, r := range adv.ID {
		if !(r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
			return fmt.Errorf("id %q may only hold A-Z, 0-9 and -", adv.ID)
		}
	}
	switch adv.Severity {
	case SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
	default:
		return fmt.Errorf("unknown severity %q", adv.Severity)
	}
	if strings.TrimSpace(adv.Title) == "" || len(adv.Title) > maxCommentLength || !utf8.ValidString(adv.Title) || hasControl(adv.Title) {
		return errors.New("title is empty, too long or not printable")
	}
	if len(adv.Summary) > maxSummaryLength || !utf8.ValidString(adv.Summary) || hasControlExceptNewline(adv.Summary) {
		return errors.New("summary is too long or not printable")
	}
	intro, err := ParseVersion(adv.Introduced)
	if err != nil {
		return fmt.Errorf("introduced: %w", err)
	}
	if adv.Fixed != "" {
		fixed, err := ParseVersion(adv.Fixed)
		if err != nil {
			return fmt.Errorf("fixed: %w", err)
		}
		if fixed.Compare(intro) <= 0 {
			return errors.New("fixed version must be newer than the introduced version")
		}
	}
	if adv.Published.IsZero() {
		return errors.New("publication time is missing")
	}
	return nil
}

func hasControlExceptNewline(s string) bool {
	for _, r := range s {
		if (r < 0x20 && r != '\n') || r == 0x7f {
			return true
		}
	}
	return false
}
