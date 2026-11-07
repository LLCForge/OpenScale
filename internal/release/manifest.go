package release

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"
)

const (
	manifestFormat      = "openscale-release-manifest-v1"
	signedReleaseFormat = "openscale-signed-release-v1"

	// Product is the only product name a manifest may carry.
	Product = "openscale"

	// MaxArtifacts bounds the number of files in one release.
	MaxArtifacts = 256
	// MaxArtifactSize bounds a single release file (4 GiB).
	MaxArtifactSize = 4 << 30
	maxNameLength   = 128
	maxBuildLength  = 64
)

// ErrNotInManifest is returned when a file is not part of the release.
var ErrNotInManifest = errors.New("file is not listed in the release manifest")

// ErrDigestMismatch is returned when a file's size or SHA-256 differs.
var ErrDigestMismatch = errors.New("file does not match the release manifest")

// Artifact is one release file, named by its base name.
type Artifact struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// Manifest lists every file of a release.
type Manifest struct {
	Format          string     `json:"format"`
	Product         string     `json:"product"`
	Version         string     `json:"version"`
	Build           string     `json:"build"`
	SourceDateEpoch int64      `json:"source_date_epoch"`
	Created         time.Time  `json:"created"`
	Artifacts       []Artifact `json:"artifacts"`
}

// SignedRelease is the release file: the signing key's certificate and the
// manifest signed by that key.
type SignedRelease struct {
	Format      string   `json:"format"`
	Certificate Envelope `json:"certificate"`
	Manifest    Envelope `json:"manifest"`
}

// NewManifest builds a manifest with the fixed format and product fields.
func NewManifest(version, build string, sourceDateEpoch int64, artifacts []Artifact) Manifest {
	a := slices.Clone(artifacts)
	slices.SortFunc(a, func(x, y Artifact) int { return strings.Compare(x.Name, y.Name) })
	return Manifest{
		Format:          manifestFormat,
		Product:         Product,
		Version:         version,
		Build:           build,
		SourceDateEpoch: sourceDateEpoch,
		Artifacts:       a,
	}
}

// HashArtifact reads r to the end and returns its artifact entry.
func HashArtifact(name string, r io.Reader) (Artifact, error) {
	if err := checkArtifactName(name); err != nil {
		return Artifact{}, err
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(r, MaxArtifactSize+1))
	if err != nil {
		return Artifact{}, fmt.Errorf("read %s: %w", name, err)
	}
	if n > MaxArtifactSize {
		return Artifact{}, fmt.Errorf("%s is larger than %d bytes", name, int64(MaxArtifactSize))
	}
	return Artifact{Name: name, Size: n, SHA256: hex.EncodeToString(h.Sum(nil))}, nil
}

// Lookup returns the artifact with the given base name.
func (m *Manifest) Lookup(name string) (Artifact, bool) {
	for _, a := range m.Artifacts {
		if a.Name == name {
			return a, true
		}
	}
	return Artifact{}, false
}

// CheckFile verifies that r has the size and SHA-256 recorded for name.
func (m *Manifest) CheckFile(name string, r io.Reader) error {
	want, ok := m.Lookup(name)
	if !ok {
		return fmt.Errorf("%s: %w", name, ErrNotInManifest)
	}
	h := sha256.New()
	// Read at most one byte past the expected size, so a huge file cannot
	// keep the verifier busy.
	n, err := io.Copy(h, io.LimitReader(r, want.Size+1))
	if err != nil {
		return fmt.Errorf("read %s: %w", name, err)
	}
	got := hex.EncodeToString(h.Sum(nil))
	if n != want.Size || subtle.ConstantTimeCompare([]byte(got), []byte(want.SHA256)) != 1 {
		return fmt.Errorf("%s: %w", name, ErrDigestMismatch)
	}
	return nil
}

// SHA256Sums renders the manifest in the format of `sha256sum` (two spaces,
// text mode), sorted by name.
func (m *Manifest) SHA256Sums() string {
	var b strings.Builder
	for _, a := range m.Artifacts {
		fmt.Fprintf(&b, "%s  %s\n", a.SHA256, a.Name)
	}
	return b.String()
}

func (m *Manifest) validate() error {
	switch {
	case m.Format != manifestFormat:
		return fmt.Errorf("unsupported manifest format %q", m.Format)
	case m.Product != Product:
		return fmt.Errorf("manifest is for product %q, not %q", m.Product, Product)
	case m.Created.IsZero():
		return errors.New("manifest has no creation time")
	case m.SourceDateEpoch < 0:
		return errors.New("negative source date epoch")
	case len(m.Build) > maxBuildLength || !isToken(m.Build):
		return errors.New("manifest build is too long or has invalid characters")
	case len(m.Artifacts) == 0 || len(m.Artifacts) > MaxArtifacts:
		return fmt.Errorf("manifest must list 1-%d artifacts", MaxArtifacts)
	}
	if _, err := ParseVersion(m.Version); err != nil {
		return err
	}
	seen := make(map[string]struct{}, len(m.Artifacts))
	for i, a := range m.Artifacts {
		if err := checkArtifactName(a.Name); err != nil {
			return fmt.Errorf("artifact %d: %w", i, err)
		}
		// Names are compared case-insensitively: on Windows and macOS two
		// entries differing only in case would name the same file.
		key := strings.ToLower(a.Name)
		if _, dup := seen[key]; dup {
			return fmt.Errorf("artifact %s is listed twice", a.Name)
		}
		seen[key] = struct{}{}
		if a.Size < 0 || a.Size > MaxArtifactSize {
			return fmt.Errorf("artifact %s has an invalid size", a.Name)
		}
		if len(a.SHA256) != sha256.Size*2 || !isLowerHex(a.SHA256) {
			return fmt.Errorf("artifact %s has an invalid sha256", a.Name)
		}
	}
	return nil
}

// checkArtifactName accepts plain base names only, so a manifest can never
// direct a verifier or installer outside its directory.
func checkArtifactName(name string) error {
	if name == "" || len(name) > maxNameLength {
		return errors.New("artifact name is empty or too long")
	}
	if name[0] == '.' || name[0] == '-' || strings.Contains(name, "..") {
		return fmt.Errorf("artifact name %q is not allowed", name)
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-' || r == '+') {
			return fmt.Errorf("artifact name %q has invalid characters", name)
		}
	}
	return nil
}

func isToken(s string) bool {
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '+') {
			return false
		}
	}
	return true
}

func isLowerHex(s string) bool {
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}
