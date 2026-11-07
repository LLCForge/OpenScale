package release

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// Independent reproduction witness (#581, ADR-0148). A second machine,
// which does not hold the release keys, rebuilds the release from the same
// source and signs what it got with its own witness key: the digest of the
// exact signed manifest and the size and SHA-256 of every file it
// reproduced. A verifier that pins the witness key then knows that two
// machines produced the same bytes, so taking over the one build machine
// is no longer enough to ship a changed program. The release manifest
// itself is unchanged: the witness is a separate file next to it.

// ContextWitness is the signature context of a witness statement.
const ContextWitness = "openscale/release-witness/v1"

// RoleWitness is the sealed key role of a witness key.
const RoleWitness = "witness"

const (
	witnessFormat = "openscale-release-witness-v1"
	// MaxWitnessSize bounds a witness file.
	MaxWitnessSize = 1 << 20
)

// ErrWitnessMismatch is returned when a witness contradicts the manifest.
var ErrWitnessMismatch = errors.New("independent build does not match the release")

// Witness is the statement of an independent build.
type Witness struct {
	Format          string    `json:"format"`
	WitnessKey      PublicKey `json:"witness_key"`
	Builder         string    `json:"builder"`
	Product         string    `json:"product"`
	Version         string    `json:"version"`
	Build           string    `json:"build"`
	SourceDateEpoch int64     `json:"source_date_epoch"`
	// ManifestSHA256 is the SHA-256 of the signed manifest payload; the
	// witness confirms exactly that manifest.
	ManifestSHA256 string     `json:"manifest_sha256"`
	Created        time.Time  `json:"created"`
	Artifacts      []Artifact `json:"artifacts"`
}

// ManifestDigest returns the SHA-256 (hex) of the manifest payload inside a
// signed release file. The caller verifies the file with Verify first.
func ManifestDigest(signedRelease []byte) (string, error) {
	if len(signedRelease) > MaxSignedReleaseSize {
		return "", errors.New("signed release is too large")
	}
	var sr SignedRelease
	if err := decodeStrict(signedRelease, &sr); err != nil {
		return "", fmt.Errorf("decode signed release: %w", err)
	}
	if len(sr.Manifest.Payload) == 0 {
		return "", errors.New("signed release has no manifest")
	}
	sum := sha256.Sum256(sr.Manifest.Payload)
	return hex.EncodeToString(sum[:]), nil
}

// NewWitness builds the statement for the files reproduced on this machine.
// Every file must be listed in the verified manifest with the same size
// and digest; a difference is reported, never signed.
func NewWitness(v *Verified, manifestDigest, builder string, reproduced []Artifact, now time.Time) (Witness, error) {
	w := Witness{
		Format:          witnessFormat,
		Builder:         builder,
		Product:         v.Manifest.Product,
		Version:         v.Manifest.Version,
		Build:           v.Manifest.Build,
		SourceDateEpoch: v.Manifest.SourceDateEpoch,
		ManifestSHA256:  manifestDigest,
		Created:         now.UTC().Truncate(time.Second),
		Artifacts:       reproduced,
	}
	if _, err := w.Confirms(&v.Manifest, manifestDigest); err != nil {
		return Witness{}, err
	}
	return w, nil
}

// SignWitness signs w with the witness key and returns the encoded envelope.
func SignWitness(priv ed25519.PrivateKey, w Witness) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid witness private key")
	}
	k, err := PublicKeyFrom(priv.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, err
	}
	w.Format = witnessFormat
	w.WitnessKey = k
	if err := w.validate(); err != nil {
		return nil, err
	}
	payload, err := marshalIndent(w)
	if err != nil {
		return nil, fmt.Errorf("encode witness: %w", err)
	}
	env, err := sign(priv, ContextWitness, payload)
	if err != nil {
		return nil, err
	}
	return marshalIndent(env)
}

// VerifyWitness checks a witness file against the pinned witness key.
func VerifyWitness(key PublicKey, data []byte) (*Witness, error) {
	if len(data) > MaxWitnessSize {
		return nil, errors.New("witness is too large")
	}
	var env Envelope
	if err := decodeStrict(data, &env); err != nil {
		return nil, fmt.Errorf("decode witness: %w", err)
	}
	payload, err := env.verify(key, ContextWitness)
	if err != nil {
		return nil, fmt.Errorf("witness: %w", err)
	}
	var w Witness
	if err := decodeStrict(payload, &w); err != nil {
		return nil, fmt.Errorf("decode witness: %w", err)
	}
	if err := w.validate(); err != nil {
		return nil, err
	}
	if !w.WitnessKey.Equal(key) {
		return nil, errors.New("witness names a different witness key")
	}
	return &w, nil
}

// Confirms checks the witness against a verified manifest and its digest
// and returns the names of the files the independent build reproduced.
func (w *Witness) Confirms(m *Manifest, manifestDigest string) ([]string, error) {
	switch {
	case w.Product != m.Product || w.Version != m.Version || w.Build != m.Build || w.SourceDateEpoch != m.SourceDateEpoch:
		return nil, fmt.Errorf("%w: witness is for %s %s (%s), release is %s %s (%s)", ErrWitnessMismatch, w.Product, w.Version, w.Build, m.Product, m.Version, m.Build)
	case !strings.EqualFold(w.ManifestSHA256, manifestDigest):
		return nil, fmt.Errorf("%w: witness confirms another manifest", ErrWitnessMismatch)
	case len(w.Artifacts) == 0:
		return nil, fmt.Errorf("%w: witness lists no files", ErrWitnessMismatch)
	}
	names := make([]string, 0, len(w.Artifacts))
	for _, a := range w.Artifacts {
		want, ok := m.Lookup(a.Name)
		if !ok {
			return nil, fmt.Errorf("%w: %s is not in the manifest", ErrWitnessMismatch, a.Name)
		}
		if want.Size != a.Size || want.SHA256 != a.SHA256 {
			return nil, fmt.Errorf("%w: %s differs (release %s, independent build %s)", ErrWitnessMismatch, a.Name, want.SHA256, a.SHA256)
		}
		names = append(names, a.Name)
	}
	return names, nil
}

func (w *Witness) validate() error {
	switch {
	case w.Format != witnessFormat:
		return fmt.Errorf("unsupported witness format %q", w.Format)
	case w.WitnessKey.IsZero():
		return errors.New("witness key is missing")
	case w.Builder == "" || len(w.Builder) > maxCommentLength || !utf8.ValidString(w.Builder) || hasControl(w.Builder):
		return errors.New("witness builder name is empty, too long or not printable")
	case w.Product != Product:
		return fmt.Errorf("witness is for product %q", w.Product)
	case len(w.Build) > maxBuildLength || !isToken(w.Build):
		return errors.New("witness build is invalid")
	case w.SourceDateEpoch < 0:
		return errors.New("negative source date epoch")
	case len(w.ManifestSHA256) != sha256.Size*2 || !isLowerHex(w.ManifestSHA256):
		return errors.New("witness manifest digest is invalid")
	case w.Created.IsZero():
		return errors.New("witness has no creation time")
	case len(w.Artifacts) == 0 || len(w.Artifacts) > MaxArtifacts:
		return fmt.Errorf("witness must list 1-%d files", MaxArtifacts)
	}
	if _, err := ParseVersion(w.Version); err != nil {
		return err
	}
	seen := map[string]bool{}
	for i, a := range w.Artifacts {
		if err := checkArtifactName(a.Name); err != nil {
			return fmt.Errorf("witness file %d: %w", i, err)
		}
		if seen[strings.ToLower(a.Name)] {
			return fmt.Errorf("witness lists %s twice", a.Name)
		}
		seen[strings.ToLower(a.Name)] = true
		if a.Size < 0 || a.Size > MaxArtifactSize || len(a.SHA256) != sha256.Size*2 || !isLowerHex(a.SHA256) {
			return fmt.Errorf("witness file %s has an invalid size or digest", a.Name)
		}
	}
	return nil
}
