package trust

import (
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const (
	bundlePrefix   = "osjoin1."
	maxBundleChars = 4 << 20
)

// ErrRootFingerprintMismatch is returned when the root key in a join bundle
// does not match the fingerprint the owner typed.
var ErrRootFingerprintMismatch = errors.New("root key fingerprint mismatch")

// JoinBundle carries what a new member needs to trust the network: the root
// public key and the current signed document. Its integrity comes from the
// owner comparing the root fingerprint, not from the channel it travels on.
type JoinBundle struct {
	RootKey  Key      `json:"root_key"`
	Document Envelope `json:"document"`
}

// EncodeJoinBundle returns a single copy-pasteable line.
func EncodeJoinBundle(b JoinBundle) (string, error) {
	data, err := json.Marshal(b)
	if err != nil {
		return "", fmt.Errorf("encode join bundle: %w", err)
	}
	return bundlePrefix + base64.RawURLEncoding.EncodeToString(data), nil
}

// OpenJoinBundle decodes a bundle, checks the root fingerprint the owner
// typed, and verifies the document signature. It returns the anchor and the
// verified document.
func OpenJoinBundle(line, rootFingerprint string) (Anchor, *Document, Envelope, error) {
	line = strings.TrimSpace(line)
	if len(line) > maxBundleChars || !strings.HasPrefix(line, bundlePrefix) {
		return Anchor{}, nil, Envelope{}, errors.New("not an OpenScale join bundle")
	}
	data, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(line, bundlePrefix))
	if err != nil {
		return Anchor{}, nil, Envelope{}, errors.New("join bundle is not valid base64")
	}
	var b JoinBundle
	if err := decodeStrict(data, &b); err != nil {
		return Anchor{}, nil, Envelope{}, fmt.Errorf("decode join bundle: %w", err)
	}
	if b.RootKey.IsZero() {
		return Anchor{}, nil, Envelope{}, errors.New("join bundle has no root key")
	}
	root := ed25519.PublicKey(b.RootKey[:])
	got := []byte(NormalizeFingerprint(RootFingerprint(root)))
	want := []byte(NormalizeFingerprint(rootFingerprint))
	if len(want) == 0 || subtle.ConstantTimeCompare(got, want) != 1 {
		return Anchor{}, nil, Envelope{}, ErrRootFingerprintMismatch
	}
	doc, err := VerifyDocumentSignature(b.Document, root)
	if err != nil {
		return Anchor{}, nil, Envelope{}, err
	}
	anchor := Anchor{RootKey: append(ed25519.PublicKey(nil), root...), NetworkID: doc.NetworkID}
	return anchor, doc, b.Document, nil
}
