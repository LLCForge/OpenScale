package trust

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Version chain (#343, ADR-0144). A document may carry prev_digest, the
// SHA-256 of the signed payload of the version it was made from. A member
// that holds version n and receives version n+1 checks the link; a mismatch
// proves that the root signed two different histories (a fork) and the new
// version is refused like an equivocation. The field is opt-in: documents
// without it encode exactly as before, and once present every following
// version carries it until the owner turns it off.

// ErrForkedHistory is returned when a document's prev_digest does not match
// the previous version this member accepted.
var ErrForkedHistory = errors.New("document does not continue the accepted version history (forked history)")

// prevDigestLen is the length of a hex SHA-256 digest.
const prevDigestLen = 64

// chainPlaceholder marks a chain that is being turned on; the owner's
// tooling replaces it with the real digest before signing and Validate
// refuses it, so it can never be signed.
var chainPlaceholder = strings.Repeat("0", prevDigestLen)

// VersionChainEnabled reports whether the document takes part in the
// version chain.
func (doc *Document) VersionChainEnabled() bool { return doc.PrevDigest != "" }

// SetVersionChain turns the version chain on or off for this (next)
// version. Turning it on leaves a placeholder that LinkVersionChain must
// replace before the document validates.
func (doc *Document) SetVersionChain(on bool) {
	switch {
	case !on:
		doc.PrevDigest = ""
	case doc.PrevDigest == "":
		doc.PrevDigest = chainPlaceholder
	}
}

// LinkVersionChain points a chained document at prev, the signed envelope
// of the version it follows. Documents outside the chain are left alone.
func (doc *Document) LinkVersionChain(prev Envelope) {
	if doc.PrevDigest == "" {
		return
	}
	doc.PrevDigest = DocumentDigest(prev)
}

func (doc *Document) validatePrevDigest() error {
	d := doc.PrevDigest
	if d == "" {
		return nil
	}
	if len(d) != prevDigestLen || strings.ToLower(d) != d {
		return errors.New("prev_digest must be 64 lowercase hex characters")
	}
	if _, err := hex.DecodeString(d); err != nil {
		return errors.New("prev_digest must be 64 lowercase hex characters")
	}
	if d == chainPlaceholder {
		return errors.New("prev_digest was not linked to the previous version")
	}
	if doc.Version < 2 {
		return errors.New("the first version cannot have a prev_digest")
	}
	return nil
}

// ChainLink is the result of comparing a document with the version before
// it.
type ChainLink int

const (
	// ChainUnchained: the document carries no prev_digest.
	ChainUnchained ChainLink = iota
	// ChainUnknown: the previous version is not the one right before the
	// document (a member skipped versions or the root changed).
	ChainUnknown
	// ChainLinked: prev_digest matches the previous version.
	ChainLinked
	// ChainForked: prev_digest names a different previous version.
	ChainForked
)

func (c ChainLink) String() string {
	switch c {
	case ChainUnchained:
		return "unchained"
	case ChainUnknown:
		return "unknown"
	case ChainLinked:
		return "linked"
	case ChainForked:
		return "forked"
	}
	return fmt.Sprintf("ChainLink(%d)", int(c))
}

// CheckChainLink compares doc with the previous version, given by its
// version, root epoch and payload digest. Only consecutive versions under
// the same root epoch can be checked.
func CheckChainLink(prevVersion, prevEpoch uint64, prevDigest [32]byte, doc *Document) ChainLink {
	if doc.PrevDigest == "" {
		return ChainUnchained
	}
	if prevVersion == 0 || doc.Version != prevVersion+1 || doc.RootEpoch != prevEpoch {
		return ChainUnknown
	}
	if doc.PrevDigest != hex.EncodeToString(prevDigest[:]) {
		return ChainForked
	}
	return ChainLinked
}

// checkChain refuses a version that forks from the one this member holds.
func (s *State) checkChain(doc *Document) error {
	if CheckChainLink(s.HighestVersion, s.Epoch, s.HighestDigest, doc) == ChainForked {
		return ErrForkedHistory
	}
	return nil
}

// VerifyChain checks that consecutive signed versions link to each other.
// docs[i] must be the verified document of envs[i], in ascending version
// order. It returns the index of the first document whose link is forked,
// or -1; gaps and unchained documents are not errors.
func VerifyChain(envs []Envelope, docs []*Document) (int, error) {
	if len(envs) != len(docs) {
		return -1, errors.New("envelopes and documents differ in number")
	}
	for i := 1; i < len(docs); i++ {
		prev, cur := docs[i-1], docs[i]
		if prev == nil || cur == nil {
			continue
		}
		if CheckChainLink(prev.Version, prev.RootEpoch, sha256.Sum256(envs[i-1].Payload), cur) == ChainForked {
			return i, nil
		}
	}
	return -1, nil
}
