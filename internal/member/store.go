// Package member stores what a network member (device or coordinator)
// trusts: the pinned anchor, the rollback state and the latest accepted
// document. Every document goes through trust.State.Accept before it is
// persisted, so a member never moves to an older or forked document.
package member

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/diskguard"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
)

const (
	anchorFile   = "anchor.json"
	stateFile    = "state.json"
	documentFile = "network.json"
	maxSmallFile = 4096
)

// ErrNotJoined is returned when the state directory has no anchor yet.
var ErrNotJoined = errors.New("not joined to a network; run 'openscale join' first")

type anchorJSON struct {
	RootKey   trust.Key `json:"root_key"`
	NetworkID string    `json:"network_id"`
}

type stateJSON struct {
	HighestVersion uint64 `json:"highest_version"`
	HighestDigest  string `json:"highest_digest"`
}

// Store is a member state directory. Methods are safe for concurrent use.
type Store struct {
	mu       sync.Mutex
	dir      string
	state    trust.State
	doc      *trust.Document
	envelope []byte
	// notes lists what Open repaired (recover.go, #206).
	notes []string
	// root is the root rotation state (root.go, ADR-0027).
	root rootExtra
	// members opens members-only documents for this device (members.go, #629).
	members membersView
}

// Join verifies a join bundle against the root fingerprint the owner typed
// and initializes dir. An existing anchor for a different network is never
// overwritten.
func Join(dir, bundle, rootFingerprint string, now time.Time) (*Store, error) {
	anchor, _, env, err := trust.OpenJoinBundle(bundle, rootFingerprint)
	if err != nil {
		return nil, err
	}
	envData, err := trust.MarshalEnvelope(env)
	if err != nil {
		return nil, err
	}
	return JoinAnchor(dir, anchor, envData, now)
}

// JoinAnchor initializes dir with an anchor the caller already trusts (from
// a join bundle or an invite code) and a document signed by it.
func JoinAnchor(dir string, anchor trust.Anchor, envData []byte, now time.Time) (*Store, error) {
	if existing, err := Open(dir); err == nil {
		if existing.state.Anchor.NetworkID != anchor.NetworkID || !existing.state.Anchor.RootKey.Equal(anchor.RootKey) {
			return nil, errors.New("this state directory already belongs to another network")
		}
		if _, err := existing.Accept(envData, now); err != nil && !errors.Is(err, trust.ErrRollback) {
			return nil, err
		}
		return existing, nil
	}
	s := &Store{dir: dir, state: trust.State{Anchor: anchor}}
	if _, err := s.Accept(envData, now); err != nil {
		return nil, err
	}
	var root trust.Key
	copy(root[:], anchor.RootKey)
	data, err := json.MarshalIndent(anchorJSON{RootKey: root, NetworkID: anchor.NetworkID}, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := securefile.Replace(filepath.Join(dir, anchorFile), data); err != nil {
		return nil, fmt.Errorf("write anchor: %w", err)
	}
	return s, nil
}

// Open loads a joined state directory. The stored document is re-verified
// against the anchor (signature only; expiry is checked when it is used).
func Open(dir string) (*Store, error) {
	data, err := securefile.ReadPrivate(filepath.Join(dir, anchorFile), maxSmallFile)
	if err != nil {
		return nil, ErrNotJoined
	}
	var a anchorJSON
	if err := json.Unmarshal(data, &a); err != nil || a.RootKey.IsZero() {
		return nil, errors.New("anchor file is corrupt")
	}
	s := &Store{dir: dir, state: trust.State{Anchor: trust.Anchor{RootKey: ed25519.PublicKey(a.RootKey[:]), NetworkID: a.NetworkID}}}
	// A rotated root, the epoch and pinned recovery keys come from root.json
	// (root.go, ADR-0027); it must be read before the document is verified.
	if err := s.loadRoot(); err != nil {
		return nil, err
	}
	// The state file and the document are read, verified and, when
	// damaged, repaired from the local copies (recover.go, #206).
	if err := s.loadState(); err != nil {
		return nil, err
	}
	s.adoptLoadedRoot()
	return s, nil
}

// Accept verifies an encoded envelope and persists it if it is newer. It
// returns true when the stored document changed.
func (s *Store) Accept(envData []byte, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	env, err := trust.UnmarshalEnvelope(envData)
	if err != nil {
		return false, err
	}
	prev := s.state
	doc, err := s.state.Accept(env, now)
	if err != nil {
		if transitionPossible(err) {
			// Signed by a new root: try the offered root transitions (root.go).
			return s.acceptWithTransitionsLocked(env, now, err)
		}
		return false, err
	}
	if s.doc != nil && doc.Version == s.doc.Version {
		return false, nil
	}
	canonical, err := trust.MarshalEnvelope(env)
	if err != nil {
		s.state = prev
		return false, err
	}
	if err := s.persist(canonical); err != nil {
		s.state = prev
		return false, err
	}
	if rootChanged(prev, s.state) {
		// Best effort: Open pins again from the verified document.
		_ = s.writeRoot()
	}
	s.doc, s.envelope = doc, canonical
	return true, nil
}

func (s *Store) persist(envData []byte) error {
	// The document always gets the disk's last space (#205): a full disk
	// frees the data directory's reserve for it.
	if err := diskguard.WriteCritical(s.dir, func() error {
		return securefile.Replace(filepath.Join(s.dir, documentFile), envData)
	}); err != nil {
		return fmt.Errorf("write document: %w", err)
	}
	if err := s.writeState(); err != nil {
		return fmt.Errorf("write state: %w", err)
	}
	// Second copy for recovery (#197, #206); best effort.
	_ = securefile.Replace(filepath.Join(s.dir, backupDocumentFile), envData)
	return nil
}

// Document returns the current verified document.
func (s *Store) Document() *trust.Document {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.viewLocked()
}

// Envelope returns the encoded current envelope and its SHA-256 digest.
func (s *Store) Envelope() ([]byte, [32]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.envelope, sha256.Sum256(s.envelope)
}

// Snapshot returns the document, its encoded envelope and digest together,
// so callers never mix data from two versions.
func (s *Store) Snapshot() (*trust.Document, []byte, [32]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.viewLocked(), s.envelope, sha256.Sum256(s.envelope)
}

// Anchor returns the pinned anchor.
func (s *Store) Anchor() trust.Anchor {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state.Anchor
}

// Dir returns the state directory.
func (s *Store) Dir() string { return s.dir }
