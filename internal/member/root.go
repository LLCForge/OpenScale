package member

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"
	"time"

	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
)

// Root rotation state of a member (ADR-0027, #7).
//
// root.json holds what trust.State keeps beyond the anchor: the current
// root key (it overrides anchor.json once a transition was applied), the
// root epoch, the pinned recovery keys, the revoked roots and the applied
// transitions this member serves to others. It is written only when one of
// those is set, so members of networks that never use them keep exactly
// the files they had.
//
// A transition changes the root and the document together. It is
// journaled: root.json is first written with the new document inside
// (pending_document), then network.json and state.json, then root.json
// again without it. Open finishes an interrupted commit, so a crash never
// leaves a document that does not verify against the stored root.

const (
	rootFile    = "root.json"
	maxRootFile = 64 << 10
	// maxOffered bounds the transitions kept in memory before the document
	// that needs them arrives.
	maxOffered = trust.MaxRootTransitions
)

type rootJSON struct {
	NetworkID    string      `json:"network_id"`
	RootKey      trust.Key   `json:"root_key"`
	Epoch        uint64      `json:"epoch,omitempty"`
	RecoveryKeys []trust.Key `json:"recovery_keys,omitempty"`
	RevokedRoots []trust.Key `json:"revoked_roots,omitempty"`
	Transitions  []string    `json:"transitions,omitempty"`
	// Pending is the document of an interrupted transition commit.
	Pending []byte `json:"pending_document,omitempty"`
}

// rootExtra is the part of Store guarded by Store.mu that root.go adds.
type rootExtra struct {
	rootFileSeen bool
	transitions  []trust.SignedRootTransition
	offered      []trust.SignedRootTransition
}

// loadRoot reads root.json into s before the document is verified, and
// finishes an interrupted transition commit. Called by Open with s fresh.
func (s *Store) loadRoot() error {
	data, err := securefile.ReadPrivate(filepath.Join(s.dir, rootFile), maxRootFile)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read root state: %w", err)
	}
	var r rootJSON
	if err := json.Unmarshal(data, &r); err != nil || r.RootKey.IsZero() || r.NetworkID != s.state.Anchor.NetworkID {
		return errors.New("root state file (root.json) is corrupt; join the network again")
	}
	x := &s.root
	x.rootFileSeen = true
	s.state.Anchor.RootKey = append(ed25519.PublicKey(nil), r.RootKey[:]...)
	s.state.Epoch = r.Epoch
	s.state.RecoveryKeys = slices.Clone(r.RecoveryKeys)
	s.state.RevokedRoots = slices.Clone(r.RevokedRoots)
	for _, line := range r.Transitions {
		if st, err := trust.DecodeRootTransition(line); err == nil {
			x.transitions = append(x.transitions, st)
		}
	}
	if len(r.Pending) == 0 {
		return nil
	}
	// Finish the interrupted commit: the pending document must verify
	// against the new root; otherwise it is dropped and the stored files
	// stay as they are (they then fail to verify and Open reports it).
	env, err := trust.UnmarshalEnvelope(r.Pending)
	if err == nil {
		var doc *trust.Document
		doc, err = trust.VerifyDocumentSignature(env, s.state.Anchor.RootKey)
		if err == nil && (doc.NetworkID != s.state.Anchor.NetworkID || doc.RootEpoch != s.state.Epoch) {
			err = errors.New("pending document does not match the root state")
		}
		if err == nil {
			s.state.HighestVersion, s.state.HighestDigest = doc.Version, sha256.Sum256(env.Payload)
			if err = s.persist(r.Pending); err == nil {
				s.notes = append(s.notes, fmt.Sprintf("yarım kalan kök anahtar geçişi tamamlandı (dönem %d)", s.state.Epoch))
			}
		}
	}
	r.Pending = nil
	if werr := s.writeRootJSON(r); werr != nil && err == nil {
		err = werr
	}
	return err
}

// adoptLoadedRoot runs after the document was loaded: it pins recovery
// keys of the verified local document when root.json does not have them
// yet, and adopts the document's epoch when there was no root.json.
func (s *Store) adoptLoadedRoot() {
	if s.doc == nil {
		return
	}
	// The approval policy of the stored (accepted) document stays pinned
	// across restarts (ADR-0121).
	s.state.PinApproval(s.doc)
	// Root base of a delegated administrator's document and the sensitive
	// device policy (ADR-0172, ADR-0174, g1_pin.go).
	s.pinStoredG1()
	x := &s.root
	changed := false
	if !x.rootFileSeen && s.state.Epoch != s.doc.RootEpoch {
		s.state.Epoch = s.doc.RootEpoch
		changed = true
	}
	if len(s.state.RecoveryKeys) == 0 && len(s.doc.RecoveryKeys) > 0 {
		s.state.RecoveryKeys = slices.Clone(s.doc.RecoveryKeys)
		changed = true
	}
	if changed {
		if err := s.writeRoot(); err != nil {
			s.notes = append(s.notes, "kök durum dosyası (root.json) yazılamadı: "+err.Error())
		}
	}
}

// needsRootFile reports whether root.json must exist for the state.
func (s *Store) needsRootFile() bool {
	x := &s.root
	return x.rootFileSeen || s.state.Epoch != 0 || len(s.state.RecoveryKeys) > 0 || len(s.state.RevokedRoots) > 0 || len(x.transitions) > 0
}

func (s *Store) rootJSONFor() (rootJSON, error) {
	x := &s.root
	root, err := keyOf(s.state.Anchor.RootKey)
	if err != nil {
		return rootJSON{}, err
	}
	r := rootJSON{
		NetworkID:    s.state.Anchor.NetworkID,
		RootKey:      root,
		Epoch:        s.state.Epoch,
		RecoveryKeys: slices.Clone(s.state.RecoveryKeys),
		RevokedRoots: slices.Clone(s.state.RevokedRoots),
	}
	for _, st := range x.transitions {
		line, err := trust.EncodeRootTransition(st)
		if err != nil {
			return rootJSON{}, err
		}
		r.Transitions = append(r.Transitions, line)
	}
	return r, nil
}

// writeRoot persists the root state when it is not the default.
func (s *Store) writeRoot() error {
	if !s.needsRootFile() {
		return nil
	}
	r, err := s.rootJSONFor()
	if err != nil {
		return err
	}
	return s.writeRootJSON(r)
}

func (s *Store) writeRootJSON(r rootJSON) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	if err := securefile.Replace(filepath.Join(s.dir, rootFile), data); err != nil {
		return fmt.Errorf("write root state: %w", err)
	}
	s.root.rootFileSeen = true
	return nil
}

// rootChanged reports whether Accept changed the root part of the state.
func rootChanged(prev, cur trust.State) bool {
	return prev.Epoch != cur.Epoch || len(prev.RecoveryKeys) != len(cur.RecoveryKeys)
}

// transitionPossible reports whether a document rejected with err could be
// accepted after a root transition.
func transitionPossible(err error) bool {
	return errors.Is(err, trust.ErrBadSignature) || errors.Is(err, trust.ErrEpochMismatch)
}

// acceptWithTransitionsLocked tries the offered transitions for env and
// commits the result with the journal. Called with s.mu held.
func (s *Store) acceptWithTransitionsLocked(env trust.Envelope, now time.Time, cause error) (bool, error) {
	x := &s.root
	if len(x.offered) == 0 {
		return false, cause
	}
	prev := s.state.Clone()
	doc, applied, err := s.state.AcceptWithTransitions(x.offered, env, now)
	if err != nil {
		return false, cause
	}
	canonical, err := trust.MarshalEnvelope(env)
	if err == nil {
		err = s.commitTransition(applied, canonical)
	}
	if err != nil {
		s.state = prev
		return false, err
	}
	s.doc, s.envelope = doc, canonical
	return true, nil
}

// commitTransition journals and writes the new root state and document.
func (s *Store) commitTransition(applied []trust.SignedRootTransition, canonical []byte) error {
	x := &s.root
	prevTransitions := x.transitions
	x.transitions = mergeTransitions(x.transitions, applied)
	r, err := s.rootJSONFor()
	if err != nil {
		x.transitions = prevTransitions
		return err
	}
	r.Pending = canonical
	if err := s.writeRootJSON(r); err != nil {
		x.transitions = prevTransitions
		return err
	}
	if err := s.persist(canonical); err != nil {
		// root.json holds the pending document: the next Open finishes it.
		return err
	}
	r.Pending = nil
	x.offered = slices.DeleteFunc(x.offered, func(o trust.SignedRootTransition) bool {
		return slices.ContainsFunc(applied, func(a trust.SignedRootTransition) bool { return sameTransition(a, o) })
	})
	return s.writeRootJSON(r)
}

// OfferTransition keeps a root transition received from the coordinator, a
// file or another member until the document that needs it arrives. Only
// transitions that apply to this member's state, possibly after other
// offered transitions, are kept; anything else is refused.
func (s *Store) OfferTransition(st trust.SignedRootTransition, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	x := &s.root
	for _, have := range append(slices.Clone(x.transitions), x.offered...) {
		if sameTransition(have, st) {
			return nil
		}
	}
	if !s.transitionApplies(st, x.offered, now) {
		return trust.ErrNoTransition
	}
	x.offered = append(x.offered, st)
	if len(x.offered) > maxOffered {
		x.offered = x.offered[len(x.offered)-maxOffered:]
	}
	return nil
}

// transitionApplies checks st against the current state and against the
// state reached through the other offered transitions.
func (s *Store) transitionApplies(st trust.SignedRootTransition, offered []trust.SignedRootTransition, now time.Time) bool {
	c := s.state.Clone()
	if _, err := c.ApplyTransition(st, now); err == nil {
		return true
	}
	chain := s.state.Clone()
	// Each offered transition applies at most once, so len(offered)
	// passes reach every chain.
	for pass := 0; pass < len(offered); pass++ {
		progress := false
		for _, o := range offered {
			if _, err := chain.ApplyTransition(o, now); err == nil {
				progress = true
			}
		}
		if !progress {
			break
		}
	}
	_, err := chain.ApplyTransition(st, now)
	return err == nil
}

// Transitions returns the applied root transitions this member keeps,
// oldest first, for serving to members that are behind.
func (s *Store) Transitions() []trust.SignedRootTransition {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.root.transitions)
}

// Epoch returns the current root epoch.
func (s *Store) Epoch() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state.Epoch
}

// AcceptTransitions offers ts and then accepts envData, for a document
// fetched together with its transitions (a device that was behind, or the
// owner's network directory after a rotation).
func (s *Store) AcceptTransitions(ts []trust.SignedRootTransition, envData []byte, now time.Time) (bool, error) {
	for _, st := range ts {
		// Irrelevant or already applied transitions are simply skipped.
		_ = s.OfferTransition(st, now)
	}
	return s.Accept(envData, now)
}

func mergeTransitions(have, add []trust.SignedRootTransition) []trust.SignedRootTransition {
	out := slices.Clone(have)
	for _, a := range add {
		if !slices.ContainsFunc(out, func(h trust.SignedRootTransition) bool { return sameTransition(h, a) }) {
			out = append(out, a)
		}
	}
	if len(out) > trust.MaxRootTransitions {
		out = out[len(out)-trust.MaxRootTransitions:]
	}
	return out
}

func sameTransition(a, b trust.SignedRootTransition) bool {
	return bytes.Equal(a.Payload, b.Payload) && bytes.Equal(a.Signature, b.Signature)
}

func keyOf(pub ed25519.PublicKey) (trust.Key, error) {
	var k trust.Key
	if len(pub) != trust.KeySize {
		return k, errors.New("invalid root key")
	}
	copy(k[:], pub)
	return k, nil
}
