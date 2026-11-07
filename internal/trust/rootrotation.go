package trust

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Root key rotation and retroactive revocation of a compromised root
// (ADR-0027, #7, F-116).
//
// A root transition moves a network from one root key to another and
// raises the root epoch. It is signed either by the old root (an ordinary
// rotation) or by one of the pinned offline recovery keys (recovery after a
// compromise). A device applies a transition only together with a document
// signed by the new root at the new epoch (State.AcceptWithTransitions), so
// it never runs without a valid document: there is no waiting state, and
// every document of the old root stops verifying at once.

// Signature contexts of root transitions. A recovery key signs nothing
// else; a root key signs documents and rotations under different contexts.
const (
	RootRotationContext   = "openscale/root-rotation/v1"
	RootRevocationContext = "openscale/root-revocation/v1"
)

// Kinds of root transitions.
const (
	TransitionRotation = "rotation"
	TransitionRecovery = "recovery"
)

// Root transition limits.
const (
	// MaxRecoveryKeys bounds the recovery keys of a network.
	MaxRecoveryKeys = 3
	// MaxRootEpoch bounds root epochs so they never overflow.
	MaxRootEpoch = 1 << 40
	// MaxRootTransitions bounds the transitions a member keeps and serves.
	MaxRootTransitions = 16
	// MaxRevokedRoots bounds the revoked roots a member remembers.
	MaxRevokedRoots = 64
	// MaxTransitionPayload keeps a transition inside one control datagram.
	MaxTransitionPayload = 640
	// maxEpochJump bounds how far a recovery may raise the epoch.
	maxEpochJump       = 1 << 20
	transitionPrefix   = "osroot1."
	maxTransitionChars = 2048
)

// Root transition errors.
var (
	ErrEpochMismatch       = errors.New("document belongs to another root epoch; a root transition is needed")
	ErrRecoveryKeysChanged = errors.New("recovery keys can only change through a recovery-signed root transition")
	ErrTransitionStale     = errors.New("root rotation does not follow this member's current document")
	ErrRootRevoked         = errors.New("root key was revoked by an earlier transition")
	ErrNoTransition        = errors.New("no applicable root transition")
)

// RootTransition is the signed payload of a root change. Documents of
// RevokedRoot newer than LastGoodVersion are what a recovery cuts off; a
// member that applied the transition accepts only NewRoot's documents of
// Epoch from then on.
type RootTransition struct {
	NetworkID       string    `json:"network_id"`
	Kind            string    `json:"kind"`
	RevokedRoot     Key       `json:"revoked_root"`
	NewRoot         Key       `json:"new_root"`
	LastGoodVersion uint64    `json:"last_good_version"`
	LastGoodDigest  string    `json:"last_good_digest"`
	Epoch           uint64    `json:"epoch"`
	IssuedAt        time.Time `json:"issued_at"`
	// RecoveryKeys replaces the pinned recovery keys; recovery kind only.
	RecoveryKeys []Key `json:"recovery_keys,omitempty"`
}

// SignedRootTransition carries the payload bytes and the signature over
// them. The signer is not named: a verifier tries the current root and the
// pinned recovery keys, each under its own context, before parsing.
type SignedRootTransition struct {
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}

// check validates the payload structure, independent of any state.
func (t *RootTransition) check() error {
	switch {
	case !isValidID(t.NetworkID):
		return errors.New("root transition has an invalid network id")
	case t.Kind != TransitionRotation && t.Kind != TransitionRecovery:
		return fmt.Errorf("unknown root transition kind %q", t.Kind)
	case t.RevokedRoot.IsZero() || t.NewRoot.IsZero() || t.RevokedRoot == t.NewRoot:
		return errors.New("root transition has invalid root keys")
	case t.Epoch == 0 || t.Epoch > MaxRootEpoch:
		return errors.New("root transition has an invalid epoch")
	case t.IssuedAt.IsZero():
		return errors.New("root transition has no issue time")
	case len(t.LastGoodDigest) != 2*sha256.Size || !isLowerHex(t.LastGoodDigest):
		return errors.New("root transition has an invalid document digest")
	case t.Kind == TransitionRotation && len(t.RecoveryKeys) != 0:
		return errors.New("only a recovery may change the recovery keys")
	}
	if len(t.RecoveryKeys) > 0 {
		if err := checkRecoveryKeys(t.RecoveryKeys); err != nil {
			return err
		}
		if slices.Contains(t.RecoveryKeys, t.NewRoot) {
			return errors.New("a recovery key cannot also be the root key")
		}
	}
	return nil
}

// SignRootRotation signs an ordinary rotation with the old root key, which
// must be t.RevokedRoot.
func SignRootRotation(oldRoot ed25519.PrivateKey, t RootTransition) (SignedRootTransition, error) {
	t.Kind = TransitionRotation
	pub, err := keyFromSlice(oldRoot.Public().(ed25519.PublicKey))
	if err != nil {
		return SignedRootTransition{}, err
	}
	if pub != t.RevokedRoot {
		return SignedRootTransition{}, errors.New("a rotation must be signed by the root it replaces")
	}
	return signTransition(oldRoot, RootRotationContext, t)
}

// SignRootRecovery signs a recovery with an offline recovery key.
func SignRootRecovery(recovery ed25519.PrivateKey, t RootTransition) (SignedRootTransition, error) {
	t.Kind = TransitionRecovery
	pub, err := keyFromSlice(recovery.Public().(ed25519.PublicKey))
	if err != nil {
		return SignedRootTransition{}, err
	}
	if pub == t.NewRoot || pub == t.RevokedRoot {
		return SignedRootTransition{}, errors.New("a recovery key cannot also be a root key")
	}
	return signTransition(recovery, RootRevocationContext, t)
}

func signTransition(priv ed25519.PrivateKey, context string, t RootTransition) (SignedRootTransition, error) {
	t.IssuedAt = roundTimestamp(t.IssuedAt)
	if err := t.check(); err != nil {
		return SignedRootTransition{}, err
	}
	payload, err := json.Marshal(t)
	if err != nil {
		return SignedRootTransition{}, fmt.Errorf("encode root transition: %w", err)
	}
	if len(payload) > MaxTransitionPayload {
		return SignedRootTransition{}, errors.New("root transition is too large")
	}
	sig, err := priv.Sign(nil, payload, &ed25519.Options{Context: context})
	if err != nil {
		return SignedRootTransition{}, fmt.Errorf("sign root transition: %w", err)
	}
	return SignedRootTransition{Payload: payload, Signature: sig}, nil
}

// VerifyRootTransition checks st against root (rotation context) and each
// recovery key (revocation context) before parsing, then parses strictly
// and checks that the kind matches the key that signed it. root may be nil
// when only recovery keys are acceptable.
func VerifyRootTransition(st SignedRootTransition, root ed25519.PublicKey, recovery []Key) (*RootTransition, error) {
	if len(st.Payload) == 0 || len(st.Payload) > MaxTransitionPayload || len(st.Signature) != ed25519.SignatureSize {
		return nil, errors.New("root transition has an invalid size")
	}
	kind := ""
	if len(root) == ed25519.PublicKeySize &&
		ed25519.VerifyWithOptions(root, st.Payload, st.Signature, &ed25519.Options{Context: RootRotationContext}) == nil {
		kind = TransitionRotation
	}
	if kind == "" {
		for _, k := range recovery {
			if ed25519.VerifyWithOptions(k[:], st.Payload, st.Signature, &ed25519.Options{Context: RootRevocationContext}) == nil {
				kind = TransitionRecovery
				break
			}
		}
	}
	if kind == "" {
		return nil, ErrBadSignature
	}
	var t RootTransition
	if err := decodeStrict(st.Payload, &t); err != nil {
		return nil, fmt.Errorf("decode root transition: %w", err)
	}
	if err := t.check(); err != nil {
		return nil, err
	}
	if t.Kind != kind {
		return nil, errors.New("root transition kind does not match its signer")
	}
	if kind == TransitionRotation {
		if pub, _ := keyFromSlice(root); pub != t.RevokedRoot {
			return nil, errors.New("root rotation names another root")
		}
	}
	return &t, nil
}

// ParseRootTransition parses a transition WITHOUT verifying it, for the
// owner's own tooling (listing what is stored in the network directory).
// Members must use State.ApplyTransition.
func ParseRootTransition(st SignedRootTransition) (*RootTransition, error) {
	if len(st.Payload) == 0 || len(st.Payload) > MaxTransitionPayload {
		return nil, errors.New("root transition has an invalid size")
	}
	var t RootTransition
	if err := decodeStrict(st.Payload, &t); err != nil {
		return nil, fmt.Errorf("decode root transition: %w", err)
	}
	return &t, t.check()
}

// ApplyTransition verifies st against the state and, if it applies, moves
// the state to the new root and epoch. The rollback state is reset: the
// new root's first document is accepted at any version. On error the
// state is unchanged.
func (s *State) ApplyTransition(st SignedRootTransition, now time.Time) (*RootTransition, error) {
	t, err := VerifyRootTransition(st, s.Anchor.RootKey, s.RecoveryKeys)
	if err != nil {
		return nil, err
	}
	current, err := keyFromSlice(s.Anchor.RootKey)
	if err != nil {
		return nil, err
	}
	switch {
	case t.NetworkID != s.Anchor.NetworkID:
		return nil, ErrWrongNetwork
	case t.Epoch <= s.Epoch:
		return nil, ErrRollback
	case now.Before(t.IssuedAt.Add(-clockSkew)):
		return nil, errors.New("root transition is dated in the future")
	case t.NewRoot == current || slices.Contains(s.RevokedRoots, t.NewRoot):
		return nil, ErrRootRevoked
	case slices.Contains(s.RecoveryKeys, t.NewRoot):
		return nil, errors.New("a recovery key cannot become the root key")
	}
	switch t.Kind {
	case TransitionRotation:
		if t.Epoch != s.Epoch+1 {
			return nil, errors.New("a root rotation must raise the epoch by one")
		}
		// Something signed by this root after the rotation point is either a
		// mistake or a compromise; only a recovery may cut it off.
		if s.HighestVersion > t.LastGoodVersion ||
			(s.HighestVersion == t.LastGoodVersion && s.HighestVersion != 0 && hex.EncodeToString(s.HighestDigest[:]) != t.LastGoodDigest) {
			return nil, ErrTransitionStale
		}
	case TransitionRecovery:
		if t.Epoch > s.Epoch+maxEpochJump {
			return nil, errors.New("root recovery raises the epoch too far")
		}
	}
	revoked := slices.Clone(s.RevokedRoots)
	for _, k := range []Key{current, t.RevokedRoot} {
		if !slices.Contains(revoked, k) {
			revoked = append(revoked, k)
		}
	}
	if len(revoked) > MaxRevokedRoots {
		revoked = revoked[len(revoked)-MaxRevokedRoots:]
	}
	s.RevokedRoots = revoked
	s.Anchor.RootKey = append(ed25519.PublicKey(nil), t.NewRoot[:]...)
	s.Epoch = t.Epoch
	s.HighestVersion = 0
	s.HighestDigest = [32]byte{}
	if len(t.RecoveryKeys) > 0 {
		s.RecoveryKeys = slices.Clone(t.RecoveryKeys)
	}
	return t, nil
}

// AcceptWithTransitions applies the transitions that lead to env's root and
// accepts env, atomically: if no transition applies or the document does
// not verify at the resulting root and epoch, the state is unchanged. The
// transitions may come in any order and may include ones already applied
// or irrelevant to this member; the lowest applicable epoch is taken first.
// It returns the document and the transitions that were applied.
func (s *State) AcceptWithTransitions(ts []SignedRootTransition, env Envelope, now time.Time) (*Document, []SignedRootTransition, error) {
	if len(ts) > 4*MaxRootTransitions {
		ts = ts[:4*MaxRootTransitions]
	}
	scratch := s.Clone()
	used := make([]bool, len(ts))
	var applied []SignedRootTransition
	for {
		best, bestEpoch := -1, uint64(0)
		var bestState State
		for i, st := range ts {
			if used[i] {
				continue
			}
			c := scratch.Clone()
			t, err := c.ApplyTransition(st, now)
			if err != nil {
				continue
			}
			if best < 0 || t.Epoch < bestEpoch {
				best, bestEpoch, bestState = i, t.Epoch, c
			}
		}
		if best < 0 {
			break
		}
		used[best] = true
		scratch = bestState
		applied = append(applied, ts[best])
	}
	if len(applied) == 0 {
		return nil, nil, ErrNoTransition
	}
	doc, err := scratch.Accept(env, now)
	if err != nil {
		return nil, nil, err
	}
	*s = scratch
	return doc, applied, nil
}

// Clone returns a deep copy of the state.
func (s State) Clone() State {
	s.Anchor.RootKey = append(ed25519.PublicKey(nil), s.Anchor.RootKey...)
	s.RecoveryKeys = slices.Clone(s.RecoveryKeys)
	s.RevokedRoots = slices.Clone(s.RevokedRoots)
	return s
}

// checkRoot enforces the root epoch and the pinned recovery keys on an
// authentic document. A fresh state (nothing accepted yet) adopts the
// document's epoch: its anchor came from the owner (bundle or invite code).
func (s *State) checkRoot(doc *Document) error {
	fresh := s.HighestVersion == 0 && s.Epoch == 0 && len(s.RevokedRoots) == 0
	if !fresh && doc.RootEpoch != s.Epoch {
		if doc.RootEpoch < s.Epoch {
			return ErrRollback
		}
		return ErrEpochMismatch
	}
	if len(s.RecoveryKeys) > 0 && !sameKeySet(s.RecoveryKeys, doc.RecoveryKeys) {
		return ErrRecoveryKeysChanged
	}
	return nil
}

// adoptRoot records the epoch and pins the recovery keys on first sight.
func (s *State) adoptRoot(doc *Document) {
	s.Epoch = doc.RootEpoch
	if len(s.RecoveryKeys) == 0 && len(doc.RecoveryKeys) > 0 {
		s.RecoveryKeys = slices.Clone(doc.RecoveryKeys)
	}
}

func sameKeySet(a, b []Key) bool {
	if len(a) != len(b) {
		return false
	}
	for _, k := range a {
		if !slices.Contains(b, k) {
			return false
		}
	}
	return true
}

func checkRecoveryKeys(keys []Key) error {
	if len(keys) > MaxRecoveryKeys {
		return fmt.Errorf("at most %d recovery keys are allowed", MaxRecoveryKeys)
	}
	for i, k := range keys {
		if k.IsZero() {
			return errors.New("recovery key must not be zero")
		}
		if slices.Contains(keys[:i], k) {
			return errors.New("recovery key is listed twice")
		}
	}
	return nil
}

func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// EncodeRootTransition returns the single-line form of a transition.
func EncodeRootTransition(st SignedRootTransition) (string, error) {
	if len(st.Payload) == 0 || len(st.Payload) > MaxTransitionPayload || len(st.Signature) != ed25519.SignatureSize {
		return "", errors.New("root transition has an invalid size")
	}
	data, err := json.Marshal(st)
	if err != nil {
		return "", fmt.Errorf("encode root transition: %w", err)
	}
	return transitionPrefix + base64.RawURLEncoding.EncodeToString(data), nil
}

// DecodeRootTransition parses a line produced by EncodeRootTransition. The
// result is untrusted until State.ApplyTransition or VerifyRootTransition
// succeeds.
func DecodeRootTransition(line string) (SignedRootTransition, error) {
	line = strings.Join(strings.Fields(line), "")
	if len(line) > maxTransitionChars || !strings.HasPrefix(line, transitionPrefix) {
		return SignedRootTransition{}, errors.New("not an OpenScale root transition")
	}
	data, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(line, transitionPrefix))
	if err != nil {
		return SignedRootTransition{}, errors.New("root transition is damaged")
	}
	var st SignedRootTransition
	if err := decodeStrict(data, &st); err != nil {
		return SignedRootTransition{}, errors.New("root transition is damaged")
	}
	if len(st.Payload) == 0 || len(st.Payload) > MaxTransitionPayload || len(st.Signature) != ed25519.SignatureSize {
		return SignedRootTransition{}, errors.New("root transition has an invalid size")
	}
	return st, nil
}

// DocumentDigest returns the hex SHA-256 of an envelope's payload, the
// digest a transition's LastGoodDigest and the rollback state use.
func DocumentDigest(env Envelope) string {
	sum := sha256.Sum256(env.Payload)
	return hex.EncodeToString(sum[:])
}
