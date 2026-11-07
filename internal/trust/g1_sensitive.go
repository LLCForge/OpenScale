package trust

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Two-person rule for sensitive devices (#610, ADR-0174): the device-level
// form of k-of-n approval (ADR-0121). A document may name sensitive
// targets (devices or tags) and their approvers. Every document must then
// carry, next to the root (or administrator) signature, approvals of at
// least Threshold approvers over the document's sensitive access
// fingerprint: a digest of the policy itself and of every rule that lets
// some device reach a sensitive device.
//
// The approvals sign the fingerprint, not the document, so they stay valid
// for later versions that do not change who can reach a sensitive device;
// the owner's tooling carries them forward. A change of that access, or of
// the policy, needs fresh approvals. A member pins the policy of the last
// document it accepted, so neither the root nor an administrator can drop
// the policy without its approvers.

// SensitiveApprovalContext is the signature context of sensitive approvals.
const SensitiveApprovalContext = "openscale/sensitive-approval/v1"

// Sensitive policy limits.
const (
	MaxSensitiveTargets = 16
	MaxSensitiveDevices = 32
)

// Sensitive errors.
var (
	ErrSensitivePolicy   = errors.New("invalid sensitive device policy")
	ErrSensitiveApproval = errors.New("access to a sensitive device needs more approvals")
)

// SensitivePolicy names sensitive devices and who must approve access to
// them.
type SensitivePolicy struct {
	// Targets are device names or "tag:<name>" entries. A device name that
	// no longer exists is allowed, so revoking a sensitive device never
	// fails.
	Targets   []string   `json:"targets"`
	Threshold int        `json:"threshold"`
	Approvers []Approver `json:"approvers"`
}

func (p *SensitivePolicy) approval() *ApprovalPolicy {
	return &ApprovalPolicy{Threshold: p.Threshold, Approvers: p.Approvers}
}

// Equal reports whether p and q are the same policy.
func (p *SensitivePolicy) Equal(q *SensitivePolicy) bool {
	if p == nil || q == nil {
		return p == q
	}
	return slices.Equal(p.Targets, q.Targets) && p.approval().Equal(q.approval())
}

func (p *SensitivePolicy) clone() *SensitivePolicy {
	if p == nil {
		return nil
	}
	return &SensitivePolicy{Targets: slices.Clone(p.Targets), Threshold: p.Threshold, Approvers: slices.Clone(p.Approvers)}
}

func (doc *Document) validateSensitive() error {
	p := doc.Sensitive
	if p == nil {
		return nil
	}
	if len(p.Targets) == 0 || len(p.Targets) > MaxSensitiveTargets {
		return fmt.Errorf("%w: 1-%d targets are allowed", ErrSensitivePolicy, MaxSensitiveTargets)
	}
	if !slices.IsSorted(p.Targets) || len(slices.Compact(slices.Clone(p.Targets))) != len(p.Targets) {
		return fmt.Errorf("%w: targets must be sorted and unique", ErrSensitivePolicy)
	}
	for _, t := range p.Targets {
		name, _ := strings.CutPrefix(t, TagPrefix)
		if !isValidLabel(name) {
			return fmt.Errorf("%w: target %q must be a device name or tag:<name>", ErrSensitivePolicy, t)
		}
	}
	if err := p.approval().Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrSensitivePolicy, err)
	}
	for _, a := range p.Approvers {
		if slices.Contains(doc.RecoveryKeys, a.Key) {
			return fmt.Errorf("%w: approver %q uses a recovery key", ErrSensitivePolicy, a.Name)
		}
	}
	if n := len(doc.sensitiveDevices(p.Targets)); n > MaxSensitiveDevices {
		return fmt.Errorf("%w: the targets cover %d devices (at most %d)", ErrSensitivePolicy, n, MaxSensitiveDevices)
	}
	return nil
}

// sensitiveDevices returns the devices the targets cover, by name.
func (doc *Document) sensitiveDevices(targets []string) []Device {
	var out []Device
	for _, d := range doc.Devices {
		for _, t := range targets {
			tag, isTag := strings.CutPrefix(t, TagPrefix)
			if (isTag && slices.Contains(d.Tags, tag)) || (!isTag && d.Name == t) {
				out = append(out, d)
				break
			}
		}
	}
	slices.SortFunc(out, func(a, b Device) int { return strings.Compare(a.Name, b.Name) })
	return out
}

// SensitiveDevices returns the names of the devices the document's policy
// covers.
func (doc *Document) SensitiveDevices() []string {
	if doc.Sensitive == nil {
		return nil
	}
	var names []string
	for _, d := range doc.sensitiveDevices(doc.Sensitive.Targets) {
		names = append(names, d.Name)
	}
	return names
}

// SensitiveFingerprint is the digest the approvers sign: the network, the
// document's policy, the sensitive devices, the admin devices (they pass
// the emergency lock) and every rule that covers traffic from another
// device to a sensitive one, with that source.
func SensitiveFingerprint(doc *Document) [32]byte {
	h := sha256.New()
	h.Write([]byte("openscale/sensitive-access/v1\x00"))
	writePart := func(b []byte) {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(b))) //nolint:gosec // bounded by MaxDocumentSize
		h.Write(l[:])
		h.Write(b)
	}
	writePart([]byte(doc.NetworkID))
	policy, _ := json.Marshal(doc.Sensitive)
	writePart(policy)
	if doc.Sensitive == nil {
		var sum [32]byte
		copy(sum[:], h.Sum(nil))
		return sum
	}
	targets := doc.sensitiveDevices(doc.Sensitive.Targets)
	var entries []string
	for _, d := range targets {
		entries = append(entries, "device\x00"+d.ID+"\x00"+d.Name)
	}
	for _, d := range doc.Devices {
		if d.HasRole(RoleAdmin) {
			entries = append(entries, "admin\x00"+d.ID)
		}
	}
	subjects := make(map[string]subject, len(doc.Devices))
	for _, d := range doc.Devices {
		subjects[d.Name] = doc.subject(d.Name)
	}
	for _, r := range doc.Rules {
		enc, _ := json.Marshal(r)
		for _, dst := range targets {
			ds := subjects[dst.Name]
			if !doc.matchesAny(r.trafficTo(), ds) && !(r.Bidirectional && doc.matchesAny(r.From, ds)) {
				continue
			}
			for _, src := range doc.Devices {
				if src.Name == dst.Name {
					continue
				}
				if doc.ruleCovers(r, subjects[src.Name], ds) {
					entries = append(entries, "rule\x00"+dst.Name+"\x00"+src.Name+"\x00"+string(enc))
				}
			}
		}
	}
	slices.Sort(entries)
	for _, e := range entries {
		writePart([]byte(e))
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum
}

// ApproveSensitive signs the document's sensitive fingerprint.
func ApproveSensitive(priv ed25519.PrivateKey, doc *Document) (Cosignature, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return Cosignature{}, errors.New("invalid ed25519 private key")
	}
	fp := SensitiveFingerprint(doc)
	sig, err := priv.Sign(nil, fp[:], &ed25519.Options{Context: SensitiveApprovalContext})
	if err != nil {
		return Cosignature{}, fmt.Errorf("sign sensitive approval: %w", err)
	}
	var k Key
	copy(k[:], priv.Public().(ed25519.PublicKey))
	return Cosignature{Key: k, Signature: sig}, nil
}

// ApproveSensitiveWith signs the fingerprint with a hardware-held key.
func ApproveSensitiveWith(signer DigestSigner, doc *Document) (Cosignature, error) {
	fp := SensitiveFingerprint(doc)
	signed, err := SignWithDigest(signer, SensitiveApprovalContext, fp[:])
	if err != nil {
		return Cosignature{}, err
	}
	var k Key
	copy(k[:], signer.PublicKey())
	return Cosignature{Key: k, Algorithm: AlgEd25519Digest, Signature: signed.Signature}, nil
}

func verifySensitiveCosig(c Cosignature, fp [32]byte) error {
	pub := ed25519.PublicKey(c.Key[:])
	switch c.Algorithm {
	case "", AlgEd25519:
		if len(c.Signature) != ed25519.SignatureSize ||
			ed25519.VerifyWithOptions(pub, fp[:], c.Signature, &ed25519.Options{Context: SensitiveApprovalContext}) != nil {
			return ErrBadSignature
		}
		return nil
	case AlgEd25519Digest:
		return verifyDigest(pub, SensitiveApprovalContext, fp[:], c.Signature)
	}
	return ErrUnsupportedAlgorithm
}

// SensitiveApproved returns the names of p's approvers with a valid
// approval of fp in list.
func SensitiveApproved(p *SensitivePolicy, list []Cosignature, fp [32]byte) []string {
	if p == nil {
		return nil
	}
	var names []string
	for _, a := range p.Approvers {
		for _, c := range list {
			if c.Key == a.Key && verifySensitiveCosig(c, fp) == nil {
				names = append(names, a.Name)
				break
			}
		}
	}
	return names
}

func checkSensitivePolicy(p *SensitivePolicy, list []Cosignature, fp [32]byte) error {
	if p == nil {
		return nil
	}
	if have := len(SensitiveApproved(p, list, fp)); have < p.Threshold {
		return fmt.Errorf("%w (%d of %d)", ErrSensitiveApproval, have, p.Threshold)
	}
	return nil
}

// AddSensitiveApproval adds c to env after checking it against the
// fingerprint of doc (the document env carries). An approval of the same
// key is replaced; approvals are kept sorted by key.
func AddSensitiveApproval(env *Envelope, doc *Document, c Cosignature) error {
	if env.Context != DocumentContext {
		return ErrWrongContext
	}
	if err := checkCosignatures([]Cosignature{c}); err != nil {
		return err
	}
	if err := verifySensitiveCosig(c, SensitiveFingerprint(doc)); err != nil {
		return err
	}
	list := slices.DeleteFunc(slices.Clone(env.SensitiveApprovals), func(o Cosignature) bool { return o.Key == c.Key })
	list = append(list, c)
	if len(list) > MaxCosignatures {
		return fmt.Errorf("at most %d approvals are allowed", MaxCosignatures)
	}
	slices.SortFunc(list, func(a, b Cosignature) int { return bytes.Compare(a.Key[:], b.Key[:]) })
	env.SensitiveApprovals = list
	return nil
}

// CarrySensitiveApprovals copies from prev the approvals that are still
// valid for next's fingerprint into env (the newly signed next), so a
// version that does not change sensitive access keeps working.
func CarrySensitiveApprovals(prev Envelope, env *Envelope, next *Document) {
	if next.Sensitive == nil || len(prev.SensitiveApprovals) == 0 {
		return
	}
	fp := SensitiveFingerprint(next)
	for _, c := range prev.SensitiveApprovals {
		if verifySensitiveCosig(c, fp) == nil {
			_ = AddSensitiveApproval(env, next, c)
		}
	}
}

// SensitiveStatus reports which approvals doc still needs, given the
// policy a member pinned before it (nil for none).
func SensitiveStatus(env Envelope, doc *Document, pinned *SensitivePolicy) error {
	fp := SensitiveFingerprint(doc)
	if err := checkSensitivePolicy(pinned, env.SensitiveApprovals, fp); err != nil {
		return err
	}
	if doc.Sensitive != nil && !doc.Sensitive.Equal(pinned) {
		return checkSensitivePolicy(doc.Sensitive, env.SensitiveApprovals, fp)
	}
	return nil
}

// checkSensitive enforces the pinned policy and the document's own one.
func (s *State) checkSensitive(env Envelope, doc *Document) error {
	if err := s.checkSensitiveApproverKeys(doc.Sensitive); err != nil {
		return err
	}
	if s.Sensitive == nil && doc.Sensitive == nil {
		return nil
	}
	return SensitiveStatus(env, doc, s.Sensitive)
}

func (s *State) checkSensitiveApproverKeys(p *SensitivePolicy) error {
	if p == nil {
		return nil
	}
	for _, a := range p.Approvers {
		if bytes.Equal(a.Key[:], s.Anchor.RootKey) || slices.Contains(s.RecoveryKeys, a.Key) || slices.Contains(s.RevokedRoots, a.Key) {
			return fmt.Errorf("%w: approver %q uses a root or recovery key", ErrSensitivePolicy, a.Name)
		}
	}
	return nil
}
