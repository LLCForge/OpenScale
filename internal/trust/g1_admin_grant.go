package trust

import (
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"strings"
	"time"
)

// Delegated administrator keys (ADR-0172). The root key signs a short-lived
// grant that lets a separate administrator key (in a file, sealed with a
// passphrase, or on a hardware token) sign network documents within a
// scope: a list of operations and, optionally, a list of device tags.
//
// An administrator-signed document travels with the grant and with the
// root-signed document it was built on (AdminProof). Every verifier checks,
// with nothing but the pinned root key:
//
//  1. the grant is root-signed, for this network, not expired when the
//     document was issued, and not revoked in the base or the document;
//  2. the base is root-signed (never administrator-signed) and older;
//  3. the administrator's signature over the document;
//  4. that the document differs from the base only by changes the grant's
//     scope allows (CheckAdminScope). Anything not explicitly allowed is
//     refused, so the root alone keeps root rotation, approval policies,
//     recovery keys, coordinators and administrator grants.
//
// A member additionally refuses a base older than the newest root-signed
// document it accepted (State.Accept), so an administrator can never
// rebuild on an old base to undo the owner's later changes.

// Signature contexts of grants and administrator-signed documents.
const (
	AdminGrantContext    = "openscale/admin-grant/v1"
	AdminDocumentContext = "openscale/admin-document/v1"
)

// Administrator limits.
const (
	// MaxAdminGrantLife bounds a grant's lifetime (owner request: 90 days).
	MaxAdminGrantLife = 90 * 24 * time.Hour
	// MaxRevokedAdmins bounds the revoked grant ids a document lists.
	MaxRevokedAdmins = 256
	// maxGrantTags bounds the tags of a grant's scope.
	maxGrantTags = MaxTags
	// maxGrantSize bounds an encoded grant envelope.
	maxGrantSize = 32 << 10
	// MaxAdminVersionStep bounds how far above its root-signed base an
	// administrator document's version may go. The root can therefore always
	// sign above every administrator version built on its documents
	// (RootOvertakeVersion), so an administrator can never block the root's
	// later documents, its revocations included. It must stay far below the
	// emergency document offset (admin.EmergencyVersionOffset, 1<<32).
	MaxAdminVersionStep uint64 = 1 << 16
)

// RootOvertakeVersion returns a version above every administrator document
// built on a root document of version base or older. It saturates, which
// only a compromised root's document can reach (recovered with a root
// transition, ADR-0027).
func RootOvertakeVersion(base uint64) uint64 {
	if base > math.MaxUint64-MaxAdminVersionStep-1 {
		return math.MaxUint64
	}
	return base + MaxAdminVersionStep + 1
}

// CheckAdminVersion reports whether version may be signed by an administrator
// on a root-signed base of baseVersion.
func CheckAdminVersion(baseVersion, version uint64) error {
	switch {
	case version <= baseVersion:
		return fmt.Errorf("%w: version must be newer than the base", ErrAdminBase)
	case version-baseVersion > MaxAdminVersionStep:
		// SECURITY FIX: CWE-400 an unbounded version would lift every
		// member's rollback floor above anything the root can sign.
		return fmt.Errorf("%w: version %d is more than %d above the base %d; the owner must sign a new version first", ErrAdminBase, version, MaxAdminVersionStep, baseVersion)
	}
	return nil
}

// AdminOp is an operation a grant allows.
type AdminOp string

// Operations of a grant's scope. Version, issue and expiry times (renewal)
// are always allowed: the version bounded by CheckAdminVersion, the times by
// the grant's end.
const (
	// AdminOpDeviceAdd adds devices without roles or routes.
	AdminOpDeviceAdd AdminOp = "device.add"
	// AdminOpDeviceRevoke revokes devices (with the usual cascade).
	AdminOpDeviceRevoke AdminOp = "device.revoke"
	// AdminOpDeviceMembership extends or ends memberships.
	AdminOpDeviceMembership AdminOp = "device.membership"
	// AdminOpDeviceTags changes device tags.
	AdminOpDeviceTags AdminOp = "device.tags"
	// AdminOpDeviceRename renames devices and changes their aliases.
	AdminOpDeviceRename AdminOp = "device.rename"
	// AdminOpRules adds, removes and changes access rules.
	AdminOpRules AdminOp = "rules"
	// AdminOpInvites creates and removes invites.
	AdminOpInvites AdminOp = "invites"
	// AdminOpDNS changes network DNS, MagicDNS and DNS profiles
	// (network-wide; never with a tag-limited grant).
	AdminOpDNS AdminOp = "dns"
	// AdminOpGroups changes groups and exit users (network-wide; never
	// with a tag-limited grant).
	AdminOpGroups AdminOp = "groups"
	// AdminOpLockdown turns the emergency lock on or off (#361, #681).
	AdminOpLockdown AdminOp = "lockdown"
	// AdminOpSSHCert lets the key sign short-lived SSH user certificates
	// (#668, ADR-0179); it allows no document change.
	AdminOpSSHCert AdminOp = "ssh.cert"
)

// AdminOps lists every operation a grant may name.
func AdminOps() []AdminOp {
	return []AdminOp{AdminOpDeviceAdd, AdminOpDeviceRevoke, AdminOpDeviceMembership, AdminOpDeviceTags,
		AdminOpDeviceRename, AdminOpRules, AdminOpInvites, AdminOpDNS, AdminOpGroups, AdminOpLockdown, AdminOpSSHCert}
}

// Administrator errors.
var (
	ErrAdminGrant    = errors.New("invalid administrator grant")
	ErrAdminRevoked  = errors.New("administrator grant is revoked")
	ErrAdminExpired  = errors.New("administrator grant is not valid at this time")
	ErrAdminScope    = errors.New("change is outside the administrator's scope")
	ErrAdminBase     = errors.New("administrator document is built on an invalid or outdated base")
	ErrAdminMismatch = errors.New("administrator key does not match the grant")
)

// AdminGrant is the root-signed delegation of an administrator key.
type AdminGrant struct {
	// ID identifies the grant for revocation: 32 lowercase hex characters.
	ID        string `json:"id"`
	NetworkID string `json:"network_id"`
	// Name is a lowercase DNS label shown to people.
	Name string `json:"name"`
	Key  Key    `json:"key"`
	// Algorithm is the signature algorithm the key signs documents with:
	// empty (Ed25519ctx, a key in a file) or AlgEd25519Digest (a key on a
	// hardware token). A token binding requires AlgEd25519Digest.
	Algorithm string    `json:"algorithm,omitempty"`
	IssuedAt  time.Time `json:"issued_at"`
	NotAfter  time.Time `json:"not_after"`
	// Operations is the scope's list of operations.
	Operations []AdminOp `json:"operations"`
	// Tags, when present, limit device and rule changes to devices that
	// carry one of these tags (without the "tag:" prefix).
	Tags []string `json:"tags,omitempty"`
	// Token binds the key to one physical hardware token (#601, ADR-0173).
	Token *TokenBinding `json:"token,omitempty"`
}

// Allows reports whether the grant's scope names op.
func (g *AdminGrant) Allows(op AdminOp) bool { return slices.Contains(g.Operations, op) }

// Validate checks the grant's structure.
func (g *AdminGrant) Validate() error {
	switch {
	case !isValidID(g.ID):
		return fmt.Errorf("%w: id must be 32 lowercase hex characters", ErrAdminGrant)
	case !isValidID(g.NetworkID):
		return fmt.Errorf("%w: network_id must be 32 lowercase hex characters", ErrAdminGrant)
	case !isValidLabel(g.Name):
		return fmt.Errorf("%w: name %q must be a lowercase DNS label", ErrAdminGrant, g.Name)
	case g.Key.IsZero():
		return fmt.Errorf("%w: key is missing", ErrAdminGrant)
	case g.Algorithm != "" && g.Algorithm != AlgEd25519Digest:
		return fmt.Errorf("%w: unsupported algorithm %q", ErrAdminGrant, g.Algorithm)
	case g.IssuedAt.IsZero() || !g.NotAfter.After(g.IssuedAt):
		return fmt.Errorf("%w: not_after must be after issued_at", ErrAdminGrant)
	case g.NotAfter.Sub(g.IssuedAt) > MaxAdminGrantLife:
		return fmt.Errorf("%w: a grant may last at most %d days", ErrAdminGrant, int(MaxAdminGrantLife.Hours()/24))
	case len(g.Operations) == 0 || len(g.Operations) > len(AdminOps()):
		return fmt.Errorf("%w: 1-%d operations are allowed", ErrAdminGrant, len(AdminOps()))
	case len(g.Tags) > maxGrantTags:
		return fmt.Errorf("%w: at most %d tags are allowed", ErrAdminGrant, maxGrantTags)
	}
	seen := make(map[AdminOp]bool, len(g.Operations))
	for _, op := range g.Operations {
		if !slices.Contains(AdminOps(), op) {
			return fmt.Errorf("%w: unknown operation %q", ErrAdminGrant, op)
		}
		if seen[op] {
			return fmt.Errorf("%w: operation %q is listed twice", ErrAdminGrant, op)
		}
		seen[op] = true
	}
	if len(g.Tags) > 0 {
		if err := validateTags(g.Tags); err != nil {
			return fmt.Errorf("%w: %v", ErrAdminGrant, err)
		}
		if !slices.IsSorted(g.Tags) || len(slices.Compact(slices.Clone(g.Tags))) != len(g.Tags) {
			return fmt.Errorf("%w: tags must be sorted and unique", ErrAdminGrant)
		}
		if g.Allows(AdminOpDNS) || g.Allows(AdminOpGroups) || g.Allows(AdminOpLockdown) {
			return fmt.Errorf("%w: dns, groups and lockdown are network-wide and cannot be tag-limited", ErrAdminGrant)
		}
	}
	if g.Token != nil {
		if g.Algorithm != AlgEd25519Digest {
			return fmt.Errorf("%w: a token-bound key must use %s", ErrAdminGrant, AlgEd25519Digest)
		}
		if err := g.Token.Validate(g.Key); err != nil {
			return fmt.Errorf("%w: %v", ErrAdminGrant, err)
		}
	}
	return nil
}

// NewAdminGrantID returns a random grant id.
func NewAdminGrantID(random io.Reader) (string, error) { return newRandomID(random) }

// SignedGrant is a decoded, root-verified grant with its encoded envelope.
type SignedGrant struct {
	Grant   AdminGrant
	Encoded []byte
}

func grantPayload(g *AdminGrant) ([]byte, error) {
	g.Operations = slices.Clone(g.Operations)
	slices.Sort(g.Operations)
	if len(g.Tags) > 0 {
		g.Tags = slices.Clone(g.Tags)
		slices.Sort(g.Tags)
	}
	if err := g.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(g)
}

// SignAdminGrant signs g with the root key.
func SignAdminGrant(g AdminGrant, root ed25519.PrivateKey) (SignedGrant, error) {
	payload, err := grantPayload(&g)
	if err != nil {
		return SignedGrant{}, err
	}
	env, err := Sign(root, AdminGrantContext, payload)
	if err != nil {
		return SignedGrant{}, err
	}
	return encodeGrant(g, env)
}

// SignAdminGrantWith signs g with a hardware-held root key.
func SignAdminGrantWith(g AdminGrant, root DigestSigner) (SignedGrant, error) {
	payload, err := grantPayload(&g)
	if err != nil {
		return SignedGrant{}, err
	}
	env, err := SignWithDigest(root, AdminGrantContext, payload)
	if err != nil {
		return SignedGrant{}, err
	}
	return encodeGrant(g, env)
}

func encodeGrant(g AdminGrant, env Envelope) (SignedGrant, error) {
	data, err := json.Marshal(env)
	if err != nil {
		return SignedGrant{}, fmt.Errorf("encode grant: %w", err)
	}
	if len(data) > maxGrantSize {
		return SignedGrant{}, fmt.Errorf("%w: grant is too large", ErrAdminGrant)
	}
	return SignedGrant{Grant: g, Encoded: data}, nil
}

// OpenAdminGrant verifies an encoded grant against the root key and
// network. It does not check time or revocation; see CheckAdminGrant.
func OpenAdminGrant(data []byte, root ed25519.PublicKey, networkID string) (*AdminGrant, error) {
	if len(data) > maxGrantSize {
		return nil, fmt.Errorf("%w: grant is too large", ErrAdminGrant)
	}
	var env Envelope
	if err := decodeStrict(data, &env); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAdminGrant, err)
	}
	if env.Admin != nil || len(env.Cosignatures) > 0 || len(env.SensitiveApprovals) > 0 {
		return nil, fmt.Errorf("%w: unexpected envelope fields", ErrAdminGrant)
	}
	if err := checkDecodeAlgorithm(env.Algorithm); err != nil {
		return nil, err
	}
	payload, err := env.verifyRootSignature(root, AdminGrantContext)
	if err != nil {
		return nil, err
	}
	var g AdminGrant
	if err := decodeStrict(payload, &g); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAdminGrant, err)
	}
	if err := g.Validate(); err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare([]byte(g.NetworkID), []byte(networkID)) != 1 {
		return nil, ErrWrongNetwork
	}
	return &g, nil
}

// CheckAdminGrant verifies an encoded grant and checks that it allows op at
// now and is not listed in revoked. SSH certificate checks (#668, G5) and
// administrator sessions use it.
func CheckAdminGrant(data []byte, root ed25519.PublicKey, networkID string, op AdminOp, now time.Time, revoked []string) (*AdminGrant, error) {
	g, err := OpenAdminGrant(data, root, networkID)
	if err != nil {
		return nil, err
	}
	if now.Before(g.IssuedAt.Add(-clockSkew)) || !now.Before(g.NotAfter) {
		return nil, ErrAdminExpired
	}
	if slices.Contains(revoked, g.ID) {
		return nil, ErrAdminRevoked
	}
	if op != "" && !g.Allows(op) {
		return nil, fmt.Errorf("%w: operation %q", ErrAdminScope, op)
	}
	return g, nil
}

// AdminProof carries what a verifier needs besides the administrator's
// signature: the root-signed grant and the root-signed base document, both
// as their encoded envelopes.
type AdminProof struct {
	Grant json.RawMessage `json:"grant"`
	Base  json.RawMessage `json:"base"`
}

func (p *AdminProof) check() error {
	if p == nil {
		return nil
	}
	if len(p.Grant) == 0 || len(p.Base) == 0 {
		return errors.New("administrator proof needs a grant and a base")
	}
	if len(p.Grant) > maxGrantSize {
		return errors.New("administrator grant is too large")
	}
	return nil
}

// SignAdminDocument signs doc, built on the root-signed base envelope, with
// an administrator key held in software.
func SignAdminDocument(doc *Document, base Envelope, grant SignedGrant, priv ed25519.PrivateKey) (Envelope, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return Envelope{}, errors.New("invalid ed25519 private key")
	}
	if subtle.ConstantTimeCompare(priv.Public().(ed25519.PublicKey), grant.Grant.Key[:]) != 1 {
		return Envelope{}, ErrAdminMismatch
	}
	if grant.Grant.Algorithm != "" {
		return Envelope{}, fmt.Errorf("%w: this grant requires a hardware token", ErrAdminMismatch)
	}
	payload, proof, err := adminPayload(doc, base, grant)
	if err != nil {
		return Envelope{}, err
	}
	sig, err := priv.Sign(nil, payload, &ed25519.Options{Context: AdminDocumentContext})
	if err != nil {
		return Envelope{}, fmt.Errorf("sign administrator document: %w", err)
	}
	return Envelope{Context: DocumentContext, Payload: payload, Signature: sig, Admin: proof}, nil
}

// SignAdminDocumentWith signs doc with an administrator key on a hardware
// token.
func SignAdminDocumentWith(doc *Document, base Envelope, grant SignedGrant, signer DigestSigner) (Envelope, error) {
	if signer == nil {
		return Envelope{}, errors.New("no signer")
	}
	if subtle.ConstantTimeCompare(signer.PublicKey(), grant.Grant.Key[:]) != 1 {
		return Envelope{}, ErrAdminMismatch
	}
	payload, proof, err := adminPayload(doc, base, grant)
	if err != nil {
		return Envelope{}, err
	}
	signed, err := SignWithDigest(signer, AdminDocumentContext, payload)
	if err != nil {
		return Envelope{}, err
	}
	return Envelope{Context: DocumentContext, Payload: payload, Signature: signed.Signature, Algorithm: AlgEd25519Digest, Admin: proof}, nil
}

func adminPayload(doc *Document, base Envelope, grant SignedGrant) ([]byte, *AdminProof, error) {
	if base.Admin != nil {
		return nil, nil, fmt.Errorf("%w: the base must be root-signed", ErrAdminBase)
	}
	payload, err := DocumentPayload(doc)
	if err != nil {
		return nil, nil, err
	}
	baseData, err := json.Marshal(base)
	if err != nil {
		return nil, nil, fmt.Errorf("encode base: %w", err)
	}
	if len(payload)*4/3+len(baseData)+len(grant.Encoded) > MaxEnvelopeSize-4096 {
		return nil, nil, fmt.Errorf("%w: document and base together are too large for an administrator signature", ErrTooLarge)
	}
	return payload, &AdminProof{Grant: grant.Encoded, Base: baseData}, nil
}

// IsAdminSigned reports whether env is signed by a delegated administrator.
func (e Envelope) IsAdminSigned() bool { return e.Admin != nil }

// AdminVerified describes a verified administrator-signed document.
type AdminVerified struct {
	Grant      *AdminGrant
	Base       *Document
	BaseDigest [32]byte
}

// verifyAdminDocument verifies an administrator-signed document using only
// the root key: grant, base, signature and scope.
func verifyAdminDocument(env Envelope, root ed25519.PublicKey) (*Document, *AdminVerified, error) {
	if err := env.Admin.check(); err != nil {
		return nil, nil, err
	}
	if env.Context != DocumentContext {
		return nil, nil, ErrWrongContext
	}
	baseEnv, err := UnmarshalEnvelope(env.Admin.Base)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrAdminBase, err)
	}
	if baseEnv.Admin != nil {
		return nil, nil, fmt.Errorf("%w: the base must be root-signed", ErrAdminBase)
	}
	base, baseDigest, err := verifyDocument(baseEnv, root)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrAdminBase, err)
	}
	g, err := OpenAdminGrant(env.Admin.Grant, root, base.NetworkID)
	if err != nil {
		return nil, nil, err
	}
	pub := ed25519.PublicKey(g.Key[:])
	switch env.Algorithm {
	case "", AlgEd25519:
		if g.Algorithm != "" {
			return nil, nil, fmt.Errorf("%w: the grant requires a hardware token signature", ErrAdminMismatch)
		}
		if len(env.Signature) != ed25519.SignatureSize ||
			ed25519.VerifyWithOptions(pub, env.Payload, env.Signature, &ed25519.Options{Context: AdminDocumentContext}) != nil {
			return nil, nil, ErrBadSignature
		}
	case AlgEd25519Digest:
		if err := verifyDigest(pub, AdminDocumentContext, env.Payload, env.Signature); err != nil {
			return nil, nil, err
		}
	default:
		return nil, nil, ErrUnsupportedAlgorithm
	}
	var doc Document
	if err := decodeStrict(env.Payload, &doc); err != nil {
		return nil, nil, fmt.Errorf("decode document: %w", err)
	}
	if err := doc.Validate(); err != nil {
		return nil, nil, fmt.Errorf("invalid document: %w", err)
	}
	if doc.NetworkID != base.NetworkID {
		return nil, nil, ErrWrongNetwork
	}
	if err := CheckAdminVersion(base.Version, doc.Version); err != nil {
		return nil, nil, err
	}
	if slices.Contains(base.RevokedAdmins, g.ID) || slices.Contains(doc.RevokedAdmins, g.ID) {
		return nil, nil, ErrAdminRevoked
	}
	if doc.IssuedAt.Before(g.IssuedAt.Add(-clockSkew)) || !doc.IssuedAt.Before(g.NotAfter) {
		return nil, nil, ErrAdminExpired
	}
	if doc.ExpiresAt.After(g.NotAfter) {
		return nil, nil, fmt.Errorf("%w: the document must expire with the grant", ErrAdminExpired)
	}
	if err := CheckAdminScope(base, &doc, g); err != nil {
		return nil, nil, err
	}
	return &doc, &AdminVerified{Grant: g, Base: base, BaseDigest: baseDigest}, nil
}

// validateRevokedAdmins checks the document's revoked grant ids.
func (doc *Document) validateRevokedAdmins() error {
	ids := doc.RevokedAdmins
	if len(ids) > MaxRevokedAdmins {
		return fmt.Errorf("at most %d revoked_admins are allowed", MaxRevokedAdmins)
	}
	for i, id := range ids {
		if !isValidID(id) {
			return errors.New("revoked_admins entries must be 32 lowercase hex characters")
		}
		if i > 0 && ids[i-1] >= id {
			return errors.New("revoked_admins must be sorted and unique")
		}
	}
	return nil
}

// RevokeAdmin lists a grant id as revoked (root only: an administrator
// document can never change this list).
func (doc *Document) RevokeAdmin(id string) error {
	if !isValidID(id) {
		return errors.New("grant id must be 32 lowercase hex characters")
	}
	if slices.Contains(doc.RevokedAdmins, id) {
		return errors.New("grant is already revoked")
	}
	if len(doc.RevokedAdmins) >= MaxRevokedAdmins {
		return fmt.Errorf("at most %d revoked_admins are allowed", MaxRevokedAdmins)
	}
	ids := append(slices.Clone(doc.RevokedAdmins), id)
	slices.Sort(ids)
	doc.RevokedAdmins = ids
	return nil
}

// --- scope ---

// CheckAdminScope reports whether next differs from base only by changes
// g allows. It replays the allowed changes on a copy of base (revocations
// and renames with their usual cascade) and then requires the copy and
// next to be identical, so any field it does not know is root-only.
func CheckAdminScope(base, next *Document, g *AdminGrant) error {
	exp, err := cloneDocument(base)
	if err != nil {
		return err
	}
	sc := scopeChecker{g: g, base: base, next: next}
	byID := func(list []Device) map[string]Device {
		m := make(map[string]Device, len(list))
		for _, d := range list {
			m[d.ID] = d
		}
		return m
	}
	baseDev, nextDev := byID(base.Devices), byID(next.Devices)
	revokedAt := make(map[string]time.Time, len(next.Revoked))
	for _, r := range next.Revoked {
		revokedAt[r.DeviceID] = r.RevokedAt
	}

	// 1. Removed devices: revoked with the usual cascade.
	for _, d := range base.Devices {
		if _, ok := nextDev[d.ID]; ok {
			continue
		}
		at, ok := revokedAt[d.ID]
		if !ok {
			return fmt.Errorf("%w: device %s left without a revocation", ErrAdminScope, d.Name)
		}
		expiredEphemeral := d.Ephemeral && !next.IssuedAt.Before(d.ExpiresAt)
		if !expiredEphemeral {
			if err := sc.need(AdminOpDeviceRevoke); err != nil {
				return err
			}
			if !sc.inScope(d) {
				return fmt.Errorf("%w: device %s is outside the grant's tags", ErrAdminScope, d.Name)
			}
		}
		if _, err := exp.RevokeDevice(d.Name, at); err != nil {
			return fmt.Errorf("%w: revoking %s: %v", ErrAdminScope, d.Name, err)
		}
	}
	// 2. Renames, with the usual cascade.
	for _, d := range next.Devices {
		old, ok := baseDev[d.ID]
		if !ok || old.Name == d.Name {
			continue
		}
		if err := sc.need(AdminOpDeviceRename); err != nil {
			return err
		}
		if !sc.inScope(old) {
			return fmt.Errorf("%w: device %s is outside the grant's tags", ErrAdminScope, old.Name)
		}
		if err := exp.RenameDevice(old.Name, d.Name); err != nil {
			return fmt.Errorf("%w: renaming %s: %v", ErrAdminScope, old.Name, err)
		}
	}
	// 3. Field changes of kept devices and added devices.
	expDev := byID(exp.Devices)
	for _, d := range next.Devices {
		cur, ok := expDev[d.ID]
		if !ok {
			if err := sc.checkAdded(d); err != nil {
				return err
			}
			continue
		}
		if err := sc.checkChanged(cur, d); err != nil {
			return err
		}
	}
	exp.Devices = next.Devices
	if !jsonEqual(exp.Revoked, next.Revoked) {
		return fmt.Errorf("%w: revocations differ from the revoked devices", ErrAdminScope)
	}
	exp.Revoked = next.Revoked
	// 4. Rules.
	if !jsonEqual(exp.Rules, next.Rules) {
		if err := sc.need(AdminOpRules); err != nil {
			return err
		}
		if err := sc.checkRules(exp.Rules, next.Rules); err != nil {
			return err
		}
		exp.Rules = next.Rules
	}
	// 5. Invites.
	if !jsonEqual(exp.Invites, next.Invites) {
		if err := sc.need(AdminOpInvites); err != nil {
			return err
		}
		if err := sc.checkInvites(exp.Invites, next.Invites); err != nil {
			return err
		}
		exp.Invites = next.Invites
	}
	// 6. Network-wide settings.
	if !jsonEqual(exp.DNS, next.DNS) || !jsonEqual(exp.MagicDNS, next.MagicDNS) || !jsonEqual(exp.DNSProfiles, next.DNSProfiles) {
		if err := sc.need(AdminOpDNS); err != nil {
			return err
		}
		exp.DNS, exp.MagicDNS, exp.DNSProfiles = next.DNS, next.MagicDNS, next.DNSProfiles
	}
	if !jsonEqual(exp.Groups, next.Groups) || !jsonEqual(exp.ExitUsers, next.ExitUsers) {
		if err := sc.need(AdminOpGroups); err != nil {
			return err
		}
		exp.Groups, exp.ExitUsers = next.Groups, next.ExitUsers
	}
	if !jsonEqual(exp.Lockdown, next.Lockdown) {
		if err := sc.need(AdminOpLockdown); err != nil {
			return err
		}
		exp.Lockdown = next.Lockdown
	}
	// 7. Renewal fields.
	exp.Version, exp.IssuedAt, exp.ExpiresAt, exp.PrevDigest = next.Version, next.IssuedAt, next.ExpiresAt, next.PrevDigest
	if !jsonEqual(exp, next) {
		return fmt.Errorf("%w: %s", ErrAdminScope, firstDifference(exp, next))
	}
	return nil
}

type scopeChecker struct {
	g          *AdminGrant
	base, next *Document
}

func (sc scopeChecker) need(op AdminOp) error {
	if !sc.g.Allows(op) {
		return fmt.Errorf("%w: operation %q is not granted", ErrAdminScope, op)
	}
	return nil
}

func (sc scopeChecker) tagLimited() bool { return len(sc.g.Tags) > 0 }

func (sc scopeChecker) inScope(d Device) bool {
	if !sc.tagLimited() {
		return true
	}
	for _, t := range d.Tags {
		if slices.Contains(sc.g.Tags, t) {
			return true
		}
	}
	return false
}

func (sc scopeChecker) tagsInScope(tags []string) bool {
	if !sc.tagLimited() {
		return true
	}
	if len(tags) == 0 {
		return false
	}
	for _, t := range tags {
		if !slices.Contains(sc.g.Tags, t) {
			return false
		}
	}
	return true
}

func (sc scopeChecker) checkAdded(d Device) error {
	if err := sc.need(AdminOpDeviceAdd); err != nil {
		return err
	}
	if len(d.Roles) > 0 || len(d.Routes) > 0 {
		return fmt.Errorf("%w: an administrator cannot add device %s with roles or routes", ErrAdminScope, d.Name)
	}
	if !sc.tagsInScope(d.Tags) {
		return fmt.Errorf("%w: device %s must carry only the grant's tags", ErrAdminScope, d.Name)
	}
	return nil
}

func (sc scopeChecker) checkChanged(cur, d Device) error {
	if !cur.ExpiresAt.Equal(d.ExpiresAt) {
		if err := sc.need(AdminOpDeviceMembership); err != nil {
			return err
		}
		if !sc.inScope(cur) {
			return fmt.Errorf("%w: device %s is outside the grant's tags", ErrAdminScope, cur.Name)
		}
		cur.ExpiresAt = d.ExpiresAt
	}
	if !slices.Equal(cur.Tags, d.Tags) {
		if err := sc.need(AdminOpDeviceTags); err != nil {
			return err
		}
		if sc.tagLimited() {
			if !sc.inScope(cur) || !sc.inScope(d) {
				return fmt.Errorf("%w: device %s must stay within the grant's tags", ErrAdminScope, cur.Name)
			}
			for _, t := range symmetricDiff(cur.Tags, d.Tags) {
				if !slices.Contains(sc.g.Tags, t) {
					return fmt.Errorf("%w: tag %s is outside the grant", ErrAdminScope, t)
				}
			}
		}
		cur.Tags = d.Tags
	}
	if !slices.Equal(cur.Aliases, d.Aliases) {
		if err := sc.need(AdminOpDeviceRename); err != nil {
			return err
		}
		if !sc.inScope(cur) {
			return fmt.Errorf("%w: device %s is outside the grant's tags", ErrAdminScope, cur.Name)
		}
		cur.Aliases = d.Aliases
	}
	if !jsonEqual(cur, d) {
		return fmt.Errorf("%w: device %s changes fields only the root may change (keys, addresses, roles, routes)", ErrAdminScope, d.Name)
	}
	return nil
}

// checkRules allows, for a tag-limited grant, only added or removed rules
// whose every entry is one of the grant's tags or a device in scope.
func (sc scopeChecker) checkRules(before, after []Rule) error {
	if !sc.tagLimited() {
		return nil
	}
	for _, r := range ruleMultisetDiff(before, after) {
		for _, e := range slices.Concat(r.From, r.To, r.Via) {
			if !sc.entryInScope(e) {
				return fmt.Errorf("%w: rule entry %q is outside the grant's tags", ErrAdminScope, e)
			}
		}
	}
	return nil
}

func (sc scopeChecker) entryInScope(e string) bool {
	if t, ok := strings.CutPrefix(e, TagPrefix); ok {
		return slices.Contains(sc.g.Tags, t)
	}
	if e == RuleWildcard || strings.HasPrefix(e, GroupPrefix) || isAddrEntry(e) {
		return false
	}
	for _, doc := range []*Document{sc.base, sc.next} {
		if d, ok := doc.DeviceByName(e); ok && sc.inScope(d) {
			return true
		}
	}
	return false
}

func (sc scopeChecker) checkInvites(before, after []Invite) error {
	if !sc.tagLimited() {
		return nil
	}
	old := make(map[string]Invite, len(before))
	for _, i := range before {
		old[i.ID] = i
	}
	seen := make(map[string]bool, len(after))
	for _, i := range after {
		seen[i.ID] = true
		if o, ok := old[i.ID]; ok && jsonEqual(o, i) {
			continue
		}
		if !sc.tagsInScope(i.Tags) {
			return fmt.Errorf("%w: invite %s must carry only the grant's tags", ErrAdminScope, i.ID)
		}
	}
	for _, i := range before {
		if !seen[i.ID] && !sc.tagsInScope(i.Tags) {
			return fmt.Errorf("%w: invite %s is outside the grant's tags", ErrAdminScope, i.ID)
		}
	}
	return nil
}

func ruleMultisetDiff(before, after []Rule) []Rule {
	count := make(map[string]int, len(before))
	enc := func(r Rule) string {
		b, _ := json.Marshal(r)
		return string(b)
	}
	for _, r := range before {
		count[enc(r)]++
	}
	var out []Rule
	for _, r := range after {
		k := enc(r)
		if count[k] > 0 {
			count[k]--
			continue
		}
		out = append(out, r)
	}
	for _, r := range before {
		k := enc(r)
		if count[k] > 0 {
			count[k]--
			out = append(out, r)
		}
	}
	return out
}

func symmetricDiff(a, b []string) []string {
	var out []string
	for _, x := range a {
		if !slices.Contains(b, x) {
			out = append(out, x)
		}
	}
	for _, x := range b {
		if !slices.Contains(a, x) {
			out = append(out, x)
		}
	}
	return out
}

func jsonEqual(a, b any) bool {
	x, err1 := json.Marshal(a)
	y, err2 := json.Marshal(b)
	return err1 == nil && err2 == nil && string(x) == string(y)
}

func cloneDocument(doc *Document) (*Document, error) {
	data, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("copy document: %w", err)
	}
	var out Document
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("copy document: %w", err)
	}
	return &out, nil
}

// firstDifference names the first top-level field that differs, for the
// error message.
func firstDifference(a, b *Document) string {
	var ma, mb map[string]json.RawMessage
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	if json.Unmarshal(x, &ma) != nil || json.Unmarshal(y, &mb) != nil {
		return "document differs"
	}
	keys := make([]string, 0, len(ma)+len(mb))
	for k := range ma {
		keys = append(keys, k)
	}
	for k := range mb {
		if _, ok := ma[k]; !ok {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	for _, k := range keys {
		if string(ma[k]) != string(mb[k]) {
			return "field " + k + " may only be changed by the root"
		}
	}
	return "document differs"
}
