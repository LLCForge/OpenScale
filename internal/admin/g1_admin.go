package admin

import (
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
)

// Delegated administrator keys, owner side (ADR-0172). Only the root issues
// and revokes grants; the administrator signs documents with its own key
// (file, portable blob or hardware token) and never sees the root key.

// AdminKeyFormat is the sealed secret format of an administrator key file.
const AdminKeyFormat = "openscale-admin-key-v1"

const (
	adminsFile    = "admins.json"
	maxAdminsFile = 1 << 20
	// maxAdminRecords bounds the grant registry.
	maxAdminRecords = 4096
)

// GenerateAdminKey creates an administrator key and returns its public key
// and the passphrase-sealed key file.
func GenerateAdminKey(passphrase []byte, params trust.Argon2Params, random io.Reader) (trust.Key, []byte, error) {
	pub, priv, err := trust.GenerateRootKey(random)
	if err != nil {
		return trust.Key{}, nil, err
	}
	defer wipe(priv)
	var k trust.Key
	copy(k[:], pub)
	seed := priv.Seed()
	defer wipe(seed)
	sealed, err := trust.SealSecret(AdminKeyFormat, k.String(), seed, passphrase, params, random)
	if err != nil {
		return trust.Key{}, nil, err
	}
	data, err := trust.MarshalSealedSecret(sealed)
	if err != nil {
		return trust.Key{}, nil, err
	}
	return k, data, nil
}

// OpenAdminKeyFile decrypts an administrator key file. The caller wipes
// the key with trust.WipeKey.
func OpenAdminKeyFile(data, passphrase []byte) (ed25519.PrivateKey, error) {
	sealed, err := trust.UnmarshalSealedSecret(data, AdminKeyFormat)
	if err != nil {
		return nil, err
	}
	seed, err := sealed.Open(AdminKeyFormat, passphrase)
	if err != nil {
		return nil, err
	}
	defer wipe(seed)
	if len(seed) != ed25519.SeedSize {
		return nil, trust.ErrWrongPassphrase
	}
	priv := ed25519.NewKeyFromSeed(seed)
	want, err := trust.ParseKey(sealed.Label)
	if err != nil || subtle.ConstantTimeCompare(priv.Public().(ed25519.PublicKey), want[:]) != 1 {
		wipe(priv)
		return nil, trust.ErrWrongPassphrase
	}
	return priv, nil
}

// AdminKeyFilePublic returns the public key recorded in a key file without
// the passphrase.
func AdminKeyFilePublic(data []byte) (trust.Key, error) {
	var s trust.SealedSecret
	if err := json.Unmarshal(data, &s); err != nil || s.Format != AdminKeyFormat {
		return trust.Key{}, errors.New("not an administrator key file")
	}
	return trust.ParseKey(s.Label)
}

// GrantRequest describes a grant the owner issues.
type GrantRequest struct {
	Name       string
	Key        trust.Key
	Lifetime   time.Duration
	Operations []trust.AdminOp
	Tags       []string
	// Token binds the key to a hardware token (#601); the key then signs
	// with AlgEd25519Digest. VendorRootDER, when given, is the token
	// vendor's root certificate the attestation chain must reach.
	Token         *trust.TokenBinding
	VendorRootDER []byte
	// OnToken marks a key on a token without a binding (digest signatures).
	OnToken bool
}

// GrantRecord is one issued grant in the owner's registry.
type GrantRecord struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Key       trust.Key       `json:"key"`
	IssuedAt  time.Time       `json:"issued_at"`
	NotAfter  time.Time       `json:"not_after"`
	Ops       []trust.AdminOp `json:"operations"`
	Tags      []string        `json:"tags,omitempty"`
	Token     string          `json:"token,omitempty"`
	Encoded   json.RawMessage `json:"grant"`
	Revoked   bool            `json:"-"`
	ExpiredAt bool            `json:"-"`
}

func (n *Network) grantFor(req GrantRequest, now time.Time) (trust.AdminGrant, error) {
	if req.Lifetime <= 0 || req.Lifetime > trust.MaxAdminGrantLife {
		return trust.AdminGrant{}, fmt.Errorf("grant lifetime must be between 1s and %d days", int(trust.MaxAdminGrantLife.Hours()/24))
	}
	id, err := trust.NewAdminGrantID(n.random)
	if err != nil {
		return trust.AdminGrant{}, err
	}
	n.mu.Lock()
	networkID := n.doc.NetworkID
	root := n.sealed.PublicKey
	n.mu.Unlock()
	if req.Key == root {
		return trust.AdminGrant{}, errors.New("the administrator key must differ from the root key")
	}
	g := trust.AdminGrant{ID: id, NetworkID: networkID, Name: req.Name, Key: req.Key,
		IssuedAt: now.UTC().Truncate(time.Second), Operations: slices.Clone(req.Operations), Tags: slices.Clone(req.Tags)}
	g.NotAfter = g.IssuedAt.Add(req.Lifetime)
	if req.Token != nil || req.OnToken {
		g.Algorithm = trust.AlgEd25519Digest
	}
	if req.Token != nil {
		if len(req.VendorRootDER) > 0 {
			if err := req.Token.CheckChain(req.VendorRootDER); err != nil {
				return trust.AdminGrant{}, err
			}
		}
		g.Token = req.Token
	}
	slices.Sort(g.Tags)
	return g, g.Validate()
}

// IssueAdminGrant signs a grant with the root key (passphrase) and records
// it in the registry.
func (n *Network) IssueAdminGrant(passphrase []byte, req GrantRequest, now time.Time) (trust.SignedGrant, error) {
	g, err := n.grantFor(req, now)
	if err != nil {
		return trust.SignedGrant{}, err
	}
	n.mu.Lock()
	sealed := n.sealed
	n.mu.Unlock()
	root, err := sealed.Open(passphrase)
	if err != nil {
		return trust.SignedGrant{}, err
	}
	defer wipe(root)
	sg, err := trust.SignAdminGrant(g, root)
	if err != nil {
		return trust.SignedGrant{}, err
	}
	return sg, n.recordGrant(sg)
}

// IssueAdminGrantWith signs a grant with a hardware-held root key.
func (n *Network) IssueAdminGrantWith(signer trust.DigestSigner, req GrantRequest, now time.Time) (trust.SignedGrant, error) {
	if signer == nil || subtle.ConstantTimeCompare(signer.PublicKey(), n.sealed.PublicKey[:]) != 1 {
		return trust.SignedGrant{}, ErrTokenKeyMismatch
	}
	g, err := n.grantFor(req, now)
	if err != nil {
		return trust.SignedGrant{}, err
	}
	sg, err := trust.SignAdminGrantWith(g, signer)
	if err != nil {
		return trust.SignedGrant{}, err
	}
	return sg, n.recordGrant(sg)
}

func (n *Network) recordGrant(sg trust.SignedGrant) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	list, err := readGrantRecords(n.dir)
	if err != nil {
		return err
	}
	if len(list) >= maxAdminRecords {
		return fmt.Errorf("at most %d grants can be recorded", maxAdminRecords)
	}
	g := sg.Grant
	rec := GrantRecord{ID: g.ID, Name: g.Name, Key: g.Key, IssuedAt: g.IssuedAt, NotAfter: g.NotAfter, Ops: g.Operations, Tags: g.Tags, Encoded: sg.Encoded}
	if g.Token != nil {
		rec.Token = fmt.Sprintf("%s:%d", g.Token.Kind, g.Token.Serial)
	} else if g.Algorithm != "" {
		rec.Token = "token"
	}
	list = append(list, rec)
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return securefile.Replace(filepath.Join(n.dir, adminsFile), append(data, '\n'))
}

func readGrantRecords(dir string) ([]GrantRecord, error) {
	data, err := securefile.ReadPrivate(filepath.Join(dir, adminsFile), maxAdminsFile)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read grant registry: %w", err)
	}
	var list []GrantRecord
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, errors.New("grant registry (admins.json) is corrupt")
	}
	return list, nil
}

// AdminGrants lists the issued grants with their revocation and expiry
// state against the current document.
func (n *Network) AdminGrants(now time.Time) ([]GrantRecord, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	list, err := readGrantRecords(n.dir)
	if err != nil {
		return nil, err
	}
	for i := range list {
		list[i].Revoked = slices.Contains(n.doc.RevokedAdmins, list[i].ID)
		list[i].ExpiredAt = !now.Before(list[i].NotAfter)
	}
	return list, nil
}

// RevokeAdminGrant returns a Change that revokes a grant (root-signed).
func RevokeAdminGrant(id string) Change {
	return func(doc *trust.Document) error {
		if err := doc.RevokeAdmin(strings.ToLower(id)); err != nil {
			return err
		}
		// The owner may not have seen everything this administrator signed;
		// the revocation must reach members above any of it.
		doc.Version = trust.RootOvertakeVersion(doc.Version)
		return nil
	}
}

// OvertakeAdminVersions returns a Change that raises the next root-signed
// version above every administrator document built on the current one. It
// is the way forward when members refuse a root document as a rollback
// because an administrator signed versions the owner has not imported.
func OvertakeAdminVersions() Change {
	return func(doc *trust.Document) error {
		doc.Version = trust.RootOvertakeVersion(doc.Version)
		return nil
	}
}

// ParseAdminOps parses a comma-separated operation list.
func ParseAdminOps(s string) ([]trust.AdminOp, error) {
	var ops []trust.AdminOp
	for _, part := range strings.Split(s, ",") {
		op := trust.AdminOp(strings.TrimSpace(part))
		if op == "" {
			continue
		}
		if !slices.Contains(trust.AdminOps(), op) {
			return nil, fmt.Errorf("unknown operation %q", op)
		}
		if !slices.Contains(ops, op) {
			ops = append(ops, op)
		}
	}
	if len(ops) == 0 {
		return nil, errors.New("at least one operation is required")
	}
	return ops, nil
}

// --- administrator side ---

// AdminContext is what an administrator works from: the trusted root key,
// its grant and the newest signed document (root- or administrator-signed).
type AdminContext struct {
	Root     ed25519.PublicKey
	Grant    trust.SignedGrant
	Current  trust.Envelope
	Document *trust.Document
	// Base is the root-signed document Current is (or is built on).
	Base trust.Envelope
}

// NewAdminContext verifies the current document and the grant against the
// root key, and that the grant is usable at now.
func NewAdminContext(root ed25519.PublicKey, grantData, currentData []byte, now time.Time) (*AdminContext, error) {
	cur, err := trust.UnmarshalEnvelope(currentData)
	if err != nil {
		return nil, err
	}
	doc, err := trust.VerifyDocumentSignature(cur, root)
	if err != nil {
		return nil, err
	}
	base := cur
	if cur.Admin != nil {
		if base, err = trust.UnmarshalEnvelope(cur.Admin.Base); err != nil {
			return nil, err
		}
	}
	baseDoc, err := trust.VerifyDocumentSignature(base, root)
	if err != nil {
		return nil, err
	}
	g, err := trust.CheckAdminGrant(grantData, root, doc.NetworkID, "", now, slices.Concat(doc.RevokedAdmins, baseDoc.RevokedAdmins))
	if err != nil {
		return nil, err
	}
	return &AdminContext{Root: root, Grant: trust.SignedGrant{Grant: *g, Encoded: append([]byte(nil), grantData...)}, Current: cur, Document: doc, Base: base}, nil
}

// AdminPlan is an administrator's prepared, unsigned change.
type AdminPlan struct {
	Next *trust.Document
	Diff Diff
	Risk RiskReport
	ctx  *AdminContext
}

// PrepareAdmin applies change to the next version and checks that the
// result is within the grant's scope before anything is signed. The new
// version expires no later than the grant.
func (c *AdminContext) PrepareAdmin(now time.Time, validity time.Duration, change Change) (*AdminPlan, error) {
	if left := c.Grant.Grant.NotAfter.Sub(now); validity > left {
		validity = left
	}
	if validity <= time.Minute {
		return nil, trust.ErrAdminExpired
	}
	next, err := c.Document.Next(now, validity)
	if err != nil {
		return nil, err
	}
	if next.ExpiresAt.After(c.Grant.Grant.NotAfter) {
		next.ExpiresAt = c.Grant.Grant.NotAfter.UTC().Truncate(time.Second)
	}
	if err := change(next); err != nil {
		return nil, err
	}
	next.PruneEphemeral(now)
	if next.VersionChainEnabled() {
		next.LinkVersionChain(c.Current)
	}
	if err := next.Validate(); err != nil {
		return nil, err
	}
	if err := next.CheckPolicyTests(); err != nil {
		return nil, err
	}
	baseDoc, err := trust.VerifyDocumentSignature(c.Base, c.Root)
	if err != nil {
		return nil, err
	}
	if err := trust.CheckAdminVersion(baseDoc.Version, next.Version); err != nil {
		return nil, err
	}
	if err := trust.CheckAdminScope(baseDoc, next, &c.Grant.Grant); err != nil {
		return nil, err
	}
	return &AdminPlan{Next: next, Diff: ComputeDiff(c.Document, next), Risk: AssessRisk(c.Document, next), ctx: c}, nil
}

// SignAdminPlan signs the plan with a software administrator key and
// returns the encoded envelope, carrying still valid sensitive approvals.
func SignAdminPlan(plan *AdminPlan, priv ed25519.PrivateKey) ([]byte, error) {
	if plan == nil || plan.ctx == nil {
		return nil, errors.New("no plan")
	}
	env, err := trust.SignAdminDocument(plan.Next, plan.ctx.Base, plan.ctx.Grant, priv)
	if err != nil {
		return nil, err
	}
	return finishAdminEnvelope(plan, env)
}

// SignAdminPlanWith signs the plan with an administrator key on a token.
func SignAdminPlanWith(plan *AdminPlan, signer trust.DigestSigner) ([]byte, error) {
	if plan == nil || plan.ctx == nil {
		return nil, errors.New("no plan")
	}
	env, err := trust.SignAdminDocumentWith(plan.Next, plan.ctx.Base, plan.ctx.Grant, signer)
	if err != nil {
		return nil, err
	}
	return finishAdminEnvelope(plan, env)
}

func finishAdminEnvelope(plan *AdminPlan, env trust.Envelope) ([]byte, error) {
	trust.CarrySensitiveApprovals(plan.ctx.Current, &env, plan.Next)
	if _, err := trust.VerifyDocumentSignature(env, plan.ctx.Root); err != nil {
		return nil, err
	}
	return trust.MarshalEnvelope(env)
}

// carrySensitive copies still valid sensitive approvals of the document on
// disk into env (root-signed saves, ADR-0174).
func carrySensitive(path string, env *trust.Envelope, doc *trust.Document) {
	if doc.Sensitive == nil {
		return
	}
	data, err := securefile.ReadPrivate(path, trust.MaxEnvelopeSize)
	if err != nil {
		return
	}
	prev, err := trust.UnmarshalEnvelope(data)
	if err != nil {
		return
	}
	trust.CarrySensitiveApprovals(prev, env, doc)
}
