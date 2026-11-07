package trust

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"
)

// pureSigner stands in for a PIV token: it signs with pure Ed25519 only.
type pureSigner struct{ priv ed25519.PrivateKey }

func (p pureSigner) PublicKey() ed25519.PublicKey { return p.priv.Public().(ed25519.PublicKey) }
func (p pureSigner) SignMessage(msg []byte) ([]byte, error) {
	return ed25519.Sign(p.priv, msg), nil
}

func newApprover(t *testing.T, name string) (Approver, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var k Key
	copy(k[:], pub)
	return Approver{Name: name, Key: k}, priv
}

func approve(t *testing.T, f *fixture, env *Envelope, priv ed25519.PrivateKey) {
	t.Helper()
	c, _, err := ApproveDocument(priv, *env, f.rootPub)
	if err != nil {
		t.Fatalf("ApproveDocument: %v", err)
	}
	if err := AddCosignature(env, c); err != nil {
		t.Fatalf("AddCosignature: %v", err)
	}
}

// roundTrip encodes and decodes env as a device would receive it.
func roundTrip(t *testing.T, env Envelope) Envelope {
	t.Helper()
	data, err := MarshalEnvelope(env)
	if err != nil {
		t.Fatal(err)
	}
	out, err := UnmarshalEnvelope(data)
	if err != nil {
		t.Fatalf("UnmarshalEnvelope: %v", err)
	}
	return out
}

func TestDocumentWithoutPolicyEncodesAsBefore(t *testing.T) {
	f := newFixture(t)
	env := f.sign(t, f.doc)
	data, err := MarshalEnvelope(env)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("cosignatures")) || bytes.Contains(env.Payload, []byte("approval")) {
		t.Fatalf("unused approval fields were encoded:\n%s", data)
	}
}

func TestApprovalPolicyTwoOfThree(t *testing.T) {
	f := newFixture(t)
	a, aPriv := newApprover(t, "laptop")
	b, bPriv := newApprover(t, "token")
	c, _ := newApprover(t, "safe")
	f.doc.Approval = &ApprovalPolicy{Threshold: 2, Approvers: []Approver{a, b, c}}

	// Introducing a policy needs its own approvals.
	env := f.sign(t, f.doc)
	st := &State{Anchor: f.anchor}
	if _, err := st.Accept(roundTrip(t, env), testNow); !errors.Is(err, ErrApprovalMissing) {
		t.Fatalf("root-only document with a policy: got %v, want ErrApprovalMissing", err)
	}
	approve(t, f, &env, aPriv)
	if _, err := st.Accept(roundTrip(t, env), testNow); !errors.Is(err, ErrApprovalMissing) {
		t.Fatalf("one approval of two: got %v", err)
	}
	// The same approver twice still counts once.
	approve(t, f, &env, aPriv)
	if len(env.Cosignatures) != 1 {
		t.Fatalf("duplicate approval kept: %d", len(env.Cosignatures))
	}
	// A hardware (digest) approval counts like any other.
	hw, _, err := ApproveDocumentWith(pureSigner{bPriv}, env, f.rootPub)
	if err != nil {
		t.Fatal(err)
	}
	if err := AddCosignature(&env, hw); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Accept(roundTrip(t, env), testNow); err != nil {
		t.Fatalf("two approvals: %v", err)
	}
	if !st.Approval.Equal(f.doc.Approval) {
		t.Fatal("policy was not pinned")
	}

	// The root alone can neither publish nor drop the policy.
	next := *f.doc
	next.Version++
	if _, err := st.Accept(roundTrip(t, f.sign(t, &next)), testNow); !errors.Is(err, ErrApprovalMissing) {
		t.Fatalf("root-only next version: got %v", err)
	}
	drop := *f.doc
	drop.Version += 2
	drop.Approval = nil
	if _, err := st.Accept(roundTrip(t, f.sign(t, &drop)), testNow); !errors.Is(err, ErrApprovalMissing) {
		t.Fatalf("root-only removal of the policy: got %v", err)
	}
	// Removing the policy with the old quorum's approval works.
	dropEnv := f.sign(t, &drop)
	approve(t, f, &dropEnv, aPriv)
	hw2, _, err := ApproveDocumentWith(pureSigner{bPriv}, dropEnv, f.rootPub)
	if err != nil {
		t.Fatal(err)
	}
	if err := AddCosignature(&dropEnv, hw2); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Accept(roundTrip(t, dropEnv), testNow); err != nil {
		t.Fatalf("approved removal: %v", err)
	}
	if st.Approval != nil {
		t.Fatal("policy still pinned after approved removal")
	}
}

func TestApprovalPinSurvivesReload(t *testing.T) {
	f := newFixture(t)
	a, aPriv := newApprover(t, "laptop")
	f.doc.Approval = &ApprovalPolicy{Threshold: 1, Approvers: []Approver{a}}
	env := f.sign(t, f.doc)
	approve(t, f, &env, aPriv)
	st := &State{Anchor: f.anchor}
	doc, err := st.Accept(roundTrip(t, env), testNow)
	if err != nil {
		t.Fatal(err)
	}
	// A reloaded state pins from its stored document.
	re := &State{Anchor: f.anchor, HighestVersion: st.HighestVersion, HighestDigest: st.HighestDigest}
	re.PinApproval(doc)
	next := *f.doc
	next.Version++
	next.Approval = nil
	if _, err := re.Accept(roundTrip(t, f.sign(t, &next)), testNow); !errors.Is(err, ErrApprovalMissing) {
		t.Fatalf("got %v, want ErrApprovalMissing", err)
	}
}

func TestApprovalRejections(t *testing.T) {
	f := newFixture(t)
	a, aPriv := newApprover(t, "laptop")
	b, _ := newApprover(t, "token")

	bad := []*ApprovalPolicy{
		{Threshold: 0, Approvers: []Approver{a}},
		{Threshold: 2, Approvers: []Approver{a}},
		{Threshold: 1, Approvers: []Approver{a, {Name: "copy", Key: a.Key}}},
		{Threshold: 1, Approvers: []Approver{a, {Name: a.Name, Key: b.Key}}},
		{Threshold: 1, Approvers: []Approver{{Name: "Bad Name", Key: b.Key}}},
		{Threshold: 1, Approvers: []Approver{{Name: "zero"}}},
		{Threshold: 1},
	}
	for i, p := range bad {
		f.doc.Approval = p
		if _, err := SignDocument(f.doc, f.rootPriv); err == nil {
			t.Errorf("policy %d was accepted", i)
		}
	}

	// The root key can never be an approver.
	var rootKey Key
	copy(rootKey[:], f.rootPub)
	f.doc.Approval = &ApprovalPolicy{Threshold: 1, Approvers: []Approver{{Name: "root", Key: rootKey}}}
	env := f.sign(t, f.doc)
	approve(t, f, &env, f.rootPriv)
	st := &State{Anchor: f.anchor}
	if _, err := st.Accept(roundTrip(t, env), testNow); !errors.Is(err, ErrApprovalPolicy) {
		t.Fatalf("root as approver: got %v", err)
	}

	// An approval of another document does not transfer.
	f.doc.Approval = &ApprovalPolicy{Threshold: 1, Approvers: []Approver{a}}
	env = f.sign(t, f.doc)
	other := *f.doc
	other.Version++
	otherEnv := f.sign(t, &other)
	approve(t, f, &otherEnv, aPriv)
	moved := otherEnv.Cosignatures[0]
	if err := AddCosignature(&env, moved); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("moved approval: got %v", err)
	}
	env.Cosignatures = []Cosignature{moved}
	if _, err := st.Accept(roundTrip(t, env), testNow); !errors.Is(err, ErrApprovalMissing) {
		t.Fatalf("moved approval accepted: %v", err)
	}

	// A root signature over the payload is not an approval (other context).
	fake := Cosignature{Key: a.Key, Signature: env.Signature}
	if err := AddCosignature(&env, fake); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("root signature as approval: got %v", err)
	}

	// Approving a document that does not verify against the root fails.
	_, otherRoot, _ := ed25519.GenerateKey(rand.Reader)
	if _, _, err := ApproveDocument(aPriv, env, otherRoot.Public().(ed25519.PublicKey)); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("approving a foreign document: got %v", err)
	}
}

func TestEnvelopeRejectsMalformedCosignatures(t *testing.T) {
	f := newFixture(t)
	a, aPriv := newApprover(t, "laptop")
	f.doc.Approval = &ApprovalPolicy{Threshold: 1, Approvers: []Approver{a}}
	env := f.sign(t, f.doc)
	approve(t, f, &env, aPriv)

	cases := map[string]func(e *Envelope){
		"duplicate key": func(e *Envelope) { e.Cosignatures = append(e.Cosignatures, e.Cosignatures[0]) },
		"short sig":     func(e *Envelope) { e.Cosignatures[0].Signature = e.Cosignatures[0].Signature[:10] },
		"zero key":      func(e *Envelope) { e.Cosignatures[0].Key = Key{} },
		"unknown alg":   func(e *Envelope) { e.Cosignatures[0].Algorithm = AlgHybridEd25519MLDSA65 },
		"too many": func(e *Envelope) {
			for i := range MaxCosignatures {
				c := e.Cosignatures[0]
				c.Key[0] ^= byte(i + 1)
				e.Cosignatures = append(e.Cosignatures, c)
			}
		},
	}
	for name, mutate := range cases {
		e := env
		e.Cosignatures = append([]Cosignature(nil), env.Cosignatures...)
		for i := range e.Cosignatures {
			e.Cosignatures[i].Signature = append([]byte(nil), e.Cosignatures[i].Signature...)
		}
		mutate(&e)
		data, err := MarshalEnvelope(e)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := UnmarshalEnvelope(data); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestDigestSignedDocument(t *testing.T) {
	f := newFixture(t)
	signer := pureSigner{f.rootPriv}
	env, err := SignDocumentWith(f.doc, signer)
	if err != nil {
		t.Fatal(err)
	}
	if env.Algorithm != AlgEd25519Digest {
		t.Fatalf("algorithm %q", env.Algorithm)
	}
	st := &State{Anchor: f.anchor}
	if _, err := st.Accept(roundTrip(t, env), testNow); err != nil {
		t.Fatalf("digest-signed document: %v", err)
	}
	// Same payload bytes as the Ed25519ctx path.
	ctxEnv := f.sign(t, f.doc)
	if !bytes.Equal(ctxEnv.Payload, env.Payload) {
		t.Fatal("payload differs between signing paths")
	}

	// Envelope.Verify (every non-document object) refuses digest signatures.
	if _, err := env.Verify(f.rootPub, DocumentContext); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("Verify accepted a digest signature: %v", err)
	}
	// A digest signature relabelled as Ed25519ctx, and the reverse, fail.
	swapped := env
	swapped.Algorithm = ""
	if _, err := VerifyDocumentSignature(swapped, f.rootPub); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("relabelled digest signature: %v", err)
	}
	ctxEnv.Algorithm = AlgEd25519Digest
	if _, err := VerifyDocumentSignature(ctxEnv, f.rootPub); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("relabelled ctx signature: %v", err)
	}
	// Another context's digest signature is not a document signature.
	other, err := SignWithDigest(signer, EnrollmentContextForTest(), env.Payload)
	if err != nil {
		t.Fatal(err)
	}
	other.Context = DocumentContext
	if _, err := VerifyDocumentSignature(other, f.rootPub); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("cross-context digest signature: %v", err)
	}
	// A token that returns a wrong signature is caught when signing.
	if _, err := SignDocumentWith(f.doc, brokenSigner{signer}); err == nil {
		t.Fatal("broken signer accepted")
	}
	// The reserved hybrid algorithm is not accepted (ADR-0122).
	h := ctxEnv
	h.Algorithm = AlgHybridEd25519MLDSA65
	data, _ := MarshalEnvelope(h)
	if _, err := UnmarshalEnvelope(data); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("hybrid algorithm: %v", err)
	}
}

func EnrollmentContextForTest() string { return "openscale/test-other/v1" }

type brokenSigner struct{ pureSigner }

func (b brokenSigner) SignMessage(msg []byte) ([]byte, error) {
	sig, _ := b.pureSigner.SignMessage(msg)
	sig[0] ^= 1
	return sig, nil
}

func TestDigestMessageLayout(t *testing.T) {
	msg, err := DigestMessage("ctx", []byte("abc"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(msg), "openscale/digest-signature/v1\x00\x03ctx") || len(msg) != 30+1+3+64 {
		t.Fatalf("unexpected layout %q (%d)", msg[:34], len(msg))
	}
	if _, err := DigestMessage("", nil); err == nil {
		t.Fatal("empty context accepted")
	}
}

func TestApprovalSurvivesRootRotation(t *testing.T) {
	f := newFixture(t)
	a, aPriv := newApprover(t, "laptop")
	f.doc.Approval = &ApprovalPolicy{Threshold: 1, Approvers: []Approver{a}}
	env := f.sign(t, f.doc)
	approve(t, f, &env, aPriv)
	st := &State{Anchor: f.anchor}
	if _, err := st.Accept(roundTrip(t, env), testNow); err != nil {
		t.Fatal(err)
	}
	// A rotation signed by the (possibly stolen) old root, with a new
	// root-only document, must still meet the pinned policy.
	newPub, newPriv, _ := ed25519.GenerateKey(rand.Reader)
	var newKey, oldKey Key
	copy(newKey[:], newPub)
	copy(oldKey[:], f.rootPub)
	tr := RootTransition{
		NetworkID: f.doc.NetworkID, Kind: TransitionRotation, RevokedRoot: oldKey, NewRoot: newKey,
		LastGoodVersion: f.doc.Version, LastGoodDigest: DocumentDigest(env), Epoch: 1, IssuedAt: testNow,
	}
	st2, err := SignRootRotation(f.rootPriv, tr)
	if err != nil {
		t.Fatal(err)
	}
	next := *f.doc
	next.Version = 1
	next.RootEpoch = 1
	next.Approval = nil
	nextEnv, err := SignDocument(&next, newPriv)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.AcceptWithTransitions([]SignedRootTransition{st2}, roundTrip(t, nextEnv), testNow.Add(time.Minute)); !errors.Is(err, ErrApprovalMissing) {
		t.Fatalf("rotation bypassed the approval policy: %v", err)
	}
}

func FuzzDecodeCosignedEnvelope(f *testing.F) {
	fx := newFixtureF(f)
	a, aPriv := newApproverF(f)
	fx.doc.Approval = &ApprovalPolicy{Threshold: 1, Approvers: []Approver{a}}
	env, err := SignDocument(fx.doc, fx.rootPriv)
	if err != nil {
		f.Fatal(err)
	}
	c, _, err := ApproveDocument(aPriv, env, fx.rootPub)
	if err != nil {
		f.Fatal(err)
	}
	_ = AddCosignature(&env, c)
	seed, _ := MarshalEnvelope(env)
	f.Add(seed)
	f.Add([]byte(`{"context":"x","payload":"","signature":"","cosignatures":[{"key":"AAAA","signature":""}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		e, err := UnmarshalEnvelope(data)
		if err != nil {
			return
		}
		st := &State{Anchor: fx.anchor}
		doc, err := st.Accept(e, testNow)
		if err != nil {
			return
		}
		// Anything accepted meets its own policy.
		if doc.Approval != nil && len(doc.Approval.Approved(e)) < doc.Approval.Threshold {
			t.Fatal("accepted a document below its approval threshold")
		}
	})
}

func newFixtureF(f *testing.F) *fixture {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	id, _ := NewNetworkID(rand.Reader)
	ula, _ := RandomULAPrefix(rand.Reader)
	doc, err := NewDocument(id, DefaultDNSDomain, DefaultIPv4Prefix, ula, testNow, DefaultValidity)
	if err != nil {
		f.Fatal(err)
	}
	return &fixture{rootPub: pub, rootPriv: priv, doc: doc, anchor: Anchor{RootKey: pub, NetworkID: id}}
}

func newApproverF(f *testing.F) (Approver, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	var k Key
	copy(k[:], pub)
	return Approver{Name: "fuzz", Key: k}, priv
}
