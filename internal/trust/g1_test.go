package trust

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
	"time"
)

// --- delegated administrators (ADR-0172) ---

type adminFixture struct {
	*fixture
	adminPriv ed25519.PrivateKey
	grant     SignedGrant
	base      Envelope
	baseDoc   *Document
}

func newAdminFixture(t *testing.T, ops []AdminOp, tags []string) *adminFixture {
	t.Helper()
	f := newFixture(t)
	// Two tagged devices and one untagged.
	for _, n := range []struct {
		name string
		tags []string
	}{{"lab-a", []string{"lab"}}, {"lab-b", []string{"lab"}}, {"office", nil}} {
		_, req := newRequest(t, n.name)
		if _, err := f.doc.AddDevice(req, n.name, nil, testNow, DefaultDeviceLife); err != nil {
			t.Fatal(err)
		}
		if n.tags != nil {
			if err := f.doc.SetDeviceTags(n.name, n.tags); err != nil {
				t.Fatal(err)
			}
		}
	}
	base := f.sign(t, f.doc)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, err := NewAdminGrantID(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var k Key
	copy(k[:], pub)
	g := AdminGrant{ID: id, NetworkID: f.doc.NetworkID, Name: "helper", Key: k, IssuedAt: testNow,
		NotAfter: testNow.Add(30 * 24 * time.Hour), Operations: ops, Tags: tags}
	sg, err := SignAdminGrant(g, f.rootPriv)
	if err != nil {
		t.Fatalf("SignAdminGrant: %v", err)
	}
	baseDoc, err := VerifyDocumentSignature(base, f.rootPub)
	if err != nil {
		t.Fatal(err)
	}
	return &adminFixture{fixture: f, adminPriv: priv, grant: sg, base: base, baseDoc: baseDoc}
}

func (a *adminFixture) next(t *testing.T, change func(*Document)) *Document {
	t.Helper()
	next, err := a.baseDoc.Next(testNow.Add(time.Hour), 20*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	change(next)
	return next
}

func (a *adminFixture) signAdmin(t *testing.T, doc *Document) Envelope {
	t.Helper()
	env, err := SignAdminDocument(doc, a.base, a.grant, a.adminPriv)
	if err != nil {
		t.Fatalf("SignAdminDocument: %v", err)
	}
	return roundTrip(t, env)
}

func TestAdminGrantValidation(t *testing.T) {
	f := newFixture(t)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	var k Key
	copy(k[:], priv.Public().(ed25519.PublicKey))
	id, _ := NewAdminGrantID(rand.Reader)
	good := AdminGrant{ID: id, NetworkID: f.doc.NetworkID, Name: "ops", Key: k, IssuedAt: testNow,
		NotAfter: testNow.Add(90 * 24 * time.Hour), Operations: []AdminOp{AdminOpRules}}
	if _, err := SignAdminGrant(good, f.rootPriv); err != nil {
		t.Fatalf("90-day grant: %v", err)
	}
	cases := map[string]func(g *AdminGrant){
		"too long":        func(g *AdminGrant) { g.NotAfter = testNow.Add(91 * 24 * time.Hour) },
		"no ops":          func(g *AdminGrant) { g.Operations = nil },
		"unknown op":      func(g *AdminGrant) { g.Operations = []AdminOp{"root.rotate"} },
		"tagged dns":      func(g *AdminGrant) { g.Tags = []string{"lab"}; g.Operations = []AdminOp{AdminOpDNS} },
		"token no digest": func(g *AdminGrant) { g.Token = &TokenBinding{Kind: TokenKindOpenPGP, Serial: 7} },
		"bad name":        func(g *AdminGrant) { g.Name = "Ops" },
	}
	for name, mutate := range cases {
		g := good
		mutate(&g)
		if _, err := SignAdminGrant(g, f.rootPriv); !errors.Is(err, ErrAdminGrant) {
			t.Errorf("%s: got %v, want ErrAdminGrant", name, err)
		}
	}
	// Another root's grant and another network are refused.
	sg, _ := SignAdminGrant(good, f.rootPriv)
	other := newFixture(t)
	if _, err := OpenAdminGrant(sg.Encoded, other.rootPub, f.doc.NetworkID); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("foreign root: %v", err)
	}
	if _, err := OpenAdminGrant(sg.Encoded, f.rootPub, other.doc.NetworkID); !errors.Is(err, ErrWrongNetwork) {
		t.Fatalf("foreign network: %v", err)
	}
	if _, err := CheckAdminGrant(sg.Encoded, f.rootPub, f.doc.NetworkID, AdminOpSSHCert, testNow, nil); !errors.Is(err, ErrAdminScope) {
		t.Fatalf("ssh op not granted: %v", err)
	}
	if _, err := CheckAdminGrant(sg.Encoded, f.rootPub, f.doc.NetworkID, AdminOpRules, testNow.Add(91*24*time.Hour), nil); !errors.Is(err, ErrAdminExpired) {
		t.Fatalf("expired: %v", err)
	}
	if _, err := CheckAdminGrant(sg.Encoded, f.rootPub, f.doc.NetworkID, AdminOpRules, testNow, []string{id}); !errors.Is(err, ErrAdminRevoked) {
		t.Fatalf("revoked: %v", err)
	}
}

func TestAdminDocumentWithinScope(t *testing.T) {
	a := newAdminFixture(t, []AdminOp{AdminOpRules, AdminOpDeviceAdd, AdminOpDeviceRevoke, AdminOpDeviceMembership}, []string{"lab"})
	st := &State{Anchor: a.anchor}
	if _, err := st.Accept(a.base, testNow); err != nil {
		t.Fatal(err)
	}
	next := a.next(t, func(d *Document) {
		if err := d.AddRule(Rule{From: []string{"tag:lab"}, To: []string{"lab-a"}, Protocol: ProtocolTCP, Ports: []string{"22"}}); err != nil {
			t.Fatal(err)
		}
		_, req := newRequest(t, "lab-c")
		if _, err := d.AddDevice(req, "lab-c", nil, testNow, DefaultDeviceLife); err != nil {
			t.Fatal(err)
		}
		if err := d.SetDeviceTags("lab-c", []string{"lab"}); err != nil {
			t.Fatal(err)
		}
		if _, err := d.RevokeDevice("lab-b", testNow.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	})
	env := a.signAdmin(t, next)
	got, err := st.Accept(env, testNow.Add(2*time.Hour))
	if err != nil {
		t.Fatalf("in-scope administrator document refused: %v", err)
	}
	if got.Version != next.Version || st.RootBaseVersion != a.baseDoc.Version {
		t.Fatalf("state after accept: version %d, root base %d", got.Version, st.RootBaseVersion)
	}
	// Owner tooling verifies it with the root key alone.
	if _, err := VerifyDocumentSignature(env, a.rootPub); err != nil {
		t.Fatalf("VerifyDocumentSignature: %v", err)
	}
	// A fresh member (no state yet) checks the scope against the base too.
	fresh := &State{Anchor: a.anchor}
	if _, err := fresh.Accept(env, testNow.Add(2*time.Hour)); err != nil {
		t.Fatalf("fresh member: %v", err)
	}
}

func TestAdminDocumentOutsideScope(t *testing.T) {
	a := newAdminFixture(t, []AdminOp{AdminOpRules, AdminOpDeviceAdd, AdminOpDeviceRevoke}, []string{"lab"})
	appr, _ := newApprover(t, "safe")
	cases := map[string]func(*testing.T, *Document){
		"approval policy": func(_ *testing.T, d *Document) {
			d.Approval = &ApprovalPolicy{Threshold: 1, Approvers: []Approver{appr}}
		},
		"recovery key": func(_ *testing.T, d *Document) { d.RecoveryKeys = []Key{appr.Key} },
		"revoked admins": func(_ *testing.T, d *Document) {
			id, _ := NewAdminGrantID(rand.Reader)
			_ = d.RevokeAdmin(id)
		},
		"untagged device revoked": func(t *testing.T, d *Document) {
			if _, err := d.RevokeDevice("office", testNow); err != nil {
				t.Fatal(err)
			}
		},
		"rule to untagged device": func(t *testing.T, d *Document) {
			if err := d.AddRule(Rule{From: []string{"tag:lab"}, To: []string{"office"}, Protocol: ProtocolAny}); err != nil {
				t.Fatal(err)
			}
		},
		"wildcard rule": func(t *testing.T, d *Document) {
			if err := d.AddRule(Rule{From: []string{"*"}, To: []string{"lab-a"}, Protocol: ProtocolAny}); err != nil {
				t.Fatal(err)
			}
		},
		"admin role": func(t *testing.T, d *Document) {
			for i := range d.Devices {
				if d.Devices[i].Name == "lab-a" {
					d.Devices[i].Roles = []Role{RoleAdmin}
				}
			}
		},
		"membership not granted": func(t *testing.T, d *Document) {
			if _, err := d.ExtendDevice("lab-a", testNow, 30*24*time.Hour); err != nil {
				t.Fatal(err)
			}
		},
		"display name": func(_ *testing.T, d *Document) { d.DisplayName = "Ev" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			next := a.next(t, func(d *Document) { change(t, d) })
			env, err := SignAdminDocument(next, a.base, a.grant, a.adminPriv)
			if err != nil {
				t.Fatal(err)
			}
			st := &State{Anchor: a.anchor}
			_, err = st.Accept(roundTrip(t, env), testNow.Add(2*time.Hour))
			if !errors.Is(err, ErrAdminScope) {
				t.Fatalf("got %v, want ErrAdminScope", err)
			}
		})
	}
}

func TestAdminDocumentRevocationAndBase(t *testing.T) {
	a := newAdminFixture(t, []AdminOp{AdminOpRules}, nil)
	adminDoc := a.next(t, func(d *Document) {
		if err := d.AddRule(Rule{From: []string{"office"}, To: []string{"lab-a"}, Protocol: ProtocolAny}); err != nil {
			t.Fatal(err)
		}
	})
	st := &State{Anchor: a.anchor}
	if _, err := st.Accept(a.signAdmin(t, adminDoc), testNow.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}

	// The root revokes the grant in a newer version; a member that saw it
	// refuses the administrator document (built on the older base).
	revoked, err := a.baseDoc.Next(testNow.Add(time.Hour), DefaultValidity)
	if err != nil {
		t.Fatal(err)
	}
	if err := revoked.RevokeAdmin(a.grant.Grant.ID); err != nil {
		t.Fatal(err)
	}
	revoked.Version = adminDoc.Version + 1
	revokedEnv := a.sign(t, revoked)
	if _, err := st.Accept(revokedEnv, testNow.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	// Built on an older base than the accepted root version.
	adminDoc2 := a.next(t, func(d *Document) {
		d.Version = revoked.Version + 1
		if err := d.AddRule(Rule{From: []string{"office"}, To: []string{"lab-b"}, Protocol: ProtocolAny}); err != nil {
			t.Fatal(err)
		}
	})
	env2 := a.signAdmin(t, adminDoc2)
	if _, err := st.Accept(env2, testNow.Add(2*time.Hour)); !errors.Is(err, ErrAdminBase) {
		t.Fatalf("old base: got %v, want ErrAdminBase", err)
	}
	// Rebuilt on the revoking version: the grant is revoked there.
	b := *a
	b.base, b.baseDoc = revokedEnv, revoked
	adminDoc3 := b.next(t, func(d *Document) {
		if err := d.AddRule(Rule{From: []string{"office"}, To: []string{"lab-b"}, Protocol: ProtocolAny}); err != nil {
			t.Fatal(err)
		}
	})
	env3, err := SignAdminDocument(adminDoc3, b.base, b.grant, b.adminPriv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Accept(roundTrip(t, env3), testNow.Add(2*time.Hour)); !errors.Is(err, ErrAdminRevoked) {
		t.Fatalf("revoked grant: got %v, want ErrAdminRevoked", err)
	}
}

func TestAdminDocumentExpiryAndKeyChecks(t *testing.T) {
	a := newAdminFixture(t, []AdminOp{AdminOpRules}, nil)
	// A document may not outlive its grant.
	long, err := a.baseDoc.Next(testNow.Add(time.Hour), 60*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	env, err := SignAdminDocument(long, a.base, a.grant, a.adminPriv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyDocumentSignature(env, a.rootPub); !errors.Is(err, ErrAdminExpired) {
		t.Fatalf("outliving document: %v", err)
	}
	// Another key cannot use the grant.
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := SignAdminDocument(a.next(t, func(*Document) {}), a.base, a.grant, other); !errors.Is(err, ErrAdminMismatch) {
		t.Fatalf("other key: %v", err)
	}
	// A forged signature by another key with a copied proof fails.
	doc := a.next(t, func(*Document) {})
	good, _ := SignAdminDocument(doc, a.base, a.grant, a.adminPriv)
	good.Signature = ed25519.Sign(other, good.Payload)
	if _, err := VerifyDocumentSignature(good, a.rootPub); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("forged: %v", err)
	}
	// The base must be root-signed.
	nested, _ := SignAdminDocument(doc, a.base, a.grant, a.adminPriv)
	if _, err := SignAdminDocument(doc, nested, a.grant, a.adminPriv); !errors.Is(err, ErrAdminBase) {
		t.Fatalf("nested base: %v", err)
	}
}

func TestAdminTokenGrantNeedsDigest(t *testing.T) {
	f := newFixture(t)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	var k Key
	copy(k[:], priv.Public().(ed25519.PublicKey))
	id, _ := NewAdminGrantID(rand.Reader)
	g := AdminGrant{ID: id, NetworkID: f.doc.NetworkID, Name: "token", Key: k, Algorithm: AlgEd25519Digest,
		IssuedAt: testNow, NotAfter: testNow.Add(24 * time.Hour), Operations: []AdminOp{AdminOpRules},
		Token: &TokenBinding{Kind: TokenKindOpenPGP, Serial: 1234}}
	sg, err := SignAdminGrantWith(g, pureSigner{f.rootPriv})
	if err != nil {
		t.Fatalf("SignAdminGrantWith: %v", err)
	}
	base := f.sign(t, f.doc)
	next, _ := f.doc.Next(testNow.Add(time.Hour), time.Hour)
	if _, err := SignAdminDocument(next, base, sg, priv); !errors.Is(err, ErrAdminMismatch) {
		t.Fatalf("software signature for a token grant: %v", err)
	}
	env, err := SignAdminDocumentWith(next, base, sg, pureSigner{priv})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyDocumentSignature(roundTrip(t, env), f.rootPub); err != nil {
		t.Fatalf("token signature: %v", err)
	}
	// A software Ed25519ctx signature by the same key is refused.
	soft := env
	soft.Algorithm = ""
	soft.Signature, _ = priv.Sign(nil, env.Payload, &ed25519.Options{Context: AdminDocumentContext})
	if _, err := VerifyDocumentSignature(soft, f.rootPub); !errors.Is(err, ErrAdminMismatch) {
		t.Fatalf("software signature accepted: %v", err)
	}
}

func TestAdminStatePinnedAcrossReload(t *testing.T) {
	a := newAdminFixture(t, []AdminOp{AdminOpRules}, nil)
	doc := a.next(t, func(d *Document) {
		if err := d.AddRule(Rule{From: []string{"office"}, To: []string{"lab-a"}, Protocol: ProtocolAny}); err != nil {
			t.Fatal(err)
		}
	})
	env := a.signAdmin(t, doc)
	st := &State{Anchor: a.anchor}
	if _, err := st.Accept(env, testNow.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	reloaded := &State{Anchor: a.anchor, HighestVersion: st.HighestVersion, HighestDigest: st.HighestDigest}
	reloaded.PinStored(env, doc)
	if reloaded.RootBaseVersion != a.baseDoc.Version || reloaded.RootBaseDigest != st.RootBaseDigest {
		t.Fatalf("PinStored: base %d, want %d", reloaded.RootBaseVersion, a.baseDoc.Version)
	}
}

func TestEnvelopeWithoutG1FieldsEncodesAsBefore(t *testing.T) {
	f := newFixture(t)
	data, err := MarshalEnvelope(f.sign(t, f.doc))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"admin", "sensitive", "revoked_admins"} {
		if bytes.Contains(data, []byte(`"`+s)) {
			t.Fatalf("unused field %q encoded", s)
		}
	}
}

// --- sensitive devices (ADR-0174) ---

func TestSensitiveTwoPersonRule(t *testing.T) {
	f := newFixture(t)
	for _, n := range []string{"vault", "laptop", "phone"} {
		_, req := newRequest(t, n)
		if _, err := f.doc.AddDevice(req, n, nil, testNow, DefaultDeviceLife); err != nil {
			t.Fatal(err)
		}
	}
	a1, p1 := newApprover(t, "alice")
	a2, p2 := newApprover(t, "bob")
	f.doc.Sensitive = &SensitivePolicy{Targets: []string{"vault"}, Threshold: 2, Approvers: []Approver{a1, a2}}
	v1 := f.sign(t, f.doc)
	st := &State{Anchor: f.anchor}
	if _, err := st.Accept(roundTrip(t, v1), testNow); !errors.Is(err, ErrSensitiveApproval) {
		t.Fatalf("policy without approvals: %v", err)
	}
	for _, p := range []ed25519.PrivateKey{p1, p2} {
		c, err := ApproveSensitive(p, f.doc)
		if err != nil {
			t.Fatal(err)
		}
		if err := AddSensitiveApproval(&v1, f.doc, c); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.Accept(roundTrip(t, v1), testNow); err != nil {
		t.Fatalf("approved policy: %v", err)
	}

	// A change that does not touch the vault keeps the carried approvals.
	v2doc, _ := f.doc.Next(testNow.Add(time.Minute), DefaultValidity)
	if err := v2doc.AddRule(Rule{From: []string{"laptop"}, To: []string{"phone"}, Protocol: ProtocolAny}); err != nil {
		t.Fatal(err)
	}
	v2 := f.sign(t, v2doc)
	CarrySensitiveApprovals(v1, &v2, v2doc)
	if _, err := st.Accept(roundTrip(t, v2), testNow.Add(2*time.Minute)); err != nil {
		t.Fatalf("unrelated change with carried approvals: %v", err)
	}

	// Opening the vault needs fresh approvals of both.
	v3doc, _ := v2doc.Next(testNow.Add(3*time.Minute), DefaultValidity)
	if err := v3doc.AddRule(Rule{From: []string{"phone"}, To: []string{"vault"}, Protocol: ProtocolTCP, Ports: []string{"22"}}); err != nil {
		t.Fatal(err)
	}
	v3 := f.sign(t, v3doc)
	CarrySensitiveApprovals(v2, &v3, v3doc)
	if _, err := st.Accept(roundTrip(t, v3), testNow.Add(4*time.Minute)); !errors.Is(err, ErrSensitiveApproval) {
		t.Fatalf("vault access without approvals: %v", err)
	}
	c1, _ := ApproveSensitive(p1, v3doc)
	if err := AddSensitiveApproval(&v3, v3doc, c1); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Accept(roundTrip(t, v3), testNow.Add(4*time.Minute)); !errors.Is(err, ErrSensitiveApproval) {
		t.Fatalf("one of two approvals: %v", err)
	}
	c2, _ := ApproveSensitive(p2, v3doc)
	if err := AddSensitiveApproval(&v3, v3doc, c2); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Accept(roundTrip(t, v3), testNow.Add(4*time.Minute)); err != nil {
		t.Fatalf("two approvals: %v", err)
	}

	// The root alone cannot drop the pinned policy.
	v4doc, _ := v3doc.Next(testNow.Add(5*time.Minute), DefaultValidity)
	v4doc.Sensitive = nil
	if _, err := st.Accept(roundTrip(t, f.sign(t, v4doc)), testNow.Add(6*time.Minute)); !errors.Is(err, ErrSensitiveApproval) {
		t.Fatalf("dropping the policy: %v", err)
	}
	// A tag change that makes a device sensitive changes the fingerprint.
	if SensitiveFingerprint(v2doc) == SensitiveFingerprint(v3doc) {
		t.Fatal("fingerprint ignores a rule to the vault")
	}
}

func TestSensitivePolicyValidation(t *testing.T) {
	f := newFixture(t)
	a1, _ := newApprover(t, "alice")
	f.doc.Sensitive = &SensitivePolicy{Targets: []string{"b", "a"}, Threshold: 1, Approvers: []Approver{a1}}
	if err := f.doc.Validate(); !errors.Is(err, ErrSensitivePolicy) {
		t.Fatalf("unsorted targets: %v", err)
	}
	f.doc.Sensitive = &SensitivePolicy{Targets: []string{"tag:Bad"}, Threshold: 1, Approvers: []Approver{a1}}
	if err := f.doc.Validate(); !errors.Is(err, ErrSensitivePolicy) {
		t.Fatalf("bad tag: %v", err)
	}
	f.doc.Sensitive = &SensitivePolicy{Targets: []string{"gone"}, Threshold: 1, Approvers: []Approver{a1}}
	if err := f.doc.Validate(); err != nil {
		t.Fatalf("a missing device name stays allowed (revocation never fails): %v", err)
	}
}

// --- token binding (ADR-0173) ---

func makeAttestation(t *testing.T, key ed25519.PublicKey, serial int64) (leaf, inter, root []byte) {
	t.Helper()
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	interKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"},
		NotBefore: testNow.Add(-time.Hour), NotAfter: testNow.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	root, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, _ := x509.ParseCertificate(root)
	interTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "test f9"},
		NotBefore: testNow.Add(-time.Hour), NotAfter: testNow.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	inter, err = x509.CreateCertificate(rand.Reader, interTmpl, rootCert, &interKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	interCert, _ := x509.ParseCertificate(inter)
	ext, _ := asn1.Marshal(serial)
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "slot 9c"},
		NotBefore: testNow.Add(-time.Hour), NotAfter: testNow.Add(time.Hour),
		ExtraExtensions: []pkix.Extension{{Id: oidYubicoSerial, Value: ext}}}
	leaf, err = x509.CreateCertificate(rand.Reader, leafTmpl, interCert, key, interKey)
	if err != nil {
		t.Fatal(err)
	}
	return leaf, inter, root
}

func TestTokenBindingAttestation(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	var k Key
	copy(k[:], pub)
	leaf, inter, root := makeAttestation(t, pub, 31337)
	b := &TokenBinding{Kind: TokenKindPIV, Serial: 31337, Attestation: leaf, Intermediate: inter}
	if err := b.Validate(k); err != nil {
		t.Fatalf("valid binding: %v", err)
	}
	if err := b.CheckChain(root); err != nil {
		t.Fatalf("chain: %v", err)
	}
	if s, ok, err := AttestationSerial(leaf); err != nil || !ok || s != 31337 {
		t.Fatalf("serial: %d %v %v", s, ok, err)
	}
	// A cloned or imported key has no attestation of its own: another
	// key's certificate does not fit.
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	var ok2 Key
	copy(ok2[:], other)
	if err := b.Validate(ok2); !errors.Is(err, ErrTokenBinding) {
		t.Fatalf("other key: %v", err)
	}
	wrongSerial := *b
	wrongSerial.Serial = 1
	if err := wrongSerial.Validate(k); !errors.Is(err, ErrTokenBinding) {
		t.Fatalf("wrong serial: %v", err)
	}
	_, inter2, root2 := makeAttestation(t, pub, 31337)
	forged := *b
	forged.Intermediate = inter2
	if err := forged.Validate(k); !errors.Is(err, ErrTokenBinding) {
		t.Fatalf("foreign intermediate: %v", err)
	}
	if err := b.CheckChain(root2); !errors.Is(err, ErrTokenBinding) {
		t.Fatalf("foreign root: %v", err)
	}
}
