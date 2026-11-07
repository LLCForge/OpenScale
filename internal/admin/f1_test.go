package admin

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
)

// highestAdminDocument signs the highest version an administrator can reach
// on the current root document and has a member accept it. The owner does
// not import it.
func highestAdminDocument(t *testing.T, n *Network) (*trust.State, trust.SignedGrant) {
	t.Helper()
	priv, sg := issueGrant(t, n, []trust.AdminOp{trust.AdminOpSSHCert}, nil, false)
	member := &trust.State{Anchor: trust.Anchor{RootKey: rootPub(n), NetworkID: n.doc.NetworkID}}
	baseEnv, err := trust.UnmarshalEnvelope(networkEnvelope(t, n))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := member.Accept(baseEnv, testNow); err != nil {
		t.Fatal(err)
	}
	doc, err := n.doc.Next(testNow.Add(time.Hour), 20*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	doc.Version = n.doc.Version + trust.MaxAdminVersionStep
	env, err := trust.SignAdminDocument(doc, baseEnv, sg, priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := member.Accept(env, testNow.Add(time.Hour)); err != nil {
		t.Fatalf("member refused the administrator document: %v", err)
	}
	return member, sg
}

// The owner's revocation reaches a member that holds the highest version the
// administrator can reach, though the owner never saw that version.
func TestRevokeGrantOvertakesAdministrator(t *testing.T) {
	n := newNetwork(t)
	addDevice(t, n, "nas")
	member, sg := highestAdminDocument(t, n)
	plan, err := n.Prepare(testNow.Add(2*time.Hour), trust.DefaultValidity, RevokeAdminGrant(sg.Grant.ID))
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Commit(plan, testPass); err != nil {
		t.Fatalf("Commit of an overtaking version: %v", err)
	}
	env, err := trust.UnmarshalEnvelope(networkEnvelope(t, n))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := member.Accept(env, testNow.Add(2*time.Hour)); err != nil {
		t.Fatalf("member refused the revocation: %v", err)
	}
	if len(member.RevokedAdmins) != 1 || member.RevokedAdmins[0] != sg.Grant.ID {
		t.Fatalf("revoked: %v", member.RevokedAdmins)
	}
	// Normal work continues from the new version.
	before := n.doc.Version
	addDevice(t, n, "later")
	if n.doc.Version != before+1 {
		t.Fatalf("version after overtake: %d, want %d", n.doc.Version, before+1)
	}
}

// The same revocation staged in a draft keeps its raised version.
func TestDraftedRevocationKeepsOvertake(t *testing.T) {
	n := newNetwork(t)
	addDevice(t, n, "nas")
	member, sg := highestAdminDocument(t, n)
	if _, err := n.StageDraft(testNow.Add(2*time.Hour), RevokeAdminGrant(sg.Grant.ID)); err != nil {
		t.Fatal(err)
	}
	plan, err := n.PrepareDraft(testNow.Add(2*time.Hour), trust.DefaultValidity)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.CommitDraft(plan, testPass); err != nil {
		t.Fatalf("CommitDraft: %v", err)
	}
	env, _ := trust.UnmarshalEnvelope(networkEnvelope(t, n))
	if _, err := member.Accept(env, testNow.Add(2*time.Hour)); err != nil {
		t.Fatalf("member refused the drafted revocation: %v", err)
	}
}

// OvertakeAdminVersions is the way forward without a revocation.
func TestOvertakeAdminVersions(t *testing.T) {
	n := newNetwork(t)
	addDevice(t, n, "nas")
	member, _ := highestAdminDocument(t, n)
	plan, err := n.Prepare(testNow.Add(2*time.Hour), trust.DefaultValidity, OvertakeAdminVersions())
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Commit(plan, testPass); err != nil {
		t.Fatal(err)
	}
	env, _ := trust.UnmarshalEnvelope(networkEnvelope(t, n))
	if _, err := member.Accept(env, testNow.Add(2*time.Hour)); err != nil {
		t.Fatalf("member refused the overtaking version: %v", err)
	}
}

// A pre-signed emergency document (+2^32) still supersedes the highest
// version an administrator can reach, and the administrator's own document on
// the emergency base stays bounded from there.
func TestEmergencyAboveAdministratorBound(t *testing.T) {
	n := newNetwork(t)
	addDevice(t, n, "nas")
	seal := []byte("acil durum zarfı 2026 kilit")
	if _, err := n.PrepareEmergency(testPass, seal, []EmergencySpec{{Kind: EmergencyLockdown}}, testNow, trust.DefaultValidity); err != nil {
		t.Fatal(err)
	}
	member, _ := highestAdminDocument(t, n)
	data, _, err := n.PublishEmergency(EmergencyLockdown, "", seal, testNow.Add(2*time.Hour))
	if err != nil {
		t.Fatalf("PublishEmergency: %v", err)
	}
	env, err := trust.UnmarshalEnvelope(data)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := member.Accept(env, testNow.Add(2*time.Hour)); err != nil {
		t.Fatalf("member refused the emergency document: %v", err)
	}
}

// An administrator's tool refuses to go past the bound before it signs.
func TestPrepareAdminStopsAtBound(t *testing.T) {
	n := newNetwork(t)
	addDevice(t, n, "nas")
	addDevice(t, n, "laptop")
	priv, sg := issueGrant(t, n, []trust.AdminOp{trust.AdminOpRules}, nil, false)
	ctx, err := NewAdminContext(rootPub(n), sg.Encoded, networkEnvelope(t, n), testNow.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := ctx.Document.Next(testNow.Add(time.Hour), 20*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	doc.Version = n.doc.Version + trust.MaxAdminVersionStep
	env, err := trust.SignAdminDocument(doc, ctx.Base, sg, priv)
	if err != nil {
		t.Fatal(err)
	}
	data, err := trust.MarshalEnvelope(env)
	if err != nil {
		t.Fatal(err)
	}
	next, err := NewAdminContext(rootPub(n), sg.Encoded, data, testNow.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	_, err = next.PrepareAdmin(testNow.Add(time.Hour), trust.DefaultValidity, func(d *trust.Document) error {
		return d.AddRule(trust.Rule{From: []string{"laptop"}, To: []string{"nas"}, Protocol: trust.ProtocolAny})
	})
	if !errors.Is(err, trust.ErrAdminBase) {
		t.Fatalf("PrepareAdmin past the bound: %v", err)
	}
}

func TestMembersOnlySwitch(t *testing.T) {
	n := newNetwork(t)
	addDevice(t, n, "nas")
	st, err := n.MembersOnlyState()
	if err != nil {
		t.Fatal(err)
	}
	if st.Enabled || st.Sealed || !st.RaisesMinClient || len(st.Blockers) != 0 || !strings.Contains(strings.Join(st.Warnings, " "), trust.MembersOnlyMinClientVersion) {
		t.Fatalf("initial state: %+v", st)
	}
	if _, err := n.PrepareMembersOnly(false, testNow, trust.DefaultValidity); !errors.Is(err, ErrMembersOnlyUnchanged) {
		t.Fatalf("off while off: %v", err)
	}
	// Wrong passphrase: the setting stays off and nothing is signed.
	version := n.doc.Version
	plan, err := n.PrepareMembersOnly(true, testNow, trust.DefaultValidity)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Next.MinClientVersion != trust.MembersOnlyMinClientVersion {
		t.Fatalf("minimum client version: %q", plan.Next.MinClientVersion)
	}
	err = n.CommitMembersOnly(true, plan, func(p *Plan) error { return n.Commit(p, []byte("yanlış parola 12345")) })
	if !errors.Is(err, trust.ErrWrongPassphrase) || n.MembersOnlyEnabled() || n.doc.Version != version {
		t.Fatalf("failed signature: %v, enabled %v, version %d", err, n.MembersOnlyEnabled(), n.doc.Version)
	}
	// On: network.json holds the public part only.
	plan, err = n.PrepareMembersOnly(true, testNow, trust.DefaultValidity)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.CommitMembersOnly(true, plan, func(p *Plan) error { return n.Commit(p, testPass) }); err != nil {
		t.Fatalf("turning on: %v", err)
	}
	raw, err := securefile.ReadPrivate(filepath.Join(n.Dir(), documentFile), trust.MaxEnvelopeSize)
	if err != nil {
		t.Fatal(err)
	}
	env, _ := trust.UnmarshalEnvelope(raw)
	pub, err := trust.VerifyDocumentSignature(env, rootPub(n))
	if err != nil {
		t.Fatal(err)
	}
	if !trust.IsMembersOnly(pub) || strings.Contains(string(env.Payload), "\"nas\"") {
		t.Fatalf("not sealed: %s", env.Payload)
	}
	if err := n.Reload(); err != nil {
		t.Fatalf("owner reload of a sealed document: %v", err)
	}
	if _, ok := n.doc.DeviceByName("nas"); !ok {
		t.Fatal("the owner lost the device name")
	}
	if _, err := n.PrepareMembersOnly(true, testNow, trust.DefaultValidity); !errors.Is(err, ErrMembersOnlyUnchanged) {
		t.Fatalf("on while on: %v", err)
	}
	// Off: the next version is plain again; the client minimum stays.
	plan, err = n.PrepareMembersOnly(false, testNow.Add(time.Hour), trust.DefaultValidity)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.CommitMembersOnly(false, plan, func(p *Plan) error { return n.Commit(p, testPass) }); err != nil {
		t.Fatalf("turning off: %v", err)
	}
	st, err = n.MembersOnlyState()
	if err != nil {
		t.Fatal(err)
	}
	if st.Enabled || st.Sealed || st.RaisesMinClient {
		t.Fatalf("state after off: %+v", st)
	}
	if _, err := os.Stat(filepath.Join(n.Dir(), membersOnlySettingFile)); err != nil {
		t.Fatal(err)
	}
}

// A policy that cannot be sealed is reported before anything is signed.
func TestMembersOnlyBlockedBySensitivePolicy(t *testing.T) {
	n := newNetwork(t)
	addDevice(t, n, "nas")
	n.doc.Sensitive = &trust.SensitivePolicy{}
	st, err := n.MembersOnlyState()
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Blockers) != 1 {
		t.Fatalf("blockers: %v", st.Blockers)
	}
}

// With the version chain on, the owner's overtaking revocation must not look
// like a fork to a member holding the highest administrator version.
func TestRevokeOvertakesWithVersionChain(t *testing.T) {
	n := newNetwork(t)
	addDevice(t, n, "nas")
	if _, err := n.SetVersionChain(testPass, true, testNow); err != nil {
		t.Fatal(err)
	}
	member, sg := highestAdminDocument(t, n)
	plan, err := n.Prepare(testNow.Add(2*time.Hour), trust.DefaultValidity, RevokeAdminGrant(sg.Grant.ID))
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Commit(plan, testPass); err != nil {
		t.Fatal(err)
	}
	env, err := trust.UnmarshalEnvelope(networkEnvelope(t, n))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := member.Accept(env, testNow.Add(2*time.Hour)); err != nil {
		t.Fatalf("member refused the revocation: %v", err)
	}
}
