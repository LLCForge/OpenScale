package admin

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
)

var g1Argon = trust.Argon2Params{Time: 1, MemoryKiB: 64 * 1024, Threads: 1}

// pureToken stands in for a hardware token (pure Ed25519, no context).
type pureToken struct {
	priv   ed25519.PrivateKey
	closed bool
}

func (p *pureToken) PublicKey() ed25519.PublicKey { return p.priv.Public().(ed25519.PublicKey) }
func (p *pureToken) SignMessage(msg []byte) ([]byte, error) {
	if p.closed {
		return nil, errors.New("token closed")
	}
	return ed25519.Sign(p.priv, msg), nil
}
func (p *pureToken) Close() error { p.closed = true; return nil }

func networkEnvelope(t *testing.T, n *Network) []byte {
	t.Helper()
	data, err := securefile.ReadPrivate(filepath.Join(n.Dir(), documentFile), trust.MaxEnvelopeSize)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func rootPub(n *Network) ed25519.PublicKey { return n.sealed.RootPublicKey() }

func issueGrant(t *testing.T, n *Network, ops []trust.AdminOp, tags []string, onToken bool) (ed25519.PrivateKey, trust.SignedGrant) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	var k trust.Key
	copy(k[:], pub)
	sg, err := n.IssueAdminGrant(testPass, GrantRequest{Name: "helper", Key: k, Lifetime: 30 * 24 * time.Hour, Operations: ops, Tags: tags, OnToken: onToken}, testNow)
	if err != nil {
		t.Fatalf("IssueAdminGrant: %v", err)
	}
	return priv, sg
}

func TestAdminDelegationEndToEnd(t *testing.T) {
	n := newNetwork(t)
	addDevice(t, n, "nas")
	addDevice(t, n, "laptop")
	priv, sg := issueGrant(t, n, []trust.AdminOp{trust.AdminOpRules, trust.AdminOpDeviceMembership}, nil, false)
	if _, err := n.IssueAdminGrant(testPass, GrantRequest{Name: "x", Key: n.sealed.PublicKey, Lifetime: time.Hour, Operations: []trust.AdminOp{trust.AdminOpRules}}, testNow); err == nil {
		t.Fatal("a grant for the root key itself was issued")
	}
	if _, err := n.IssueAdminGrant(testPass, GrantRequest{Name: "x", Key: sg.Grant.Key, Lifetime: 91 * 24 * time.Hour, Operations: []trust.AdminOp{trust.AdminOpRules}}, testNow); err == nil {
		t.Fatal("a 91-day grant was issued")
	}
	list, err := n.AdminGrants(testNow)
	if err != nil || len(list) != 1 || list[0].ID != sg.Grant.ID {
		t.Fatalf("registry: %v %+v", err, list)
	}

	// The administrator works from the published document only.
	ctx, err := NewAdminContext(rootPub(n), sg.Encoded, networkEnvelope(t, n), testNow.Add(time.Hour))
	if err != nil {
		t.Fatalf("NewAdminContext: %v", err)
	}
	plan, err := ctx.PrepareAdmin(testNow.Add(time.Hour), trust.DefaultValidity, func(doc *trust.Document) error {
		return doc.AddRule(trust.Rule{From: []string{"laptop"}, To: []string{"nas"}, Protocol: trust.ProtocolTCP, Ports: []string{"445"}})
	})
	if err != nil {
		t.Fatalf("PrepareAdmin: %v", err)
	}
	if !plan.Next.ExpiresAt.Equal(sg.Grant.NotAfter) && plan.Next.ExpiresAt.After(sg.Grant.NotAfter) {
		t.Fatal("plan outlives the grant")
	}
	if !plan.Risk.Widens || !strings.Contains(plan.Risk.Summary, "genişletecek") {
		t.Fatalf("risk: %+v", plan.Risk)
	}
	data, err := SignAdminPlan(plan, priv)
	if err != nil {
		t.Fatalf("SignAdminPlan: %v", err)
	}
	// A member that holds the root-signed version accepts it.
	env, _ := trust.UnmarshalEnvelope(networkEnvelope(t, n))
	doc, _ := trust.VerifyDocumentSignature(env, rootPub(n))
	st := &trust.State{Anchor: trust.Anchor{RootKey: rootPub(n), NetworkID: doc.NetworkID}}
	if _, err := st.Accept(env, testNow.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	adminEnv, err := trust.UnmarshalEnvelope(data)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Accept(adminEnv, testNow.Add(2*time.Hour)); err != nil {
		t.Fatalf("member refused the administrator document: %v", err)
	}
	// Out of scope: adding a device is not granted.
	if _, err := ctx.PrepareAdmin(testNow.Add(time.Hour), trust.DefaultValidity, func(doc *trust.Document) error {
		doc.DisplayName = "Ev"
		return nil
	}); !errors.Is(err, trust.ErrAdminScope) {
		t.Fatalf("out of scope plan: %v", err)
	}

	// The owner imports the administrator's version and keeps signing on
	// top of it with the root key; then revokes the grant.
	if err := securefile.Replace(filepath.Join(n.Dir(), documentFile), data); err != nil {
		t.Fatal(err)
	}
	if err := n.Reload(); err != nil {
		t.Fatalf("owner reload of an administrator document: %v", err)
	}
	p2, err := n.Prepare(testNow.Add(3*time.Hour), trust.DefaultValidity, RevokeAdminGrant(sg.Grant.ID))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(p2.Diff.Lines(), "\n"), "Yönetici yetkisi geri alındı") {
		t.Fatalf("diff does not show the revocation: %v", p2.Diff.Lines())
	}
	if err := n.Commit(p2, testPass); err != nil {
		t.Fatal(err)
	}
	if _, err := NewAdminContext(rootPub(n), sg.Encoded, networkEnvelope(t, n), testNow.Add(4*time.Hour)); !errors.Is(err, trust.ErrAdminRevoked) {
		t.Fatalf("revoked grant still usable: %v", err)
	}
}

type memBlobStore struct {
	mu sync.Mutex
	m  map[string][]byte
}

func (s *memBlobStore) PutAdminBlob(_ context.Context, id string, blob []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[id] = append([]byte(nil), blob...)
	return nil
}
func (s *memBlobStore) GetAdminBlob(_ context.Context, id string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.m[id]
	if !ok {
		return nil, os.ErrNotExist
	}
	return b, nil
}
func (s *memBlobStore) DeleteAdminBlob(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, id)
	return nil
}

func TestPortableAdminBlob(t *testing.T) {
	n := newNetwork(t)
	priv, sg := issueGrant(t, n, []trust.AdminOp{trust.AdminOpRules}, nil, false)
	store := &memBlobStore{m: map[string][]byte{}}
	pass := []byte("taşınabilir yönetici 42!")
	id, err := UploadPortableAdmin(context.Background(), store, priv, sg, pass, g1Argon, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	blob := store.m[id]
	if strings.Contains(string(blob), "helper") || strings.Contains(string(blob), sg.Grant.Key.String()) {
		t.Fatal("blob reveals the grant")
	}
	got, g, err := DownloadPortableAdmin(context.Background(), store, "helper", pass, rootPub(n), n.doc.NetworkID)
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	if !got.Equal(priv) || g.Grant.ID != sg.Grant.ID {
		t.Fatal("portable key differs")
	}
	if _, _, err := OpenPortableAdmin(blob, []byte("yanlış parola uzun 99!"), rootPub(n), n.doc.NetworkID); !errors.Is(err, trust.ErrWrongPassphrase) {
		t.Fatalf("wrong passphrase: %v", err)
	}
	// A blob of another kind (key file) is not opened as portable.
	_, keyFile, err := GenerateAdminKey(pass, g1Argon, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenPortableAdmin(keyFile, pass, rootPub(n), n.doc.NetworkID); err == nil {
		t.Fatal("key file opened as portable blob")
	}
	k, err := OpenAdminKeyFile(keyFile, pass)
	if err != nil {
		t.Fatalf("OpenAdminKeyFile: %v", err)
	}
	if pub, _ := AdminKeyFilePublic(keyFile); string(pub[:]) != string(k.Public().(ed25519.PublicKey)) {
		t.Fatal("key file public key differs")
	}
}

func TestTokenSession(t *testing.T) {
	n := newNetwork(t)
	addDevice(t, n, "nas")
	adminPriv, sg := issueGrant(t, n, []trust.AdminOp{trust.AdminOpRules}, nil, true)
	clock := testNow.Add(time.Hour)
	now := func() time.Time { return clock }
	tok := &pureToken{priv: adminPriv}
	s, err := OpenTokenSession(context.Background(), func(context.Context) (TokenSigner, error) { return tok, nil },
		rootPub(n), n.doc.NetworkID, sg.Encoded, nil, SessionOptions{Idle: 5 * time.Minute, Now: now})
	if err != nil {
		t.Fatalf("OpenTokenSession: %v", err)
	}
	if info := s.Info(); info.Role != SessionAdmin || info.Name != "helper" || !info.Active {
		t.Fatalf("info: %+v", info)
	}
	ctx, err := NewAdminContext(rootPub(n), sg.Encoded, networkEnvelope(t, n), clock)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := ctx.PrepareAdmin(clock, trust.DefaultValidity, func(doc *trust.Document) error {
		return doc.AddRule(trust.Rule{From: []string{"nas"}, To: []string{"nas"}, Protocol: trust.ProtocolAny})
	})
	if err != nil {
		t.Fatalf("PrepareAdmin: %v", err)
	}
	if _, err := s.SignAdminPlan(plan); err != nil {
		t.Fatalf("SignAdminPlan: %v", err)
	}
	if err := s.CommitRoot(n, nil); !errors.Is(err, ErrSessionRole) {
		t.Fatalf("admin session committing as root: %v", err)
	}
	clock = clock.Add(6 * time.Minute)
	if s.Active() || !tok.closed {
		t.Fatal("idle session still active")
	}
	if _, err := s.SignAdminPlan(plan); !errors.Is(err, ErrSessionClosed) {
		t.Fatalf("closed session: %v", err)
	}
	// A token with an unknown key opens no session.
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := OpenTokenSession(context.Background(), func(context.Context) (TokenSigner, error) { return &pureToken{priv: other}, nil },
		rootPub(n), n.doc.NetworkID, sg.Encoded, nil, SessionOptions{Now: now}); !errors.Is(err, trust.ErrAdminMismatch) {
		t.Fatalf("foreign token: %v", err)
	}
}

func TestDuressPassphrase(t *testing.T) {
	n := newNetwork(t)
	duress := []byte("zararsız görünüm 7 kapı")
	if err := n.SetDuressPassphrase(testPass, duress); !errors.Is(err, ErrDuressNoBackup) {
		t.Fatalf("without backup: %v", err)
	}
	if _, err := n.CreateBackup(testPass, []byte("yedek parola kasa 1234"), "kasa", testNow); err != nil {
		t.Fatal(err)
	}
	if err := n.SetDuressPassphrase(testPass, testPass); !errors.Is(err, ErrDuressSame) {
		t.Fatalf("same passphrase: %v", err)
	}
	if err := n.SetDuressPassphrase(testPass, duress); err != nil {
		t.Fatal(err)
	}
	if got := n.CheckLogin(testPass); got != LoginRoot {
		t.Fatalf("root login: %v", got)
	}
	if got := n.CheckLogin([]byte("tamamen yanlış parola 0")); got != LoginWrong {
		t.Fatalf("wrong login: %v", got)
	}
	if got := n.CheckLogin(duress); got != LoginDuress {
		t.Fatalf("duress login: %v", got)
	}
	extra := filepath.Join(n.Dir(), "helper.adminkey")
	if err := securefile.Replace(extra, []byte("gizli yönetici anahtarı")); err != nil {
		t.Fatal(err)
	}
	res := TriggerDuress(context.Background(), n.Dir(), []string{extra}, nil, n.doc.NetworkID, testNow)
	if !res.FakeReadOnly || len(res.Wiped) != 2 || !res.AlarmQueued {
		t.Fatalf("result: %+v", res)
	}
	for _, p := range []string{filepath.Join(n.Dir(), rootKeyFile), extra} {
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s still exists", p)
		}
	}
	entries, _ := os.ReadDir(n.Dir())
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") && !e.IsDir() {
			t.Fatalf("wipe left %s behind", e.Name())
		}
	}
	alarms, err := PendingAlarms(n.Dir())
	if err != nil || len(alarms) != 1 || alarms[0].Kind != "duress" {
		t.Fatalf("alarms: %v %+v", err, alarms)
	}
	decoy := DuressDecoy(n.doc, "nope")
	if len(decoy.Devices) != 0 || len(decoy.Rules) != 0 {
		t.Fatal("decoy shows the network")
	}
}

func TestEmergencyDocuments(t *testing.T) {
	n := newNetwork(t)
	addDevice(t, n, "nas")
	addDevice(t, n, "stolen")
	seal := []byte("acil durum zarfı 2026 kilit")
	recs, err := n.PrepareEmergency(testPass, seal, []EmergencySpec{{Kind: EmergencyLockdown}, {Kind: EmergencyRemove, Device: "stolen"}}, testNow, trust.DefaultValidity)
	if err != nil {
		t.Fatalf("PrepareEmergency: %v", err)
	}
	if len(recs) != 2 || recs[0].Version <= n.doc.Version+EmergencyVersionOffset-1 {
		t.Fatalf("records: %+v", recs)
	}
	member := &trust.State{Anchor: trust.Anchor{RootKey: rootPub(n), NetworkID: n.doc.NetworkID}}
	env, _ := trust.UnmarshalEnvelope(networkEnvelope(t, n))
	if _, err := member.Accept(env, testNow); err != nil {
		t.Fatal(err)
	}
	// Normal work continues below the emergency versions.
	addDevice(t, n, "later")
	st, _ := n.EmergencyStatus(testNow)
	if !st[0].Stale {
		t.Fatal("status does not report a stale document")
	}
	if _, _, err := n.PublishEmergency(EmergencyLockdown, "", []byte("yanlış zarf parolası 11"), testNow); !errors.Is(err, trust.ErrWrongPassphrase) {
		t.Fatalf("wrong passphrase: %v", err)
	}
	// The panic button: no root passphrase involved.
	data, doc, err := n.PublishEmergency(EmergencyLockdown, "", seal, testNow.Add(time.Hour))
	if err != nil {
		t.Fatalf("PublishEmergency: %v", err)
	}
	if doc.Lockdown == nil || len(doc.Invites) != 0 {
		t.Fatal("emergency document is not a lock")
	}
	pub, _ := trust.UnmarshalEnvelope(data)
	if _, err := member.Accept(pub, testNow.Add(time.Hour)); err != nil {
		t.Fatalf("member refused the emergency document: %v", err)
	}
	// The remove document of the same set is lower: refused as outdated.
	if _, _, err := n.PublishEmergency(EmergencyRemove, "stolen", seal, testNow.Add(time.Hour)); !errors.Is(err, ErrEmergencyOutdated) {
		t.Fatalf("second document: %v", err)
	}
	// The owner keeps signing after it.
	plan, err := n.Prepare(testNow.Add(2*time.Hour), trust.DefaultValidity, SetLockdown(false, "", testNow))
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Commit(plan, testPass); err != nil {
		t.Fatalf("commit after emergency: %v", err)
	}
}

func TestRiskSummaryAndPII(t *testing.T) {
	n := newNetwork(t)
	addDevice(t, n, "nas")
	prev, _ := n.Document()
	next, _ := prev.Next(testNow, trust.DefaultValidity)
	if err := next.AddRule(trust.Rule{From: []string{"*"}, To: []string{"nas"}, Protocol: trust.ProtocolAny, Description: "ahmet@example.com istedi"}); err != nil {
		t.Fatal(err)
	}
	r := AssessRisk(prev, next)
	if !r.Widens || r.Level == RiskLow || !strings.Contains(r.Summary, "1 kural erişimi genişletecek") {
		t.Fatalf("risk: %+v", r)
	}
	if !strings.HasPrefix(r.Lines()[1], "[!]") {
		t.Fatalf("widening item not flagged: %v", r.Lines())
	}
	if low := AssessRisk(prev, prev); low.Level != RiskLow || low.Widens {
		t.Fatalf("no-op risk: %+v", low)
	}
	if err := next.RenameDevice("nas", "zeynep-telefon"); err != nil {
		t.Fatal(err)
	}
	next.DisplayName = "05321234567"
	ws := PersonalDataWarnings(next)
	kinds := map[string]bool{}
	for _, w := range ws {
		kinds[w.Kind] = true
	}
	for _, k := range []string{PIIEmail, PIIName, PIIPhone} {
		if !kinds[k] {
			t.Errorf("missing %s warning: %+v", k, ws)
		}
	}
	if piiKinds("10000000146")[0] != PIINationID {
		t.Fatalf("TCKN: %v", piiKinds("10000000146"))
	}
	for _, clean := range []string{"nas", "router-1", "alias", "office-printer"} {
		if k := piiKinds(clean); len(k) != 0 {
			t.Errorf("%s flagged as %v", clean, k)
		}
	}
	d := ComputeDiff(prev, next)
	if !strings.Contains(strings.Join(d.SettingsChange, "\n"), "kişisel veri") {
		t.Fatalf("diff without PII warning: %v", d.SettingsChange)
	}
}

func TestSSHUserCertificates(t *testing.T) {
	n := newNetwork(t)
	adminPriv, sg := issueGrant(t, n, []trust.AdminOp{trust.AdminOpSSHCert}, nil, false)
	_, userPriv, _ := ed25519.GenerateKey(rand.Reader)
	userPub, err := ssh.NewPublicKey(userPriv.Public())
	if err != nil {
		t.Fatal(err)
	}
	req := SSHCertRequest{UserKey: userPub, Principals: []string{"deploy"}, KeyID: "helper"}
	cert, err := SignSSHUserCertWithKey(adminPriv, n.doc.NetworkID, &sg, req, testNow)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if life := time.Unix(int64(cert.ValidBefore), 0).Sub(testNow); life != DefaultSSHCertLife { //nolint:gosec // test value
		t.Fatalf("lifetime %s", life)
	}
	// The target (G5) checks the CA through the carried grant.
	caPub, _ := ssh.NewPublicKey(adminPriv.Public())
	checker := &ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			g, err := trust.CheckAdminGrant([]byte(cert.Permissions.Extensions[SSHGrantExtension]), rootPub(n), n.doc.NetworkID, trust.AdminOpSSHCert, testNow, nil)
			return err == nil && string(auth.Marshal()) == string(caPub.Marshal()) && g.Key == sg.Grant.Key
		},
		Clock: func() time.Time { return testNow },
	}
	if err := checker.CheckCert("deploy", cert); err != nil {
		t.Fatalf("CheckCert: %v", err)
	}
	if _, err := SignSSHUserCertWithKey(adminPriv, n.doc.NetworkID, &sg, SSHCertRequest{UserKey: userPub, Principals: []string{"root"}}, testNow); err == nil {
		t.Fatal("root principal signed")
	}
	if _, err := SignSSHUserCertWithKey(adminPriv, n.doc.NetworkID, &sg, SSHCertRequest{UserKey: userPub, Principals: []string{"deploy"}, Lifetime: 2 * time.Hour}, testNow); err == nil {
		t.Fatal("two-hour certificate signed")
	}
	other, sg2 := issueGrant(t, n, []trust.AdminOp{trust.AdminOpRules}, nil, false)
	if _, err := SignSSHUserCertWithKey(other, n.doc.NetworkID, &sg2, req, testNow); !errors.Is(err, trust.ErrAdminScope) {
		t.Fatalf("grant without ssh.cert: %v", err)
	}
	// Token CA (pure Ed25519 through the adapter).
	tok := &pureToken{priv: adminPriv}
	if _, err := SignSSHUserCertWith(tok, n.doc.NetworkID, &sg, req, testNow); err != nil {
		t.Fatalf("token CA: %v", err)
	}
}

func TestSensitiveThroughNetwork(t *testing.T) {
	n := newNetwork(t)
	addDevice(t, n, "vault")
	addDevice(t, n, "laptop")
	aPub, aPriv, _ := ed25519.GenerateKey(rand.Reader)
	bPub, bPriv, _ := ed25519.GenerateKey(rand.Reader)
	var ak, bk trust.Key
	copy(ak[:], aPub)
	copy(bk[:], bPub)
	policy := &trust.SensitivePolicy{Targets: []string{"vault"}, Threshold: 2, Approvers: []trust.Approver{{Name: "alice", Key: ak}, {Name: "bob", Key: bk}}}
	plan, err := n.Prepare(testNow, trust.DefaultValidity, SetSensitivePolicy(policy))
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Commit(plan, testPass); err != nil {
		t.Fatal(err)
	}
	st, err := n.Sensitive()
	if err != nil || st.Complete || st.Needed != 2 {
		t.Fatalf("before approvals: %v %+v", err, st)
	}
	for _, p := range []ed25519.PrivateKey{aPriv, bPriv} {
		c, _, err := ApproveSensitiveWithKey(p, networkEnvelope(t, n), rootPub(n))
		if err != nil {
			t.Fatal(err)
		}
		if st, err = n.AddSensitiveApproval(c); err != nil {
			t.Fatal(err)
		}
	}
	if !st.Complete {
		t.Fatalf("after approvals: %+v", st)
	}
	// An unrelated change carries the approvals forward.
	plan, err = n.Prepare(testNow.Add(time.Minute), trust.DefaultValidity, func(doc *trust.Document) error {
		doc.DisplayName = "Ev ağı"
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Commit(plan, testPass); err != nil {
		t.Fatal(err)
	}
	if st, _ := n.Sensitive(); !st.Complete {
		t.Fatalf("approvals not carried: %+v", st)
	}
	// Opening the vault needs fresh approvals.
	plan, err = n.Prepare(testNow.Add(2*time.Minute), trust.DefaultValidity, func(doc *trust.Document) error {
		return doc.AddRule(trust.Rule{From: []string{"laptop"}, To: []string{"vault"}, Protocol: trust.ProtocolAny})
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Commit(plan, testPass); err != nil {
		t.Fatal(err)
	}
	if st, _ := n.Sensitive(); st.Complete {
		t.Fatal("vault access counted as approved")
	}
}
