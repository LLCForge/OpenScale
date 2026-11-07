package admin

import (
	"bytes"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
)

var recoveryPass = []byte("kurtarma kayık fener 42")

func withCoordinator(t *testing.T, n *Network) {
	t.Helper()
	var k trust.Key
	if _, err := rand.Read(k[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := n.Apply(testPass, testNow, func(doc *trust.Document) error {
		return doc.SetCoordinator("vpn.example.org:41820", k)
	}); err != nil {
		t.Fatal(err)
	}
}

// joinMember joins a member state directory from the owner's bundle.
func joinMember(t *testing.T, n *Network) *member.Store {
	t.Helper()
	line, err := n.JoinBundle()
	if err != nil {
		t.Fatal(err)
	}
	st, err := member.Join(t.TempDir(), line, n.RootFingerprint(), testNow)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func networkJSON(t *testing.T, n *Network) []byte {
	t.Helper()
	data, err := securefile.ReadPrivate(filepath.Join(n.Dir(), documentFile), trust.MaxEnvelopeSize)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestRootRotationThroughAdmin(t *testing.T) {
	n := newNetwork(t)
	addDevice(t, n, "laptop")
	file, fp, err := n.AddRecoveryKey(testPass, recoveryPass, testNow)
	if err != nil {
		t.Fatalf("AddRecoveryKey: %v", err)
	}
	if fp == "" || len(file) == 0 {
		t.Fatal("no recovery key returned")
	}
	if _, _, err := n.AddRecoveryKey(testPass, testPass, testNow); !errors.Is(err, ErrRecoveryPassphrase) {
		t.Fatalf("same passphrase: %v", err)
	}
	dev := joinMember(t, n)
	oldFP := n.RootFingerprint()

	change, err := n.RotateRoot(testPass, nil, testNow)
	if err != nil {
		t.Fatalf("RotateRoot: %v", err)
	}
	if change.Epoch != 1 || n.RootFingerprint() == oldFP || change.OldFingerprint != oldFP {
		t.Fatalf("change %+v", change)
	}
	// The network directory reloads with the new root.
	reloaded, err := Load(n.Dir(), testOpts)
	if err != nil {
		t.Fatalf("Load after rotation: %v", err)
	}
	if reloaded.RootFingerprint() != n.RootFingerprint() {
		t.Fatal("reloaded root differs")
	}
	// A member follows with the stored transitions; without them it cannot.
	doc := networkJSON(t, n)
	if _, err := dev.Accept(doc, testNow.Add(time.Hour)); err == nil {
		t.Fatal("member accepted the new root without a transition")
	}
	ts, err := n.RootTransitions()
	if err != nil || len(ts) != 1 {
		t.Fatalf("transitions %v %v", ts, err)
	}
	changed, err := dev.AcceptTransitions(ts, doc, testNow.Add(time.Hour))
	if err != nil || !changed {
		t.Fatalf("AcceptTransitions: %v", err)
	}
	if dev.Epoch() != 1 || len(dev.Transitions()) != 1 {
		t.Fatal("member did not record the transition")
	}
	// The member reopens on the new root (root.json overrides anchor.json).
	reopened, err := member.Open(dev.Dir())
	if err != nil {
		t.Fatalf("member.Open after rotation: %v", err)
	}
	if reopened.Epoch() != 1 || reopened.Document().RootEpoch != 1 {
		t.Fatal("reopened member lost the epoch")
	}
	// Normal edits continue with the new root and the member follows.
	addDevice(t, n, "phone")
	if _, err := reopened.Accept(networkJSON(t, n), testNow.Add(time.Hour)); err != nil {
		t.Fatalf("next version: %v", err)
	}
	report, err := n.VerifyHistory()
	if err != nil || !report.OK() {
		t.Fatalf("history after rotation: %v %v", report.Problems, err)
	}
}

func TestRootRecoveryThroughAdmin(t *testing.T) {
	n := newNetwork(t)
	addDevice(t, n, "laptop")
	file, _, err := n.AddRecoveryKey(testPass, recoveryPass, testNow)
	if err != nil {
		t.Fatal(err)
	}
	good, _ := n.Document()
	dev := joinMember(t, n)

	// The attacker stole root.key and its passphrase: it signs versions
	// that add a device, and one member follows them.
	stolen, err := Load(n.Dir(), testOpts)
	if err != nil {
		t.Fatal(err)
	}
	line, _ := requestLine(t)
	pending, _ := stolen.InspectRequest(line, testNow)
	plan, err := stolen.Prepare(testNow, trust.DefaultValidity, func(doc *trust.Document) error {
		_, err := doc.AddDevice(pending.Request, "evil", nil, testNow, trust.DefaultDeviceLife)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := stolen.Commit(plan, testPass); err != nil {
		t.Fatal(err)
	}
	bad := networkJSON(t, stolen)
	if _, err := dev.Accept(bad, testNow); err != nil {
		t.Fatal(err)
	}

	change, err := RecoverRoot(n.Dir(), RecoverOptions{
		RecoveryKey: file, RecoveryPassphrase: recoveryPass, NewPassphrase: []byte("yeni kök parola uzun 77"),
		LastGoodVersion: good.Version, BadDocuments: [][]byte{bad}, MinEpoch: 3,
	}, testOpts, testNow.Add(time.Hour))
	if err != nil {
		t.Fatalf("RecoverRoot: %v", err)
	}
	if change.Epoch != 4 || len(change.Revoked) != 1 || change.Revoked[0] != "evil" {
		t.Fatalf("change %+v", change)
	}
	recovered, err := Load(n.Dir(), testOpts)
	if err != nil {
		t.Fatal(err)
	}
	doc, _ := recovered.Document()
	if _, ok := doc.DeviceByName("evil"); ok || len(doc.Revoked) != 1 || doc.Version <= plan.Next.Version {
		t.Fatalf("recovered document %+v", doc)
	}
	// The member that followed the attacker returns to the owner's network.
	ts, _ := recovered.RootTransitions()
	if _, err := dev.AcceptTransitions(ts, networkJSON(t, recovered), testNow.Add(time.Hour)); err != nil {
		t.Fatalf("member recovery: %v", err)
	}
	if dev.Epoch() != 4 {
		t.Fatal("member not on the recovered root")
	}
	if _, err := dev.Accept(bad, testNow.Add(time.Hour)); err == nil {
		t.Fatal("attacker document accepted after recovery")
	}
	// The old passphrase no longer opens the root key.
	if err := recovered.CheckPassphrase(testPass); err == nil {
		t.Fatal("compromised passphrase still works")
	}
	// A wrong recovery passphrase or an unknown version fails.
	if _, err := RecoverRoot(n.Dir(), RecoverOptions{RecoveryKey: file, RecoveryPassphrase: []byte("yanlış parola uzun 11"), NewPassphrase: testPass, LastGoodVersion: good.Version}, testOpts, testNow); err == nil {
		t.Fatal("wrong recovery passphrase accepted")
	}
	if _, err := RecoverRoot(n.Dir(), RecoverOptions{RecoveryKey: file, RecoveryPassphrase: recoveryPass, NewPassphrase: testPass, LastGoodVersion: 999}, testOpts, testNow); !errors.Is(err, ErrLastGoodUnavailable) {
		t.Fatalf("unknown version: %v", err)
	}
}

func TestInterruptedRootChangeFinishes(t *testing.T) {
	n := newNetwork(t)
	if _, err := n.RotateRoot(testPass, nil, testNow); err != nil {
		t.Fatal(err)
	}
	// Simulate a crash after network.json but before root.key: put the new
	// key back as root.key.next and restore the old sealed key.
	dir := n.Dir()
	keyData, err := securefile.ReadPrivate(filepath.Join(dir, rootKeyFile), trust.MaxSealedKeySize)
	if err != nil {
		t.Fatal(err)
	}
	if err := securefile.Replace(filepath.Join(dir, nextRootKeyFile), keyData); err != nil {
		t.Fatal(err)
	}
	other, err := Init(t.TempDir(), InitOptions{DNSDomain: trust.DefaultDNSDomain, IPv4Prefix: trust.DefaultIPv4Prefix, Validity: trust.DefaultValidity}, testPass, testOpts, testNow)
	if err != nil {
		t.Fatal(err)
	}
	oldKey, _ := securefile.ReadPrivate(filepath.Join(other.Dir(), rootKeyFile), trust.MaxSealedKeySize)
	if err := securefile.Replace(filepath.Join(dir, rootKeyFile), oldKey); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir, testOpts); err != nil {
		t.Fatalf("Load did not finish the root change: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, nextRootKeyFile)); !os.IsNotExist(err) {
		t.Fatal("root.key.next left behind")
	}
}

func TestMultiUseInviteRejectAndApprove(t *testing.T) {
	n := newNetwork(t)
	withCoordinator(t, n)
	created, err := n.CreateInviteWith(testPass, testNow, InviteRequest{Life: time.Hour, MaxUses: 2, Note: "Ayşe'nin cihazları"})
	if err != nil {
		t.Fatal(err)
	}
	if n.InviteNotes()[created.Invite.ID] != "Ayşe'nin cihazları" {
		t.Fatal("note not stored")
	}
	if _, err := n.CreateInviteWith(testPass, testNow, InviteRequest{Life: time.Hour, Note: "kötü\x00not"}); !errors.Is(err, ErrInvalidNote) {
		t.Fatalf("bad note: %v", err)
	}
	doc, _ := n.Document()
	if bytes.Contains(networkJSON(t, n), []byte("Ayşe")) {
		t.Fatal("the note leaked into the signed document")
	}
	code, _ := trust.DecodeInviteCode(created.Code)
	enroll := func(host string) trust.SignedInviteEnrollment {
		s, _ := trust.GenerateDeviceSecrets(rand.Reader, testNow)
		se, _, err := s.NewInviteEnrollment(code, host, testNow)
		if err != nil {
			t.Fatal(err)
		}
		return se
	}
	a, b, c := enroll("a"), enroll("b"), enroll("c")
	if got := n.VerifyPending([]trust.SignedInviteEnrollment{a, b, c}, testNow); len(got) != 3 {
		t.Fatalf("pending %d, want 3 for a multi-use invite", len(got))
	}
	reqC, _, _ := trust.OpenInviteEnrollment(doc, c, testNow)
	if err := n.RejectPending(created.Invite.ID, reqC.DeviceID, testNow); err != nil {
		t.Fatal(err)
	}
	if got := n.VerifyPending([]trust.SignedInviteEnrollment{a, b, c}, testNow); len(got) != 2 {
		t.Fatalf("pending after reject %d, want 2", len(got))
	}
	if _, err := n.ApproveInviteWith(testPass, a, "a", nil, ApproveOptions{Ephemeral: true}, testNow); err != nil {
		t.Fatal(err)
	}
	if _, err := n.ApproveInvite(testPass, b, "b", nil, testNow); err != nil {
		t.Fatal(err)
	}
	if _, err := n.ApproveInvite(testPass, c, "c", nil, testNow); err == nil {
		t.Fatal("third device approved with a two-use invite")
	}
	doc, _ = n.Document()
	d, _ := doc.DeviceByName("a")
	if !d.Ephemeral || d.ExpiresAt.Sub(d.AddedAt) != trust.DefaultEphemeralLife {
		t.Fatalf("ephemeral device %+v", d)
	}
	// The expired ephemeral device leaves with the next signed version.
	plan, err := n.Prepare(testNow.Add(2*trust.DefaultEphemeralLife), trust.DefaultValidity, func(*trust.Document) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := plan.Next.DeviceByName("a"); ok || len(plan.Diff.RemovedDevices) != 1 {
		t.Fatal("expired ephemeral device not pruned")
	}
}

func TestPreauthLeaveInactiveThroughAdmin(t *testing.T) {
	n := newNetwork(t)
	withCoordinator(t, n)
	line, dev, err := n.CreatePreauthKey(testPass, trust.PreauthOptions{Name: "ci", Tags: []string{"ci"}, Ephemeral: true}, testNow)
	if err != nil {
		t.Fatalf("CreatePreauthKey: %v", err)
	}
	k, anchor, doc, err := trust.OpenPreauthKey(line, testNow)
	if err != nil {
		t.Fatalf("OpenPreauthKey: %v", err)
	}
	if anchor.NetworkID != doc.NetworkID || k.Device.DeviceID != dev.ID || !dev.Preauthorized || !dev.Ephemeral {
		t.Fatal("preauthorized device wrong")
	}
	// The device asks to leave; the owner applies it with one signature.
	sl, err := k.Device.NewLeaveRequest(rand.Reader, doc.NetworkID, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if got := n.VerifyLeaves([]trust.SignedLeave{sl, {DeviceID: dev.ID, Payload: []byte("{}"), Signature: make([]byte, 64)}}, testNow); len(got) != 1 || got[0].Name != "ci" {
		t.Fatalf("verified leaves %+v", got)
	}
	if _, err := n.ApplyLeave(testPass, sl, testNow); err != nil {
		t.Fatal(err)
	}
	cur, _ := n.Document()
	if _, ok := cur.DeviceByName("ci"); ok {
		t.Fatal("device still listed after leave")
	}
	// Inactive devices: never seen and added long ago.
	addDevice(t, n, "old")
	addDevice(t, n, "fresh")
	cur, _ = n.Document()
	fresh, _ := cur.DeviceByName("fresh")
	later := testNow.Add(60 * 24 * time.Hour)
	if err := n.RecordSeen(map[string]time.Time{fresh.ID: later.Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	list := n.InactiveDevices(nil, 0, later)
	if len(list) != 1 || list[0].Name != "old" || list[0].Days < 59 {
		t.Fatalf("inactive %+v", list)
	}
	if _, err := n.RemoveDevices(testPass, []string{"old"}, later); err != nil {
		t.Fatal(err)
	}
	if _, err := n.SetMinClientVersion(testPass, "1.2.3", later); err != nil {
		t.Fatal(err)
	}
	if _, err := n.SetMinClientVersion(testPass, "1.2", later); err == nil {
		t.Fatal("invalid version accepted")
	}
}
