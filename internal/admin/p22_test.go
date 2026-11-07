package admin

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
)

type fileSigner struct{ priv ed25519.PrivateKey }

func (f fileSigner) PublicKey() ed25519.PublicKey { return f.priv.Public().(ed25519.PublicKey) }
func (f fileSigner) SignMessage(msg []byte) ([]byte, error) {
	return ed25519.Sign(f.priv, msg), nil
}

func memberState(t *testing.T, n *Network) *trust.State {
	t.Helper()
	doc, err := n.Document()
	if err != nil {
		t.Fatal(err)
	}
	return &trust.State{Anchor: trust.Anchor{RootKey: n.sealed.RootPublicKey(), NetworkID: doc.NetworkID}}
}

func acceptCurrent(n *Network, st *trust.State) error {
	data, err := n.SignedDocument()
	if err != nil {
		return err
	}
	env, err := trust.UnmarshalEnvelope(data)
	if err != nil {
		return err
	}
	_, err = st.Accept(env, testNow)
	return err
}

func TestApprovalThroughAdmin(t *testing.T) {
	n := newNetwork(t)
	st := memberState(t, n)
	if err := acceptCurrent(n, st); err != nil {
		t.Fatal(err)
	}
	pubA, privA, _ := ed25519.GenerateKey(rand.Reader)
	pubB, _, _ := ed25519.GenerateKey(rand.Reader)
	var ka, kb trust.Key
	copy(ka[:], pubA)
	copy(kb[:], pubB)
	policy := &trust.ApprovalPolicy{Threshold: 1, Approvers: []trust.Approver{{Name: "laptop", Key: ka}, {Name: "token", Key: kb}}}
	plan, err := n.Prepare(testNow, trust.DefaultValidity, SetApprovalPolicy(policy))
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Commit(plan, testPass); err != nil {
		t.Fatal(err)
	}
	status, err := n.Approvals()
	if err != nil {
		t.Fatal(err)
	}
	if status.Complete || len(status.Missing) != 2 {
		t.Fatalf("status before approval: %+v", status)
	}
	if err := acceptCurrent(n, st); !errors.Is(err, trust.ErrApprovalMissing) {
		t.Fatalf("member accepted an unapproved policy: %v", err)
	}
	// An approval from a stranger is refused.
	_, stranger, _ := ed25519.GenerateKey(rand.Reader)
	data, _ := n.SignedDocument()
	c, _, err := ApproveWithKey(stranger, data, n.sealed.RootPublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := n.AddApproval(c); !errors.Is(err, trust.ErrApprovalPolicy) {
		t.Fatalf("stranger's approval: %v", err)
	}
	c, doc, err := ApproveWithKey(privA, data, n.sealed.RootPublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if doc.Approval == nil {
		t.Fatal("approver did not see the policy")
	}
	status, err = n.AddApproval(c)
	if err != nil {
		t.Fatal(err)
	}
	if !status.Complete || len(status.Approved) != 1 || status.Approved[0] != "laptop" {
		t.Fatalf("status after approval: %+v", status)
	}
	if err := acceptCurrent(n, st); err != nil {
		t.Fatalf("member rejected the approved document: %v", err)
	}
	// The next root-only version is incomplete until approved again.
	plan, err = n.Prepare(testNow, trust.DefaultValidity, func(*trust.Document) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Commit(plan, testPass); err != nil {
		t.Fatal(err)
	}
	if status, _ := n.Approvals(); status.Complete {
		t.Fatal("next version reported complete without approvals")
	}
	if err := acceptCurrent(n, st); !errors.Is(err, trust.ErrApprovalMissing) {
		t.Fatalf("member accepted a root-only version: %v", err)
	}
}

func TestCommitWithHardwareSigner(t *testing.T) {
	n := newNetwork(t)
	priv, err := n.sealed.Open(testPass)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := n.Prepare(testNow, trust.DefaultValidity, func(doc *trust.Document) error { doc.DisplayName = "Ev"; return nil })
	if err != nil {
		t.Fatal(err)
	}
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	if err := n.CommitWith(plan, fileSigner{other}); !errors.Is(err, ErrTokenKeyMismatch) {
		t.Fatalf("foreign token: %v", err)
	}
	if err := n.CommitWith(plan, fileSigner{priv}); err != nil {
		t.Fatalf("CommitWith: %v", err)
	}
	re, err := Load(n.Dir(), testOpts)
	if err != nil {
		t.Fatalf("Load after hardware commit: %v", err)
	}
	if err := acceptCurrent(re, memberState(t, re)); err != nil {
		t.Fatalf("member rejected the token-signed document: %v", err)
	}
	// The passphrase path keeps working afterwards.
	plan, err = re.Prepare(testNow, trust.DefaultValidity, func(*trust.Document) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := re.Commit(plan, testPass); err != nil {
		t.Fatal(err)
	}
}

func snapshotDir(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(dir, path)
		data, err := os.ReadFile(path)
		out[filepath.ToSlash(rel)] = data
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestTravelRoundTrip(t *testing.T) {
	n := newNetwork(t)
	addDevice(t, n, "laptop")
	backupPass := []byte("yedek kopya kapı lamba 31")
	backup, err := n.CreateBackup(testPass, backupPass, "usb", testNow)
	if err != nil {
		t.Fatal(err)
	}
	dir := n.Dir()
	before := snapshotDir(t, dir)
	archive := filepath.Join(t.TempDir(), "seyahat.osarchive")

	// Refusals leave everything in place.
	if _, err := PrepareTravel(dir, backup, []byte("yanlış parola uzun 12345"), archive, rand.Reader, testNow); err == nil {
		t.Fatal("wrong backup passphrase accepted")
	}
	if _, err := PrepareTravel(dir, backup, backupPass, filepath.Join(dir, "a.bin"), rand.Reader, testNow); err == nil {
		t.Fatal("archive inside the network directory accepted")
	}
	if got := snapshotDir(t, dir); len(got) != len(before) {
		t.Fatal("a refused travel preparation changed the directory")
	}

	rep, err := PrepareTravel(dir, backup, backupPass, archive, rand.Reader, testNow)
	if err != nil {
		t.Fatalf("PrepareTravel: %v", err)
	}
	if rep.Files != len(before)-1 {
		t.Fatalf("archived %d files, want %d", rep.Files, len(before)-1)
	}
	after := snapshotDir(t, dir)
	if _, ok := after[rootKeyFile]; ok {
		t.Fatal("root.key is still on the device")
	}
	if len(after) != 2 || after[documentFile] == nil || after[travelMarkerFile] == nil {
		t.Fatalf("left behind: %v", keys(after))
	}
	if !Traveling(dir) {
		t.Fatal("not in travel mode")
	}
	if _, err := Load(dir, testOpts); err == nil {
		t.Fatal("network could be loaded while traveling")
	}
	arch, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(arch, []byte("laptop")) {
		t.Fatal("archive is not encrypted")
	}
	// A tampered archive is refused.
	bad := append([]byte(nil), arch...)
	bad[len(bad)/2] ^= 1
	if _, err := ReturnFromTravel(dir, backup, backupPass, bad); !errors.Is(err, ErrArchiveMismatch) {
		t.Fatalf("tampered archive: %v", err)
	}
	if _, err := ReturnFromTravel(dir, backup, backupPass, arch); err != nil {
		t.Fatalf("ReturnFromTravel: %v", err)
	}
	restored := snapshotDir(t, dir)
	if len(restored) != len(before) {
		t.Fatalf("restored %d files, want %d", len(restored), len(before))
	}
	for name, data := range before {
		if !bytes.Equal(restored[name], data) {
			t.Fatalf("%s differs after return", name)
		}
	}
	if _, err := Load(dir, testOpts); err != nil {
		t.Fatalf("Load after return: %v", err)
	}
}

func keys(m map[string][]byte) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestAirGapTransfer(t *testing.T) {
	n := newNetwork(t)
	usb := t.TempDir()
	relay := filepath.Join(t.TempDir(), "net")
	if _, err := n.ExportTransfer(n.Dir()); err == nil {
		t.Fatal("export into the network directory accepted")
	}
	names, err := n.ExportTransfer(usb)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 || names[0] != documentFile {
		t.Fatalf("exported %v", names)
	}
	if _, err := os.Stat(filepath.Join(usb, rootKeyFile)); err == nil {
		t.Fatal("root key crossed the air gap")
	}
	root := n.sealed.RootPublicKey()
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := ImportTransfer(usb, relay, other.Public().(ed25519.PublicKey)); !errors.Is(err, trust.ErrBadSignature) {
		t.Fatalf("foreign root: %v", err)
	}
	doc, err := ImportTransfer(usb, relay, root)
	if err != nil {
		t.Fatalf("ImportTransfer: %v", err)
	}
	if doc.Version != 1 {
		t.Fatalf("version %d", doc.Version)
	}
	// A newer version replaces it; the older one cannot come back.
	addDevice(t, n, "laptop")
	usb2 := t.TempDir()
	if _, err := n.ExportTransfer(usb2); err != nil {
		t.Fatal(err)
	}
	if _, err := ImportTransfer(usb2, relay, root); err != nil {
		t.Fatal(err)
	}
	if _, err := ImportTransfer(usb, relay, root); err == nil {
		t.Fatal("older document replaced a newer one")
	}
	data, err := securefile.ReadLimited(filepath.Join(relay, documentFile), trust.MaxEnvelopeSize)
	if err != nil {
		t.Fatal(err)
	}
	env, _ := trust.UnmarshalEnvelope(data)
	if d, _ := trust.VerifyDocumentSignature(env, root); d == nil || d.Version != 2 {
		t.Fatal("relay directory does not hold the newest document")
	}
	if _, err := OfflineCheck(); err != nil {
		t.Fatalf("OfflineCheck: %v", err)
	}
}
