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

// signElsewhere signs the next version with the root key outside the
// network directory, like a stolen copy of the key would.
func signElsewhere(t *testing.T, n *Network) trust.Envelope {
	t.Helper()
	priv, err := n.sealed.Open(testPass)
	if err != nil {
		t.Fatal(err)
	}
	defer wipe(priv)
	cur, _ := n.Document()
	next, err := cur.Next(testNow.Add(time.Hour), trust.DefaultValidity)
	if err != nil {
		t.Fatal(err)
	}
	env, err := trust.SignDocument(next, priv)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func TestLedgerRecordsAndDetectsForeignSignature(t *testing.T) {
	n := newNetwork(t)
	addDevice(t, n, "laptop")
	addDevice(t, n, "telefon")
	entries, err := n.Ledger()
	if err != nil || len(entries) != 3 {
		t.Fatalf("ledger: %d %v", len(entries), err)
	}
	if c, err := n.CheckSigned(historyEnvelope(t, n, 2)); err != nil || c.Verdict != LedgerKnown {
		t.Fatalf("own version: %+v %v", c, err)
	}
	foreign := signElsewhere(t, n)
	c, err := n.CheckSigned(foreign)
	if err != nil || c.Verdict != LedgerForeign {
		t.Fatalf("foreign version: %+v %v", c, err)
	}
	if msg, _ := n.CheckRunningVersion(4); !strings.Contains(msg, "KRİTİK") {
		t.Fatalf("running v4: %q", msg)
	}
	if msg, _ := n.CheckRunningVersion(3); msg != "" {
		t.Fatalf("running v3: %q", msg)
	}
	st, err := n.LedgerStatus()
	if err != nil || len(st.Problems) != 0 || st.Last != 3 {
		t.Fatalf("status: %+v %v", st, err)
	}
	// A foreign network.json is reported.
	data, _ := trust.MarshalEnvelope(foreign)
	if err := securefile.Replace(filepath.Join(n.Dir(), documentFile), data); err != nil {
		t.Fatal(err)
	}
	st, err = n.LedgerStatus()
	if err != nil || !st.ForeignSeen {
		t.Fatalf("foreign network.json: %+v %v", st, err)
	}
}

func TestLedgerTamperIsReported(t *testing.T) {
	n := newNetwork(t)
	addDevice(t, n, "laptop")
	path := filepath.Join(n.Dir(), ledgerFile)
	data, err := securefile.ReadPrivate(path, maxLedgerSize)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.SplitAfter(string(data), "\n")
	if err := securefile.Replace(path, []byte(lines[1])); err != nil { // drop the first entry
		t.Fatal(err)
	}
	st, err := n.LedgerStatus()
	if err != nil || len(st.Problems) == 0 {
		t.Fatalf("tampered ledger: %+v %v", st, err)
	}
	if _, err := n.Ledger(); !errors.Is(err, ErrLedgerBroken) {
		t.Fatalf("err = %v", err)
	}
	// Signing refuses to extend a broken ledger.
	if _, err := n.Apply(testPass, testNow, SetMaxKeyAge(0)); err == nil {
		t.Fatal("signing must not continue a broken ledger")
	}
}

func TestDraftSignsManyEditsOnce(t *testing.T) {
	n := newNetwork(t)
	addDevice(t, n, "laptop") // v2
	addDevice(t, n, "phone")  // v3
	if _, err := n.Draft(); !errors.Is(err, ErrNoDraft) {
		t.Fatalf("no draft: %v", err)
	}
	rename := func(doc *trust.Document) error { return doc.RenameDevice("laptop", "dizustu") }
	if _, err := n.StageDraft(testNow, rename); err != nil {
		t.Fatal(err)
	}
	tags := func(doc *trust.Document) error { return doc.SetDeviceTags("dizustu", []string{"is"}) }
	if _, err := n.StageDraft(testNow, tags); err != nil {
		t.Fatal(err)
	}
	if l, err := n.StageDraft(testNow, tags); err == nil {
		t.Fatalf("an edit that changes nothing: %q", l)
	}
	doc, _ := n.Document()
	if doc.Version != 3 {
		t.Fatal("staging must not sign")
	}
	d, err := n.Draft()
	if err != nil || d.Problem != "" || len(d.Lines) == 0 {
		t.Fatalf("draft: %+v %v", d, err)
	}
	plan, err := n.PrepareDraft(testNow.Add(time.Minute), trust.DefaultValidity)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.CommitDraft(plan, testPass); err != nil {
		t.Fatal(err)
	}
	doc, _ = n.Document()
	dev, ok := doc.DeviceByName("dizustu")
	if doc.Version != 4 || !ok || len(dev.Tags) != 1 {
		t.Fatalf("v%d %+v", doc.Version, dev)
	}
	if _, err := os.Stat(filepath.Join(n.Dir(), draftFile)); !os.IsNotExist(err) {
		t.Fatal("the draft must be removed after signing")
	}
}

func TestDraftGoesStale(t *testing.T) {
	n := newNetwork(t)
	addDevice(t, n, "laptop")
	if _, err := n.StageDraft(testNow, SetMaxKeyAge(30)); err != nil {
		t.Fatal(err)
	}
	addDevice(t, n, "phone") // signed outside the draft
	if _, err := n.PrepareDraft(testNow, trust.DefaultValidity); !errors.Is(err, ErrDraftStale) {
		t.Fatalf("err = %v", err)
	}
	if _, err := n.StageDraft(testNow, SetMaxKeyAge(60)); !errors.Is(err, ErrDraftStale) {
		t.Fatalf("stage err = %v", err)
	}
	if d, _ := n.Draft(); d == nil || !d.Stale {
		t.Fatal("draft must be stale")
	}
	if err := n.DiscardDraft(); err != nil {
		t.Fatal(err)
	}
	if err := n.DiscardDraft(); !errors.Is(err, ErrNoDraft) {
		t.Fatal(err)
	}
}

func TestBulkMembershipOneSignature(t *testing.T) {
	n := newNetwork(t)
	addDevice(t, n, "a")
	addDevice(t, n, "b")
	addDevice(t, n, "c") // v4
	change, err := BulkMembership([]string{"a", "b"}, BulkOp{Extend: 30 * 24 * time.Hour, AddTags: []string{"ofis"}}, testNow)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := n.Apply(testPass, testNow, change)
	if err != nil {
		t.Fatal(err)
	}
	doc, _ := n.Document()
	if plan.Next.Version != 5 || doc.Version != 5 {
		t.Fatal("one version for the whole batch")
	}
	for _, name := range []string{"a", "b"} {
		d, _ := doc.DeviceByName(name)
		if !d.ExpiresAt.Equal(testNow.Add(30*24*time.Hour)) || len(d.Tags) != 1 {
			t.Fatalf("%s: %+v", name, d)
		}
	}
	if c, _ := doc.DeviceByName("c"); len(c.Tags) != 0 {
		t.Fatal("c untouched")
	}
	bad, _ := BulkMembership([]string{"a", "yok"}, BulkOp{Expire: true}, testNow)
	if _, err := n.Apply(testPass, testNow, bad); err == nil {
		t.Fatal("an unknown device fails the whole batch")
	}
	if d, _ := n.Document(); d.Version != 5 {
		t.Fatal("nothing signed")
	}
	for _, args := range []struct {
		names []string
		op    BulkOp
	}{
		{nil, BulkOp{Expire: true}},
		{[]string{"a", "a"}, BulkOp{Expire: true}},
		{[]string{"a"}, BulkOp{}},
		{[]string{"a"}, BulkOp{Expire: true, Extend: time.Hour}},
	} {
		if _, err := BulkMembership(args.names, args.op, testNow); err == nil {
			t.Fatalf("%v %+v must be refused", args.names, args.op)
		}
	}
}

func TestLockdownDiffWarnsOldDevices(t *testing.T) {
	n := newNetwork(t)
	plan, err := n.Prepare(testNow, trust.DefaultValidity, SetLockdown(true, "test", testNow))
	if err != nil {
		t.Fatal(err)
	}
	all := strings.Join(plan.Diff.Lines(), "\n")
	if !strings.Contains(all, "ACİL KİLİT") || !strings.Contains(all, "ADR-0151") {
		t.Fatalf("diff: %s", all)
	}
}
