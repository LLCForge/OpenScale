package admin

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
)

func historyEnvelope(t *testing.T, n *Network, version uint64) trust.Envelope {
	t.Helper()
	data, err := securefile.ReadPrivate(filepath.Join(n.Dir(), historyDir, historyName(version)), trust.MaxEnvelopeSize)
	if err != nil {
		t.Fatal(err)
	}
	env, err := trust.UnmarshalEnvelope(data)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func TestVersionChainLinksEveryVersion(t *testing.T) {
	n := newNetwork(t)
	addDevice(t, n, "laptop")                               // v2, unchained
	plan, err := n.SetVersionChain(testPass, true, testNow) // v3
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(plan.Diff.Lines(), "\n"), "Sürüm zinciri: açıldı") {
		t.Fatalf("diff = %v", plan.Diff.Lines())
	}
	addDevice(t, n, "masaustu") // v4
	doc, err := n.Document()
	if err != nil {
		t.Fatal(err)
	}
	if doc.Version != 4 || doc.PrevDigest != trust.DocumentDigest(historyEnvelope(t, n, 3)) {
		t.Fatalf("v%d prev_digest %q not linked to v3", doc.Version, doc.PrevDigest)
	}
	v3, err := trust.VerifyDocumentSignature(historyEnvelope(t, n, 3), n.sealed.RootPublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if v3.PrevDigest != trust.DocumentDigest(historyEnvelope(t, n, 2)) {
		t.Fatal("v3 not linked to v2")
	}
	report, err := n.VerifyHistory()
	if err != nil || !report.OK() {
		t.Fatalf("history: %v %+v", err, report.Problems)
	}

	if _, err := n.SetVersionChain(testPass, false, testNow); err != nil { // v5
		t.Fatal(err)
	}
	addDevice(t, n, "telefon") // v6
	doc, _ = n.Document()
	if doc.VersionChainEnabled() {
		t.Fatal("chain must stay off")
	}
}

func TestVerifyHistoryReportsForkedChain(t *testing.T) {
	n := newNetwork(t)
	if _, err := n.SetVersionChain(testPass, true, testNow); err != nil { // v2
		t.Fatal(err)
	}
	addDevice(t, n, "laptop") // v3
	// Replace v3 in the history with a version signed by the same root but
	// linked to a different v2.
	priv, err := n.sealed.Open(testPass)
	if err != nil {
		t.Fatal(err)
	}
	defer wipe(priv)
	doc, err := n.Document()
	if err != nil {
		t.Fatal(err)
	}
	doc.PrevDigest = strings.Repeat("ab", 32)
	env, err := trust.SignDocument(doc, priv)
	if err != nil {
		t.Fatal(err)
	}
	data, err := trust.MarshalEnvelope(env)
	if err != nil {
		t.Fatal(err)
	}
	if err := securefile.Replace(filepath.Join(n.Dir(), historyDir, historyName(3)), data); err != nil {
		t.Fatal(err)
	}
	report, err := n.VerifyHistory()
	if err != nil {
		t.Fatal(err)
	}
	if report.OK() || !strings.Contains(strings.Join(report.Problems, "\n"), "çatallanmış") {
		t.Fatalf("problems = %v", report.Problems)
	}
}
