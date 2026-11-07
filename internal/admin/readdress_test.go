package admin

import (
	"net/netip"
	"testing"

	"github.com/openscale/openscale/internal/trust"
)

func TestPrepareReaddressSignsOneVersion(t *testing.T) {
	n := newNetwork(t)
	addDevice(t, n, "laptop")
	addDevice(t, n, "phone")
	before, _ := n.Document()

	newV4 := netip.MustParsePrefix("10.77.0.0/24")
	plan, moves, err := n.PrepareReaddress(testNow, trust.DefaultValidity, newV4, netip.Prefix{})
	if err != nil {
		t.Fatalf("PrepareReaddress: %v", err)
	}
	if len(moves) != 2 {
		t.Fatalf("moves = %+v", moves)
	}
	// Dry run: nothing changed on disk.
	if cur, _ := n.Document(); cur.Version != before.Version || cur.IPv4Prefix != before.IPv4Prefix {
		t.Fatal("prepare changed the document")
	}
	if err := n.Commit(plan, testPass); err != nil {
		t.Fatal(err)
	}
	re, err := Load(n.Dir(), testOpts)
	if err != nil {
		t.Fatal(err)
	}
	doc, _ := re.Document()
	if doc.Version != before.Version+1 || doc.IPv4Prefix != newV4 {
		t.Fatalf("version %d prefix %s", doc.Version, doc.IPv4Prefix)
	}
	for _, d := range doc.Devices {
		if !newV4.Contains(d.IPv4) {
			t.Fatalf("%s still at %s", d.Name, d.IPv4)
		}
	}
	if _, err := re.VerifyHistory(); err != nil {
		t.Fatalf("history: %v", err)
	}
}
