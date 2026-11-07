package admin

import (
	"errors"
	"strings"
	"testing"

	"github.com/openscale/openscale/internal/trust"
)

// ADR-0232: signing a document with an icon, a range in a group, exit_users
// or via, or a support rule raises min_client_version to 1.0.0-beta.2, and
// never lowers a higher one.

func commitChange(t *testing.T, n *Network, change Change) *Plan {
	t.Helper()
	plan, err := n.Prepare(testNow, trust.DefaultValidity, change)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := n.Commit(plan, testPass); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return plan
}

func TestF4AIconRaisesMinClientVersion(t *testing.T) {
	n := newNetwork(t)
	addDevice(t, n, "laptop")
	doc, _ := n.Document()
	if doc.MinClientVersion != "" {
		t.Fatalf("a fresh network has no minimum, got %q", doc.MinClientVersion)
	}
	plan, err := n.SetDeviceIcon("laptop", trust.IconLaptop, testNow, trust.DefaultValidity)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Next.MinClientVersion != trust.SchemaV2MinClientVersion {
		t.Fatalf("min_client_version = %q, want %q", plan.Next.MinClientVersion, trust.SchemaV2MinClientVersion)
	}
	joined := strings.Join(plan.Diff.Lines(), "\n")
	if !strings.Contains(joined, "simge - -> laptop") || !strings.Contains(joined, "1.0.0-beta.2") {
		t.Fatalf("the owner must see the icon and the minimum in the diff:\n%s", joined)
	}
	if err := n.Commit(plan, testPass); err != nil {
		t.Fatal(err)
	}
	if _, err := n.SetDeviceIcon("laptop", "toaster", testNow, trust.DefaultValidity); !errors.Is(err, trust.ErrUnknownIcon) {
		t.Fatalf("unknown icon: %v", err)
	}
	if Describe(trust.ErrUnknownIcon) == trust.ErrUnknownIcon.Error() {
		t.Fatal("the icon error needs a Turkish message")
	}
}

func TestF4ANeverLowersMinimum(t *testing.T) {
	n := newNetwork(t)
	addDevice(t, n, "laptop")
	commitChange(t, n, func(doc *trust.Document) error { return doc.SetMinClientVersion("1.2.0") })
	plan, err := n.SetDeviceIcon("laptop", trust.IconServer, testNow, trust.DefaultValidity)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Next.MinClientVersion != "1.2.0" {
		t.Fatalf("a higher minimum must stay, got %q", plan.Next.MinClientVersion)
	}
}

func TestF4ARangesAndSupportRaiseMinimum(t *testing.T) {
	n := newNetwork(t)
	addDevice(t, n, "laptop")
	addDevice(t, n, "nas")
	doc, _ := n.Document()
	nas, _ := doc.DeviceByName("nas")
	cidr := trust.NormalizeAddrEntry(nas.IPv4.String())
	cases := map[string]Change{
		"group range": func(d *trust.Document) error { return d.SetGroup("depo", []string{cidr}) },
		"exit range":  func(d *trust.Document) error { return d.SetExitUsers([]string{cidr}) },
		"support rule": func(d *trust.Document) error {
			return d.AddRule(trust.Rule{From: []string{"laptop"}, To: []string{"nas"}, Service: trust.ServiceSupport, AllowKill: true})
		},
	}
	for name, change := range cases {
		plan, err := n.Prepare(testNow, trust.DefaultValidity, change)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if plan.Next.MinClientVersion != trust.SchemaV2MinClientVersion {
			t.Fatalf("%s: min_client_version = %q", name, plan.Next.MinClientVersion)
		}
	}
	// A change that uses none of the additions leaves the minimum alone.
	plan, err := n.Prepare(testNow, trust.DefaultValidity, func(d *trust.Document) error { return d.SetGroup("depo", []string{"nas"}) })
	if err != nil {
		t.Fatal(err)
	}
	if plan.Next.MinClientVersion != "" {
		t.Fatalf("no addition, no minimum: %q", plan.Next.MinClientVersion)
	}
	if !strings.Contains(ServiceRuleDetail(trust.Rule{Service: trust.ServiceSupport, AllowKill: true}), "support.kill") {
		t.Fatal("the change list must spell out the kill permission")
	}
}
