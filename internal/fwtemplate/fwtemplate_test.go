package fwtemplate

import (
	"crypto/rand"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/trust"
)

var now = time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)

func addDevice(t *testing.T, doc *trust.Document, name string, roles ...trust.Role) {
	t.Helper()
	s, err := trust.GenerateDeviceSecrets(rand.Reader, now)
	if err != nil {
		t.Fatal(err)
	}
	_, req, err := s.NewEnrollmentRequest(name, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := doc.AddDevice(req, name, roles, now, 365*24*time.Hour); err != nil {
		t.Fatal(err)
	}
}

// homeDoc: laptop (admin), nas, tv and lamba tagged iot, ha (controller),
// misafir. laptop may reach everything; tv has a narrow rule to nas and
// a broad rule covers tag:iot and laptop together.
func homeDoc(t *testing.T) *trust.Document {
	t.Helper()
	id, err := trust.NewNetworkID(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := trust.NewDocument(id, "ev.test", netip.MustParsePrefix("100.64.0.0/24"), netip.MustParsePrefix("fd7a:115c:a1e0::/64"), now, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	addDevice(t, doc, "laptop", trust.RoleAdmin)
	for _, n := range []string{"nas", "tv", "lamba", "ha", "misafir"} {
		addDevice(t, doc, n)
	}
	for i := range doc.Devices {
		if doc.Devices[i].Name == "tv" || doc.Devices[i].Name == "lamba" {
			doc.Devices[i].Tags = []string{"iot"}
		}
	}
	for _, r := range []trust.Rule{
		{From: []string{"laptop"}, To: []string{"*"}, Protocol: trust.ProtocolAny},
		{From: []string{"tv"}, To: []string{"nas"}, Protocol: trust.ProtocolTCP, Ports: []string{"445"}},
		{From: []string{"tag:iot", "laptop"}, To: []string{"ha"}, Protocol: trust.ProtocolTCP, Ports: []string{"8123"}},
		{From: []string{"misafir"}, To: []string{"*"}, Protocol: trust.ProtocolAny},
	} {
		if err := doc.AddRule(r); err != nil {
			t.Fatal(err)
		}
	}
	return doc
}

func TestTemplatesListed(t *testing.T) {
	if len(Templates()) != 6 {
		t.Fatal("template count")
	}
}

func TestInternetOnly(t *testing.T) {
	doc := homeDoc(t)
	if err := doc.SetExitUsers([]string{"laptop"}); err != nil {
		t.Fatal(err)
	}
	plan, err := Build(doc, InternetOnly, Params{Subject: "misafir"})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Added) != 1 || !plan.Added[0].IsDeny() || !plan.ExitUsersChanged || len(plan.ExitUsers) != 2 {
		t.Fatalf("%+v", plan)
	}
	if !hasReach(plan, "misafir", "nas", "tcp/445", true, false) {
		t.Fatalf("reach: %+v", plan.Reach)
	}
	if err := plan.Apply(doc); err != nil {
		t.Fatal(err)
	}
	if doc.Allows("misafir", "nas", trust.ProtocolTCP, 445) || !doc.MayUseExitNode("misafir") {
		t.Fatal("not applied")
	}
	if _, err := Build(doc, InternetOnly, Params{Subject: "misafir"}); !errors.Is(err, ErrNoChange) {
		t.Fatalf("second build: %v", err)
	}
}

func hasReach(p Plan, from, to, probe string, before, after bool) bool {
	for _, r := range p.Reach {
		if r.From == from && r.To == to && r.Probe == probe && r.Before == before && r.After == after {
			return true
		}
	}
	return false
}

func TestNASOnlyDisablesNarrowWarnsBroad(t *testing.T) {
	doc := homeDoc(t)
	plan, err := Build(doc, NASOnly, Params{Subject: "tv", Targets: []string{"nas"}, Ports: []string{"445", "2049"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Disabled) != 1 || plan.Disabled[0] != 1 {
		t.Fatalf("disabled %v", plan.Disabled)
	}
	if len(plan.Warnings) != 1 || !strings.Contains(plan.Warnings[0], "Kural 3") {
		t.Fatalf("warnings %v", plan.Warnings)
	}
	if !hasReach(plan, "tv", "nas", "tcp/2049", false, true) {
		t.Fatalf("reach %+v", plan.Reach)
	}
	if err := plan.Apply(doc); err != nil {
		t.Fatal(err)
	}
	if !doc.Rules[1].Disabled || !doc.Allows("tv", "nas", trust.ProtocolTCP, 2049) {
		t.Fatal("not applied")
	}
}

func TestGuestWithExpiry(t *testing.T) {
	doc := homeDoc(t)
	until := now.Add(48 * time.Hour)
	plan, err := Build(doc, Guest, Params{Subject: "misafir", Targets: []string{"nas"}, Ports: []string{"631"}, Until: until})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Added) != 2 || !plan.Added[0].NotAfter.Equal(until) || !plan.Added[1].IsDeny() {
		t.Fatalf("%+v", plan.Added)
	}
	if len(plan.Disabled) != 1 || plan.Disabled[0] != 3 {
		t.Fatalf("misafir's own broad rule should be disabled: %v", plan.Disabled)
	}
	if _, err := Build(doc, NASOnly, Params{Subject: "tv", Targets: []string{"nas"}, Ports: []string{"1"}, Until: until}); err == nil {
		t.Fatal("until accepted outside guest")
	}
}

func TestIoTIsolationByTag(t *testing.T) {
	doc := homeDoc(t)
	plan, err := Build(doc, IoTIsolation, Params{Subject: "tag:iot", Targets: []string{"ha"}, Ports: []string{"1883"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Added) != 2 || plan.Added[0].From[0] != "ha" || plan.Added[0].Protocol != trust.ProtocolAny {
		t.Fatalf("%+v", plan.Added)
	}
	if !hasReach(plan, "ha", "lamba", "tcp/22", false, true) || !hasReach(plan, "lamba", "ha", "tcp/1883", false, true) {
		t.Fatalf("reach %+v", plan.Reach)
	}
	if err := plan.Apply(doc); err != nil {
		t.Fatal(err)
	}
}

func TestQuarantineAndAdmin(t *testing.T) {
	doc := homeDoc(t)
	q, err := Build(doc, Quarantine, Params{Subject: "laptop"})
	if err != nil {
		t.Fatal(err)
	}
	if len(q.Added) != 2 || !hasReach(q, "laptop", "nas", "tcp/22", true, false) {
		t.Fatalf("%+v", q)
	}
	a, err := Build(doc, AdminEverywhere, Params{Subject: "nas"})
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Warnings) != 1 {
		t.Fatalf("non-admin not warned: %v", a.Warnings)
	}
	if _, err := Build(doc, AdminEverywhere, Params{Subject: "laptop"}); !errors.Is(err, ErrNoChange) {
		t.Fatalf("existing rule re-added: %v", err)
	}
}

func TestBuildErrors(t *testing.T) {
	doc := homeDoc(t)
	cases := []struct {
		kind Kind
		p    Params
	}{
		{InternetOnly, Params{Subject: "*"}},
		{InternetOnly, Params{Subject: "yok"}},
		{InternetOnly, Params{Subject: "10.0.0.0/8"}},
		{NASOnly, Params{Subject: "tv"}},
		{NASOnly, Params{Subject: "tv", Targets: []string{"tv"}, Ports: []string{"1"}}},
		{NASOnly, Params{Subject: "tv", Targets: []string{"nas"}, Ports: []string{"0"}}},
		{NASOnly, Params{Subject: "tv", Targets: []string{"nas"}, Protocol: trust.ProtocolAny, Ports: []string{"1"}}},
		{"x", Params{Subject: "tv"}},
	}
	for _, c := range cases {
		if _, err := Build(doc, c.kind, c.p); err == nil {
			t.Errorf("accepted %s %+v", c.kind, c.p)
		}
	}
}

func TestApplyStale(t *testing.T) {
	doc := homeDoc(t)
	plan, err := Build(doc, Quarantine, Params{Subject: "tv"})
	if err != nil {
		t.Fatal(err)
	}
	if err := doc.AddRule(trust.Rule{From: []string{"nas"}, To: []string{"tv"}, Protocol: trust.ProtocolICMP}); err != nil {
		t.Fatal(err)
	}
	n := len(doc.Rules)
	if err := plan.Apply(doc); !errors.Is(err, ErrStale) || len(doc.Rules) != n {
		t.Fatalf("stale plan applied: %v", err)
	}
}
