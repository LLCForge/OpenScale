package trust

import (
	"slices"
	"testing"
)

func TestPanelServiceRule(t *testing.T) {
	doc := rdeskDoc(t)
	names := []string{}
	for _, d := range doc.Devices {
		names = append(names, d.Name)
	}
	if len(names) < 3 {
		t.Fatalf("test document needs three devices, has %d", len(names))
	}
	owner, laptop, other := names[0], names[1], names[2]

	if ServicePanel.Port() != PanelPort || PanelPort != 4049 {
		t.Fatal("panel port")
	}
	if slices.Contains(Services(), ServicePanel) {
		t.Fatal("the panel serves itself; Services must not list it")
	}
	bad := []Rule{
		{From: []string{laptop}, To: []string{owner}, Service: ServicePanel, Protocol: ProtocolTCP, Ports: []string{"4049"}},
		{From: []string{laptop}, To: []string{owner}, Service: ServicePanel, Users: []string{"alice"}},
		{From: []string{laptop}, To: []string{owner}, Service: ServicePanel, AllowControl: true},
	}
	for i, r := range bad {
		if err := doc.AddRule(r); err == nil {
			t.Errorf("bad rule %d accepted", i)
		}
	}
	if doc.AllowsPanel(laptop, owner) {
		t.Fatal("no rule must not allow")
	}
	if err := doc.AddRule(Rule{From: []string{"*"}, To: []string{"*"}, Protocol: ProtocolAny}); err != nil {
		t.Fatal(err)
	}
	if doc.AllowsPanel(laptop, owner) {
		t.Fatal("a broad any rule must not grant the panel")
	}
	if err := doc.AddRule(Rule{From: []string{laptop}, To: []string{owner}, Service: ServicePanel}); err != nil {
		t.Fatal(err)
	}
	if !doc.AllowsPanel(laptop, owner) {
		t.Fatal("panel rule must allow")
	}
	if doc.AllowsPanel(other, owner) || doc.AllowsPanel(owner, laptop) || doc.AllowsPanel(owner, owner) {
		t.Fatal("panel rule allows only its own direction and devices")
	}
	if !doc.HostsService(owner, ServicePanel) || doc.HostsService(laptop, ServicePanel) {
		t.Fatal("HostsService must follow the panel rule")
	}
	if err := doc.AddRule(Rule{From: []string{laptop}, To: []string{owner}, Service: ServicePanel, Action: RuleDeny}); err != nil {
		t.Fatal(err)
	}
	if doc.AllowsPanel(laptop, owner) {
		t.Fatal("deny panel rule must win")
	}
}
