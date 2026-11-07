package admin

import (
	"errors"
	"strings"
	"testing"

	"github.com/openscale/openscale/internal/trust"
)

// retireNetwork has nas referenced from every place a retirement cleans.
func retireNetwork(t *testing.T) *Network {
	t.Helper()
	n := newNetwork(t)
	for _, name := range []string{"laptop", "nas", "vps", "vps2", "tel"} {
		addDevice(t, n, name)
	}
	if _, err := n.Apply(testPass, testNow, func(doc *trust.Document) error {
		for _, x := range []string{"nas", "vps", "vps2"} {
			if err := doc.SetExitNode(x, true); err != nil {
				return err
			}
		}
		if err := doc.SetDeviceTags("nas", []string{"sunucu"}); err != nil {
			return err
		}
		if err := doc.SetGroup("ev", []string{"nas", "laptop"}); err != nil {
			return err
		}
		if err := doc.SetGroup("yalniz", []string{"nas"}); err != nil {
			return err
		}
		nas, _ := doc.DeviceByName("nas")
		if err := doc.SetMagicDNS(&trust.MagicDNSSettings{Records: []trust.DNSRecord{
			{Name: "depo", Type: trust.RecordA, Value: nas.IPv4.String()},
			{Name: "baska", Type: trust.RecordA, Value: "100.64.0.200"},
		}}); err != nil {
			return err
		}
		rules := []trust.Rule{
			{From: []string{"laptop"}, To: []string{"nas"}, Protocol: trust.ProtocolTCP, Ports: []string{"445"}},              // 1 removed
			{From: []string{"laptop", "tel"}, To: []string{"nas", "vps"}, Protocol: trust.ProtocolTCP, Ports: []string{"80"}}, // 2 trimmed
			{From: []string{"laptop"}, To: []string{"tag:sunucu"}, Protocol: trust.ProtocolAny},                               // 3 indirect
			{From: []string{"laptop"}, To: []string{"nas"}, Service: trust.ServiceSSH, Users: []string{"ali"}},                // 4 ssh
			{From: []string{"laptop"}, To: []string{"vps"}, Protocol: trust.ProtocolICMP},                                     // 5 untouched
		}
		for _, r := range rules {
			if err := doc.AddRule(r); err != nil {
				return err
			}
		}
		if err := doc.AddRule(trust.Rule{From: []string{"laptop"}, To: []string{"tel"}, Service: trust.ServiceWake, Via: []string{"nas"}}); err != nil { // 6 wake relay
			return err
		}
		if err := doc.SetExitChain("vps", "nas"); err != nil {
			return err
		}
		return doc.SetExitUsers([]string{"nas", "laptop"})
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

func sectionOf(p RetirePreview, id string) []RetireItem {
	for _, s := range p.Sections {
		if s.ID == id {
			return s.Items
		}
	}
	return nil
}

func hasItem(items []RetireItem, title, effect string) bool {
	for _, it := range items {
		if strings.Contains(it.Title, title) && strings.Contains(it.Effect, effect) {
			return true
		}
	}
	return false
}

func TestPreviewRetireListsEveryReference(t *testing.T) {
	n := retireNetwork(t)
	p, err := n.PreviewRetire("nas", testNow)
	if err != nil {
		t.Fatal(err)
	}
	if p.Device != "nas" || !p.ExitNode || p.IPv4 == "" {
		t.Fatalf("header: %+v", p)
	}
	rules := sectionOf(p, RetireRules)
	if !hasItem(rules, "Kural 1:", "Kural silinir") || !hasItem(rules, "Kural 2:", "kuraldan çıkarılır") || !hasItem(rules, "Kural 3:", "artık eşleşmez") {
		t.Fatalf("rules: %+v", rules)
	}
	if hasItem(rules, "Kural 5:", "") {
		t.Fatalf("untouched rule listed: %+v", rules)
	}
	if !hasItem(sectionOf(p, RetireSSH), "Kural 4:", "silinir") || !hasItem(sectionOf(p, RetireWake), "Kural 6:", "aracı") {
		t.Fatalf("ssh/wake: %+v", p.Sections)
	}
	groups := sectionOf(p, RetireGroups)
	if !hasItem(groups, "group:ev", "çıkarılır") || !hasItem(groups, "group:yalniz", "boş kalır") || !hasItem(groups, "Çıkış düğümü kullanıcıları", "") {
		t.Fatalf("groups: %+v", groups)
	}
	dns := sectionOf(p, RetireDNS)
	if !hasItem(dns, "depo A", "silinir") || hasItem(dns, "baska", "") {
		t.Fatalf("dns: %+v", dns)
	}
	if !hasItem(sectionOf(p, RetireExit), "vps -> nas", "Zincir silinir") {
		t.Fatalf("exit: %+v", sectionOf(p, RetireExit))
	}
	if p.Cleaned < 8 || len(p.Notes) < 3 {
		t.Fatalf("counts: %d notes %v", p.Cleaned, p.Notes)
	}
	// The preview does not change the network.
	doc, _ := n.Document()
	if _, ok := doc.DeviceByName("nas"); !ok || len(doc.ExitChains) != 1 {
		t.Fatal("preview modified the document")
	}
}

func TestRetireSignsEverythingInOneVersion(t *testing.T) {
	n := retireNetwork(t)
	before, _ := n.Document()
	plan, err := n.Apply(testPass, testNow, RetireChange("nas", testNow))
	if err != nil {
		t.Fatal(err)
	}
	if plan.Next.Version != before.Version+1 {
		t.Fatalf("one signature: %d -> %d", before.Version, plan.Next.Version)
	}
	doc, _ := n.Document()
	if _, ok := doc.DeviceByName("nas"); ok {
		t.Fatal("device still listed")
	}
	if len(doc.ExitChains) != 0 {
		t.Fatalf("exit chain left: %+v", doc.ExitChains)
	}
	for _, r := range doc.Rules {
		for _, e := range append(append(append([]string{}, r.From...), r.To...), r.Via...) {
			if e == "nas" {
				t.Fatalf("rule still names nas: %+v", r)
			}
		}
	}
	for _, g := range doc.Groups {
		for _, m := range g.Members {
			if m == "nas" {
				t.Fatalf("group still names nas: %+v", g)
			}
		}
	}
	if users, _ := doc.ExitUsersList(); len(users) != 1 || users[0] != "laptop" {
		t.Fatalf("exit users: %v", users)
	}
	if doc.MagicDNS == nil || len(doc.MagicDNS.Records) != 1 || doc.MagicDNS.Records[0].Name != "baska" {
		t.Fatalf("dns: %+v", doc.MagicDNS)
	}
	if len(doc.Revoked) == 0 || doc.Revoked[len(doc.Revoked)-1].Name != "nas" {
		t.Fatal("not revoked")
	}
}

func TestRetireUnknownDevice(t *testing.T) {
	n := retireNetwork(t)
	if _, err := n.PreviewRetire("yok", testNow); !errors.Is(err, trust.ErrUnknownDevice) {
		t.Fatalf("preview: %v", err)
	}
	if _, err := n.Prepare(testNow, trust.DefaultValidity, RetireChange("yok", testNow)); !errors.Is(err, trust.ErrUnknownDevice) {
		t.Fatalf("change: %v", err)
	}
}
