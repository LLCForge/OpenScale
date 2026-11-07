package magicdns

import (
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/openscale/openscale/internal/trust"
)

func TestPanelName(t *testing.T) {
	doc := zoneDoc()
	name := PanelLabel + "." + doc.DNSDomain + "."
	rcode := func() dnsmessage.Message { return unpack(t, Answer(doc, query(t, name, dnsmessage.TypeA))) }
	if m := rcode(); m.RCode != dnsmessage.RCodeNameError || PanelName(doc) != "" {
		t.Fatalf("panel name without a panel rule: %v %q", m.RCode, PanelName(doc))
	}
	doc.Rules = append(doc.Rules, trust.Rule{From: []string{"*"}, To: []string{"masaustu"}, Service: trust.ServicePanel})
	m := rcode()
	if m.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 1 {
		t.Fatalf("%v %+v", m.RCode, m.Answers)
	}
	if a := netip.AddrFrom4(m.Answers[0].Body.(*dnsmessage.AResource).A); a != netip.MustParseAddr("100.80.0.3") {
		t.Fatalf("answered %s", a)
	}
	if PanelName(doc) != "yonetim."+doc.DNSDomain {
		t.Fatalf("PanelName %q", PanelName(doc))
	}
	// A record or device with the label makes the name ambiguous: neither
	// MagicDNS nor the panel uses it.
	doc.MagicDNS.Records = append(doc.MagicDNS.Records, trust.DNSRecord{Name: PanelLabel, Type: trust.RecordA, Value: "192.168.1.66"})
	if PanelHosts(doc) != nil {
		t.Fatal("record did not disable the panel name")
	}
	m = rcode()
	if len(m.Answers) != 1 || netip.AddrFrom4(m.Answers[0].Body.(*dnsmessage.AResource).A) != netip.MustParseAddr("192.168.1.66") {
		t.Fatalf("record must win: %+v", m.Answers)
	}
	doc.MagicDNS.Records = doc.MagicDNS.Records[:len(doc.MagicDNS.Records)-1]
	doc.Devices = append(doc.Devices, trust.Device{Name: PanelLabel, IPv4: netip.MustParseAddr("100.80.0.7")})
	if PanelHosts(doc) != nil {
		t.Fatal("device name did not disable the panel name")
	}
	if PanelHosts(nil) != nil {
		t.Fatal("nil doc")
	}
}
