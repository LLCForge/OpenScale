package magicdns

import (
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/openscale/openscale/internal/trust"
)

func TestServiceNames(t *testing.T) {
	doc := zoneDoc()
	doc.MagicDNS.DeviceSubdomains = false
	rcode := func(name string) dnsmessage.RCode {
		return unpack(t, Answer(doc, query(t, name, dnsmessage.TypeA))).RCode
	}
	if rc := rcode("grafana.masaustu.openscale.internal."); rc != dnsmessage.RCodeNameError {
		t.Fatalf("service name without a serve rule: %v", rc)
	}
	doc.Rules = append(doc.Rules, trust.Rule{From: []string{"*"}, To: []string{"masaustu"}, Service: trust.ServiceServe})
	for _, name := range []string{"grafana.masaustu.openscale.internal.", "grafana.nas.openscale.internal."} {
		m := unpack(t, Answer(doc, query(t, name, dnsmessage.TypeA)))
		if m.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 1 {
			t.Fatalf("%s: %v %+v", name, m.RCode, m.Answers)
		}
	}
	// Only one label below the device, and only valid labels.
	for _, name := range []string{"a.b.masaustu.openscale.internal.", "x_y.masaustu.openscale.internal."} {
		if rc := rcode(name); rc != dnsmessage.RCodeNameError {
			t.Fatalf("%s: %v", name, rc)
		}
	}
	// A disabled serve rule does not count.
	doc.Rules[len(doc.Rules)-1].Disabled = true
	if rc := rcode("grafana.masaustu.openscale.internal."); rc != dnsmessage.RCodeNameError {
		t.Fatalf("disabled rule: %v", rc)
	}
}
