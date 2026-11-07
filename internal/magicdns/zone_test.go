package magicdns

import (
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/openscale/openscale/internal/trust"
)

func zoneDoc() *trust.Document {
	doc := testDoc()
	doc.Devices = append(doc.Devices, trust.Device{
		Name: "masaustu", Aliases: []string{"nas"},
		IPv4: netip.MustParseAddr("100.80.0.3"), IPv6: netip.MustParseAddr("fd00::3"),
	})
	doc.MagicDNS = &trust.MagicDNSSettings{
		DeviceSubdomains: true,
		Records: []trust.DNSRecord{
			{Name: "yazici", Type: trust.RecordA, Value: "192.168.1.20"},
			{Name: "pano", Type: trust.RecordCNAME, Value: "nas.openscale.internal"},
			{Name: "eski", Type: trust.RecordCNAME, Value: "pano.openscale.internal"},
			{Name: "dis", Type: trust.RecordCNAME, Value: "example.com"},
			{Name: "_rdp._tcp.masaustu", Type: trust.RecordSRV, Value: "masaustu.openscale.internal", Priority: 10, Weight: 1, Port: 3389},
			{Name: "*.lab", Type: trust.RecordA, Value: "192.168.2.1"},
			{Name: "bilgi", Type: trust.RecordTXT, Value: "merhaba"},
			{Name: "gizli", Type: trust.RecordA, Value: "100.80.0.9"}, // not a device in this view
		},
	}
	return doc
}

func unpack(t *testing.T, data []byte) dnsmessage.Message {
	t.Helper()
	var m dnsmessage.Message
	if err := m.Unpack(data); err != nil {
		t.Fatalf("unpack: %v", err)
	}
	return m
}

func TestZoneRecords(t *testing.T) {
	doc := zoneDoc()
	a := func(name string) (dnsmessage.RCode, []string) {
		m := unpack(t, Answer(doc, query(t, name, dnsmessage.TypeA)))
		var out []string
		for _, r := range m.Answers {
			switch b := r.Body.(type) {
			case *dnsmessage.AResource:
				out = append(out, netip.AddrFrom4(b.A).String())
			case *dnsmessage.CNAMEResource:
				out = append(out, "cname:"+b.CNAME.String())
			}
		}
		return m.RCode, out
	}
	cases := map[string][]string{
		"nas.openscale.internal.":          {"100.80.0.3"},
		"yazici.openscale.internal.":       {"192.168.1.20"},
		"pano.openscale.internal.":         {"cname:nas.openscale.internal.", "100.80.0.3"},
		"eski.openscale.internal.":         {"cname:pano.openscale.internal.", "cname:nas.openscale.internal.", "100.80.0.3"},
		"dis.openscale.internal.":          {"cname:example.com."},
		"web.masaustu.openscale.internal.": {"100.80.0.3"},
		"a.b.nas.openscale.internal.":      {"100.80.0.3"},
		"x.lab.openscale.internal.":        {"192.168.2.1"},
	}
	for name, want := range cases {
		rc, got := a(name)
		if rc != dnsmessage.RCodeSuccess || len(got) != len(want) {
			t.Errorf("%s: %v %v, want %v", name, rc, got, want)
			continue
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("%s: %v, want %v", name, got, want)
			}
		}
	}
	for _, name := range []string{"yok.openscale.internal.", "lab2.openscale.internal.", "x.yok.openscale.internal."} {
		if rc, _ := a(name); rc != dnsmessage.RCodeNameError {
			t.Errorf("%s: rcode %v, want NXDOMAIN", name, rc)
		}
	}
	// A record pointing at an address outside this view stays silent.
	if rc, got := a("gizli.openscale.internal."); rc != dnsmessage.RCodeSuccess || len(got) != 0 {
		t.Errorf("hidden address answered: %v %v", rc, got)
	}
	// Empty non-terminal: exists without data.
	if rc, got := a("_tcp.masaustu.openscale.internal."); rc != dnsmessage.RCodeSuccess || len(got) != 0 {
		t.Errorf("empty non-terminal: %v %v", rc, got)
	}

	m := unpack(t, Answer(doc, query(t, "_rdp._tcp.masaustu.openscale.internal.", dnsmessage.TypeSRV)))
	if len(m.Answers) != 1 || len(m.Additionals) != 2 {
		t.Fatalf("SRV answer %+v", m)
	}
	srv := m.Answers[0].Body.(*dnsmessage.SRVResource)
	if srv.Port != 3389 || srv.Priority != 10 || srv.Target.String() != "masaustu.openscale.internal." {
		t.Fatalf("SRV = %+v", srv)
	}
	m = unpack(t, Answer(doc, query(t, "bilgi.openscale.internal.", dnsmessage.TypeTXT)))
	if len(m.Answers) != 1 || m.Answers[0].Body.(*dnsmessage.TXTResource).TXT[0] != "merhaba" {
		t.Fatalf("TXT %+v", m.Answers)
	}
	// Subdomains only with the setting.
	doc.MagicDNS.DeviceSubdomains = false
	if rc, _ := a("web.masaustu.openscale.internal."); rc != dnsmessage.RCodeNameError {
		t.Fatalf("subdomain without the setting: %v", rc)
	}
	// Reverse names keep the device name, not the alias.
	if _, target := ptrTarget(t, Answer(doc, query(t, "3.0.80.100.in-addr.arpa.", dnsmessage.TypePTR))); target != "masaustu.openscale.internal." {
		t.Fatalf("PTR = %s", target)
	}
}

func TestAnswerStreamIsNotTruncated(t *testing.T) {
	doc := zoneDoc()
	for i := 0; i < 60; i++ {
		doc.MagicDNS.Records = append(doc.MagicDNS.Records, trust.DNSRecord{Name: "cok", Type: trust.RecordTXT, Value: string(rune('a'+i%26)) + "0123456789012345678901234567890123456789"})
	}
	q := query(t, "cok.openscale.internal.", dnsmessage.TypeTXT)
	if m := unpack(t, Answer(doc, q)); !m.Truncated {
		t.Fatal("large UDP answer not truncated")
	}
	if m := unpack(t, AnswerStream(doc, q)); m.Truncated || len(m.Answers) != 60 {
		t.Fatalf("stream answer truncated=%v answers=%d", m.Truncated, len(m.Answers))
	}
}

func FuzzAnswerZone(f *testing.F) {
	f.Add(seedPTR)
	doc := zoneDoc()
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, out := range [][]byte{Answer(doc, data), AnswerStream(doc, data)} {
			if out == nil {
				continue
			}
			var m dnsmessage.Message
			if err := m.Unpack(out); err != nil {
				t.Fatalf("answer does not parse: %v", err)
			}
		}
		if out := Answer(doc, data); len(out) > 512 && len(out) > UDPLimit(data) {
			t.Fatalf("answer too large: %d", len(out))
		}
	})
}
