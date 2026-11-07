package magicdns

import (
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestShortNames(t *testing.T) {
	t.Cleanup(func() { SetShortNames(nil) })
	doc := zoneDoc()
	ask := func(label string) dnsmessage.Message {
		return unpack(t, Answer(doc, query(t, label+"."+doc.DNSDomain+".", dnsmessage.TypeA)))
	}
	if m := ask("medya"); m.RCode != dnsmessage.RCodeNameError {
		t.Fatalf("unset short name answered: %v", m.RCode)
	}
	SetShortNames(map[string]string{"Medya": "masaustu", "hayalet": "yok", "yazici": "masaustu"})
	m := ask("medya")
	if m.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 1 {
		t.Fatalf("short name: %v %+v", m.RCode, m.Answers)
	}
	dev, _ := doc.DeviceByName("masaustu")
	want := dev.IPv4
	if a := netip.AddrFrom4(m.Answers[0].Body.(*dnsmessage.AResource).A); a != want {
		t.Fatalf("answered %s, want %s", a, want)
	}
	// A device that is not in the signed document gives nothing.
	if m := ask("hayalet"); m.RCode != dnsmessage.RCodeNameError {
		t.Fatalf("short name of a missing device: %v", m.RCode)
	}
	// A signed record with the same label wins.
	if m := ask("yazici"); len(m.Answers) != 1 || netip.AddrFrom4(m.Answers[0].Body.(*dnsmessage.AResource).A) != netip.MustParseAddr("192.168.1.20") {
		t.Fatalf("record must win: %+v", m.Answers)
	}
	if got := ShortNames(); got["medya"] != "masaustu" {
		t.Fatalf("table %v", got)
	}
	SetShortNames(nil)
	if m := ask("medya"); m.RCode != dnsmessage.RCodeNameError {
		t.Fatal("short names not turned off")
	}
}
