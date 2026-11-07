package netreport

import (
	"encoding/base64"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/trust"
)

func sampleDoc() *trust.Document {
	key := func(b byte) trust.Key {
		var k trust.Key
		for i := range k {
			k[i] = b
		}
		return k
	}
	exitUsers := []string{"laptop", "group:aile"}
	return &trust.Document{
		NetworkID:   "net1",
		Version:     7,
		IssuedAt:    time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC),
		ExpiresAt:   time.Date(2027, 10, 1, 0, 0, 0, 0, time.UTC),
		DNSDomain:   "ev.internal",
		DisplayName: "Ev",
		IPv4Prefix:  netip.MustParsePrefix("100.80.0.0/16"),
		Coordinator: &trust.Coordinator{Endpoint: "vpn.example.com:41641", WireGuardKey: key(9)},
		Devices: []trust.Device{
			{ID: "d2", Name: "nas", SigningKey: key(1), WireGuardKey: key(2), IPv4: netip.MustParseAddr("100.80.0.2"), Roles: []trust.Role{trust.RoleExitNode}, Tags: []string{"sunucu"}, ExpiresAt: time.Date(2027, 1, 2, 0, 0, 0, 0, time.UTC)},
			{ID: "d1", Name: "laptop", SigningKey: key(3), WireGuardKey: key(4), IPv4: netip.MustParseAddr("100.80.0.1"), Roles: []trust.Role{trust.RoleAdmin}},
		},
		Groups: []trust.Group{{Name: "aile", Members: []string{"laptop", "tag:telefon"}}},
		Rules: []trust.Rule{
			{From: []string{"group:aile"}, To: []string{"nas"}, Protocol: trust.ProtocolTCP, Ports: []string{"445", "8080"}, Description: "Paylaşım <script>alert(1)</script> | x"},
			{From: []string{"*"}, To: []string{"tag:sunucu"}, Protocol: trust.ProtocolICMP},
			{From: []string{"laptop"}, To: []string{"nas"}, Service: trust.ServiceSSH, Users: []string{"ali"}},
			{From: []string{"tag:misafir"}, To: []string{"*"}, Protocol: trust.ProtocolAny, Action: trust.RuleDeny, Disabled: true},
		},
		ExitUsers: &exitUsers,
		DNS:       &trust.DNSSettings{Nameservers: []netip.Addr{netip.MustParseAddr("192.168.1.1")}},
	}
}

func TestBuildSentences(t *testing.T) {
	r := Build(sampleDoc(), time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC))
	if r.Network != "Ev" || len(r.Devices) != 2 || r.Devices[0].Name != "laptop" {
		t.Fatalf("report: %+v", r)
	}
	if r.Devices[1].Roles != "çıkış düğümü" || r.Devices[1].Expires != "2027-01-02" {
		t.Fatalf("nas row: %+v", r.Devices[1])
	}
	want := []string{
		"'aile' grubu → nas: TCP 445, 8080 portları erişebilir.",
		"Bütün cihazlar → 'sunucu' etiketli cihazlar: ping (ICMP) erişebilir.",
		"laptop → nas: SSH hizmeti (kullanıcılar: ali) erişebilir.",
		"'misafir' etiketli cihazlar → bütün cihazlar: her türlü trafik erişemez. (Devre dışı; uygulanmıyor.)",
	}
	for i, w := range want {
		if !strings.HasPrefix(r.Rules[i].Sentence, strings.TrimSuffix(w, ".")) && r.Rules[i].Sentence != w {
			t.Errorf("rule %d = %q, want %q", i+1, r.Rules[i].Sentence, w)
		}
	}
	if r.Rules[3].Allow || !r.Rules[3].Disabled {
		t.Fatalf("deny rule flags: %+v", r.Rules[3])
	}
	if !strings.Contains(r.ExitUsers, "laptop ve 'aile' grubu") {
		t.Fatalf("exit users: %q", r.ExitUsers)
	}
}

func TestNoKeysAndEscaping(t *testing.T) {
	doc := sampleDoc()
	r := Build(doc, time.Now())
	md := Markdown(r)
	page, err := HTML(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range doc.Devices {
		for _, k := range []trust.Key{d.SigningKey, d.WireGuardKey} {
			enc := base64.StdEncoding.EncodeToString(k[:])
			if strings.Contains(md, enc) || strings.Contains(page, enc) {
				t.Fatal("a key leaked into the report")
			}
		}
	}
	if strings.Contains(page, "<script>") || !strings.Contains(page, "&lt;script&gt;") {
		t.Fatal("HTML not escaped")
	}
	if strings.Contains(md, "<script>") || strings.Contains(md, " | x") {
		t.Fatal("Markdown not escaped")
	}
	if !strings.Contains(page, "default-src 'none'") || strings.Contains(page, "<script") || strings.Contains(page, "http://") || strings.Contains(page, "https://") {
		t.Fatal("HTML page is not self-contained")
	}
	if !strings.Contains(md, "| laptop | 100.80.0.1 | yönetici |") {
		t.Fatalf("device table:\n%s", md)
	}
}

func TestEmptyDocument(t *testing.T) {
	r := Build(&trust.Document{DNSDomain: "x.internal"}, time.Now())
	md := Markdown(r)
	if !strings.Contains(md, "Kural yok") || !strings.Contains(md, "Koordinatör kayıtlı değil") {
		t.Fatalf("empty:\n%s", md)
	}
	if _, err := HTML(r); err != nil {
		t.Fatal(err)
	}
}
