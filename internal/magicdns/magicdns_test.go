package magicdns

import (
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/openscale/openscale/internal/trust"
)

func testDoc() *trust.Document {
	return &trust.Document{
		DNSDomain:  "openscale.internal",
		IPv4Prefix: netip.MustParsePrefix("100.80.0.0/16"),
		IPv6Prefix: netip.MustParsePrefix("fd00::/48"),
		Devices: []trust.Device{
			{Name: "laptop", IPv4: netip.MustParseAddr("100.80.0.2"), IPv6: netip.MustParseAddr("fd00::2")},
		},
		Coordinator: &trust.Coordinator{IPv4: netip.MustParseAddr("100.80.0.1"), IPv6: netip.MustParseAddr("fd00::1")},
	}
}

func query(t *testing.T, name string, typ dnsmessage.Type) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 4242, RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatal(err)
	}
	out, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func parse(t *testing.T, data []byte) (dnsmessage.Header, []dnsmessage.Resource) {
	t.Helper()
	var m dnsmessage.Message
	if err := m.Unpack(data); err != nil {
		t.Fatalf("unpack: %v", err)
	}
	return m.Header, m.Answers
}

func TestAnswer(t *testing.T) {
	doc := testDoc()
	h, ans := parse(t, Answer(doc, query(t, "LapTop.openscale.internal.", dnsmessage.TypeA)))
	if h.ID != 4242 || !h.Response || h.RCode != dnsmessage.RCodeSuccess || len(ans) != 1 {
		t.Fatalf("A answer %+v %v", h, ans)
	}
	if a := ans[0].Body.(*dnsmessage.AResource).A; netip.AddrFrom4(a).String() != "100.80.0.2" {
		t.Fatalf("A = %v", a)
	}
	_, ans = parse(t, Answer(doc, query(t, "laptop.openscale.internal.", dnsmessage.TypeAAAA)))
	if len(ans) != 1 || netip.AddrFrom16(ans[0].Body.(*dnsmessage.AAAAResource).AAAA).String() != "fd00::2" {
		t.Fatalf("AAAA %v", ans)
	}
	_, ans = parse(t, Answer(doc, query(t, "coordinator.openscale.internal.", dnsmessage.TypeA)))
	if len(ans) != 1 {
		t.Fatal("coordinator name not answered")
	}
	// Existing name, other type: NOERROR with no data.
	h, ans = parse(t, Answer(doc, query(t, "laptop.openscale.internal.", dnsmessage.TypeMX)))
	if h.RCode != dnsmessage.RCodeSuccess || len(ans) != 0 {
		t.Fatalf("MX %+v %v", h, ans)
	}
	h, _ = parse(t, Answer(doc, query(t, "yok.openscale.internal.", dnsmessage.TypeA)))
	if h.RCode != dnsmessage.RCodeNameError {
		t.Fatalf("unknown name rcode %v", h.RCode)
	}
	h, _ = parse(t, Answer(doc, query(t, "a.laptop.openscale.internal.", dnsmessage.TypeA)))
	if h.RCode != dnsmessage.RCodeNameError {
		t.Fatalf("subdomain rcode %v", h.RCode)
	}
	h, _ = parse(t, Answer(doc, query(t, "example.com.", dnsmessage.TypeA)))
	if h.RCode != dnsmessage.RCodeRefused {
		t.Fatalf("foreign name rcode %v", h.RCode)
	}
}

func TestAnswerDropsGarbage(t *testing.T) {
	doc := testDoc()
	if Answer(doc, []byte{1, 2, 3}) != nil {
		t.Fatal("garbage answered")
	}
	resp := Answer(doc, query(t, "laptop.openscale.internal.", dnsmessage.TypeA))
	if Answer(doc, resp) != nil {
		t.Fatal("response packet answered")
	}
	if Answer(nil, query(t, "laptop.openscale.internal.", dnsmessage.TypeA)) != nil {
		t.Fatal("answered without a document")
	}
}

func ptrTarget(t *testing.T, data []byte) (dnsmessage.Header, string) {
	t.Helper()
	h, ans := parse(t, data)
	if len(ans) == 0 {
		return h, ""
	}
	if len(ans) != 1 {
		t.Fatalf("PTR answers %v", ans)
	}
	return h, ans[0].Body.(*dnsmessage.PTRResource).PTR.String()
}

func TestAnswerPTR(t *testing.T) {
	doc := testDoc()
	h, got := ptrTarget(t, Answer(doc, query(t, "2.0.80.100.in-addr.arpa.", dnsmessage.TypePTR)))
	if h.RCode != dnsmessage.RCodeSuccess || !h.Authoritative || got != "laptop.openscale.internal." {
		t.Fatalf("IPv4 PTR %+v %q", h, got)
	}
	v6 := "2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.D.F.ip6.arpa."
	if _, got := ptrTarget(t, Answer(doc, query(t, v6, dnsmessage.TypePTR))); got != "laptop.openscale.internal." {
		t.Fatalf("IPv6 PTR %q", got)
	}
	if _, got := ptrTarget(t, Answer(doc, query(t, "1.0.80.100.in-addr.arpa.", dnsmessage.TypePTR))); got != "coordinator.openscale.internal." {
		t.Fatalf("coordinator PTR %q", got)
	}
	// In the network but unused: the address has no name.
	if h, _ := ptrTarget(t, Answer(doc, query(t, "9.0.80.100.in-addr.arpa.", dnsmessage.TypePTR))); h.RCode != dnsmessage.RCodeNameError {
		t.Fatalf("unused address rcode %v", h.RCode)
	}
	// Existing reverse name, other type: NOERROR with no data.
	if h, got := ptrTarget(t, Answer(doc, query(t, "2.0.80.100.in-addr.arpa.", dnsmessage.TypeA))); h.RCode != dnsmessage.RCodeSuccess || got != "" {
		t.Fatalf("A on reverse name %+v %q", h, got)
	}
	// Outside the network, partial and malformed names stay someone
	// else's, as before.
	for _, name := range []string{
		"8.8.8.8.in-addr.arpa.", "80.100.in-addr.arpa.", "02.0.80.100.in-addr.arpa.", "256.0.80.100.in-addr.arpa.",
		"2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.2.ip6.arpa.",
		"0.0.d.f.ip6.arpa.", "x.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa.",
	} {
		if h, _ := parse(t, Answer(doc, query(t, name, dnsmessage.TypePTR))); h.RCode != dnsmessage.RCodeRefused {
			t.Errorf("%s rcode %v", name, h.RCode)
		}
	}
}

func TestHandles(t *testing.T) {
	doc := testDoc()
	for name, want := range map[string]bool{
		"laptop.openscale.internal.": true,
		"openscale.internal.":        true,
		"2.0.80.100.in-addr.arpa.":   true,
		"8.8.8.8.in-addr.arpa.":      false,
		"example.com.":               false,
	} {
		if got := Handles(doc, query(t, name, dnsmessage.TypeA)); got != want {
			t.Errorf("Handles(%s) = %v", name, got)
		}
	}
	if Handles(doc, []byte{1, 2, 3}) || Handles(nil, query(t, "laptop.openscale.internal.", dnsmessage.TypeA)) {
		t.Fatal("garbage handled")
	}
}

func queryEDNS(t *testing.T, name string, size int) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 7, RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatal(err)
	}
	if err := b.StartAdditionals(); err != nil {
		t.Fatal(err)
	}
	var h dnsmessage.ResourceHeader
	if err := h.SetEDNS0(size, dnsmessage.RCodeSuccess, false); err != nil {
		t.Fatal(err)
	}
	if err := b.OPTResource(h, dnsmessage.OPTResource{}); err != nil {
		t.Fatal(err)
	}
	out, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestUDPLimitAndTruncation(t *testing.T) {
	if got := UDPLimit(query(t, "a.example.", dnsmessage.TypeA)); got != 512 {
		t.Fatalf("limit without EDNS %d", got)
	}
	for size, want := range map[int]int{1232: 1232, 100: 512, 65000: 4096} {
		if got := UDPLimit(queryEDNS(t, "a.example.", size)); got != want {
			t.Errorf("EDNS %d: limit %d, want %d", size, got, want)
		}
	}
	if UDPLimit([]byte{1}) != 512 {
		t.Fatal("garbage limit")
	}

	doc := testDoc()
	q := query(t, "laptop.openscale.internal.", dnsmessage.TypeALL)
	full := answer(doc, q, 512)
	cut := answer(doc, q, len(full)-1)
	h, ans := parse(t, cut)
	if !h.Truncated || len(ans) != 0 || h.ID != 4242 || len(cut) >= len(full) {
		t.Fatalf("truncated answer %+v %v", h, ans)
	}
	var m dnsmessage.Message
	if err := m.Unpack(cut); err != nil || len(m.Questions) != 1 || m.Questions[0].Name.String() != "laptop.openscale.internal." {
		t.Fatalf("question lost: %v %+v", err, m.Questions)
	}
	if h, _ := parse(t, full); h.Truncated {
		t.Fatal("answer within the limit truncated")
	}
	if Truncate([]byte{1, 2}) != nil {
		t.Fatal("garbage truncated")
	}
}

// seedPTR is a PTR query for 100.80.0.2.
var seedPTR = []byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0,
	1, '2', 1, '0', 2, '8', '0', 3, '1', '0', '0', 7, 'i', 'n', '-', 'a', 'd', 'd', 'r', 4, 'a', 'r', 'p', 'a', 0,
	0, 12, 0, 1}

func FuzzAnswer(f *testing.F) {
	f.Add([]byte{0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	f.Add(seedPTR)
	doc := testDoc()
	f.Fuzz(func(t *testing.T, data []byte) {
		out := Answer(doc, data)
		if len(out) > UDPLimit(data) || len(out) > 512 {
			t.Fatalf("answer too large: %d", len(out))
		}
		if out != nil && Handles(doc, data) {
			var m dnsmessage.Message
			if err := m.Unpack(out); err != nil || m.RCode == dnsmessage.RCodeRefused {
				t.Fatalf("handled query answered badly: %v %v", err, m.RCode)
			}
		}
		if tr := Truncate(data); tr != nil && len(tr) > len(data)+12 {
			t.Fatalf("truncation grew the message: %d > %d", len(tr), len(data))
		}
	})
}
