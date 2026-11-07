package osnet

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/openscale/openscale/internal/dnsguard"
)

// Every test here uses fakes: no nft, pfctl or WFP call reaches the host.

func dnsTestRules(t *testing.T, iface string) []dnsguard.Rule {
	t.Helper()
	rules, err := dnsguard.EnforceRules(dnsguard.EnforceConfig{
		Tunnel:    iface,
		Resolvers: []netip.Addr{netip.MustParseAddr("100.64.0.7")},
		DoH:       dnsguard.DoHList{Prefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.53/32"), netip.MustParsePrefix("2001:db8::53/128")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return rules
}

type fakeCmd struct {
	calls  []string
	stdin  []string
	answer func(call string) ([]byte, error)
}

func (f *fakeCmd) run(_ context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	call := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, call)
	f.stdin = append(f.stdin, string(stdin))
	if f.answer != nil {
		return f.answer(call)
	}
	return nil, nil
}

func TestNFTDNSEnforceScript(t *testing.T) {
	script, err := nftDNSEnforceScript(dnsTestRules(t, "openscale0"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"table inet openscale_dns\ndelete table inet openscale_dns\n",
		"policy accept;\n\t\tmeta mark 0x4f53 accept comment \"OpenScale\"\n",
		`oifname "openscale0" ip daddr 100.64.0.7/32 udp dport 53 accept`,
		`oifname != "openscale0" udp dport 53 drop`,
		`oifname != "openscale0" tcp dport 853 drop`,
		`ip daddr 192.0.2.53/32 tcp dport 443 drop`,
		`ip6 daddr 2001:db8::53/128 udp dport 443 drop`,
	} {
		if !strings.Contains(script, want) {
			t.Errorf("betikte yok: %q\n%s", want, script)
		}
	}
	// The mark exception comes before every rule.
	if strings.Index(script, "meta mark") > strings.Index(script, "dport") {
		t.Error("program istisnası kurallardan sonra")
	}
	if _, err := nftDNSEnforceScript(dnsTestRules(t, "cok-uzun-arayuz-adi-x")); err == nil {
		t.Error("15 bayttan uzun arayüz adı kabul edildi")
	}
}

func TestNFTDNSEnforcerCalls(t *testing.T) {
	f := &fakeCmd{}
	n := &nftDNSEnforcer{run: f.run, has: func(string) bool { return true }}
	if err := n.Apply(dnsTestRules(t, "openscale0")); err != nil {
		t.Fatal(err)
	}
	if err := n.Remove(); err != nil {
		t.Fatal(err)
	}
	want := []string{"nft -f -", "nft delete table inet openscale_dns"}
	if fmt.Sprint(f.calls) != fmt.Sprint(want) {
		t.Fatalf("çağrılar %q, beklenen %q", f.calls, want)
	}
	if !strings.Contains(f.stdin[0], "table inet openscale_dns {") {
		t.Fatal("nft -f betiği almadı")
	}
	// Removing what is not there is not an error; other failures are.
	f.answer = func(string) ([]byte, error) {
		return nil, errors.New("Error: No such file or directory; did you mean table 'openscale_killswitch'")
	}
	if err := n.Remove(); err != nil {
		t.Fatalf("olmayan tablo: %v", err)
	}
	f.answer = func(string) ([]byte, error) { return nil, errors.New("Operation not permitted") }
	if err := n.Remove(); err == nil {
		t.Fatal("izin hatası yutuldu")
	}
	// Without nft nothing is run.
	f.calls = nil
	n.has = func(string) bool { return false }
	if err := n.Apply(dnsTestRules(t, "openscale0")); err == nil {
		t.Fatal("nft yokken uygulandı")
	}
	if err := n.Remove(); err != nil || len(f.calls) != 0 {
		t.Fatalf("nft yokken: %v %q", err, f.calls)
	}
}

func TestPFDNSEnforceRules(t *testing.T) {
	text, err := pfDNSEnforceRules(dnsTestRules(t, "utun5"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"pass out quick on utun5 inet proto udp from any to 100.64.0.7/32 port 53\n",
		"block drop out quick on ! utun5 proto tcp from any to any port 853\n",
		"block drop out quick inet proto tcp from any to 192.0.2.53/32 port 443\n",
		"block drop out quick inet6 proto udp from any to 2001:db8::53/128 port 443\n",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("kurallarda yok: %q\n%s", want, text)
		}
	}
	if _, err := pfDNSEnforceRules([]dnsguard.Rule{{Action: "reject", Proto: dnsguard.ProtoUDP, Port: 53}}); err == nil {
		t.Error("bilinmeyen eylem kabul edildi")
	}
}

func TestPFKillSwitchCallsDNSAnchor(t *testing.T) {
	rules, err := pfKillSwitchRules(KillSwitchConfig{Interface: "utun5"})
	if err != nil {
		t.Fatal(err)
	}
	a, tun := strings.Index(rules, `anchor "dns"`), strings.Index(rules, "pass quick on utun5 all")
	if a < 0 || tun < 0 || a > tun {
		t.Fatalf("DNS alt çapası tünel izninden önce çağrılmalı:\n%s", rules)
	}
}

func TestPFDNSEnforcerActivity(t *testing.T) {
	f := &fakeCmd{answer: func(call string) ([]byte, error) {
		switch call {
		case darwinPfctl + " -a com.openscale -s rules":
			return []byte("pass quick on lo0 all\nanchor \"dns\" all\n"), nil
		case darwinPfctl + " -s rules":
			return []byte("anchor \"com.openscale\" all\n"), nil
		}
		return nil, nil
	}}
	p := &pfDNSEnforcer{run: f.run, exists: func(string) bool { return true }}
	if err := p.Apply(dnsTestRules(t, "utun5")); err != nil {
		t.Fatal(err)
	}
	if f.calls[0] != darwinPfctl+" -a com.openscale/dns -f -" || !strings.Contains(f.stdin[0], "port 853") {
		t.Fatalf("ilk çağrı %q", f.calls[0])
	}
	// Kill switch off: the main ruleset does not call the anchor.
	f.answer = func(call string) ([]byte, error) {
		if strings.HasSuffix(call, "-a com.openscale -s rules") {
			return nil, errors.New("pfctl: Anchor does not exist.")
		}
		return []byte("scrub-anchor \"com.apple/*\" all\n"), nil
	}
	if err := p.Apply(dnsTestRules(t, "utun5")); !errors.Is(err, ErrDNSEnforceInactive) {
		t.Fatalf("etkisiz kurallar başarı sayıldı: %v", err)
	}
	f.calls = nil
	f.answer = nil
	if err := p.Remove(); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(f.calls) != fmt.Sprint([]string{darwinPfctl + " -a com.openscale/dns -F rules"}) {
		t.Fatalf("geri alma çağrıları %q", f.calls)
	}
}

func TestDNSWFPPlan(t *testing.T) {
	rules := dnsTestRules(t, "OpenScale")
	plan, err := dnsWFPPlan(rules)
	if err != nil {
		t.Fatal(err)
	}
	if !plan[0].App || !plan[0].Permit || !plan[1].App || !plan[1].IPv6 {
		t.Fatal("ilk iki kural program izni olmalı")
	}
	var v4, v6, notTunnel int
	for i, f := range plan {
		if i > 1 && f.Weight > plan[i-1].Weight {
			t.Fatalf("ağırlık sırası bozuk: %d", i)
		}
		if f.IPv6 {
			v6++
		} else {
			v4++
		}
		if f.Iface == wfpIfaceNotEqual {
			notTunnel++
			if f.Permit || f.Prefix.IsValid() {
				t.Fatalf("tünel dışı DNS kuralı yanlış: %+v", f)
			}
		}
		if f.Prefix.IsValid() && f.Prefix.Addr().Is6() != f.IPv6 {
			t.Fatalf("katman ailesi yanlış: %+v", f)
		}
	}
	// 4 resolver permits (v4), 4 "outside the tunnel" drops on both
	// families, 2 + 2 DoH drops, 2 program permits.
	if notTunnel != 8 || len(plan) != 2+4+8+4 || v4 == 0 || v6 == 0 {
		t.Fatalf("plan boyutu: toplam %d, tünel dışı %d", len(plan), notTunnel)
	}
	// The first matching rule of Evaluate keeps the highest weight.
	if plan[2].Weight <= plan[len(plan)-1].Weight {
		t.Fatal("ilk kural en yüksek ağırlıkta değil")
	}
}

type fakeWFP struct {
	calls  []string
	next   uint64
	failAt string
}

func (f *fakeWFP) do(c string) error {
	f.calls = append(f.calls, c)
	if c == f.failAt {
		return errors.New("WFP hatası")
	}
	return nil
}

func (f *fakeWFP) open() error        { return f.do("open") }
func (f *fakeWFP) close() error       { return f.do("close") }
func (f *fakeWFP) begin() error       { return f.do("begin") }
func (f *fakeWFP) commit() error      { return f.do("commit") }
func (f *fakeWFP) abort() error       { return f.do("abort") }
func (f *fakeWFP) addSublayer() error { return f.do("sublayer") }
func (f *fakeWFP) addFilter(d dnsWFPFilter, luid uint64) (uint64, error) {
	if d.Iface != wfpIfaceAny && luid != 77 {
		return 0, errors.New("yanlış LUID")
	}
	if err := f.do("add"); err != nil {
		return 0, err
	}
	f.next++
	return f.next, nil
}
func (f *fakeWFP) deleteFilter(id uint64) error { return f.do(fmt.Sprintf("del%d", id)) }

func compact(calls []string) string {
	var out []string
	for i := 0; i < len(calls); {
		j := i
		for j < len(calls) && calls[j] == calls[i] {
			j++
		}
		if j-i > 1 {
			out = append(out, fmt.Sprintf("%s*%d", calls[i], j-i))
		} else {
			out = append(out, calls[i])
		}
		i = j
	}
	return strings.Join(out, " ")
}

func TestWFPDNSEnforcerSequence(t *testing.T) {
	f := &fakeWFP{}
	w := &wfpDNSEnforcer{ops: f, luidOf: func(name string) (uint64, error) {
		if name != "OpenScale" {
			return 0, errors.New("tünel arayüzü bulunamadı")
		}
		return 77, nil
	}}
	rules := dnsTestRules(t, "OpenScale")
	if err := w.Apply(rules); err != nil {
		t.Fatal(err)
	}
	if got := compact(f.calls); got != "open begin sublayer add*18 commit" {
		t.Fatalf("ilk uygulama: %s", got)
	}
	// A new rule set replaces the old one in the same session.
	f.calls = nil
	if err := w.Apply(rules[:4]); err != nil {
		t.Fatal(err)
	}
	if got := f.calls; got[0] != "begin" || got[1] != "del1" || got[18] != "del18" || got[len(got)-1] != "commit" || compact(got[19:len(got)-1]) != "add*6" {
		t.Fatalf("yenileme: %s", compact(got))
	}
	// A failed replacement keeps the previous filters and the session.
	f.calls, f.failAt = nil, "commit"
	if err := w.Apply(rules); err == nil {
		t.Fatal("hata yutuldu")
	}
	if got := f.calls[len(f.calls)-1]; got != "abort" || !w.opened || len(w.ids) != 6 {
		t.Fatalf("başarısız yenilemeden sonra: %s, açık=%v, %d kural", compact(f.calls), w.opened, len(w.ids))
	}
	// Remove closes the dynamic session: WFP drops every filter.
	f.calls, f.failAt = nil, ""
	if err := w.Remove(); err != nil {
		t.Fatal(err)
	}
	if err := w.Remove(); err != nil {
		t.Fatal(err)
	}
	if got := compact(f.calls); got != "close" {
		t.Fatalf("geri alma: %s", got)
	}
	// No tunnel interface: nothing is opened.
	f.calls = nil
	if err := w.Apply(dnsTestRules(t, "Yok")); err == nil || len(f.calls) != 0 {
		t.Fatalf("tünel yokken: %v %q", err, f.calls)
	}
	// A failure on a fresh session closes it again.
	f.failAt = "add"
	if err := w.Apply(rules); err == nil {
		t.Fatal("hata yutuldu")
	}
	if got := compact(f.calls); got != "open begin sublayer add abort close" || w.opened {
		t.Fatalf("ilk uygulama hatası: %s", got)
	}
}
