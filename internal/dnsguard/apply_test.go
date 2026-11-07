package dnsguard

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

type fakeApplier struct {
	applied [][]Rule
	removed int
	fail    error
}

func (f *fakeApplier) Apply(r []Rule) error {
	if f.fail != nil {
		return f.fail
	}
	f.applied = append(f.applied, r)
	return nil
}

func (f *fakeApplier) Remove() error { f.removed++; return nil }

func enforceCfg(t *testing.T) EnforceConfig {
	doh, err := ParseDoHList(strings.NewReader("9.9.9.9\n"))
	if err != nil {
		t.Fatal(err)
	}
	return EnforceConfig{Tunnel: "openscale0", Resolvers: []netip.Addr{netip.MustParseAddr("100.64.0.1")}, AllowLoopback: true, DoH: doh}
}

func TestRenderNFT(t *testing.T) {
	rules, err := EnforceRules(enforceCfg(t))
	if err != nil {
		t.Fatal(err)
	}
	s, err := RenderNFT(rules)
	if err != nil {
		t.Fatal(err)
	}
	allow := `oifname "openscale0" ip daddr 100.64.0.1/32 udp dport 53 accept`
	drop := `oifname != "openscale0" udp dport 53 drop`
	for _, want := range []string{"delete table inet openscale_dns", allow, drop, `ip daddr 9.9.9.9/32 tcp dport 443 drop`, `ip daddr 127.0.0.0/8 udp dport 53 accept`} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in\n%s", want, s)
		}
	}
	if strings.Index(s, allow) > strings.Index(s, drop) {
		t.Fatal("rule order lost")
	}
	if _, err := RenderNFT([]Rule{{Action: ActionDrop, Proto: ProtoUDP, Port: 53, Interface: "x\"; flush ruleset; \""}}); err == nil {
		t.Fatal("injected interface accepted")
	}
	if _, err := RenderNFT([]Rule{{Action: "reject", Proto: ProtoUDP}}); err == nil {
		t.Fatal("unknown action accepted")
	}
	if c := nftComment("a\"b\\c\nd"); c != "abcd" {
		t.Fatalf("comment %q", c)
	}
}

func TestRenderWFP(t *testing.T) {
	rules, _ := EnforceRules(enforceCfg(t))
	fs, err := RenderWFP(rules)
	if err != nil || len(fs) != len(rules) {
		t.Fatalf("%v %d", err, len(fs))
	}
	for i := 1; i < len(fs); i++ {
		if fs[i].Weight >= fs[i-1].Weight {
			t.Fatal("weights must fall with rule order")
		}
	}
	var sawDrop bool
	for _, f := range fs {
		if !f.Permit && f.NotInterface && f.Interface == "openscale0" && f.RemotePort == 53 {
			sawDrop = true
		}
	}
	if !sawDrop {
		t.Fatalf("outside DNS drop missing: %+v", fs)
	}
}

func TestEnforcerFollowsTunnel(t *testing.T) {
	f := &fakeApplier{}
	e := &Enforcer{Applier: f}
	cfg := enforceCfg(t)
	if err := e.Sync(true, false, cfg); err != nil || len(f.applied) != 0 || e.Installed() {
		t.Fatal("rules installed while the tunnel is down")
	}
	if err := e.Sync(true, true, cfg); err != nil || len(f.applied) != 1 || !e.Installed() {
		t.Fatalf("not installed: %v", err)
	}
	if err := e.Sync(true, true, cfg); err != nil || len(f.applied) != 1 {
		t.Fatal("unchanged rules re-applied")
	}
	cfg.Resolvers = append(cfg.Resolvers, netip.MustParseAddr("100.64.0.2"))
	if err := e.Sync(true, true, cfg); err != nil || len(f.applied) != 2 {
		t.Fatal("changed rules not applied")
	}
	if err := e.Sync(true, false, cfg); err != nil || f.removed != 1 || e.Installed() {
		t.Fatal("rules kept after the tunnel went down")
	}
	if err := e.Sync(false, false, cfg); err != nil || f.removed != 1 {
		t.Fatal("removed twice")
	}
	f.fail = errors.New("nft yok")
	if err := e.Sync(true, true, cfg); err == nil || e.Installed() {
		t.Fatal("failed apply reported as installed")
	}
}
