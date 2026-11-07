package osnet

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/openscale/openscale/internal/dnsguard"
)

// "openscale up" keeps a local resolver on loopback reachable (the
// systemd-resolved stub on Linux): the native rules must accept it before the
// rule that drops DNS outside the tunnel. Fakes only; nothing reaches the host.
func TestDNSEnforceLoopbackRulesComeBeforeDrop(t *testing.T) {
	rulesFor := func(iface string) []dnsguard.Rule {
		rules, err := dnsguard.EnforceRules(dnsguard.EnforceConfig{
			Tunnel:        iface,
			Resolvers:     []netip.Addr{netip.MustParseAddr("100.64.0.7")},
			AllowLoopback: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		return rules
	}
	nft, err := nftDNSEnforceScript(rulesFor("openscale0"))
	if err != nil {
		t.Fatal(err)
	}
	pf, err := pfDNSEnforceRules(rulesFor("utun5"))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, text, allow, drop string
	}{
		{"nft", nft, `ip daddr 127.0.0.0/8 udp dport 53 accept`, `oifname != "openscale0" udp dport 53 drop`},
		{"nft", nft, `ip6 daddr ::1/128 tcp dport 53 accept`, `oifname != "openscale0" tcp dport 53 drop`},
		{"pf", pf, `pass out quick inet proto udp from any to 127.0.0.0/8 port 53`, `block drop out quick on ! utun5 proto udp from any to any port 53`},
		{"pf", pf, `pass out quick inet6 proto tcp from any to ::1/128 port 53`, `block drop out quick on ! utun5 proto tcp from any to any port 53`},
	} {
		a, d := strings.Index(c.text, c.allow), strings.Index(c.text, c.drop)
		if a < 0 || d < 0 || a > d {
			t.Errorf("%s: izin %q (%d), düşürme %q (%d)\n%s", c.name, c.allow, a, c.drop, d, c.text)
		}
	}
}
