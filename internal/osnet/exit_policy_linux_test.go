//go:build linux

package osnet

import (
	"context"
	"net/netip"
	"strings"
	"testing"
)

// Without any policy the nft script is exactly the one before P04.
func TestExitPolicyAbsentKeepsScript(t *testing.T) {
	script, err := nftExitScript(testExitNAT)
	if err != nil {
		t.Fatal(err)
	}
	s := string(script)
	for _, bad := range []string{"quota", "dport", "snat", "os-up0", "443"} {
		if strings.Contains(s, bad) {
			t.Fatalf("policy rule %q without a policy:\n%s", bad, s)
		}
	}
	if !strings.Contains(s, "type nat hook postrouting priority srcnat; policy accept;\n\t\toifname != \"OpenScale\" ip saddr 100.80.0.0/16 masquerade") {
		t.Fatalf("postrouting changed:\n%s", s)
	}
	if !strings.Contains(s, "table inet openscale_exit {\n\tchain forward {") {
		t.Fatalf("table head changed:\n%s", s)
	}
}

func policyNAT() ExitNAT {
	c := testExitNAT
	c.BlockPorts = []ExitPort{{"tcp", 25}, {"tcp", 465}, {"udp", 1900}}
	c.BlockDoH = []netip.Prefix{netip.MustParsePrefix("1.1.1.1/32"), netip.MustParsePrefix("2606:4700::/32")}
	c.Sources = []ExitSource{
		{Source: netip.MustParseAddr("203.0.113.5")},
		{Member: netip.MustParseAddr("100.80.0.7"), Source: netip.MustParseAddr("203.0.113.6")},
	}
	c.Quota = true
	return c
}

func TestExitPolicyNFT(t *testing.T) {
	script, err := nftExitScript(policyNAT())
	if err != nil {
		t.Fatal(err)
	}
	s := string(script)
	for _, want := range []string{
		"set quota4 { type ipv4_addr; }",
		`iifname "OpenScale" ip saddr @quota4 drop`,
		`oifname "OpenScale" ip6 daddr @quota6 drop`,
		`iifname "OpenScale" tcp dport { 25, 465 } drop`,
		`iifname "OpenScale" udp dport { 1900 } drop`,
		`iifname "OpenScale" ip daddr { 1.1.1.1/32 } meta l4proto { tcp, udp } th dport 443 drop`,
		`iifname "OpenScale" ip6 daddr { 2606:4700::/32 } meta l4proto { tcp, udp } th dport 443 drop`,
		`oifname "os-up0" ip saddr 100.80.0.0/16 masquerade`,
		`oifname != "OpenScale" ip saddr 100.80.0.7 snat ip to 203.0.113.6`,
		`oifname != "OpenScale" ip saddr 100.80.0.0/16 snat ip to 203.0.113.5`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in:\n%s", want, s)
		}
	}
	// Member source before the default, both before the plain masquerade.
	member := strings.Index(s, "snat ip to 203.0.113.6")
	def := strings.Index(s, "snat ip to 203.0.113.5")
	masq := strings.Index(s, `oifname != "OpenScale" ip saddr 100.80.0.0/16 masquerade`)
	if !(member < def && def < masq) {
		t.Fatalf("nat order wrong:\n%s", s)
	}
	if strings.Contains(s, "ip6 saddr fd7a:1:2::/48 snat") || strings.Contains(s, `oifname "os-up0" ip6`) {
		t.Fatalf("IPv6 source rules without an IPv6 source:\n%s", s)
	}
}

func TestExitPolicyIPTables(t *testing.T) {
	f := newFakeSys()
	f.have["nft"] = false
	f.have["iptables"], f.have["ip6tables"] = true, true
	f.fail = func(cmd string) bool { return strings.Contains(cmd, " -C ") }
	s := &exitNATState{mode: NetfilterAuto}
	ctx := context.Background()
	if err := s.enable(ctx, f.ops(), policyNAT()); err != nil {
		t.Fatal(err)
	}
	cmds := f.commands()
	indexOf(t, cmds, "iptables -w 5 -t filter -A OPENSCALE-EXIT -i OpenScale -s 100.80.0.0/16 -p tcp --dport 25 -j DROP")
	indexOf(t, cmds, "ip6tables -w 5 -t filter -A OPENSCALE-EXIT -i OpenScale -s fd7a:1:2::/48 -p udp --dport 1900 -j DROP")
	indexOf(t, cmds, "iptables -w 5 -t filter -A OPENSCALE-EXIT -i OpenScale -d 1.1.1.1/32 -p udp --dport 443 -j DROP")
	indexOf(t, cmds, "ip6tables -w 5 -t filter -A OPENSCALE-EXIT -i OpenScale -d 2606:4700::/32 -p tcp --dport 443 -j DROP")
	quotaNew := indexOf(t, cmds, "iptables -w 5 -t filter -N OPENSCALE-EXIT-Q")
	quotaJump := indexOf(t, cmds, "iptables -w 5 -t filter -A OPENSCALE-EXIT -i OpenScale -j OPENSCALE-EXIT-Q")
	up := indexOf(t, cmds, "iptables -w 5 -t nat -A OPENSCALE-EXIT-NAT -o os-up0 -s 100.80.0.0/16 -j MASQUERADE")
	member := indexOf(t, cmds, "iptables -w 5 -t nat -A OPENSCALE-EXIT-NAT ! -o OpenScale -s 100.80.0.7 -j SNAT --to-source 203.0.113.6")
	def := indexOf(t, cmds, "iptables -w 5 -t nat -A OPENSCALE-EXIT-NAT ! -o OpenScale -s 100.80.0.0/16 -j SNAT --to-source 203.0.113.5")
	masq := indexOf(t, cmds, "iptables -w 5 -t nat -A OPENSCALE-EXIT-NAT ! -o OpenScale -s 100.80.0.0/16 -j MASQUERADE")
	if !(quotaNew < quotaJump && up < member && member < def && def < masq) {
		t.Fatalf("order wrong:\n%s", strings.Join(cmds, "\n"))
	}

	f.reset()
	if err := s.setQuotaBlocked(ctx, f.ops(), []netip.Addr{netip.MustParseAddr("100.80.0.9"), netip.MustParseAddr("fd7a:1:2::9")}); err != nil {
		t.Fatal(err)
	}
	cmds = f.commands()
	indexOf(t, cmds, "iptables -w 5 -t filter -F OPENSCALE-EXIT-Q")
	indexOf(t, cmds, "iptables -w 5 -t filter -A OPENSCALE-EXIT-Q -s 100.80.0.9 -j DROP")
	indexOf(t, cmds, "ip6tables -w 5 -t filter -A OPENSCALE-EXIT-Q -d fd7a:1:2::9 -j DROP")

	f.reset()
	f.fail = func(cmd string) bool { return strings.Contains(cmd, " -D ") }
	if err := s.disable(ctx, f.ops()); err != nil {
		t.Fatal(err)
	}
	cmds = f.commands()
	indexOf(t, cmds, "iptables -w 5 -t filter -X OPENSCALE-EXIT-Q")
	if err := s.setQuotaBlocked(ctx, f.ops(), nil); err != ErrExitNotActive {
		t.Fatalf("quota without exit rules: %v", err)
	}
}

func TestExitQuotaNFT(t *testing.T) {
	f := newFakeSys()
	s := &exitNATState{mode: NetfilterAuto}
	ctx := context.Background()
	if err := s.enable(ctx, f.ops(), policyNAT()); err != nil {
		t.Fatal(err)
	}
	f.reset()
	if err := s.setQuotaBlocked(ctx, f.ops(), []netip.Addr{netip.MustParseAddr("100.80.0.9")}); err != nil {
		t.Fatal(err)
	}
	if len(f.stdin) != 1 || !strings.Contains(f.stdin[0], "flush set inet openscale_exit quota6") ||
		!strings.Contains(f.stdin[0], "add element inet openscale_exit quota4 { 100.80.0.9 }") || strings.Contains(f.stdin[0], "quota6 {") {
		t.Fatalf("quota script: %q", f.stdin)
	}
}
