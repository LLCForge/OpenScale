package osnet

import (
	"net/netip"
	"strings"
	"testing"
)

var (
	testMagic   = DNSConfig{Interface: "OpenScale", Server: netip.MustParseAddr("100.80.255.254"), Domain: "openscale.internal"}
	testOverlay = []netip.Prefix{netip.MustParsePrefix("100.80.0.0/16"), netip.MustParsePrefix("fd12:3456:789a::/48")}
)

func TestNRPTScriptMagicOnly(t *testing.T) {
	script, err := nrptScript(testMagic, NetworkDNS{Overlay: testOverlay})
	if err != nil {
		t.Fatal(err)
	}
	want := "$ErrorActionPreference='Stop'; " +
		"Get-DnsClientNrptRule | Where-Object { $_.Comment -eq 'OpenScale' } | ForEach-Object { Remove-DnsClientNrptRule -Name $_.Name -Force }; " +
		"Add-DnsClientNrptRule -Namespace '.openscale.internal' -NameServers '100.80.255.254' -Comment 'OpenScale' | Out-Null; " +
		"try { Set-DnsClient -InterfaceAlias 'OpenScale' -ConnectionSpecificSuffix '' } catch { }; " +
		"Clear-DnsClientCache"
	if script != want {
		t.Fatalf("script =\n%s\nwant\n%s", script, want)
	}
}

func TestNRPTScriptSplitAndGlobal(t *testing.T) {
	n := NetworkDNS{
		Nameservers: []netip.Addr{netip.MustParseAddr("100.80.0.5")},
		Split: []SplitDomain{
			{Domain: "ev.lan", Nameservers: []netip.Addr{netip.MustParseAddr("100.80.0.5"), netip.MustParseAddr("fd12:3456:789a::5")}},
			{Domain: "corp", Nameservers: []netip.Addr{netip.MustParseAddr("100.80.0.9")}},
		},
		Overlay: testOverlay,
	}
	script, err := nrptScript(testMagic, n)
	if err != nil {
		t.Fatal(err)
	}
	for _, part := range []string{
		"Add-DnsClientNrptRule -Namespace '.openscale.internal' -NameServers '100.80.255.254' -Comment 'OpenScale'",
		"Add-DnsClientNrptRule -Namespace '.ev.lan' -NameServers '100.80.0.5','fd12:3456:789a::5' -Comment 'OpenScale'",
		"Add-DnsClientNrptRule -Namespace '.corp' -NameServers '100.80.0.9' -Comment 'OpenScale'",
		"Add-DnsClientNrptRule -Namespace '.' -NameServers '100.80.0.5' -Comment 'OpenScale'",
	} {
		if !strings.Contains(script, part) {
			t.Errorf("script lacks %q:\n%s", part, script)
		}
	}
	// The old OpenScale rules are removed before any rule is added, and
	// only rules carrying the OpenScale comment are touched.
	if strings.Index(script, "Remove-DnsClientNrptRule") > strings.Index(script, "Add-DnsClientNrptRule") {
		t.Fatal("rules are added before the old ones are removed")
	}
	if strings.Count(script, "Remove-DnsClientNrptRule") != 1 || !strings.Contains(script, "$_.Comment -eq 'OpenScale'") {
		t.Fatal("removal is not limited to OpenScale rules")
	}
	// Without network-wide resolvers there is no catch-all rule.
	n.Nameservers = nil
	script, err = nrptScript(testMagic, n)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(script, "-Namespace '.' ") {
		t.Fatal("catch-all rule without network-wide resolvers")
	}
}

func TestNetworkDNSRejectsUnsafeValues(t *testing.T) {
	ok := netip.MustParseAddr("100.80.0.5")
	bad := []NetworkDNS{
		// A public resolver: queries would leave the tunnel.
		{Nameservers: []netip.Addr{netip.MustParseAddr("1.1.1.1")}},
		{Split: []SplitDomain{{Domain: "lan", Nameservers: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}}},
		// Injection attempts through the domain.
		{Split: []SplitDomain{{Domain: "lan'; Remove-Item C:\\ -Recurse; '", Nameservers: []netip.Addr{ok}}}},
		{Split: []SplitDomain{{Domain: "Ev.Lan", Nameservers: []netip.Addr{ok}}}},
		// Overlapping MagicDNS.
		{Split: []SplitDomain{{Domain: "openscale.internal", Nameservers: []netip.Addr{ok}}}},
		{Split: []SplitDomain{{Domain: "internal", Nameservers: []netip.Addr{ok}}}},
		{Split: []SplitDomain{{Domain: "x.openscale.internal", Nameservers: []netip.Addr{ok}}}},
		// Structure.
		{Split: []SplitDomain{{Domain: "lan"}}},
		{Split: []SplitDomain{{Domain: "lan", Nameservers: []netip.Addr{ok}}, {Domain: "lan", Nameservers: []netip.Addr{ok}}}},
		{Nameservers: []netip.Addr{netip.MustParseAddr("fe80::1%eth0")}},
		{Nameservers: []netip.Addr{{}}},
		{Nameservers: []netip.Addr{ok, ok, ok, ok, ok}},
	}
	for i, n := range bad {
		n.Overlay = testOverlay
		if _, err := nrptScript(testMagic, n); err == nil {
			t.Errorf("case %d accepted: %+v", i, n)
		}
	}
	// Without the overlay ranges no resolver is acceptable (fail closed).
	if _, err := nrptScript(testMagic, NetworkDNS{Nameservers: []netip.Addr{ok}}); err == nil {
		t.Error("resolver accepted without overlay ranges")
	}
}

func TestNetworkDNSKeyAndEmpty(t *testing.T) {
	a := NetworkDNS{Split: []SplitDomain{{Domain: "lan", Nameservers: []netip.Addr{netip.MustParseAddr("100.80.0.5")}}}}
	b := NetworkDNS{Nameservers: []netip.Addr{netip.MustParseAddr("100.80.0.5")}}
	if a.Key() == b.Key() || a.Key() == (NetworkDNS{}).Key() {
		t.Fatal("different settings share a key")
	}
	if !(NetworkDNS{}).Empty() || a.Empty() || b.Empty() {
		t.Fatal("Empty is wrong")
	}
}
