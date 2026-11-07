package osnet

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// Linux kill switch and leak guard rulesets (ADR-0023, Linux bölümü). The
// scripts are built here without a build tag so their content is tested on
// every platform; killswitch_linux.go and leakguard_linux.go apply them.

const (
	// TunnelBypassMark is the socket mark (SO_MARK) of OpenScale's own
	// sockets that must leave outside the tunnel on Linux: WireGuard UDP,
	// the TCP fallback and the captive portal check. Marked packets skip
	// the exit node routing table and pass the kill switch; setting a mark
	// needs CAP_NET_ADMIN, so ordinary programs cannot claim it.
	TunnelBypassMark = 0x4f53

	// killSwitchTable is the persistent kill switch's nftables table.
	killSwitchTable = "openscale_killswitch"
	// leakGuardTable holds the DNS and IPv6 leak rules while an exit node
	// is used (#75, #93); it goes away with the exit node routes.
	leakGuardTable = "openscale_leakguard"
	// captiveSet holds the gateway addresses of a captive portal exception
	// (#85); elements carry a timeout so the kernel removes them even if
	// OpenScale is gone.
	captiveSet = "captive4"
	dotPort    = 853
)

// Captive portal exception bounds (#85).
const (
	CaptiveDefaultDuration = 5 * time.Minute
	CaptiveMaxDuration     = 15 * time.Minute
)

// ErrKillSwitchNotInstalled is returned by the captive portal exception
// when there is no kill switch to open a hole in.
var ErrKillSwitchNotInstalled = errors.New("kill switch kurulu değil; giriş sayfası için istisna gerekmiyor")

// validNftIfname reports whether an interface name is safe inside a
// quoted nft string: kernel names are at most 15 bytes and never contain
// quotes, spaces or slashes.
func validNftIfname(name string) bool {
	if name == "" || len(name) > 15 {
		return false
	}
	for _, c := range name {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_', c == '.', c == '@', c == ':':
		default:
			return false
		}
	}
	return true
}

func joinPrefixes(ps []netip.Prefix) string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.Masked().String()
	}
	return strings.Join(out, ", ")
}

// ndpTypes are the ICMPv6 types a computer needs to keep its link:
// neighbor discovery (RFC 4861) and multicast listener messages.
const ndpTypes = "nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert, nd-redirect, mld-listener-query, mld-listener-report, mld-listener-done, mld2-listener-report"

// nftKillSwitchScript returns the ruleset of the persistent kill switch:
// the Linux counterpart of the WFP plan (killSwitchPlan). Output, input
// and forward default to drop; the permits are loopback, the tunnel
// interface, OpenScale's marked sockets, DHCP, DHCPv6, neighbor discovery,
// the captive portal set and, if allowed, the local network without DNS.
// The script replaces the table atomically ("nft -f" applies it in one
// transaction), so the computer is never left half protected.
func nftKillSwitchScript(cfg KillSwitchConfig) (string, error) {
	if cfg.Interface != "" && !validNftIfname(cfg.Interface) {
		return "", fmt.Errorf("geçersiz arayüz adı %q", cfg.Interface)
	}
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	mark := "0x" + strconv.FormatUint(TunnelBypassMark, 16)
	dns := fmt.Sprintf("{ %d, %d }", dnsPort, dotPort)

	w("table inet %s", killSwitchTable)
	w("delete table inet %s", killSwitchTable)
	w("table inet %s {", killSwitchTable)
	w("\tset %s {", captiveSet)
	w("\t\ttype ipv4_addr")
	w("\t\tflags timeout")
	w("\t}")

	// output: what this computer sends.
	w("\tchain output {")
	w("\t\ttype filter hook output priority filter - 5; policy accept;")
	w("\t\toifname \"lo\" accept")
	if cfg.Interface != "" {
		w("\t\toifname \"%s\" accept", cfg.Interface)
	}
	w("\t\tmeta mark %s accept", mark)
	w("\t\tudp sport 68 udp dport 67 accept")
	w("\t\tmeta nfproto ipv6 udp sport %d udp dport %d accept", dhcpv6ClientPort, dhcpv6ServerPort)
	w("\t\ticmpv6 type { %s } accept", ndpTypes)
	w("\t\tip daddr @%s tcp dport { 80, 443 } accept", captiveSet)
	if cfg.AllowLAN {
		w("\t\tip daddr { %s } udp dport %s drop", joinPrefixes(lanPrefixes4), dns)
		w("\t\tip daddr { %s } tcp dport %s drop", joinPrefixes(lanPrefixes4), dns)
		w("\t\tip6 daddr { %s } udp dport %s drop", joinPrefixes(lanPrefixes6), dns)
		w("\t\tip6 daddr { %s } tcp dport %s drop", joinPrefixes(lanPrefixes6), dns)
		w("\t\tip daddr { %s } accept", joinPrefixes(lanPrefixes4))
		w("\t\tip6 daddr { %s } accept", joinPrefixes(lanPrefixes6))
	}
	w("\t\tcounter drop")
	w("\t}")

	// input: what reaches this computer. Replies to permitted connections
	// are established; anything new from outside the tunnel is dropped,
	// like the WFP receive/accept layer.
	w("\tchain input {")
	w("\t\ttype filter hook input priority filter - 5; policy accept;")
	w("\t\tiifname \"lo\" accept")
	if cfg.Interface != "" {
		w("\t\tiifname \"%s\" accept", cfg.Interface)
	}
	w("\t\tct state established,related accept")
	w("\t\tudp sport 67 udp dport 68 accept")
	w("\t\tmeta nfproto ipv6 udp sport %d udp dport %d accept", dhcpv6ServerPort, dhcpv6ClientPort)
	w("\t\ticmpv6 type { %s } accept", ndpTypes)
	if cfg.AllowLAN {
		w("\t\tip saddr { %s } udp sport %s drop", joinPrefixes(lanPrefixes4), dns)
		w("\t\tip saddr { %s } tcp sport %s drop", joinPrefixes(lanPrefixes4), dns)
		w("\t\tip6 saddr { %s } udp sport %s drop", joinPrefixes(lanPrefixes6), dns)
		w("\t\tip6 saddr { %s } tcp sport %s drop", joinPrefixes(lanPrefixes6), dns)
		w("\t\tip saddr { %s } accept", joinPrefixes(lanPrefixes4))
		w("\t\tip6 saddr { %s } accept", joinPrefixes(lanPrefixes6))
	}
	w("\t\tcounter drop")
	w("\t}")

	// forward: containers and virtual machines behind this computer must
	// not reach the internet outside the tunnel either.
	w("\tchain forward {")
	w("\t\ttype filter hook forward priority filter - 5; policy accept;")
	if cfg.Interface != "" {
		w("\t\tiifname \"%s\" accept", cfg.Interface)
		w("\t\toifname \"%s\" accept", cfg.Interface)
	}
	if cfg.AllowLAN {
		w("\t\tip daddr { %s } udp dport %s drop", joinPrefixes(lanPrefixes4), dns)
		w("\t\tip daddr { %s } tcp dport %s drop", joinPrefixes(lanPrefixes4), dns)
		w("\t\tip6 daddr { %s } udp dport %s drop", joinPrefixes(lanPrefixes6), dns)
		w("\t\tip6 daddr { %s } tcp dport %s drop", joinPrefixes(lanPrefixes6), dns)
		w("\t\tip daddr { %s } accept", joinPrefixes(lanPrefixes4))
		w("\t\tip6 daddr { %s } accept", joinPrefixes(lanPrefixes6))
	}
	w("\t\tcounter drop")
	w("\t}")
	w("}")
	return b.String(), nil
}

// nftLeakGuardScript returns the rules that hold while an exit node is in
// use, with or without the kill switch: DNS (53, and 853 for DNS over TLS
// or QUIC) and global IPv6 may only leave through the tunnel (#93, #75).
// The routes already send both into the tunnel; these rules catch what
// bypasses them: resolvers on the local network (more specific LAN routes
// win over the split default routes), programs bound to the physical
// interface, and DNS servers of other links.
func nftLeakGuardScript(iface string) (string, error) {
	if !validNftIfname(iface) {
		return "", fmt.Errorf("geçersiz arayüz adı %q", iface)
	}
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	dns := fmt.Sprintf("{ %d, %d }", dnsPort, dotPort)
	w("table inet %s", leakGuardTable)
	w("delete table inet %s", leakGuardTable)
	w("table inet %s {", leakGuardTable)
	w("\tchain output {")
	w("\t\ttype filter hook output priority filter - 4; policy accept;")
	w("\t\toifname { \"lo\", \"%s\" } accept", iface)
	w("\t\tmeta mark 0x%s accept", strconv.FormatUint(TunnelBypassMark, 16))
	w("\t\tudp dport %s counter drop", dns)
	w("\t\ttcp dport %s counter drop", dns)
	w("\t\tip6 daddr 2000::/3 counter drop")
	w("\t}")
	w("}")
	return b.String(), nil
}

// captiveAllowed limits a captive portal exception to local IPv4 next hops
// (the same rule as the captive portal check, F-018): never a public
// address.
func captiveAllowed(a netip.Addr) bool {
	a = a.Unmap()
	return a.Is4() && (a.IsPrivate() || a.IsLinkLocalUnicast() || cgnatPrefix.Contains(a))
}

var cgnatPrefix = netip.MustParsePrefix("100.64.0.0/10")

// validCaptive checks the addresses and the duration of an exception.
func validCaptive(addrs []netip.Addr, d time.Duration) ([]netip.Addr, error) {
	if d <= 0 || d > CaptiveMaxDuration {
		return nil, fmt.Errorf("istisna süresi 1 saniye ile %s arasında olmalı", CaptiveMaxDuration)
	}
	if len(addrs) == 0 || len(addrs) > 4 {
		return nil, errors.New("giriş sayfası istisnası için 1-4 yerel adres gerekli")
	}
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		if !captiveAllowed(a) {
			return nil, fmt.Errorf("%s yerel bir ağ geçidi adresi değil; istisna yalnızca yerel IPv4 adreslerine verilir", a)
		}
		out = append(out, a.Unmap())
	}
	return out, nil
}

// nftCaptiveArgs returns the nft arguments that add the exception.
func nftCaptiveArgs(addrs []netip.Addr, d time.Duration) []string {
	secs := int64(d / time.Second)
	if secs < 1 {
		secs = 1
	}
	elems := make([]string, len(addrs))
	for i, a := range addrs {
		elems[i] = a.String() + " timeout " + strconv.FormatInt(secs, 10) + "s"
	}
	return []string{"add", "element", "inet", killSwitchTable, captiveSet, "{ " + strings.Join(elems, ", ") + " }"}
}
