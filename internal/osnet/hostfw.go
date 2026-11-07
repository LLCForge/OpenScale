package osnet

import (
	"fmt"
	"strings"
)

// Host firewall cooperation (#283, F-082): a firewalld zone, an ufw default
// or a hand-written nftables input policy can drop the tunnel's traffic
// although OpenScale's own rules are right. The check finds these and
// either fixes them for this run only (firewalld runtime zone) or tells the
// owner the exact command; it never edits a persistent firewall
// configuration by itself.

// Host firewall modes.
const (
	// HostFirewallAuto fixes what can be fixed without a persistent change
	// (firewalld runtime zone) and warns about the rest.
	HostFirewallAuto = "auto"
	// HostFirewallWarn only reports.
	HostFirewallWarn = "warn"
	// HostFirewallOff turns the check off.
	HostFirewallOff = "off"
)

// ValidHostFirewallMode checks a --host-firewall value.
func ValidHostFirewallMode(mode string) error {
	switch mode {
	case HostFirewallAuto, HostFirewallWarn, HostFirewallOff:
		return nil
	}
	return fmt.Errorf("geçersiz güvenlik duvarı kipi %q (auto, warn veya off)", mode)
}

// HostFirewallFinding is one host firewall that may drop tunnel traffic.
type HostFirewallFinding struct {
	Tool string `json:"tool"`
	// Fixed: OpenScale added the permission for this run.
	Fixed   bool   `json:"fixed"`
	Message string `json:"message"`
	// Fix is the command the owner can run, when not fixed.
	Fix string `json:"fix,omitempty"`
}

// nftInputDrops parses "nft list ruleset" and returns "family table chain"
// for every input chain with policy drop whose table never mentions the
// interface. OpenScale's own tables and firewalld's (checked separately)
// are skipped.
func nftInputDrops(ruleset, iface string) []string {
	var out []string
	var family, table, chain string
	var body strings.Builder
	var chains []string
	flush := func() {
		if table == "" {
			return
		}
		if !strings.HasPrefix(table, "openscale_") && table != "firewalld" && !strings.Contains(body.String(), `"`+iface+`"`) {
			for _, c := range chains {
				out = append(out, family+" "+table+" "+c)
			}
		}
		table, chains = "", nil
		body.Reset()
	}
	for _, line := range strings.Split(ruleset, "\n") {
		t := strings.TrimSpace(line)
		f := strings.Fields(t)
		switch {
		case len(f) >= 3 && f[0] == "table" && strings.HasSuffix(t, "{"):
			flush()
			family, table = f[1], f[2]
		case len(f) >= 2 && f[0] == "chain" && strings.HasSuffix(t, "{"):
			chain = f[1]
		case strings.Contains(t, "hook input") && strings.Contains(t, "policy drop"):
			chains = append(chains, chain)
		}
		if table != "" {
			body.WriteString(t)
			body.WriteByte('\n')
		}
	}
	flush()
	return out
}

// ufwBlocks reports whether an active ufw denies incoming traffic by
// default without a rule for the interface ("ufw status verbose").
func ufwBlocks(status, iface string) bool {
	if !strings.Contains(status, "Status: active") {
		return false
	}
	if !strings.Contains(status, "deny (incoming)") && !strings.Contains(status, "reject (incoming)") {
		return false
	}
	for _, line := range strings.Split(status, "\n") {
		if strings.Contains(line, " on "+iface) && strings.Contains(line, "ALLOW IN") {
			return false
		}
	}
	return true
}

// tailscaleCGNAT is the range Tailscale reserves. OpenScale's default
// prefix (100.80.0.0/16) lies inside it, so Tailscale's input rule that
// drops this range from every other interface also drops the tunnel.
const tailscaleCGNAT = "100.64.0.0/10"

// tailscaleDropsTunnel parses "iptables -S ts-input" and reports whether
// the chain drops the CGNAT range from interfaces other than Tailscale's
// before anything accepts iface.
func tailscaleDropsTunnel(rules, iface string) bool {
	for _, line := range strings.Split(rules, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || f[0] != "-A" || f[1] != "ts-input" {
			continue
		}
		in, accept, drop, src, negIn := "", false, false, "", false
		for i := 2; i < len(f); i++ {
			switch f[i] {
			case "!":
				if i+1 < len(f) && f[i+1] == "-i" {
					negIn = true
				}
			case "-i":
				if i+1 < len(f) {
					in = f[i+1]
				}
			case "-s":
				if i+1 < len(f) {
					src = f[i+1]
				}
			case "-j":
				if i+1 < len(f) {
					accept, drop = f[i+1] == "ACCEPT", f[i+1] == "DROP"
				}
			}
		}
		if accept && !negIn && in == iface {
			return false // an exception for the tunnel comes first
		}
		if drop && negIn && src == tailscaleCGNAT && in != iface {
			return true
		}
	}
	return false
}
