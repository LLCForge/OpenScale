//go:build linux

package osnet

import (
	"fmt"
	"strconv"
)

// Per-member rate limit on the exit node (#83, ADR-0133). Each member's
// overlay address gets its own token bucket per direction (nft dynamic
// sets, iptables hashlimit), so one member cannot use up the exit node's
// uplink. A zero limit adds nothing and the rules stay as before.

// rateBurst allows short bursts of a quarter second, at least 64 kB.
func rateBurst(rate uint64) uint64 {
	if b := rate / 4; b > MinExitRateLimit {
		return b
	}
	return MinExitRateLimit
}

func subnetMarkHex() string { return "0x" + strconv.FormatUint(SubnetForwardMark, 16) }

func exitRateSets(c ExitNAT) string {
	if c.RateLimit == 0 {
		return ""
	}
	return "\n\tset up4 { type ipv4_addr; flags dynamic,timeout; timeout 5m; }" +
		"\n\tset down4 { type ipv4_addr; flags dynamic,timeout; timeout 5m; }" +
		"\n\tset up6 { type ipv6_addr; flags dynamic,timeout; timeout 5m; }" +
		"\n\tset down6 { type ipv6_addr; flags dynamic,timeout; timeout 5m; }"
}

func exitRateRules(c ExitNAT) string {
	if c.RateLimit == 0 {
		return ""
	}
	limit := fmt.Sprintf("limit rate over %d bytes/second burst %d bytes", c.RateLimit, rateBurst(c.RateLimit))
	return fmt.Sprintf("\n\t\tiifname %q update @up4 { ip saddr %s } drop", c.Interface, limit) +
		fmt.Sprintf("\n\t\toifname %q update @down4 { ip daddr %s } drop", c.Interface, limit) +
		fmt.Sprintf("\n\t\tiifname %q update @up6 { ip6 saddr %s } drop", c.Interface, limit) +
		fmt.Sprintf("\n\t\toifname %q update @down6 { ip6 daddr %s } drop", c.Interface, limit)
}

// exitRateSteps are the iptables hashlimit rules of the same limit.
func exitRateSteps(c ExitNAT) []iptablesStep {
	if c.RateLimit == 0 {
		return nil
	}
	kb := c.RateLimit / 1024
	burst := rateBurst(c.RateLimit) / 1024
	var steps []iptablesStep
	for _, f := range []struct {
		tool, prefix, tag string
	}{{"iptables", c.IPv4.Masked().String(), "4"}, {"ip6tables", c.IPv6.Masked().String(), "6"}} {
		steps = append(steps,
			iptablesStep{tool: f.tool, args: []string{"-w", "5", "-t", "filter", "-A", exitChain, "-i", c.Interface, "-s", f.prefix,
				"-m", "hashlimit", "--hashlimit-name", "osup" + f.tag, "--hashlimit-mode", "srcip",
				"--hashlimit-above", strconv.FormatUint(kb, 10) + "kb/s", "--hashlimit-burst", strconv.FormatUint(burst, 10) + "kb", "-j", "DROP"}},
			iptablesStep{tool: f.tool, args: []string{"-w", "5", "-t", "filter", "-A", exitChain, "-o", c.Interface, "-d", f.prefix,
				"-m", "hashlimit", "--hashlimit-name", "osdown" + f.tag, "--hashlimit-mode", "dstip",
				"--hashlimit-above", strconv.FormatUint(kb, 10) + "kb/s", "--hashlimit-burst", strconv.FormatUint(burst, 10) + "kb", "-j", "DROP"}},
		)
	}
	return steps
}
