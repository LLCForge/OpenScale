//go:build linux

package osnet

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// exitQuotaChain is the iptables chain holding the quota drops (#401).
const exitQuotaChain = "OPENSCALE-EXIT-Q"

// ErrExitNotActive is returned by SetExitQuotaBlocked while this host is
// not an exit node.
var ErrExitNotActive = errors.New("çıkış düğümü kuralları kurulu değil")

func exitPolicySets(c ExitNAT) string {
	if !c.Quota {
		return ""
	}
	return "\n\tset quota4 { type ipv4_addr; }" +
		"\n\tset quota6 { type ipv6_addr; }"
}

func exitPolicyRules(c ExitNAT) string {
	var b strings.Builder
	if c.Quota {
		fmt.Fprintf(&b, "\n\t\tiifname %q ip saddr @quota4 drop", c.Interface)
		fmt.Fprintf(&b, "\n\t\toifname %q ip daddr @quota4 drop", c.Interface)
		fmt.Fprintf(&b, "\n\t\tiifname %q ip6 saddr @quota6 drop", c.Interface)
		fmt.Fprintf(&b, "\n\t\toifname %q ip6 daddr @quota6 drop", c.Interface)
	}
	for _, proto := range []string{"tcp", "udp"} {
		var ports []string
		for _, p := range c.BlockPorts {
			if p.Proto == proto {
				ports = append(ports, strconv.Itoa(int(p.Port)))
			}
		}
		if len(ports) > 0 {
			fmt.Fprintf(&b, "\n\t\tiifname %q %s dport { %s } drop", c.Interface, proto, strings.Join(ports, ", "))
		}
	}
	var v4, v6 []string
	for _, p := range c.BlockDoH {
		if p.Addr().Is4() {
			v4 = append(v4, p.String())
		} else {
			v6 = append(v6, p.String())
		}
	}
	if len(v4) > 0 {
		fmt.Fprintf(&b, "\n\t\tiifname %q ip daddr { %s } meta l4proto { tcp, udp } th dport 443 drop", c.Interface, strings.Join(v4, ", "))
	}
	if len(v6) > 0 {
		fmt.Fprintf(&b, "\n\t\tiifname %q ip6 daddr { %s } meta l4proto { tcp, udp } th dport 443 drop", c.Interface, strings.Join(v6, ", "))
	}
	return b.String()
}

// exitSourceRules come before the masquerade rules: the upstream tunnel
// keeps its masquerade, then member-specific and default sources.
func exitSourceRules(c ExitNAT) string {
	var b strings.Builder
	for _, f := range []struct {
		v4     bool
		family string
		prefix string
	}{{true, "ip", c.IPv4.Masked().String()}, {false, "ip6", c.IPv6.Masked().String()}} {
		members, def := c.sourcesFor(f.v4)
		if len(members) == 0 && !def.IsValid() {
			continue
		}
		fmt.Fprintf(&b, "\n\t\toifname %q %s saddr %s masquerade", UpstreamInterface, f.family, f.prefix)
		for _, s := range members {
			fmt.Fprintf(&b, "\n\t\toifname != %q %s saddr %s snat %s to %s", c.Interface, f.family, s.Member, f.family, s.Source)
		}
		if def.IsValid() {
			fmt.Fprintf(&b, "\n\t\toifname != %q %s saddr %s snat %s to %s", c.Interface, f.family, f.prefix, f.family, def)
		}
	}
	return b.String()
}

// exitSourceSteps are the iptables equivalent of exitSourceRules for one
// family; they go into the nat chain before its MASQUERADE rule.
func exitSourceSteps(c ExitNAT, tool, prefix string) []iptablesStep {
	members, def := c.sourcesFor(tool == "iptables")
	if len(members) == 0 && !def.IsValid() {
		return nil
	}
	cmd := func(args ...string) []string {
		return append([]string{"-w", "5", "-t", "nat", "-A", exitNATChain}, args...)
	}
	steps := []iptablesStep{{tool: tool, args: cmd("-o", UpstreamInterface, "-s", prefix, "-j", "MASQUERADE")}}
	for _, s := range members {
		steps = append(steps, iptablesStep{tool: tool, args: cmd("!", "-o", c.Interface, "-s", s.Member.String(), "-j", "SNAT", "--to-source", s.Source.String())})
	}
	if def.IsValid() {
		steps = append(steps, iptablesStep{tool: tool, args: cmd("!", "-o", c.Interface, "-s", prefix, "-j", "SNAT", "--to-source", def.String())})
	}
	return steps
}

// exitPolicySteps are the iptables filter rules of the port policy, the
// DoH list and the quota chain.
func exitPolicySteps(c ExitNAT) []iptablesStep {
	var steps []iptablesStep
	for _, f := range []struct {
		tool, prefix string
		v4           bool
	}{{"iptables", c.IPv4.Masked().String(), true}, {"ip6tables", c.IPv6.Masked().String(), false}} {
		add := func(args ...string) {
			steps = append(steps, iptablesStep{tool: f.tool, args: append([]string{"-w", "5", "-t", "filter"}, args...)})
		}
		if c.Quota {
			steps = append(steps,
				iptablesStep{tool: f.tool, args: []string{"-w", "5", "-t", "filter", "-N", exitQuotaChain}, mayFail: true},
				iptablesStep{tool: f.tool, args: []string{"-w", "5", "-t", "filter", "-F", exitQuotaChain}},
			)
			add("-A", exitChain, "-i", c.Interface, "-j", exitQuotaChain)
			add("-A", exitChain, "-o", c.Interface, "-j", exitQuotaChain)
		}
		for _, p := range c.BlockPorts {
			add("-A", exitChain, "-i", c.Interface, "-s", f.prefix, "-p", p.Proto, "--dport", strconv.Itoa(int(p.Port)), "-j", "DROP")
		}
		for _, p := range c.BlockDoH {
			if p.Addr().Is4() != f.v4 {
				continue
			}
			for _, proto := range []string{"tcp", "udp"} {
				add("-A", exitChain, "-i", c.Interface, "-d", p.String(), "-p", proto, "--dport", "443", "-j", "DROP")
			}
		}
	}
	return steps
}

// removeExitPolicyChains deletes the quota chain after the exit chain that
// jumps to it is gone.
func removeExitPolicyChains(ctx context.Context, o sysOps, tool string) {
	_, _ = o.run(ctx, nil, tool, "-w", "5", "-t", "filter", "-F", exitQuotaChain)
	_, _ = o.run(ctx, nil, tool, "-w", "5", "-t", "filter", "-X", exitQuotaChain)
}

// SetExitQuotaBlocked replaces the members whose internet traffic the exit
// node drops because their data quota is used up (#401, ADR-0155). The
// rules must have been installed with ExitNAT.Quota.
func SetExitQuotaBlocked(ctx context.Context, members []netip.Addr) error {
	return hostExitNAT.setQuotaBlocked(ctx, hostOps, members)
}

func (s *exitNATState) setQuotaBlocked(ctx context.Context, o sysOps, members []netip.Addr) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch s.backend {
	case NetfilterNFTables:
		_, err := o.run(ctx, nftQuotaScript(members), "nft", "-f", "-")
		return err
	case NetfilterIPTables:
		for _, step := range iptablesQuotaSteps(members) {
			if _, err := o.run(ctx, nil, step.tool, step.args...); err != nil {
				return err
			}
		}
		return nil
	}
	return ErrExitNotActive
}

func nftQuotaScript(members []netip.Addr) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "flush set inet %s quota4\nflush set inet %s quota6\n", exitTable, exitTable)
	var v4, v6 []string
	for _, a := range members {
		if a.Unmap().Is4() {
			v4 = append(v4, a.Unmap().String())
		} else if a.Is6() {
			v6 = append(v6, a.String())
		}
	}
	if len(v4) > 0 {
		fmt.Fprintf(&b, "add element inet %s quota4 { %s }\n", exitTable, strings.Join(v4, ", "))
	}
	if len(v6) > 0 {
		fmt.Fprintf(&b, "add element inet %s quota6 { %s }\n", exitTable, strings.Join(v6, ", "))
	}
	return []byte(b.String())
}

func iptablesQuotaSteps(members []netip.Addr) []iptablesStep {
	steps := []iptablesStep{
		{tool: "iptables", args: []string{"-w", "5", "-t", "filter", "-F", exitQuotaChain}},
		{tool: "ip6tables", args: []string{"-w", "5", "-t", "filter", "-F", exitQuotaChain}},
	}
	for _, a := range members {
		tool := "ip6tables"
		if a.Unmap().Is4() {
			a, tool = a.Unmap(), "iptables"
		}
		steps = append(steps,
			iptablesStep{tool: tool, args: []string{"-w", "5", "-t", "filter", "-A", exitQuotaChain, "-s", a.String(), "-j", "DROP"}},
			iptablesStep{tool: tool, args: []string{"-w", "5", "-t", "filter", "-A", exitQuotaChain, "-d", a.String(), "-j", "DROP"}},
		)
	}
	return steps
}
