//go:build linux

package osnet

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"text/template"
)

const (
	exitTable = "openscale_exit"
	// exitChain and exitNATChain are the iptables equivalents of the nft
	// table, used when nft is not installed.
	exitChain    = "OPENSCALE-EXIT"
	exitNATChain = "OPENSCALE-EXIT-NAT"
)

// Netfilter backends for the exit node rules.
const (
	NetfilterAuto     = "auto"
	NetfilterNFTables = "nftables"
	NetfilterIPTables = "iptables"
)

// Destinations a member must never reach through the exit node: the exit
// node's own LAN, loopback, link-local, multicast and the overlay itself.
var (
	exitBlocked4 = []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4"}
	exitBlocked6 = []string{"::1/128", "fc00::/7", "fe80::/10", "ff00::/8"}
)

// The exit node forwards members' traffic to the internet only: private,
// link-local and multicast destinations (the exit node's own LAN) are
// dropped, and member addresses are masqueraded behind this host.
var exitRules = template.Must(template.New("exit").Parse(`table inet {{.Table}}
delete table inet {{.Table}}
table inet {{.Table}} {{"{"}}{{.RateSets}}{{.PolicySets}}
	chain forward {
		type filter hook forward priority filter - 10; policy accept;
		meta mark {{.SubnetMark}} accept
		iifname "{{.If}}" ip daddr { {{.Blocked4}} } drop
		iifname "{{.If}}" ip6 daddr { {{.Blocked6}} } drop
		iifname "{{.If}}" ip saddr != {{.V4}} drop
		iifname "{{.If}}" ip6 saddr != {{.V6}} drop{{.RateRules}}{{.PolicyRules}}
	}
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;{{.SourceRules}}
		oifname != "{{.If}}" ip saddr {{.V4}} masquerade
		oifname != "{{.If}}" ip6 saddr {{.V6}} masquerade
	}
}
`))

// exitSysctls remembers the values EnableExitNAT changed, so DisableExitNAT
// can put them back (ADR-0023).
type exitSysctls struct {
	forward4, forward6 string
	// acceptRA maps an interface to its accept_ra value before it was
	// raised to 2.
	acceptRA map[string]string
}

// exitNATState is the exit node configuration this process applied.
type exitNATState struct {
	mu      sync.Mutex
	mode    string
	saved   *exitSysctls
	backend string
	// shared: forwarding is shared with the subnet router (subnet_linux.go,
	// ADR-0133); only the last user restores it.
	shared bool
}

var hostExitNAT = &exitNATState{mode: NetfilterAuto, shared: true}

// SetNetfilterMode chooses how the exit node rules are installed: "auto"
// (nft when installed, otherwise iptables), "nftables" or "iptables".
func SetNetfilterMode(mode string) error {
	if err := validNetfilterMode(mode); err != nil {
		return err
	}
	hostExitNAT.mu.Lock()
	hostExitNAT.mode = mode
	hostExitNAT.mu.Unlock()
	return nil
}

func validNetfilterMode(mode string) error {
	switch mode {
	case NetfilterAuto, NetfilterNFTables, NetfilterIPTables:
		return nil
	}
	return fmt.Errorf("geçersiz netfilter kipi %q (auto, nftables veya iptables)", mode)
}

// EnableExitNAT turns on forwarding and NAT for members' internet traffic.
func EnableExitNAT(ctx context.Context, c ExitNAT) error {
	return hostExitNAT.enable(ctx, hostOps, c)
}

// DisableExitNAT removes the NAT rules and restores forwarding and
// accept_ra to the values they had before EnableExitNAT (ADR-0023).
func DisableExitNAT(ctx context.Context) error {
	return hostExitNAT.disable(ctx, hostOps)
}

func (s *exitNATState) enable(ctx context.Context, o sysOps, c ExitNAT) error {
	if err := c.validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	backend, err := chooseBackend(o, s.mode)
	if err != nil {
		return err
	}
	if s.saved == nil {
		saved, err := readExitSysctls(o, c.Interface)
		if err != nil {
			return err
		}
		s.saved = shareForwarding(s, saved)
	}
	if err := s.raiseSysctls(ctx, o); err != nil {
		s.restoreLocked(ctx, o)
		return err
	}
	if err := installExitRules(ctx, o, backend, c); err != nil {
		removeExitRules(ctx, o)
		s.restoreLocked(ctx, o)
		return err
	}
	s.backend = backend
	return nil
}

func (s *exitNATState) disable(ctx context.Context, o sysOps) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	removeExitRules(ctx, o)
	s.backend = ""
	return s.restoreLocked(ctx, o)
}

// readExitSysctls records the current forwarding values and the accept_ra
// value of every interface with an IPv6 default route.
func readExitSysctls(o sysOps, tunnel string) (*exitSysctls, error) {
	f4, err := o.sysctlGet("net/ipv4/ip_forward")
	if err != nil {
		return nil, fmt.Errorf("IPv4 iletim ayarı okunamadı: %w", err)
	}
	f6, err := o.sysctlGet("net/ipv6/conf/all/forwarding")
	if err != nil {
		return nil, fmt.Errorf("IPv6 iletim ayarı okunamadı: %w", err)
	}
	saved := &exitSysctls{forward4: f4, forward6: f6, acceptRA: map[string]string{}}
	for _, dev := range o.ipv6DefaultInterfaces(tunnel) {
		v, err := o.sysctlGet("net/ipv6/conf/" + dev + "/accept_ra")
		if err != nil {
			continue
		}
		// With forwarding on, the kernel ignores router advertisements
		// unless accept_ra is 2; a SLAAC-configured VPS would lose its
		// IPv6 default route (F-047).
		if v == "1" {
			saved.acceptRA[dev] = v
		}
	}
	return saved, nil
}

// raiseSysctls keeps router advertisements working, then turns forwarding
// on. accept_ra must change first: forwarding alone drops the RA route.
func (s *exitNATState) raiseSysctls(ctx context.Context, o sysOps) error {
	for dev := range s.saved.acceptRA {
		if err := o.sysctlSet(ctx, "net/ipv6/conf/"+dev+"/accept_ra", "2"); err != nil {
			return err
		}
	}
	if err := o.sysctlSet(ctx, "net/ipv4/ip_forward", "1"); err != nil {
		return err
	}
	return o.sysctlSet(ctx, "net/ipv6/conf/all/forwarding", "1")
}

// restoreLocked puts forwarding back first and accept_ra afterwards, the
// reverse of raiseSysctls. A value someone else changed in the meantime is
// left alone.
func (s *exitNATState) restoreLocked(ctx context.Context, o sysOps) error {
	saved := s.saved
	if saved == nil {
		return nil
	}
	s.saved = nil
	if !releaseForwarding(s) {
		// The subnet router still forwards (ADR-0133).
		return nil
	}
	var errs []error
	restore := func(key, old, ours string) {
		if old == ours {
			return
		}
		if cur, err := o.sysctlGet(key); err != nil || cur != ours {
			return
		}
		if err := o.sysctlSet(ctx, key, old); err != nil {
			errs = append(errs, err)
		}
	}
	restore("net/ipv4/ip_forward", saved.forward4, "1")
	restore("net/ipv6/conf/all/forwarding", saved.forward6, "1")
	for dev, old := range saved.acceptRA {
		restore("net/ipv6/conf/"+dev+"/accept_ra", old, "2")
	}
	return errors.Join(errs...)
}

func chooseBackend(o sysOps, mode string) (string, error) {
	switch mode {
	case NetfilterNFTables:
		if !o.has("nft") {
			return "", errors.New("nft bulunamadı (--netfilter-mode nftables)")
		}
		return NetfilterNFTables, nil
	case NetfilterIPTables:
		if !o.has("iptables") || !o.has("ip6tables") {
			return "", errors.New("iptables veya ip6tables bulunamadı (--netfilter-mode iptables)")
		}
		return NetfilterIPTables, nil
	case NetfilterAuto, "":
		if o.has("nft") {
			return NetfilterNFTables, nil
		}
		if o.has("iptables") && o.has("ip6tables") {
			return NetfilterIPTables, nil
		}
		return "", errors.New("çıkış düğümü için nft veya iptables/ip6tables gerekli; hiçbiri bulunamadı")
	}
	return "", validNetfilterMode(mode)
}

func installExitRules(ctx context.Context, o sysOps, backend string, c ExitNAT) error {
	if backend == NetfilterNFTables {
		script, err := nftExitScript(c)
		if err != nil {
			return err
		}
		if _, err := o.run(ctx, script, "nft", "-f", "-"); err != nil {
			return err
		}
		return nil
	}
	for _, step := range iptablesExitSteps(c) {
		if step.ifMissing != nil {
			// Insert the jump only once; -C fails when it is absent.
			if _, err := o.run(ctx, nil, step.tool, step.ifMissing...); err == nil {
				continue
			}
		}
		if _, err := o.run(ctx, nil, step.tool, step.args...); err != nil && !step.mayFail {
			return err
		}
	}
	return nil
}

func nftExitScript(c ExitNAT) ([]byte, error) {
	var script bytes.Buffer
	if err := exitRules.Execute(&script, map[string]string{
		"Table": exitTable, "If": c.Interface, "V4": c.IPv4.Masked().String(), "V6": c.IPv6.Masked().String(),
		"Blocked4": strings.Join(exitBlocked4, ", "), "Blocked6": strings.Join(exitBlocked6, ", "),
		// Subnet router traffic and per-member rate limits (ADR-0133).
		"SubnetMark": subnetMarkHex(), "RateSets": exitRateSets(c), "RateRules": exitRateRules(c),
		// Port policy, DoH list, source address and quota (P04).
		"PolicySets": exitPolicySets(c), "PolicyRules": exitPolicyRules(c), "SourceRules": exitSourceRules(c),
	}); err != nil {
		return nil, err
	}
	return script.Bytes(), nil
}

// iptablesStep is one iptables or ip6tables call.
type iptablesStep struct {
	tool string
	args []string
	// ifMissing, when set, is a check (-C) that skips args when it passes.
	ifMissing []string
	// mayFail marks steps whose failure is expected (creating a chain
	// that already exists).
	mayFail bool
}

// iptablesExitSteps builds the same rules as the nft table: one filter
// chain and one nat chain per address family, each jumped to from the
// built-in chain.
func iptablesExitSteps(c ExitNAT) []iptablesStep {
	var steps []iptablesStep
	family := func(tool, prefix string, blocked []string) {
		w := []string{"-w", "5"}
		cmd := func(args ...string) []string { return append(append([]string{}, w...), args...) }
		steps = append(steps,
			iptablesStep{tool: tool, args: cmd("-t", "filter", "-N", exitChain), mayFail: true},
			iptablesStep{tool: tool, args: cmd("-t", "filter", "-F", exitChain)},
		)
		for _, d := range blocked {
			steps = append(steps, iptablesStep{tool: tool, args: cmd("-t", "filter", "-A", exitChain, "-i", c.Interface, "-d", d, "-j", "DROP")})
		}
		steps = append(steps,
			iptablesStep{tool: tool, args: cmd("-t", "filter", "-A", exitChain, "-i", c.Interface, "!", "-s", prefix, "-j", "DROP")},
			iptablesStep{tool: tool, args: cmd("-t", "filter", "-I", "FORWARD", "1", "-j", exitChain), ifMissing: cmd("-t", "filter", "-C", "FORWARD", "-j", exitChain)},
			iptablesStep{tool: tool, args: cmd("-t", "nat", "-N", exitNATChain), mayFail: true},
			iptablesStep{tool: tool, args: cmd("-t", "nat", "-F", exitNATChain)},
		)
		steps = append(steps, exitSourceSteps(c, tool, prefix)...) // #408
		steps = append(steps,
			iptablesStep{tool: tool, args: cmd("-t", "nat", "-A", exitNATChain, "!", "-o", c.Interface, "-s", prefix, "-j", "MASQUERADE")},
			iptablesStep{tool: tool, args: cmd("-t", "nat", "-I", "POSTROUTING", "1", "-j", exitNATChain), ifMissing: cmd("-t", "nat", "-C", "POSTROUTING", "-j", exitNATChain)},
		)
	}
	family("iptables", c.IPv4.Masked().String(), exitBlocked4)
	family("ip6tables", c.IPv6.Masked().String(), exitBlocked6)
	steps = append(steps, exitRateSteps(c)...)  // #83, ADR-0133
	return append(steps, exitPolicySteps(c)...) // P04
}

// removeExitRules deletes both backends' rules; whichever is absent is
// skipped. A daemon that crashed may have left either behind.
func removeExitRules(ctx context.Context, o sysOps) {
	if o.has("nft") {
		_, _ = o.run(ctx, nil, "nft", "delete", "table", "inet", exitTable)
	}
	for _, tool := range []string{"iptables", "ip6tables"} {
		if !o.has(tool) {
			continue
		}
		for _, t := range []struct{ table, parent, chain string }{
			{"filter", "FORWARD", exitChain},
			{"nat", "POSTROUTING", exitNATChain},
		} {
			// Remove every jump (at most a few), then the chain itself.
			for i := 0; i < 8; i++ {
				if _, err := o.run(ctx, nil, tool, "-w", "5", "-t", t.table, "-D", t.parent, "-j", t.chain); err != nil {
					break
				}
			}
			_, _ = o.run(ctx, nil, tool, "-w", "5", "-t", t.table, "-F", t.chain)
			_, _ = o.run(ctx, nil, tool, "-w", "5", "-t", t.table, "-X", t.chain)
		}
		removeExitPolicyChains(ctx, o, tool) // P04
	}
}
