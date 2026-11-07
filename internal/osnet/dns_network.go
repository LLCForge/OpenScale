package osnet

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// Network-wide DNS from the signed document (ADR-0024, F-051, F-052).

// Limits mirror the document's dns section; they also bound the size of
// the generated commands.
const (
	maxNetworkNameservers = 4
	maxNetworkSplit       = 32
	maxSplitNameservers   = 4
)

// NRPTComment marks every Name Resolution Policy Table rule OpenScale owns
// on Windows, so only those are ever replaced or removed.
const NRPTComment = "OpenScale"

// ErrNetworkDNSUnsupported is returned where network DNS cannot be applied
// without breaking MagicDNS.
var ErrNetworkDNSUnsupported = errors.New("network DNS settings are not supported on this system")

// NetworkDNS is the part of the document's dns section this device
// applies. Nameservers are used for every name MagicDNS does not answer;
// callers leave them out while an exit node is in use (the exit node then
// resolves, ADR-0018). Split sends a domain and its subdomains to its own
// resolvers.
type NetworkDNS struct {
	Nameservers []netip.Addr
	Split       []SplitDomain
	// Search lists the search domains (F-053): the network domain or split
	// domains, checked against Split.
	Search []string
	// ExitActive is set while an exit node is in use: on Linux every name
	// then goes through MagicDNS, which forwards it to the exit node
	// (ADR-0034); Windows keeps the exit node's own rule.
	ExitActive bool
	// CatchAll sends every name to MagicDNS on Windows (one "." NRPT rule)
	// when network-wide resolvers are set; MagicDNS then forwards split
	// domains and the rest itself (F-063).
	CatchAll bool
	// Overlay holds the network's address ranges. Every resolver must lie
	// inside them, so no setting can send queries outside the tunnel even
	// if a document were wrong (the document already requires tunnel
	// addresses of devices).
	Overlay []netip.Prefix
}

// SplitDomain is one split DNS entry.
type SplitDomain struct {
	Domain      string
	Nameservers []netip.Addr
}

// Empty reports whether there is nothing to apply.
func (n NetworkDNS) Empty() bool {
	return len(n.Nameservers) == 0 && len(n.Split) == 0 && len(n.Search) == 0
}

// Key is a canonical text form, for noticing a change.
func (n NetworkDNS) Key() string {
	var b strings.Builder
	b.WriteString(joinAddrs(n.Nameservers, ","))
	for _, s := range n.Split {
		b.WriteString(";" + s.Domain + "=" + joinAddrs(s.Nameservers, ","))
	}
	if len(n.Search) > 0 {
		b.WriteString(";search=" + strings.Join(n.Search, ","))
	}
	if n.ExitActive {
		b.WriteString(";exit")
	}
	if n.CatchAll {
		b.WriteString(";catchall")
	}
	return b.String()
}

func (n NetworkDNS) validate(magic DNSConfig) error {
	if len(n.Nameservers) > maxNetworkNameservers || len(n.Split) > maxNetworkSplit {
		return errors.New("too many DNS entries")
	}
	if err := n.checkResolvers(n.Nameservers); err != nil {
		return err
	}
	seen := make(map[string]bool, len(n.Split))
	for _, s := range n.Split {
		if !validDomain(s.Domain) {
			return fmt.Errorf("invalid split DNS domain %q", s.Domain)
		}
		if domainsOverlap(s.Domain, magic.Domain) {
			return fmt.Errorf("split DNS domain %q overlaps the MagicDNS domain", s.Domain)
		}
		if seen[s.Domain] {
			return fmt.Errorf("split DNS domain %q is listed twice", s.Domain)
		}
		seen[s.Domain] = true
		if len(s.Nameservers) == 0 || len(s.Nameservers) > maxSplitNameservers {
			return fmt.Errorf("split DNS domain %q needs 1-%d resolvers", s.Domain, maxSplitNameservers)
		}
		if err := n.checkResolvers(s.Nameservers); err != nil {
			return err
		}
	}
	if len(n.Search) > maxSearchDomains {
		return errors.New("too many search domains")
	}
	for _, d := range n.Search {
		// Only names this device already sends inside the tunnel.
		if d != magic.Domain && !seen[d] {
			return fmt.Errorf("search domain %q is neither the network domain nor a split domain", d)
		}
	}
	return nil
}

// maxSearchDomains mirrors the document's limit.
const maxSearchDomains = 8

// ErrDNSOverwritten reports that another program replaced the DNS settings
// OpenScale applied (F-061); applying them again repairs it.
var ErrDNSOverwritten = errors.New("DNS settings were changed by another program")

// VerifyNetworkDNS checks that the settings ConfigureNetworkDNS applied
// (or ConfigureDNS, for an empty n) are still in place. It returns
// ErrDNSOverwritten when they were changed, nil when they are intact or
// cannot be checked on this system.
func VerifyNetworkDNS(ctx context.Context, magic DNSConfig, n NetworkDNS) error {
	if err := magic.validate(); err != nil {
		return err
	}
	return verifyNetworkDNS(ctx, magic, n)
}

// DNSSystemStatus describes how this system resolves names, for the
// health checks (F-062): the Linux backend in use and, on Windows,
// whether Group Policy NRPT rules override OpenScale's own rules (F-063).
type DNSSystemStatus struct {
	Backend DNSBackend
	// GroupPolicyNRPT is set when Group Policy defines NRPT rules: Windows
	// then ignores locally added rules, MagicDNS included.
	GroupPolicyNRPT bool
	// GroupPolicyRules are those rules (at most maxGPORules), for the
	// conflict details of NRPTGroupPolicyConflict (#272).
	GroupPolicyRules []NRPTRuleInfo
}

// SystemDNSStatus returns the DNS status of this system for the tunnel
// interface.
func SystemDNSStatus(iface string) DNSSystemStatus { return systemDNSStatus(iface) }

func (n NetworkDNS) checkResolvers(addrs []netip.Addr) error {
	for _, a := range addrs {
		if !a.IsValid() || a.Zone() != "" || a.Is4In6() || a.IsUnspecified() {
			return fmt.Errorf("invalid DNS resolver %v", a)
		}
		inside := false
		for _, p := range n.Overlay {
			if p.IsValid() && p.Contains(a) {
				inside = true
			}
		}
		if !inside {
			return fmt.Errorf("DNS resolver %v is outside the network", a)
		}
	}
	return nil
}

// domainsOverlap reports whether a equals b or one is below the other.
func domainsOverlap(a, b string) bool {
	return a == b || strings.HasSuffix(a, "."+b) || strings.HasSuffix(b, "."+a)
}

func joinAddrs(addrs []netip.Addr, sep string) string {
	parts := make([]string, len(addrs))
	for i, a := range addrs {
		parts[i] = a.String()
	}
	return strings.Join(parts, sep)
}

// nrptScript builds the PowerShell script that replaces every OpenScale
// NRPT rule with: the MagicDNS rule, one rule per split domain and, when
// network-wide resolvers are given, a "." rule for every other name. It is
// built only from validated values: domains are lowercase labels and
// addresses are formatted by netip, so nothing can break out of the single
// quotes.
func nrptScript(magic DNSConfig, n NetworkDNS) (string, error) {
	if err := magic.validate(); err != nil {
		return "", err
	}
	if err := n.validate(magic); err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("$ErrorActionPreference='Stop'; ")
	b.WriteString("Get-DnsClientNrptRule | Where-Object { $_.Comment -eq '" + NRPTComment + "' } | ForEach-Object { Remove-DnsClientNrptRule -Name $_.Name -Force }; ")
	add := func(namespace string, servers []netip.Addr) {
		b.WriteString("Add-DnsClientNrptRule -Namespace '" + namespace + "' -NameServers " + quotedAddrs(servers) +
			" -Comment '" + NRPTComment + "' | Out-Null; ")
	}
	add("."+magic.Domain, []netip.Addr{magic.Server})
	if n.CatchAll && len(n.Nameservers) > 0 {
		// One "." rule to MagicDNS, which forwards split domains and every
		// other name through the tunnel (F-063, ADR-0034).
		add(".", []netip.Addr{magic.Server})
	} else {
		for _, s := range n.Split {
			add("."+s.Domain, s.Nameservers)
		}
		if len(n.Nameservers) > 0 {
			add(".", n.Nameservers)
		}
	}
	// Short names (F-053): Windows appends the adapter's suffix; NRPT
	// itself has no search list. Only the first search domain fits.
	suffix := ""
	if len(n.Search) > 0 {
		suffix = n.Search[0]
	}
	b.WriteString("try { Set-DnsClient -InterfaceAlias '" + magic.Interface + "' -ConnectionSpecificSuffix '" + suffix + "' } catch { }; ")
	b.WriteString("Clear-DnsClientCache")
	return b.String(), nil
}

func quotedAddrs(addrs []netip.Addr) string {
	parts := make([]string, len(addrs))
	for i, a := range addrs {
		parts[i] = "'" + a.String() + "'"
	}
	return strings.Join(parts, ",")
}

// ConfigureNetworkDNS applies MagicDNS together with the network's DNS
// settings, replacing whatever OpenScale applied before. An empty n leaves
// only MagicDNS, which is how the settings are removed while the tunnel
// stays up; RemoveDNS removes everything when the tunnel goes down.
func ConfigureNetworkDNS(ctx context.Context, magic DNSConfig, n NetworkDNS) error {
	if err := magic.validate(); err != nil {
		return err
	}
	if err := n.validate(magic); err != nil {
		return err
	}
	return configureNetworkDNS(ctx, magic, n)
}

// runDNSCommand runs one DNS command; tests replace it with a recorder so
// no test changes the host.
var runDNSCommand = run
