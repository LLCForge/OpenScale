//go:build windows

package osnet

import (
	"context"
	"errors"
	"slices"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// Windows DNS details (F-061, F-062, F-063, ADR-0034).

const (
	// nrptLocalKey holds the NRPT rules added with Add-DnsClientNrptRule.
	nrptLocalKey = `SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig`
	// nrptGPOKey holds rules from Group Policy. While it has any, Windows
	// ignores the local rules (OpenScale's included).
	nrptGPOKey = `SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig`
)

// adapterHardening is the script part that keeps the tunnel adapter out of
// dynamic DNS registration (the tunnel address must not be written to a
// corporate DNS server) and turns NetBIOS off on it. Failures are ignored:
// they leave Windows' defaults, never break MagicDNS. iface is validated
// (no quotes).
func adapterHardening(iface string) string {
	return "try { Set-DnsClient -InterfaceAlias '" + iface + "' -RegisterThisConnectionsAddress $false } catch { }; " +
		"try { $i = (Get-NetAdapter -Name '" + iface + "' -ErrorAction Stop).InterfaceIndex; " +
		"Get-CimInstance Win32_NetworkAdapterConfiguration -Filter \"InterfaceIndex=$i\" | " +
		"Invoke-CimMethod -MethodName SetTcpipNetbios -Arguments @{TcpipNetbiosOptions=[uint32]2} | Out-Null } catch { }; "
}

// nrptRule is one rule as stored in the registry.
type nrptRule struct {
	namespaces []string
	servers    []string
}

// readNRPT returns the rules under key; a missing key is no rules. Tests
// replace it.
var readNRPT = func(key string) ([]nrptRule, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, key, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer k.Close()
	names, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return nil, err
	}
	var out []nrptRule
	for _, n := range names {
		sk, err := registry.OpenKey(k, n, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		ns, _, _ := sk.GetStringsValue("Name")
		servers, _, _ := sk.GetStringValue("GenericDNSServers")
		sk.Close()
		var list []string
		for _, s := range strings.Split(servers, ";") {
			if s = strings.TrimSpace(s); s != "" {
				list = append(list, s)
			}
		}
		out = append(out, nrptRule{namespaces: ns, servers: list})
	}
	return out, nil
}

// verifyNetworkDNS checks that the NRPT still sends the network domain and
// the split domains where OpenScale put them (F-061). Unreadable rules are
// not reported as a change.
func verifyNetworkDNS(_ context.Context, magic DNSConfig, n NetworkDNS) error {
	rules, err := readNRPT(nrptLocalKey)
	if err != nil {
		return nil
	}
	has := func(namespace, server string) bool {
		for _, r := range rules {
			if slices.Contains(r.namespaces, namespace) && slices.Contains(r.servers, server) {
				return true
			}
		}
		return false
	}
	if !has("."+magic.Domain, magic.Server.String()) {
		return ErrDNSOverwritten
	}
	if n.CatchAll && len(n.Nameservers) > 0 {
		if !has(".", magic.Server.String()) {
			return ErrDNSOverwritten
		}
		return nil
	}
	for _, s := range n.Split {
		if len(s.Nameservers) > 0 && !has("."+s.Domain, s.Nameservers[0].String()) {
			return ErrDNSOverwritten
		}
	}
	return nil
}

// systemDNSStatus reports Group Policy NRPT rules, which make Windows
// ignore OpenScale's rules (F-063).
func systemDNSStatus(string) DNSSystemStatus {
	rules, err := readNRPT(nrptGPOKey)
	st := DNSSystemStatus{Backend: BackendNRPT, GroupPolicyNRPT: err == nil && len(rules) > 0}
	if st.GroupPolicyNRPT {
		for _, r := range rules[:min(len(rules), maxGPORules)] {
			st.GroupPolicyRules = append(st.GroupPolicyRules, NRPTRuleInfo{Namespaces: slices.Clone(r.namespaces), Servers: slices.Clone(r.servers)})
		}
	}
	return st
}

// NRPTGroupPolicyWarning returns the owner's warning when Group Policy NRPT
// rules make Windows ignore the rule for the network domain (#272); empty
// otherwise. It only reads the registry.
func NRPTGroupPolicyWarning(magic DNSConfig) string {
	c := NRPTGroupPolicyConflict(systemDNSStatus(magic.Interface), magic.Domain, magic.Server.String())
	return c.Message(magic.Domain)
}
