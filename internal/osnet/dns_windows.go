//go:build windows

package osnet

import (
	"context"
)

// nrptComment marks the rules OpenScale owns, so only those are removed.
const nrptComment = NRPTComment

// configureDNS adds a Name Resolution Policy Table rule: the DNS client
// sends queries for ".<domain>" to the resolver and nothing else changes.
func configureDNS(ctx context.Context, c DNSConfig) error {
	script := "$ErrorActionPreference='Stop'; " +
		"Get-DnsClientNrptRule | Where-Object { $_.Comment -eq '" + nrptComment + "' } | ForEach-Object { Remove-DnsClientNrptRule -Name $_.Name -Force }; " +
		"Add-DnsClientNrptRule -Namespace '." + c.Domain + "' -NameServers '" + c.Server.String() + "' -Comment '" + nrptComment + "' | Out-Null; " +
		adapterHardening(c.Interface) +
		"Clear-DnsClientCache"
	return runPowerShell(ctx, script)
}

func removeDNS(ctx context.Context, _ DNSConfig) error {
	script := "$ErrorActionPreference='Stop'; " +
		"Get-DnsClientNrptRule | Where-Object { $_.Comment -eq '" + nrptComment + "' } | ForEach-Object { Remove-DnsClientNrptRule -Name $_.Name -Force }; " +
		"Clear-DnsClientCache"
	return runPowerShell(ctx, script)
}

// configureNetworkDNS replaces the OpenScale NRPT rules with MagicDNS, the
// split domains and, without an exit node, the "." rule (ADR-0024).
func configureNetworkDNS(ctx context.Context, magic DNSConfig, n NetworkDNS) error {
	script, err := nrptScript(magic, n)
	if err != nil {
		return err
	}
	return runPowerShell(ctx, script)
}

// runPowerShell runs a fixed script built only from validated values. The
// program is named, not given as a path: run finds it in the system folders
// and refuses absolute paths (F-125).
func runPowerShell(ctx context.Context, script string) error {
	return runDNSCommand(ctx, "powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
}
