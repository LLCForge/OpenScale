//go:build !linux

package osnet

import "context"

// CheckHostFirewall has nothing to check here: the Windows service adds
// its own firewall rule (OS-143).
func CheckHostFirewall(context.Context, string, string) ([]HostFirewallFinding, error) {
	return nil, nil
}
