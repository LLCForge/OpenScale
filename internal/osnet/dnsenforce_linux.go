//go:build linux

package osnet

import "github.com/openscale/openscale/internal/dnsguard"

// NewDNSEnforcer returns the Linux applier of the #717 rules: the
// nftables table "inet openscale_dns" (dnsenforce.go). The table lives in
// the kernel and outlives a crashed service; the service removes a stale
// one when it starts.
func NewDNSEnforcer() dnsguard.Applier {
	return &nftDNSEnforcer{run: hostOps.run, has: hostOps.has}
}

// DNSEnforceSupported reports whether nft is installed.
func DNSEnforceSupported() bool { return hostOps.has("nft") }
