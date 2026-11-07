//go:build darwin

package osnet

import "github.com/openscale/openscale/internal/dnsguard"

// NewDNSEnforcer returns the macOS applier of the #717 rules: the pf
// sub-anchor "com.openscale/dns" (dnsenforce.go), evaluated while the
// kill switch anchor is in place.
func NewDNSEnforcer() dnsguard.Applier {
	return &pfDNSEnforcer{run: cmdRunner(darwinRun), exists: darwinExists}
}

// DNSEnforceSupported reports whether pfctl is present.
func DNSEnforceSupported() bool { return darwinExists(darwinPfctl) }
