//go:build !linux && !darwin && (!windows || !(amd64 || arm64))

package osnet

import "github.com/openscale/openscale/internal/dnsguard"

// unsupportedDNSEnforcer refuses to apply and has nothing to remove.
type unsupportedDNSEnforcer struct{}

func (unsupportedDNSEnforcer) Apply([]dnsguard.Rule) error { return ErrDNSEnforceUnsupported }
func (unsupportedDNSEnforcer) Remove() error               { return nil }

// NewDNSEnforcer returns an applier that reports the missing support.
func NewDNSEnforcer() dnsguard.Applier { return unsupportedDNSEnforcer{} }

// DNSEnforceSupported reports false: no DNS enforcement on this system.
func DNSEnforceSupported() bool { return false }
