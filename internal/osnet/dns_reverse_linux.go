//go:build linux

package osnet

import (
	"context"
	"net/netip"
)

// ConfigureReverseDNS routes the reverse (PTR) zones of the network ranges
// to MagicDNS as well, so "100.80.0.2" resolves to its device name
// (ADR-0024, F-056). It replaces the link's domain list, keeping the
// network domain from ConfigureDNS. Without systemd-resolved every query
// reaches MagicDNS first anyway (ADR-0034), so there is nothing to do.
func ConfigureReverseDNS(ctx context.Context, c DNSConfig, v4, v6 netip.Prefix) error {
	if err := c.validate(); err != nil {
		return err
	}
	if linuxDNS.backendFor(c.Interface) != BackendResolved {
		return nil
	}
	args := append([]string{"domain", c.Interface}, linkDomains(c.Domain, v4, v6)...)
	_, err := linuxDNS.sys.run(ctx, nil, "resolvectl", args...)
	return err
}
