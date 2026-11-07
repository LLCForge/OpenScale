//go:build darwin

package osnet

import "context"

// MagicDNS and split DNS through /etc/resolver (ADR-0100).

func configureDNS(ctx context.Context, c DNSConfig) error { return hostDarwinDNS.configure(ctx, c) }

func removeDNS(ctx context.Context, _ DNSConfig) error { return hostDarwinDNS.removeAll(ctx) }

func verifyNetworkDNS(_ context.Context, magic DNSConfig, n NetworkDNS) error {
	return hostDarwinDNS.verify(magic, n)
}

func systemDNSStatus(string) DNSSystemStatus { return DNSSystemStatus{Backend: BackendResolverDir} }

func configureNetworkDNS(ctx context.Context, magic DNSConfig, n NetworkDNS) error {
	return hostDarwinDNS.configureNetwork(ctx, magic, n)
}
