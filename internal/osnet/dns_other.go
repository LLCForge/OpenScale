//go:build !linux && !windows && !darwin

package osnet

import (
	"context"
	"errors"
)

func configureDNS(context.Context, DNSConfig) error {
	return errors.New("MagicDNS is only implemented for Linux and Windows")
}

func removeDNS(context.Context, DNSConfig) error { return nil }

func verifyNetworkDNS(context.Context, DNSConfig, NetworkDNS) error { return nil }

func systemDNSStatus(string) DNSSystemStatus { return DNSSystemStatus{} }

func configureNetworkDNS(_ context.Context, _ DNSConfig, n NetworkDNS) error {
	if n.Empty() {
		return nil
	}
	return ErrNetworkDNSUnsupported
}
