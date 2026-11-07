package osnet

import (
	"context"
	"errors"
	"net/netip"
	"strings"
)

// DNSConfig routes one domain to the MagicDNS resolver (ADR-0016). Only
// names under Domain go there; every other query keeps its normal path.
type DNSConfig struct {
	Interface string
	Server    netip.Addr
	Domain    string
}

func (c DNSConfig) validate() error {
	if c.Interface == "" || strings.ContainsAny(c.Interface, " \"'\t\n;&|`$") {
		return errors.New("invalid interface name")
	}
	if !c.Server.Is4() {
		return errors.New("invalid DNS server address")
	}
	if !validDomain(c.Domain) {
		return errors.New("invalid DNS domain")
	}
	return nil
}

// validDomain allows lowercase labels only, so the domain is safe to place
// in command arguments.
func validDomain(d string) bool {
	if len(d) == 0 || len(d) > 253 {
		return false
	}
	for _, label := range strings.Split(d, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}

// ConfigureDNS sends queries for the domain to the resolver.
func ConfigureDNS(ctx context.Context, c DNSConfig) error {
	if err := c.validate(); err != nil {
		return err
	}
	return configureDNS(ctx, c)
}

// RemoveDNS undoes ConfigureDNS. Missing settings are not an error.
func RemoveDNS(ctx context.Context, c DNSConfig) error {
	if err := c.validate(); err != nil {
		return err
	}
	return removeDNS(ctx, c)
}
