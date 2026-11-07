//go:build windows

package osnet

import (
	"context"
	"net"
	"strconv"
)

func configure(ctx context.Context, c Config) error {
	mask := net.IP(net.CIDRMask(c.IPv4.Bits(), 32)).String()
	steps := [][]string{
		{"interface", "ipv4", "set", "address", "name=" + c.Interface, "source=static", "address=" + c.IPv4.Addr().String(), "mask=" + mask},
		{"interface", "ipv6", "add", "address", "interface=" + c.Interface, "address=" + c.IPv6.String(), "store=active"},
		{"interface", "ipv4", "set", "subinterface", c.Interface, "mtu=" + strconv.Itoa(c.MTU), "store=active"},
		{"interface", "ipv6", "set", "subinterface", c.Interface, "mtu=" + strconv.Itoa(c.MTU), "store=active"},
	}
	for _, args := range steps {
		if err := run(ctx, "netsh", args...); err != nil {
			return err
		}
	}
	return nil
}
