//go:build linux

package osnet

import (
	"context"
	"strconv"
)

// configure sets the addresses with "replace": an interface kept across an
// update (TUNSETPERSIST, tun_persist_linux.go) already has them.
func configure(ctx context.Context, c Config) error {
	steps := [][]string{
		{"link", "set", "dev", c.Interface, "mtu", strconv.Itoa(c.MTU)},
		{"-4", "addr", "replace", c.IPv4.String(), "dev", c.Interface},
		{"-6", "addr", "replace", c.IPv6.String(), "dev", c.Interface},
		{"link", "set", "dev", c.Interface, "up"},
	}
	for _, args := range steps {
		if err := run(ctx, "ip", args...); err != nil {
			return err
		}
	}
	return nil
}
