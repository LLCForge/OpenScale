// Package osnet assigns the overlay addresses to the OS tunnel interface.
// Commands are executed directly with fixed arguments, never through a
// shell. Addresses and routes disappear together with the interface when
// the daemon closes it, so no separate rollback is needed.
package osnet

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// Config describes the interface addresses.
type Config struct {
	Interface string
	// IPv4 and IPv6 are this device's addresses with the network prefix
	// length, e.g. 100.80.0.1/16, so the whole overlay routes through the
	// interface.
	IPv4 netip.Prefix
	IPv6 netip.Prefix
	MTU  int
}

const commandTimeout = 15 * time.Second

func run(ctx context.Context, name string, args ...string) error {
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	// System tools only by absolute path (F-125).
	cmd, err := toolCommand(ctx, name, args...)
	if err != nil {
		return err
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (c Config) validate() error {
	if c.Interface == "" || strings.ContainsAny(c.Interface, " \"'\t\n;&|") {
		return fmt.Errorf("invalid interface name %q", c.Interface)
	}
	if !c.IPv4.IsValid() || !c.IPv4.Addr().Is4() || !c.IPv6.IsValid() || !c.IPv6.Addr().Is6() {
		return fmt.Errorf("invalid interface addresses")
	}
	if c.MTU < 1280 || c.MTU > 9000 {
		return fmt.Errorf("invalid MTU %d", c.MTU)
	}
	return nil
}

// Configure assigns addresses and MTU and brings the interface up.
func Configure(ctx context.Context, c Config) error {
	if err := c.validate(); err != nil {
		return err
	}
	return configure(ctx, c)
}
