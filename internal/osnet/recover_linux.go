//go:build linux

package osnet

import (
	"context"
	"errors"
)

// RecoverExitClient removes the exit node policy rules, the tunnel route
// table, the leak guard and the client table a crashed run left behind.
// The interface itself, and with it its routes and resolvectl settings,
// disappears with the process.
func RecoverExitClient(ctx context.Context, iface string) error {
	if !validRecoverInterface(iface) {
		return errors.New("invalid interface name in the change journal")
	}
	o := hostOps
	deleteExitRules(ctx, o, true)
	removeLeakGuard(ctx, o)
	if o.has("nft") {
		_, _ = o.run(ctx, nil, "nft", "delete", "table", "inet", exitClientTable)
	}
	if o.has("resolvectl") {
		_, _ = o.run(ctx, nil, "resolvectl", "revert", iface)
		_, _ = o.run(ctx, nil, "resolvectl", "flush-caches")
	}
	return nil
}

// RecoverExitNAT removes exit node forwarding and NAT rules of either
// backend. Forwarding sysctls are left as they are.
func RecoverExitNAT(ctx context.Context) error {
	removeExitRules(ctx, hostOps)
	RecoverUpstream(ctx) // ADR-0142: upstream exit rules of a crashed run
	return nil
}
