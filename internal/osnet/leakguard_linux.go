//go:build linux

package osnet

import (
	"context"
	"fmt"
	"sync/atomic"
)

// leakGuardOn records whether this process installed the DNS and IPv6 leak
// guard (#75, #93) with the exit node routes.
var leakGuardOn atomic.Bool

// LeakGuardActive reports whether DNS and global IPv6 are held to the
// tunnel while the exit node is in use (#75, #93).
func LeakGuardActive() bool { return leakGuardOn.Load() }

// installLeakGuard adds the leak guard table. Without nft the exit node
// still works (the routes keep DNS and IPv6 in the tunnel), but the guard
// is missing and the leak test says so; when nft exists and fails, the
// exit node is refused instead of running unguarded (fail closed).
func installLeakGuard(ctx context.Context, o sysOps, st *exitRouterState) error {
	if !o.has("nft") {
		leakGuardOn.Store(false)
		return nil
	}
	script, err := nftLeakGuardScript(st.iface)
	if err != nil {
		return err
	}
	if _, err := o.run(ctx, []byte(script), "nft", "-f", "-"); err != nil {
		return fmt.Errorf("DNS/IPv6 sızıntı engeli kurulamadı: %w", err)
	}
	leakGuardOn.Store(true)
	return nil
}

// removeLeakGuard deletes the leak guard table; a missing table is fine.
func removeLeakGuard(ctx context.Context, o sysOps) {
	leakGuardOn.Store(false)
	if o.has("nft") {
		_, _ = o.run(ctx, nil, "nft", "delete", "table", "inet", leakGuardTable)
	}
}
