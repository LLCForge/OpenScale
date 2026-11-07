//go:build linux

package osnet

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/openscale/openscale/internal/trust"
)

const (
	// exitFwMark marks WireGuard's own UDP packets ("OS"). Marked packets
	// skip the tunnel table and use the real default route, so they never
	// loop into the tunnel.
	exitFwMark = TunnelBypassMark
	// exitRouteTable holds the split routes into the tunnel.
	exitRouteTable = "20307"
	// Rule priorities: first the main table without its default routes
	// (LAN and overlay stay reachable), then the tunnel table for every
	// unmarked packet. They sit before the main table (32766).
	exitRulePrioMain   = "5270"
	exitRulePrioTunnel = "5271"
	// exitClientTable restores the mark on replies when rp_filter is
	// strict, the same way wg-quick does.
	exitClientTable = "openscale_client"
)

var exitClientRules = `table inet ` + exitClientTable + `
delete table inet ` + exitClientTable + `
table inet ` + exitClientTable + ` {
	chain premangle {
		type filter hook prerouting priority mangle; policy accept;
		meta l4proto udp meta mark set ct mark
	}
	chain postmangle {
		type filter hook postrouting priority mangle; policy accept;
		meta l4proto udp meta mark ` + strconv.Itoa(exitFwMark) + ` ct mark set meta mark
	}
}
`

// linuxExitRouter sends all internet traffic into the tunnel while an exit
// node is used (ADR-0018). The split routes live in their own table, so
// the real default route is never touched: WireGuard's marked packets and
// every more specific main-table route (LAN, overlay) keep working. If the
// exit node is unreachable, traffic stays in the tunnel instead of leaking.
//
// The socket mark is set once through bind.SetMark. The engine hands over a
// bind whose SetMark stores the mark in the WireGuard device, which applies
// it again every time it reopens its sockets (device up, port change), so
// no periodic re-marking is needed.
type linuxExitRouter struct {
	ops sysOps

	mu    sync.Mutex
	state *exitRouterState
}

// exitRouterState is what Enable changed, for Disable to undo.
type exitRouterState struct {
	iface        string
	bind         conn.Bind
	ipv6         bool
	connmark     bool
	srcValidMark string // old value, "" when unchanged
	resolver     netip.Addr
	// domains are the link's MagicDNS routing domains (network domain and
	// reverse zones), restored by Disable.
	domains []string
}

// NewExitRouter returns the OS router for using an exit node.
func NewExitRouter() interface {
	Enable(trust.Device, *trust.Document, string, conn.Bind) error
	Disable() error
} {
	return &linuxExitRouter{ops: hostOps}
}

func (r *linuxExitRouter) Enable(exit trust.Device, doc *trust.Document, iface string, bind conn.Bind) error {
	if !validSysctlName(iface) {
		return fmt.Errorf("invalid interface name %q", iface)
	}
	if err := (DNSConfig{Interface: iface, Server: exit.IPv4, Domain: "x.internal"}).validate(); err != nil {
		return err
	}
	if bind == nil {
		return errors.New("WireGuard soketleri işaretlenemiyor")
	}
	_ = r.Disable()
	if !r.ops.has("resolvectl") {
		// Without split DNS the system resolver (often the LAN router)
		// would see every query: refuse instead of leaking (ADR-0018).
		return errors.New("systemd-resolved (resolvectl) bulunamadı; DNS sızıntısını önlemek için çıkış düğümü açılmadı")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	st := &exitRouterState{iface: iface, bind: bind}
	if doc != nil && validDomain(doc.DNSDomain) {
		st.resolver, st.domains = doc.DNSResolverIPv4(), linkDomains(doc.DNSDomain, doc.IPv4Prefix, doc.IPv6Prefix)
	}
	_, err := r.ops.read("/proc/net/if_inet6")
	st.ipv6 = err == nil

	if err := bind.SetMark(exitFwMark); err != nil {
		return fmt.Errorf("WireGuard soketleri işaretlenemedi: %w", err)
	}
	if err := r.setup(ctx, st, exit.IPv4); err != nil {
		_ = r.cleanup(ctx, st)
		return err
	}

	r.mu.Lock()
	r.state = st
	r.mu.Unlock()
	return nil
}

func (r *linuxExitRouter) setup(ctx context.Context, st *exitRouterState, exitDNS netip.Addr) error {
	o := r.ops
	// Rules left behind by a daemon that crashed would be duplicated.
	deleteExitRules(ctx, o, st.ipv6)
	if strictRPFilter(o) {
		// Replies from peers arrive unmarked; strict reverse-path checks
		// would look them up in the tunnel table and drop them.
		if !o.has("nft") {
			return errors.New("rp_filter sıkı kipte ve nft bulunamadı; çıkış düğümü kullanılamıyor")
		}
		old, err := o.sysctlGet("net/ipv4/conf/all/src_valid_mark")
		if err != nil {
			return err
		}
		if old != "1" {
			if err := o.sysctlSet(ctx, "net/ipv4/conf/all/src_valid_mark", "1"); err != nil {
				return err
			}
			st.srcValidMark = old
		}
		st.connmark = true
		if _, err := o.run(ctx, []byte(exitClientRules), "nft", "-f", "-"); err != nil {
			return err
		}
	}

	mark := strconv.Itoa(exitFwMark)
	families := []struct {
		flag   string
		routes []string
	}{{"-4", []string{"0.0.0.0/1", "128.0.0.0/1"}}}
	if st.ipv6 {
		families = append(families, struct {
			flag   string
			routes []string
		}{"-6", []string{"::/1", "8000::/1"}})
	}
	for _, f := range families {
		for _, p := range f.routes {
			if _, err := o.run(ctx, nil, "ip", f.flag, "route", "replace", p, "dev", st.iface, "table", exitRouteTable); err != nil {
				return err
			}
		}
		if _, err := o.run(ctx, nil, "ip", f.flag, "rule", "add", "priority", exitRulePrioMain, "table", "main", "suppress_prefixlength", "0"); err != nil {
			return err
		}
		if _, err := o.run(ctx, nil, "ip", f.flag, "rule", "add", "priority", exitRulePrioTunnel, "not", "fwmark", mark, "table", exitRouteTable); err != nil {
			return err
		}
	}

	// Every query goes to the exit node; MagicDNS names sent there are
	// still answered locally by the daemon.
	if _, err := o.run(ctx, nil, "resolvectl", "dns", st.iface, exitDNS.String()); err != nil {
		return err
	}
	domains := append([]string{"domain", st.iface, "~."}, st.domains...)
	if _, err := o.run(ctx, nil, "resolvectl", domains...); err != nil {
		return err
	}
	_, _ = o.run(ctx, nil, "resolvectl", "flush-caches")
	// DNS and global IPv6 only through the tunnel (#93, #75).
	return installLeakGuard(ctx, o, st)
}

func (r *linuxExitRouter) Disable() error {
	r.mu.Lock()
	st := r.state
	r.state = nil
	r.mu.Unlock()
	if st == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	return r.cleanup(ctx, st)
}

// cleanup undoes setup; every step runs even if an earlier one fails.
func (r *linuxExitRouter) cleanup(ctx context.Context, st *exitRouterState) error {
	o := r.ops
	var errs []error
	if err := st.bind.SetMark(0); err != nil {
		errs = append(errs, err)
	}
	deleteExitRules(ctx, o, st.ipv6)
	removeLeakGuard(ctx, o)
	if st.connmark {
		_, _ = o.run(ctx, nil, "nft", "delete", "table", "inet", exitClientTable)
	}
	if st.srcValidMark != "" {
		if err := o.sysctlSet(ctx, "net/ipv4/conf/all/src_valid_mark", st.srcValidMark); err != nil {
			errs = append(errs, err)
		}
	}
	// Back to MagicDNS only (ADR-0016).
	if len(st.domains) > 0 {
		if _, err := o.run(ctx, nil, "resolvectl", "dns", st.iface, st.resolver.String()); err != nil {
			errs = append(errs, err)
		}
		if _, err := o.run(ctx, nil, "resolvectl", append([]string{"domain", st.iface}, st.domains...)...); err != nil {
			errs = append(errs, err)
		}
	} else {
		_, _ = o.run(ctx, nil, "resolvectl", "revert", st.iface)
	}
	_, _ = o.run(ctx, nil, "resolvectl", "flush-caches")
	return errors.Join(errs...)
}

// deleteExitRules removes the policy rules and the tunnel table routes.
func deleteExitRules(ctx context.Context, o sysOps, ipv6 bool) {
	flags := []string{"-4"}
	if ipv6 {
		flags = append(flags, "-6")
	}
	for _, f := range flags {
		for _, prio := range []string{exitRulePrioTunnel, exitRulePrioMain} {
			for i := 0; i < 8; i++ {
				if _, err := o.run(ctx, nil, "ip", f, "rule", "del", "priority", prio); err != nil {
					break
				}
			}
		}
		_, _ = o.run(ctx, nil, "ip", f, "route", "flush", "table", exitRouteTable)
	}
}

// strictRPFilter reports whether reverse-path filtering is strict (1) for
// the interface of the IPv4 default route. The kernel uses the larger of
// the "all" and the interface value.
func strictRPFilter(o sysOps) bool {
	all, err := o.sysctlGet("net/ipv4/conf/all/rp_filter")
	if err != nil {
		return false // no /proc: nothing to adapt to
	}
	effective := all
	for _, dev := range o.ipv4DefaultInterfaces() {
		v, err := o.sysctlGet("net/ipv4/conf/" + dev + "/rp_filter")
		if err == nil && v > effective {
			effective = v
		}
	}
	return effective == "1"
}
