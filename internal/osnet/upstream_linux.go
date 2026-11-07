//go:build linux

package osnet

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"text/template"
)

const (
	upstreamTable = "openscale_upstream"
	// upstreamRouteTable holds the upstream default route, the drop
	// routes and the overlay routes for replies.
	upstreamRouteTable = "20308"
	// Rule priorities, before the exit client rules (5269-5271): the exit
	// node's own queries from the tunnel address, then members' marked
	// packets. Nothing else on this host uses the table.
	upstreamRulePrioFrom = "5250"
	upstreamRulePrioMark = "5251"
	// Routes in the table: the tunnel route wins over the drop route by
	// metric; the drop route stays when the tunnel device disappears.
	upstreamTunnelMetric = "1"
	upstreamDropMetric   = "65535"
)

// Members' internet traffic is marked on arrival and its connection
// remembers the mark, so replies are routed (and reverse-path checked)
// with the same table. Marked traffic may leave only through the upstream
// tunnel unless the owner chose fail-open; nothing from the provider side
// may start a connection to this host or to a member.
var upstreamRules = template.Must(template.New("upstream").Parse(`table inet {{.Table}}
delete table inet {{.Table}}
table inet {{.Table}} {
	chain prerouting {
		type filter hook prerouting priority mangle; policy accept;
		iifname "{{.Overlay}}" ip saddr {{.V4}} ip daddr != { {{.Blocked4}} } meta mark set {{.Mark}} ct mark set meta mark
		iifname "{{.Overlay}}" ip6 saddr {{.V6}} ip6 daddr != { {{.Blocked6}} } meta mark set {{.Mark}} ct mark set meta mark
		iifname != "{{.Overlay}}" ct mark {{.Mark}} meta mark set ct mark
	}
	chain forward {
		type filter hook forward priority filter - 15; policy accept;
		oifname "{{.Up}}" tcp flags & (syn|rst) == syn tcp option maxseg size set rt mtu
		iifname "{{.Up}}" tcp flags & (syn|rst) == syn tcp option maxseg size set rt mtu
		oifname "{{.Up}}" meta mark != {{.Mark}} drop
		iifname "{{.Up}}" oifname != "{{.Overlay}}" drop
		iifname "{{.Up}}" ct state != { established, related } drop
{{- if not .FailOpen}}
		iifname "{{.Overlay}}" meta mark {{.Mark}} oifname != "{{.Up}}" drop
{{- end}}
	}
	chain input {
		type filter hook input priority filter - 5; policy accept;
		iifname "{{.Up}}" ct state { established, related } accept
		iifname "{{.Up}}" drop
	}
	chain postrouting {
		type nat hook postrouting priority srcnat - 5; policy accept;
		oifname "{{.Up}}" meta mark {{.Mark}} masquerade
	}
}
`))

// UpstreamRouter installs the policy routing of an upstream exit on a
// Linux exit node (ADR-0142). The exit node's own traffic (SSH, the
// coordinator, updates) never matches: only packets arriving from members
// on the OpenScale interface are marked, and only sockets bound to the
// tunnel address use the table.
type UpstreamRouter struct {
	ops sysOps

	mu sync.Mutex
	// installed is true once the mark rules are in place in this process.
	installed bool
	cur       UpstreamRoute
	direct    bool
	ipv6      bool
	// fromRules are the "from <tunnel address>" rules, for removal.
	fromRules [][]string
	// srcValidMark is the old value when Apply raised it, "" otherwise.
	srcValidMark string
}

// NewUpstreamRouter returns the router for this host.
func NewUpstreamRouter() *UpstreamRouter { return &UpstreamRouter{ops: hostOps} }

// UpstreamSupported reports whether this OS can be an upstream exit.
func UpstreamSupported() bool { return true }

// Apply installs or updates the routing for r. While no tunnel is up
// (invalid Address4) members' internet traffic is dropped unless FailOpen.
func (u *UpstreamRouter) Apply(ctx context.Context, r UpstreamRoute) error {
	if err := r.validate(); err != nil {
		return err
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	o := u.ops
	if !o.has("nft") || !o.has("ip") {
		return errors.New("üst çıkış için nft ve ip (iproute2) gerekli")
	}
	if !u.installed {
		_, err := o.read("/proc/net/if_inet6")
		u.ipv6 = err == nil
		// Rules a crashed run left behind would be duplicated.
		deleteUpstreamRules(ctx, o, u.ipv6)
	}
	// 1. The packet filter first: marked traffic can leave only through
	// the upstream interface from here on (fail closed).
	script, err := upstreamScript(r)
	if err != nil {
		return err
	}
	if _, err := o.run(ctx, script, "nft", "-f", "-"); err != nil {
		return err
	}
	// Replies from the tunnel are checked against the marked table when
	// reverse-path filtering is strict.
	if u.srcValidMark == "" && upstreamStrictRP(o, r) {
		old, err := o.sysctlGet("net/ipv4/conf/all/src_valid_mark")
		if err != nil {
			return err
		}
		if old != "1" {
			if err := o.sysctlSet(ctx, "net/ipv4/conf/all/src_valid_mark", "1"); err != nil {
				return err
			}
			u.srcValidMark = old
		}
	}
	// 2. Drop and overlay routes, then the rules that use them.
	if err := u.baseRoutes(ctx, r); err != nil {
		return err
	}
	if !u.installed {
		for _, f := range u.families() {
			if _, err := o.run(ctx, nil, "ip", f, "rule", "add", "priority", upstreamRulePrioMark, "fwmark", markHex(UpstreamForwardMark), "lookup", upstreamRouteTable); err != nil {
				return err
			}
		}
		u.installed = true
	}
	// 3. The tunnel: addresses, the default route and the rule for the
	// exit node's own DNS queries from the tunnel address.
	for _, rule := range u.fromRules {
		_, _ = o.run(ctx, nil, "ip", append([]string{rule[0], "rule", "del"}, rule[1:]...)...)
	}
	u.fromRules = nil
	if prev := u.cur; prev.TunnelUp() && !u.direct && (!r.TunnelUp() || prev.Interface != r.Interface) {
		// A tunnel device that still exists keeps its routes.
		_ = u.tunnelRoutes(ctx, prev, false)
	}
	u.cur, u.direct = r, false
	if !r.TunnelUp() {
		return nil
	}
	if _, err := o.run(ctx, nil, "ip", "link", "set", "dev", r.Interface, "mtu", strconv.Itoa(r.MTU), "up"); err != nil {
		return err
	}
	if _, err := o.run(ctx, nil, "ip", "-4", "addr", "replace", r.Address4.String()+"/32", "dev", r.Interface); err != nil {
		return err
	}
	if r.Address6.IsValid() && u.ipv6 {
		if _, err := o.run(ctx, nil, "ip", "-6", "addr", "replace", r.Address6.String()+"/128", "dev", r.Interface, "nodad"); err != nil {
			return err
		}
	}
	from := [][]string{{"-4", "priority", upstreamRulePrioFrom, "from", r.Address4.String(), "lookup", upstreamRouteTable}}
	if r.Address6.IsValid() && u.ipv6 {
		from = append(from, []string{"-6", "priority", upstreamRulePrioFrom, "from", r.Address6.String(), "lookup", upstreamRouteTable})
	}
	for _, rule := range from {
		if _, err := o.run(ctx, nil, "ip", append([]string{rule[0], "rule", "add"}, rule[1:]...)...); err != nil {
			return err
		}
		u.fromRules = append(u.fromRules, rule)
	}
	return u.tunnelRoutes(ctx, r, true)
}

// SetDirect switches a fail-open upstream between the tunnel (false) and
// leaving from this host (true). Without FailOpen it refuses: a fail-closed
// upstream never sends members' traffic from this host.
func (u *UpstreamRouter) SetDirect(ctx context.Context, direct bool) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if !u.installed {
		return errors.New("üst çıkış kurulu değil")
	}
	if direct && !u.cur.FailOpen {
		return errors.New("üst çıkış kapalı-hata kipinde; doğrudan çıkışa geçilmez")
	}
	if direct == u.direct {
		return nil
	}
	if !u.cur.TunnelUp() {
		u.direct = direct
		return nil
	}
	if err := u.tunnelRoutes(ctx, u.cur, !direct); err != nil {
		return err
	}
	u.direct = direct
	return nil
}

// Remove deletes every rule, route and filter the router installed.
func (u *UpstreamRouter) Remove(ctx context.Context) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	o := u.ops
	ipv6 := u.ipv6
	if !u.installed {
		_, err := o.read("/proc/net/if_inet6")
		ipv6 = err == nil
	}
	deleteUpstreamRules(ctx, o, ipv6)
	removeUpstreamTable(ctx, o)
	var errs []error
	if u.srcValidMark != "" {
		if err := o.sysctlSet(ctx, "net/ipv4/conf/all/src_valid_mark", u.srcValidMark); err != nil {
			errs = append(errs, err)
		}
	}
	u.installed, u.fromRules, u.srcValidMark, u.direct = false, nil, "", false
	u.cur = UpstreamRoute{}
	return errors.Join(errs...)
}

func (u *UpstreamRouter) families() []string {
	if u.ipv6 {
		return []string{"-4", "-6"}
	}
	return []string{"-4"}
}

// baseRoutes installs the drop routes and the overlay routes replies use.
// IPv6 without a provider address is always dropped, even fail-open:
// otherwise members' IPv6 would leave from this host while the tunnel works.
func (u *UpstreamRouter) baseRoutes(ctx context.Context, r UpstreamRoute) error {
	o := u.ops
	drop4 := !r.FailOpen
	drop6 := !r.FailOpen || !r.Address6.IsValid()
	set := func(family string, drop bool, overlay string) error {
		if drop {
			if _, err := o.run(ctx, nil, "ip", family, "route", "replace", "unreachable", "default", "metric", upstreamDropMetric, "table", upstreamRouteTable); err != nil {
				return err
			}
		} else {
			_, _ = o.run(ctx, nil, "ip", family, "route", "del", "unreachable", "default", "metric", upstreamDropMetric, "table", upstreamRouteTable)
		}
		_, err := o.run(ctx, nil, "ip", family, "route", "replace", overlay, "dev", r.Overlay, "table", upstreamRouteTable)
		return err
	}
	if err := set("-4", drop4, r.OverlayV4.Masked().String()); err != nil {
		return err
	}
	if u.ipv6 {
		return set("-6", drop6, r.OverlayV6.Masked().String())
	}
	return nil
}

// tunnelRoutes adds (on) or removes the default routes into the tunnel.
func (u *UpstreamRouter) tunnelRoutes(ctx context.Context, r UpstreamRoute, on bool) error {
	o := u.ops
	families := []string{"-4"}
	if r.Address6.IsValid() && u.ipv6 {
		families = append(families, "-6")
	}
	for _, f := range families {
		if on {
			if _, err := o.run(ctx, nil, "ip", f, "route", "replace", "default", "dev", r.Interface, "metric", upstreamTunnelMetric, "table", upstreamRouteTable); err != nil {
				return err
			}
			continue
		}
		if _, err := o.run(ctx, nil, "ip", f, "route", "del", "default", "dev", r.Interface, "metric", upstreamTunnelMetric, "table", upstreamRouteTable); err != nil {
			return err
		}
	}
	return nil
}

func upstreamScript(r UpstreamRoute) ([]byte, error) {
	var b bytes.Buffer
	err := upstreamRules.Execute(&b, map[string]any{
		"Table": upstreamTable, "Overlay": r.Overlay, "Up": r.Interface,
		"V4": r.OverlayV4.Masked().String(), "V6": r.OverlayV6.Masked().String(),
		"Blocked4": strings.Join(exitBlocked4, ", "), "Blocked6": strings.Join(exitBlocked6, ", "),
		"Mark": markHex(UpstreamForwardMark), "FailOpen": r.FailOpen,
	})
	if err != nil {
		return nil, fmt.Errorf("üst çıkış kuralları üretilemedi: %w", err)
	}
	return b.Bytes(), nil
}

func markHex(m uint32) string { return "0x" + strconv.FormatUint(uint64(m), 16) }

// upstreamStrictRP reports whether reverse-path filtering is strict on an
// interface members' packets or their replies arrive on.
func upstreamStrictRP(o sysOps, r UpstreamRoute) bool {
	all, err := o.sysctlGet("net/ipv4/conf/all/rp_filter")
	if err != nil {
		return false
	}
	for _, dev := range []string{r.Overlay, r.Interface, "default"} {
		v, err := o.sysctlGet("net/ipv4/conf/" + dev + "/rp_filter")
		if err == nil && max(v, all) == "1" {
			return true
		}
	}
	return all == "1"
}

// deleteUpstreamRules removes the policy rules and flushes the table.
func deleteUpstreamRules(ctx context.Context, o sysOps, ipv6 bool) {
	families := []string{"-4"}
	if ipv6 {
		families = append(families, "-6")
	}
	for _, f := range families {
		for _, prio := range []string{upstreamRulePrioFrom, upstreamRulePrioMark} {
			for i := 0; i < 8; i++ {
				if _, err := o.run(ctx, nil, "ip", f, "rule", "del", "priority", prio); err != nil {
					break
				}
			}
		}
		_, _ = o.run(ctx, nil, "ip", f, "route", "flush", "table", upstreamRouteTable)
	}
}

func removeUpstreamTable(ctx context.Context, o sysOps) {
	if o.has("nft") {
		_, _ = o.run(ctx, nil, "nft", "delete", "table", "inet", upstreamTable)
	}
}

// RecoverUpstream removes what a crashed upstream exit (or Tor exit) left
// behind.
func RecoverUpstream(ctx context.Context) {
	deleteUpstreamRules(ctx, hostOps, true)
	removeUpstreamTable(ctx, hostOps)
	removeTorTable(ctx, hostOps)
}

func (r UpstreamRoute) validate() error {
	if !validSysctlName(r.Overlay) {
		return errors.New("geçersiz OpenScale arayüz adı")
	}
	if !r.OverlayV4.IsValid() || !r.OverlayV4.Addr().Is4() || !r.OverlayV6.IsValid() || !r.OverlayV6.Addr().Is6() {
		return errors.New("geçersiz ağ aralıkları")
	}
	if !validSysctlName(r.Interface) || r.Interface == r.Overlay {
		return errors.New("geçersiz üst tünel arayüz adı")
	}
	if !r.TunnelUp() {
		return nil
	}
	if r.MTU < 1280 || r.MTU > 1500 {
		return errors.New("geçersiz üst tünel MTU değeri")
	}
	if !r.Address4.Is4() {
		return errors.New("üst tünelin IPv4 adresi geçersiz")
	}
	if r.Address6.IsValid() && (!r.Address6.Is6() || r.Address6.Is4In6()) {
		return errors.New("üst tünelin IPv6 adresi geçersiz")
	}
	return nil
}
