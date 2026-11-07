//go:build linux

package osnet

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"sync"
	"text/template"
	"time"
)

const (
	subnetTable = "openscale_subnet"
	// subnetChain and subnetNATChain are the iptables equivalents.
	subnetChain    = "OPENSCALE-SUBNET"
	subnetNATChain = "OPENSCALE-SUBNET-NAT"
	// exceptRulePrio sends exit node exceptions (#79) to the main table
	// before the exit node rules (5270, 5271).
	exceptRulePrio = "5269"
)

// The router forwards members' traffic only to its approved subnets and
// marks it, so the exit node table (if any) lets it reach these private
// destinations. Unless the device is also an exit node, every other
// forwarding to or from the tunnel is dropped. TCP MSS is clamped to the
// route MTU: LAN hosts have 1500 bytes, the tunnel 1280 (F-048).
var subnetRules = template.Must(template.New("subnet").Parse(`table inet {{.Table}}
delete table inet {{.Table}}
table inet {{.Table}} {
	chain forward {
		type filter hook forward priority filter - 20; policy accept;
		iifname "{{.If}}" tcp flags & (syn|rst) == syn tcp option maxseg size set rt mtu
		oifname "{{.If}}" tcp flags & (syn|rst) == syn tcp option maxseg size set rt mtu
{{- if .R4}}
		iifname "{{.If}}" ip saddr {{.V4}} ip daddr { {{.R4}} } meta mark set {{.Mark}} accept
		oifname "{{.If}}" ip saddr { {{.R4}} } ip daddr {{.V4}} meta mark set {{.Mark}} accept
{{- end}}
{{- if .R6}}
		iifname "{{.If}}" ip6 saddr {{.V6}} ip6 daddr { {{.R6}} } meta mark set {{.Mark}} accept
		oifname "{{.If}}" ip6 saddr { {{.R6}} } ip6 daddr {{.V6}} meta mark set {{.Mark}} accept
{{- end}}
{{- if not .Exit}}
		iifname "{{.If}}" drop
		oifname "{{.If}}" drop
{{- end}}
	}
{{- if .Masq}}
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
{{- if .R4}}
		oifname != "{{.If}}" ip saddr {{.V4}} ip daddr { {{.R4}} } masquerade
{{- end}}
{{- if .R6}}
		oifname != "{{.If}}" ip6 saddr {{.V6}} ip6 daddr { {{.R6}} } masquerade
{{- end}}
	}
{{- end}}
}
`))

// forwardShare lets the exit node and the subnet router share IP
// forwarding: the first user's saved values are the originals, and only
// the last user to stop restores them.
var forwardShare = struct {
	mu    sync.Mutex
	users map[*exitNATState]bool
	orig  *exitSysctls
}{users: map[*exitNATState]bool{}}

// shareForwarding registers s and returns the values s restores later.
func shareForwarding(s *exitNATState, saved *exitSysctls) *exitSysctls {
	if !s.shared {
		return saved
	}
	forwardShare.mu.Lock()
	defer forwardShare.mu.Unlock()
	if len(forwardShare.users) == 0 || forwardShare.orig == nil {
		forwardShare.orig = saved
	} else {
		// Interfaces seen only now keep their own original accept_ra.
		for dev, v := range saved.acceptRA {
			if _, ok := forwardShare.orig.acceptRA[dev]; !ok {
				forwardShare.orig.acceptRA[dev] = v
			}
		}
	}
	forwardShare.users[s] = true
	c := *forwardShare.orig
	c.acceptRA = maps.Clone(forwardShare.orig.acceptRA)
	return &c
}

// releaseForwarding unregisters s and reports whether it was the last
// user, which then restores the original values.
func releaseForwarding(s *exitNATState) bool {
	if !s.shared {
		return true
	}
	forwardShare.mu.Lock()
	defer forwardShare.mu.Unlock()
	delete(forwardShare.users, s)
	if len(forwardShare.users) > 0 {
		return false
	}
	forwardShare.orig = nil
	return true
}

// hostSubnetFwd holds the forwarding values the subnet router changed.
var hostSubnetFwd = &exitNATState{mode: NetfilterAuto, shared: true}

// SubnetRouter applies RouteConfig on Linux.
type SubnetRouter struct {
	ops sysOps
	fwd *exitNATState

	mu        sync.Mutex
	iface     string
	client    []netip.Prefix
	except    []netip.Prefix
	router    bool
	routerKey string
	backend   string
}

// NewSubnetRouter returns the system's subnet router.
func NewSubnetRouter() *SubnetRouter { return &SubnetRouter{ops: hostOps, fwd: hostSubnetFwd} }

// Apply changes the routes and forwarding to match cfg. Only the
// differences are applied; an empty configuration removes everything.
func (r *SubnetRouter) Apply(cfg RouteConfig) error {
	if err := cfg.validate(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var errs []error
	if err := r.applyClient(ctx, cfg); err != nil {
		errs = append(errs, err)
	}
	if err := r.applyExcept(ctx, cfg); err != nil {
		errs = append(errs, err)
	}
	if err := r.applyRouter(ctx, cfg); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// Close removes everything Apply installed.
func (r *SubnetRouter) Close() error {
	return r.Apply(RouteConfig{Interface: r.iface})
}

func family(p netip.Prefix) string {
	if p.Addr().Is4() {
		return "-4"
	}
	return "-6"
}

func (r *SubnetRouter) applyClient(ctx context.Context, cfg RouteConfig) error {
	have := r.client
	if r.iface != cfg.Interface {
		// The interface changed (a new tunnel): its routes went with it.
		have = nil
	}
	add, del := prefixDiff(have, cfg.Client)
	var errs []error
	for _, p := range del {
		if _, err := r.ops.run(ctx, nil, "ip", family(p), "route", "del", p.String(), "dev", r.iface); err != nil {
			errs = append(errs, err)
		}
	}
	installed := slices.DeleteFunc(slices.Clone(have), func(p netip.Prefix) bool { return slices.Contains(del, p) })
	for _, p := range add {
		if _, err := r.ops.run(ctx, nil, "ip", family(p), "route", "replace", p.String(), "dev", cfg.Interface, "proto", "static"); err != nil {
			errs = append(errs, err)
			continue
		}
		installed = append(installed, p)
	}
	r.iface, r.client = cfg.Interface, installed
	return errors.Join(errs...)
}

func (r *SubnetRouter) applyExcept(ctx context.Context, cfg RouteConfig) error {
	var want []netip.Prefix
	if cfg.ExitActive {
		want = cfg.ExitExcept
	}
	add, del := prefixDiff(r.except, want)
	var errs []error
	for _, p := range del {
		if _, err := r.ops.run(ctx, nil, "ip", family(p), "rule", "del", "priority", exceptRulePrio, "to", p.String(), "lookup", "main"); err != nil {
			errs = append(errs, err)
		}
	}
	kept := slices.DeleteFunc(slices.Clone(r.except), func(p netip.Prefix) bool { return slices.Contains(del, p) })
	for _, p := range add {
		if _, err := r.ops.run(ctx, nil, "ip", family(p), "rule", "add", "priority", exceptRulePrio, "to", p.String(), "lookup", "main"); err != nil {
			errs = append(errs, err)
			continue
		}
		kept = append(kept, p)
	}
	r.except = kept
	return errors.Join(errs...)
}

func (r *SubnetRouter) applyRouter(ctx context.Context, cfg RouteConfig) error {
	if len(cfg.Own) == 0 {
		if !r.router {
			return nil
		}
		removeSubnetRules(ctx, r.ops)
		r.router, r.routerKey = false, ""
		r.fwd.mu.Lock()
		defer r.fwd.mu.Unlock()
		return r.fwd.restoreLocked(ctx, r.ops)
	}
	key := fmt.Sprint(cfg.Interface, cfg.Own, cfg.Overlay4, cfg.Overlay6, cfg.ExitRole, cfg.NoMasquerade)
	if r.router && key == r.routerKey {
		return nil
	}
	backend, err := chooseBackend(r.ops, r.fwd.mode)
	if err != nil {
		return err
	}
	r.fwd.mu.Lock()
	if r.fwd.saved == nil {
		saved, err := readExitSysctls(r.ops, cfg.Interface)
		if err != nil {
			r.fwd.mu.Unlock()
			return err
		}
		r.fwd.saved = shareForwarding(r.fwd, saved)
	}
	if err := r.fwd.raiseSysctls(ctx, r.ops); err != nil {
		_ = r.fwd.restoreLocked(ctx, r.ops)
		r.fwd.mu.Unlock()
		return err
	}
	r.fwd.mu.Unlock()
	if err := installSubnetRules(ctx, r.ops, backend, cfg); err != nil {
		removeSubnetRules(ctx, r.ops)
		r.fwd.mu.Lock()
		_ = r.fwd.restoreLocked(ctx, r.ops)
		r.fwd.mu.Unlock()
		r.router, r.routerKey = false, ""
		return err
	}
	r.router, r.routerKey, r.backend = true, key, backend
	return nil
}

func nftSubnetScript(cfg RouteConfig) ([]byte, error) {
	r4, r6 := split46(cfg.Own)
	var b bytes.Buffer
	err := subnetRules.Execute(&b, map[string]any{
		"Table": subnetTable, "If": cfg.Interface, "Mark": subnetMarkHex(),
		"V4": cfg.Overlay4.Masked().String(), "V6": cfg.Overlay6.Masked().String(),
		"R4": joinPrefixes(r4), "R6": joinPrefixes(r6), "Exit": cfg.ExitRole, "Masq": !cfg.NoMasquerade,
	})
	return b.Bytes(), err
}

func installSubnetRules(ctx context.Context, o sysOps, backend string, cfg RouteConfig) error {
	if backend == NetfilterNFTables {
		script, err := nftSubnetScript(cfg)
		if err != nil {
			return err
		}
		_, err = o.run(ctx, script, "nft", "-f", "-")
		return err
	}
	for _, step := range iptablesSubnetSteps(cfg) {
		if step.ifMissing != nil {
			if _, err := o.run(ctx, nil, step.tool, step.ifMissing...); err == nil {
				continue
			}
		}
		if _, err := o.run(ctx, nil, step.tool, step.args...); err != nil && !step.mayFail {
			return err
		}
	}
	return nil
}

// iptablesSubnetSteps builds the same rules for iptables. The FORWARD jump
// is moved to the top on every apply, so it stays in front of the exit
// node chain, whose private-destination drops would otherwise win.
func iptablesSubnetSteps(cfg RouteConfig) []iptablesStep {
	r4, r6 := split46(cfg.Own)
	var steps []iptablesStep
	fam := func(tool, overlay string, routes []netip.Prefix) {
		cmd := func(args ...string) []string { return append([]string{"-w", "5"}, args...) }
		steps = append(steps,
			iptablesStep{tool: tool, args: cmd("-t", "filter", "-N", subnetChain), mayFail: true},
			iptablesStep{tool: tool, args: cmd("-t", "filter", "-F", subnetChain)},
		)
		for _, p := range routes {
			steps = append(steps,
				iptablesStep{tool: tool, args: cmd("-t", "filter", "-A", subnetChain, "-i", cfg.Interface, "-s", overlay, "-d", p.String(), "-j", "ACCEPT")},
				iptablesStep{tool: tool, args: cmd("-t", "filter", "-A", subnetChain, "-o", cfg.Interface, "-s", p.String(), "-d", overlay, "-j", "ACCEPT")},
			)
		}
		if !cfg.ExitRole {
			steps = append(steps,
				iptablesStep{tool: tool, args: cmd("-t", "filter", "-A", subnetChain, "-i", cfg.Interface, "-j", "DROP")},
				iptablesStep{tool: tool, args: cmd("-t", "filter", "-A", subnetChain, "-o", cfg.Interface, "-j", "DROP")},
			)
		}
		steps = append(steps,
			iptablesStep{tool: tool, args: cmd("-t", "filter", "-D", "FORWARD", "-j", subnetChain), mayFail: true},
			iptablesStep{tool: tool, args: cmd("-t", "filter", "-I", "FORWARD", "1", "-j", subnetChain)},
			iptablesStep{tool: tool, args: cmd("-t", "nat", "-N", subnetNATChain), mayFail: true},
			iptablesStep{tool: tool, args: cmd("-t", "nat", "-F", subnetNATChain)},
		)
		if !cfg.NoMasquerade {
			for _, p := range routes {
				steps = append(steps, iptablesStep{tool: tool, args: cmd("-t", "nat", "-A", subnetNATChain, "!", "-o", cfg.Interface, "-s", overlay, "-d", p.String(), "-j", "MASQUERADE")})
			}
		}
		steps = append(steps, iptablesStep{tool: tool, args: cmd("-t", "nat", "-I", "POSTROUTING", "1", "-j", subnetNATChain),
			ifMissing: cmd("-t", "nat", "-C", "POSTROUTING", "-j", subnetNATChain)})
	}
	fam("iptables", cfg.Overlay4.Masked().String(), r4)
	fam("ip6tables", cfg.Overlay6.Masked().String(), r6)
	return steps
}

// removeSubnetRules deletes both backends' rules; absent ones are skipped.
func removeSubnetRules(ctx context.Context, o sysOps) {
	if o.has("nft") {
		_, _ = o.run(ctx, nil, "nft", "delete", "table", "inet", subnetTable)
	}
	for _, tool := range []string{"iptables", "ip6tables"} {
		if !o.has(tool) {
			continue
		}
		for _, t := range []struct{ table, parent, chain string }{
			{"filter", "FORWARD", subnetChain},
			{"nat", "POSTROUTING", subnetNATChain},
		} {
			for i := 0; i < 8; i++ {
				if _, err := o.run(ctx, nil, tool, "-w", "5", "-t", t.table, "-D", t.parent, "-j", t.chain); err != nil {
					break
				}
			}
			_, _ = o.run(ctx, nil, tool, "-w", "5", "-t", t.table, "-F", t.chain)
			_, _ = o.run(ctx, nil, tool, "-w", "5", "-t", t.table, "-X", t.chain)
		}
	}
}

// RouterSupported reports whether this system can be a subnet router.
func RouterSupported() bool { return true }

// RouterStatus is a short status line for diagnostics.
func (r *SubnetRouter) RouterStatus() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.router {
		return "kapalı"
	}
	return "açık (" + r.backend + ")"
}
