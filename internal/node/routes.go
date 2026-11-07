package node

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"

	"github.com/openscale/openscale/internal/osnet"
	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/internal/wgconf"
)

// Subnet routing, exit node exceptions and plain WireGuard exit nodes in
// the engine (ADR-0133).

// RouteApplier is the OS side of subnet routing (osnet.SubnetRouter).
type RouteApplier interface {
	Apply(osnet.RouteConfig) error
	Close() error
}

// MaxExitExceptions bounds the destinations kept out of the exit node.
const MaxExitExceptions = 64

// localNetworks lists this computer's networks (tests replace it).
var localNetworks = osnet.LocalNetworks

// routingState is the engine's subnet routing state.
type routingState struct {
	mu sync.Mutex
	// except are destinations kept out of the exit node (#79).
	except []netip.Prefix
	// noMasquerade forwards with members' own addresses (F-032 option).
	noMasquerade bool
	// conflicts are the overlaps found at the last apply (#165).
	conflicts []osnet.RouteConflict
	// client and own are the routes applied last time.
	client, own []netip.Prefix
	lastErr     string
	applied     bool
}

// RoutingStatus is the subnet routing state for the CLI and diagnostics.
type RoutingStatus struct {
	// Client are the peers' subnets routed into the tunnel.
	Client []netip.Prefix `json:"client"`
	// Own are the subnets this device forwards.
	Own []netip.Prefix `json:"own"`
	// ExitExceptions are destinations kept out of the exit node.
	ExitExceptions []netip.Prefix        `json:"exit_exceptions"`
	Conflicts      []osnet.RouteConflict `json:"conflicts"`
	Error          string                `json:"error,omitempty"`
}

// Routing returns the subnet routing state.
func (e *Engine) Routing() RoutingStatus {
	r := &e.routing
	r.mu.Lock()
	defer r.mu.Unlock()
	return RoutingStatus{Client: slices.Clone(r.client), Own: slices.Clone(r.own), ExitExceptions: slices.Clone(r.except),
		Conflicts: slices.Clone(r.conflicts), Error: r.lastErr}
}

// SetExitExceptions sets the destinations kept out of the exit node (#79).
// Only private-free ranges make sense, but any masked prefix narrower than
// /1 is accepted; the change is applied by the run loop.
func (e *Engine) SetExitExceptions(prefixes []netip.Prefix) error {
	if len(prefixes) > MaxExitExceptions {
		return fmt.Errorf("en fazla %d istisna", MaxExitExceptions)
	}
	for _, p := range prefixes {
		if !p.IsValid() || p != p.Masked() || p.Bits() < 1 || p.Addr().Zone() != "" {
			return fmt.Errorf("geçersiz istisna %s", p)
		}
	}
	r := &e.routing
	r.mu.Lock()
	r.except = slices.Clone(prefixes)
	r.mu.Unlock()
	e.kickReapply()
	return nil
}

// SetSubnetMasquerade chooses whether forwarded subnet traffic is
// masqueraded behind this router (the default) or keeps the members'
// overlay addresses, which needs a route back to the overlay on the LAN.
func (e *Engine) SetSubnetMasquerade(on bool) {
	r := &e.routing
	r.mu.Lock()
	r.noMasquerade = !on
	r.mu.Unlock()
	e.kickReapply()
}

func (e *Engine) kickReapply() {
	select {
	case e.reapply <- struct{}{}:
	default:
	}
}

// routerKeys returns the WireGuard keys of routers whose subnets this
// device reaches; they stay configured even with lazy peers, because a
// packet to a subnet does not name the router.
func (e *Engine) routerKeys(doc *trust.Document, self trust.Device) []trust.Key {
	var keys []trust.Key
	now := e.cfg.Now()
	for _, d := range doc.Devices {
		if d.Name != self.Name && len(d.Routes) > 0 && now.Before(d.ExpiresAt) && doc.RouteVisible(self.Name, d.Name) {
			keys = append(keys, d.WireGuardKey)
		}
	}
	return keys
}

// applyRoutes brings the OS in line with the document: peers' subnets into
// the tunnel (minus those that overlap a local network, #165), this
// device's own subnets forwarded, and the exit node exceptions.
func (e *Engine) applyRoutes(doc *trust.Document, self trust.Device, expired bool) {
	var client, own []netip.Prefix
	routes := map[netip.Prefix]string{}
	now := e.cfg.Now()
	if !expired {
		own = slices.Clone(self.Routes)
		for _, d := range doc.Devices {
			if d.Name == self.Name || len(d.Routes) == 0 || !now.Before(d.ExpiresAt) {
				continue
			}
			for _, p := range doc.RoutesVia(self.Name, d.Name) {
				client = append(client, p)
				routes[p] = d.Name
			}
		}
	}
	iface := ""
	if e.cfg.TUN != nil {
		iface, _ = e.cfg.TUN.Name()
	}
	var conflicts []osnet.RouteConflict
	if locals, err := localNetworks(iface); err == nil {
		conflicts = osnet.RouteConflicts([]netip.Prefix{doc.IPv4Prefix, doc.IPv6Prefix}, routes, locals)
		client = osnet.SkipConflicting(client, locals)
	}
	r := &e.routing
	r.mu.Lock()
	except, noMasq := slices.Clone(r.except), r.noMasquerade
	changed := !slices.Equal(conflictKeys(r.conflicts), conflictKeys(conflicts))
	r.conflicts = conflicts
	r.mu.Unlock()
	if changed {
		for _, c := range conflicts {
			e.logger.Warn("route conflict", "kind", c.Kind, "prefix", c.Prefix.String(), "local", c.Local.Prefix.String(), "interface", c.Local.Interface)
		}
	}
	e.mu.Lock()
	exitActive := e.exitActive != ""
	e.mu.Unlock()
	cfg := osnet.RouteConfig{Interface: iface, Client: client, Own: own, Overlay4: doc.IPv4Prefix, Overlay6: doc.IPv6Prefix,
		ExitRole: !expired && self.HasRole(trust.RoleExitNode), NoMasquerade: noMasq, ExitActive: exitActive, ExitExcept: except}
	errText := ""
	if e.cfg.Routes != nil && (!cfg.Empty() || e.routingApplied()) {
		if err := e.cfg.Routes.Apply(cfg); err != nil {
			errText = err.Error()
			e.logger.Warn("subnet routes", "error", errText)
		}
	}
	r.mu.Lock()
	r.client, r.own, r.lastErr = client, own, errText
	r.applied = r.applied || !cfg.Empty()
	r.mu.Unlock()
}

func (e *Engine) routingApplied() bool {
	r := &e.routing
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.applied
}

func conflictKeys(cs []osnet.RouteConflict) []string {
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = c.Kind + c.Prefix.String() + c.Local.Prefix.String() + c.Local.Interface
	}
	return out
}

// stopRoutes undoes the OS routing when the engine stops.
func (e *Engine) stopRoutes() {
	if e.cfg.Routes == nil || !e.routingApplied() {
		return
	}
	if err := e.cfg.Routes.Close(); err != nil {
		e.logger.Warn("subnet routes", "error", err.Error())
	}
	r := &e.routing
	r.mu.Lock()
	r.client, r.own, r.applied = nil, nil, false
	r.mu.Unlock()
}

// --- plain WireGuard exit nodes (F-045, #264) ---

// externalKeepalive keeps the NAT mapping to a plain server open.
const externalKeepalive = 25

// isExternalExit reports whether name is a plain WireGuard exit node of the
// current document that this device may use.
func (e *Engine) isExternalExit(name string) bool {
	doc := e.cfg.Store.Document()
	if doc == nil {
		return false
	}
	if _, dev := doc.DeviceByName(name); dev {
		return false
	}
	if _, ok := doc.ExternalExitByName(name); !ok {
		return false
	}
	self, err := e.selfIn(doc)
	return err == nil && doc.MayUseExitNode(self.Name)
}

// externalExitFor returns a plain WireGuard exit node as the device the
// exit code works with: its key, and its resolver as the address DNS and
// the filter use. The empty ID marks it as not a member.
func externalExitFor(doc *trust.Document, self trust.Device, name string) *trust.Device {
	x, ok := doc.ExternalExitByName(name)
	if !ok || !doc.MayUseExitNode(self.Name) {
		return nil
	}
	return &trust.Device{Name: x.Name, WireGuardKey: x.WireGuardKey, IPv4: x.DNS, Roles: []trust.Role{trust.RoleExitNode}, ExpiresAt: doc.ExpiresAt}
}

// addExternalExitPeer configures the plain WireGuard exit node in use as a
// peer carrying every internet address. It returns exit, or nil when the
// server's endpoint cannot be resolved (the exit is then not claimed).
func (e *Engine) addExternalExitPeer(ctx context.Context, doc *trust.Document, exit *trust.Device, want map[trust.Key]wgconf.Peer) *trust.Device {
	if exit == nil || exit.ID != "" {
		return exit
	}
	x, ok := doc.ExternalExitByName(exit.Name)
	if !ok {
		return nil
	}
	ep, err := e.resolveEndpoint(ctx, x.Endpoint)
	if err != nil {
		e.logger.Warn("external exit node endpoint", "exit", x.Name, "error", err.Error())
		return nil
	}
	if _, clash := want[x.WireGuardKey]; clash {
		e.logger.Warn("external exit node key is already a peer", "exit", x.Name)
		return nil
	}
	want[x.WireGuardKey] = wgconf.Peer{PublicKey: x.WireGuardKey, Endpoint: ep, Keepalive: externalKeepalive,
		AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}}
	return exit
}

// ErrNoRoutes is returned by route commands on a device without routes.
var ErrNoRoutes = errors.New("bu cihazın onaylı alt ağ rotası yok")
