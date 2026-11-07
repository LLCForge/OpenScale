package node

import (
	"bufio"
	"context"
	"errors"
	"net/netip"
	"os"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/openscale/openscale/internal/packet"
	"github.com/openscale/openscale/internal/trust"
)

// ExitRouter moves this device's internet traffic into the tunnel while an
// exit node is in use (ADR-0018). Enable is called again when the exit node
// changes; Disable restores the normal routes.
type ExitRouter interface {
	Enable(exit trust.Device, doc *trust.Document, iface string, bind conn.Bind) error
	Disable() error
}

// ErrNoExitNode is returned for a name that is not an exit node.
var ErrNoExitNode = errors.New("this device is not an exit node")

const (
	exitDNSConcurrency = 64
	exitDNSTimeout     = 4 * time.Second
	maxDNSPacket       = 1500
)

// SetExitNode chooses the exit node by name ("" for none). The change is
// applied by the run loop.
func (e *Engine) SetExitNode(name string) error {
	if name != "" && !e.isExternalExit(name) { // ADR-0133 (F-045)
		doc := e.cfg.Store.Document()
		d, ok := doc.DeviceByName(name)
		if !ok || !d.HasRole(trust.RoleExitNode) {
			return ErrNoExitNode
		}
		if d.WireGuardKey == e.wgKey {
			return errors.New("a device cannot be its own exit node")
		}
	}
	e.mu.Lock()
	e.exitWant = name
	e.mu.Unlock()
	select {
	case e.reapply <- struct{}{}:
	default:
	}
	return nil
}

// ExitNode returns the exit node in use, "" for none.
func (e *Engine) ExitNode() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.exitActive
}

// exitFor returns the chosen exit node if it is still valid in doc.
func (e *Engine) exitFor(doc *trust.Document, self trust.Device) *trust.Device {
	e.mu.Lock()
	want := e.exitWant
	e.mu.Unlock()
	if want == "" || want == self.Name {
		return nil
	}
	d, ok := doc.DeviceByName(want)
	if !ok {
		return externalExitFor(doc, self, want) // ADR-0133 (F-045)
	}
	if !d.HasRole(trust.RoleExitNode) || !e.cfg.Now().Before(d.ExpiresAt) {
		return nil
	}
	return &d
}

// applyExit updates the filter, OS routes and forwarding for the current
// exit node choice and role.
func (e *Engine) applyExit(doc *trust.Document, self trust.Device, exit *trust.Device, role bool) {
	var exitAddr netip.Addr
	if exit != nil {
		exitAddr = exit.IPv4
	}
	e.filter.SetExit(exitAddr, role)
	e.g7SyncExtensions(doc, role) // ADR-0220
	e.mu.Lock()
	prevActive, prevRole := e.exitActive, e.exitRole
	e.exitRole = role
	e.mu.Unlock()

	if role != prevRole && e.cfg.OnExitRole != nil {
		e.cfg.OnExitRole(role)
	}
	name := ""
	if exit != nil {
		name = exit.Name
	}
	if r := e.cfg.ExitRouter; r != nil && name != prevActive {
		var err error
		if exit != nil {
			iface, _ := e.cfg.TUN.Name()
			err = r.Enable(*exit, doc, iface, e.exitBind())
		} else {
			err = r.Disable()
		}
		if err != nil {
			e.logger.Warn("exit node routes", "error", err.Error())
			if exit != nil {
				// Without routes no traffic uses the exit; do not claim it.
				name = ""
			}
		}
	}
	e.mu.Lock()
	e.exitActive = name
	e.status.ExitNode = name
	e.mu.Unlock()
	if name != prevActive {
		e.logger.Info("exit node", "using", name)
	}
}

// exitBind is the bind the ExitRouter marks or binds to an interface.
// Marks go through the WireGuard device, which keeps them across every
// reopen of its sockets; before this, the Linux router had to re-mark the
// sockets every second, because the exit node is enabled before WireGuard
// opens them.
func (e *Engine) exitBind() conn.Bind {
	return markBind{relayBind: e.relay, setMark: func(mark uint32) error {
		e.mu.Lock()
		dev := e.dev
		e.mu.Unlock()
		if dev == nil {
			return nil // the device is gone and its sockets with it
		}
		return dev.BindSetMark(mark)
	}}
}

// stopExit undoes the OS changes when the engine stops.
func (e *Engine) stopExit() {
	e.stopRoutes() // subnet routes and exit exceptions (ADR-0133)
	e.mu.Lock()
	active, role := e.exitActive, e.exitRole
	e.exitActive, e.exitRole = "", false
	e.mu.Unlock()
	if active != "" && e.cfg.ExitRouter != nil {
		if err := e.cfg.ExitRouter.Disable(); err != nil {
			e.logger.Warn("exit node routes", "error", err.Error())
		}
	}
	if role && e.cfg.OnExitRole != nil {
		e.cfg.OnExitRole(false)
	}
}

// serveExitDNS forwards a member's DNS query sent to this exit node's
// overlay address to the exit node's own resolver, so a device using the
// exit node does not leak its queries to its local network.
func (e *Engine) serveExitDNS(pkt []byte) bool {
	in, err := packet.Parse(pkt)
	if err != nil || in.Proto != packet.ProtoUDP || in.DstPort != dnsPort || in.Fragment {
		return false
	}
	e.mu.Lock()
	role, self := e.exitRole, e.self
	e.mu.Unlock()
	if !role || in.Dst != self.IPv4 || len(in.Payload) > maxDNSPacket {
		return false
	}
	doc := e.cfg.Store.Document()
	member, allowed := false, false
	var client exitClient
	var peer string
	for _, d := range doc.Devices {
		if d.IPv4 == in.Src && d.Name != self.Name {
			member, allowed = true, doc.MayUseExitNode(d.Name) && e.cfg.Now().Before(d.ExpiresAt)
			client = exitClientFor(doc, d.Name) // P05: rate limit, profile
			peer = d.Name
			break
		}
	}
	if !member {
		return false
	}
	if !allowed || e.exitDNSRefused(peer) {
		// Only devices allowed to use exit nodes get the exit's resolver
		// (exit_users, ADR-0021); a quarantined peer or any peer in lost
		// mode gets nothing (exitdns_g3.go). The query is dropped.
		return true
	}
	select {
	case e.dnsSem <- struct{}{}:
	default:
		return true // too many queries in flight: drop, the client retries
	}
	query := append([]byte(nil), in.Payload...)
	go func() {
		defer func() { <-e.dnsSem }()
		fwd, err := e.exitDNSForwarder() // ADR-0142
		if err != nil {
			e.logExitDNSUpstream(err)
			return
		}
		answer, err := fwd.forwardFrom(context.Background(), client, query, false)
		if err != nil {
			e.logger.Debug("exit DNS", "error", err.Error())
			return
		}
		if e.exitDNSRefused(peer) {
			return // quarantined or isolated while the query was in flight
		}
		reply, err := packet.BuildUDP4(self.IPv4, in.Src, dnsPort, in.SrcPort, answer)
		if err == nil {
			e.wrap.Inject(reply)
		}
	}()
	return true
}

// systemResolver returns the first nameserver in /etc/resolv.conf.
func systemResolver() string {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return ""
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) >= 2 && fields[0] == "nameserver" {
			if a, err := netip.ParseAddr(fields[1]); err == nil {
				return a.String()
			}
		}
	}
	return ""
}
