package openscale

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/node"
	"github.com/openscale/openscale/internal/trust"
)

// startOptions are the app's choices, passed as JSON to Plan and
// Tunnel.Start. The same string goes to both, so the routes Android
// installs and the engine's exit node always agree.
type startOptions struct {
	// ExitNode is the exit node to use ("" for none). Changing it means
	// a new Plan and a restart: Android routes cannot change under a
	// running VPN interface.
	ExitNode string `json:"exit_node,omitempty"`
	// BatterySaver selects the battery-friendly profile (#178); nil is on.
	BatterySaver *bool `json:"battery_saver,omitempty"`
	// MTU of the VPN interface; 0 is node.DefaultMTU.
	MTU int `json:"mtu,omitempty"`
	// ForceRelay reaches every peer through the coordinator.
	ForceRelay bool `json:"force_relay,omitempty"`
	// Debug logs at debug level (includes endpoint addresses).
	Debug bool `json:"debug,omitempty"`
	// AppsMode and Apps are the per-app split tunnel (F-049, P27):
	// "include" sends only the listed apps through the VPN, "exclude"
	// all but them; "" is every app. See apps.go.
	AppsMode string   `json:"apps_mode,omitempty"`
	Apps     []string `json:"apps,omitempty"`
}

func parseOptions(s string) (startOptions, error) {
	var o startOptions
	if len(s) > maxOptions {
		return o, errors.New("seçenekler fazla büyük")
	}
	if strings.TrimSpace(s) != "" {
		d := json.NewDecoder(bytes.NewReader([]byte(s)))
		d.DisallowUnknownFields()
		if err := d.Decode(&o); err != nil {
			return o, fmt.Errorf("seçenekler okunamadı: %w", err)
		}
	}
	o.ExitNode = strings.TrimSpace(o.ExitNode)
	if len(o.ExitNode) > 253 {
		return o, errors.New("çıkış düğümü adı fazla uzun")
	}
	if o.MTU == 0 {
		o.MTU = node.DefaultMTU
	}
	if err := node.ValidateMTU(o.MTU); err != nil {
		return o, err
	}
	if o.ForceRelay && o.MTU > node.DefaultMTU {
		return o, fmt.Errorf("aktarıcı zorunluyken MTU en fazla %d olabilir", node.DefaultMTU)
	}
	if err := o.checkApps(); err != nil {
		return o, err
	}
	return o, nil
}

func (o startOptions) batterySaver() bool { return o.BatterySaver == nil || *o.BatterySaver }

// vpnPlan is what VpnService.Builder needs, as JSON for the app.
type vpnPlan struct {
	// Session is the name Android shows for the VPN.
	Session string `json:"session"`
	// Addresses and Routes are prefixes ("100.80.0.7/16").
	Addresses []string `json:"addresses"`
	Routes    []string `json:"routes"`
	// DNSServers is set only when MagicDNS forwards every other name (an
	// exit node or network-wide resolvers in the document); otherwise
	// Android keeps its own resolver.
	DNSServers    []string `json:"dns_servers,omitempty"`
	SearchDomains []string `json:"search_domains,omitempty"`
	MTU           int      `json:"mtu"`
	ExitNode      string   `json:"exit_node,omitempty"`
	// FullTunnel is true when every internet route goes through the
	// tunnel: only then is "block connections without VPN" safe to turn
	// on (#175); without an exit node it would cut the internet. A per-app
	// split tunnel is never full.
	FullTunnel bool `json:"full_tunnel"`
	// AllowedApps (only these apps use the VPN) and DisallowedApps (these
	// apps bypass it) are the per-app split tunnel; at most one is set.
	// The app adds its own package to neither: it always stays outside
	// its VPN (ADR-0101).
	AllowedApps    []string `json:"allowed_apps,omitempty"`
	DisallowedApps []string `json:"disallowed_apps,omitempty"`
}

// exitDevice returns the named exit node if doc allows it for self now.
func exitDevice(doc *trust.Document, self trust.Device, name string, now time.Time) (trust.Device, error) {
	if name == self.Name {
		return trust.Device{}, errors.New("cihaz kendisini çıkış düğümü olarak kullanamaz")
	}
	d, ok := doc.DeviceByName(name)
	if !ok || !d.HasRole(trust.RoleExitNode) {
		return trust.Device{}, fmt.Errorf("%q ağda bir çıkış düğümü değil", name)
	}
	if !now.Before(d.ExpiresAt) {
		return trust.Device{}, fmt.Errorf("%q çıkış düğümünün üyeliği dolmuş", name)
	}
	return d, nil
}

// planFor computes the VPN interface for self in doc.
func planFor(doc *trust.Document, self trust.Device, o startOptions, now time.Time) (vpnPlan, error) {
	if !self.IPv4.Is4() || !doc.IPv4Prefix.IsValid() {
		return vpnPlan{}, errors.New("ağ belgesinde bu cihazın IPv4 adresi yok")
	}
	p := vpnPlan{Session: "OpenScale", MTU: o.MTU}
	p.Addresses = append(p.Addresses, netip.PrefixFrom(self.IPv4, doc.IPv4Prefix.Bits()).String())
	p.Routes = append(p.Routes, doc.IPv4Prefix.Masked().String())
	if self.IPv6.IsValid() && doc.IPv6Prefix.IsValid() {
		p.Addresses = append(p.Addresses, netip.PrefixFrom(self.IPv6, doc.IPv6Prefix.Bits()).String())
		p.Routes = append(p.Routes, doc.IPv6Prefix.Masked().String())
	}
	forward := doc.DNS != nil && len(doc.DNS.Nameservers) > 0
	if o.ExitNode != "" {
		exit, err := exitDevice(doc, self, o.ExitNode, now)
		if err != nil {
			return vpnPlan{}, err
		}
		p.ExitNode, p.FullTunnel = exit.Name, true
		// The default routes: IPv6 without an IPv6 exit goes nowhere
		// rather than around the tunnel.
		p.Routes = append(p.Routes, "0.0.0.0/0", "::/0")
		forward = true
	}
	if forward {
		p.DNSServers = append(p.DNSServers, doc.DNSResolverIPv4().String())
		if doc.DNSDomain != "" {
			p.SearchDomains = append(p.SearchDomains, doc.DNSDomain)
		}
	}
	o.applyApps(&p)
	return p, nil
}

// Plan returns, as JSON, the addresses, routes, DNS and MTU the app gives
// VpnService.Builder before it establishes the interface and calls
// Tunnel.Start with the same options.
func Plan(stateDir string, secrets []byte, options string) (string, error) {
	if err := checkStateDir(stateDir); err != nil {
		return "", err
	}
	o, err := parseOptions(options)
	if err != nil {
		return "", err
	}
	store, err := member.Open(stateDir)
	if err != nil {
		return "", err
	}
	s, err := parseSecrets(secrets)
	if err != nil {
		return "", err
	}
	defer wipeSecrets(s)
	doc := store.Document()
	self, err := selfDevice(doc, s)
	if err != nil {
		return "", err
	}
	p, err := planFor(doc, self, o, time.Now())
	if err != nil {
		return "", err
	}
	out, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	return string(out), nil
}
