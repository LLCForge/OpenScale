package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/node"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/internal/wgconf"
)

// Diagnostics shared by the desktop service and a foreground "openscale
// up" (F-014, F-016, F-057, F-110, F-191, F-208). Everything is read from
// the running engine and the signed document; nothing here changes the
// network except DiagReconnect.

// ErrTunnelNotRunning is returned while no tunnel runs.
var ErrTunnelNotRunning = errors.New("tünel çalışmıyor; önce bağlantıyı açın")

// errUnknownDevice is returned for names and addresses not in the document.
var errUnknownDevice = errors.New("ağ belgesinde böyle bir cihaz yok")

// EngineDiag answers the engine-backed diagnostics.
type EngineDiag struct {
	// Engine returns the running engine or nil.
	Engine func() *node.Engine
	// Interface returns the tunnel interface name ("" if unknown).
	Interface func() string
	Now       func() time.Time
	// Ping sends one ICMP echo through the tunnel; nil uses PingICMPv4.
	Ping func(ctx context.Context, src, dst netip.Addr) (time.Duration, error)
	// Lookup resolves name with the MagicDNS resolver at server; nil uses
	// a DNS client over UDP.
	Lookup func(ctx context.Context, server netip.AddrPort, name string) ([]netip.Addr, error)
}

func (d *EngineDiag) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

func (d *EngineDiag) engine() (*node.Engine, error) {
	if d.Engine == nil {
		return nil, ErrTunnelNotRunning
	}
	e := d.Engine()
	if e == nil {
		return nil, ErrTunnelNotRunning
	}
	return e, nil
}

// pathOf classifies WireGuard's view of a peer.
func pathOf(s wgconf.PeerStatus, ok bool) string {
	switch {
	case !ok:
		return panel.PathNone
	case s.Relayed:
		return panel.PathRelay
	case s.Endpoint.IsValid():
		return panel.PathDirect
	}
	return panel.PathNone
}

func roleNames(rs []trust.Role) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, string(r))
	}
	return out
}

// SelfOf describes the device for "status" and "whoami".
func SelfOf(doc *trust.Document, self trust.Device) *panel.DiagSelf {
	s := &panel.DiagSelf{Name: self.Name, FQDN: self.Name + "." + doc.DNSDomain, IPv4: self.IPv4.String(), IPv6: self.IPv6.String(),
		Tags: slices.Clone(self.Tags), Roles: roleNames(self.Roles)}
	if !self.ExpiresAt.IsZero() {
		t := self.ExpiresAt
		s.ExpiresAt = &t
	}
	return s
}

// BaseStatus fills the engine part of "openscale status".
func (d *EngineDiag) BaseStatus() (panel.DiagStatus, error) {
	st := panel.DiagStatus{Schema: panel.DiagSchema, Peers: []panel.DiagPeer{}, Health: []panel.HealthAlert{}}
	e, err := d.engine()
	if err != nil {
		return st, nil
	}
	doc := e.Document()
	self, err := e.Self()
	if err != nil {
		return st, err
	}
	st.Running = true
	st.Self = SelfOf(doc, self)
	st.DocumentVersion = doc.Version
	if d.Interface != nil {
		st.Interface = d.Interface()
	}
	es := e.Status()
	if !es.LastSync.IsZero() {
		t := es.LastSync
		st.LastSync = &t
	}
	st.LastSyncError = es.LastSyncError
	st.ExitNode = e.ExitNode()
	st.Peers = d.peers(e, doc, self)
	st.Traffic = diagTraffic(e)
	return st, nil
}

func (d *EngineDiag) peers(e *node.Engine, doc *trust.Document, self trust.Device) []panel.DiagPeer {
	stats, _ := e.PeerStats()
	paths, _ := e.PeerPaths()
	byName := make(map[string]node.PeerPath, len(paths))
	for _, p := range paths {
		byName[p.Name] = p
	}
	now := d.now()
	exit := e.ExitNode()
	out := []panel.DiagPeer{}
	for _, dev := range doc.TunnelPeersOf(self.Name) {
		s, ok := stats[dev.WireGuardKey]
		p := panel.DiagPeer{Name: dev.Name, FQDN: dev.Name + "." + doc.DNSDomain, IPv4: dev.IPv4.String(), IPv6: dev.IPv6.String(),
			Path: pathOf(s, ok), ExitNode: dev.HasRole(trust.RoleExitNode), ActiveExit: exit != "" && exit == dev.Name}
		if ok {
			p.RxBytes, p.TxBytes = s.RxBytes, s.TxBytes
			if s.Endpoint.IsValid() && !s.Relayed {
				p.Endpoint = s.Endpoint.String()
			}
			if s.LastHandshakeUnix > 0 {
				t := time.Unix(s.LastHandshakeUnix, 0)
				p.LastHandshake = &t
				p.Online = now.Sub(t) < onlineWindow
			}
		}
		if pp, ok := byName[dev.Name]; ok {
			p.PostQuantum = pp.PostQuantum
			if pp.ProbeRTT > 0 {
				ms := panel.Millis(pp.ProbeRTT)
				p.LatencyMS = &ms
			}
		}
		out = append(out, p)
	}
	return out
}

// DiagNetCheck implements panel.Diagnostics.
func (d *EngineDiag) DiagNetCheck(ctx context.Context) (node.NetReport, error) {
	e, err := d.engine()
	if err != nil {
		return node.NetReport{}, err
	}
	return e.NetCheck(ctx)
}

// DiagPaths implements panel.Diagnostics.
func (d *EngineDiag) DiagPaths() ([]node.PeerPath, error) {
	e, err := d.engine()
	if err != nil {
		return nil, err
	}
	return e.PeerPaths()
}

// DiagReconnect implements panel.Diagnostics.
func (d *EngineDiag) DiagReconnect() error {
	e, err := d.engine()
	if err != nil {
		return err
	}
	e.ForceReconnect()
	return nil
}

// FindDevice resolves a device name, FQDN or overlay address.
func FindDevice(doc *trust.Document, q string) (trust.Device, bool) {
	q = strings.TrimSuffix(strings.TrimSpace(q), ".")
	if a, err := netip.ParseAddr(q); err == nil {
		a = a.Unmap()
		for _, dev := range doc.Devices {
			if dev.IPv4 == a || dev.IPv6 == a {
				return dev, true
			}
		}
		return trust.Device{}, false
	}
	name := strings.ToLower(q)
	if base, ok := strings.CutSuffix(name, "."+strings.ToLower(doc.DNSDomain)); ok {
		name = base
	}
	return doc.DeviceByName(name)
}

// DiagRelayTest implements panel.Diagnostics.
func (d *EngineDiag) DiagRelayTest(ctx context.Context, peer string) (time.Duration, error) {
	e, err := d.engine()
	if err != nil {
		return 0, err
	}
	dev, ok := FindDevice(e.Document(), peer)
	if !ok {
		return 0, errUnknownDevice
	}
	return e.TestRelay(ctx, dev.Name)
}

// DiagPing implements panel.Diagnostics: one ICMP echo through the tunnel
// to the peer's overlay address. When ICMP cannot be used (no permission,
// the peer's firewall), a relayed peer is measured through the relay and a
// direct one by its last path probe.
func (d *EngineDiag) DiagPing(ctx context.Context, peer string) (panel.PingResult, error) {
	e, err := d.engine()
	if err != nil {
		return panel.PingResult{}, err
	}
	doc := e.Document()
	self, err := e.Self()
	if err != nil {
		return panel.PingResult{}, err
	}
	dev, ok := FindDevice(doc, peer)
	if !ok {
		return panel.PingResult{}, errUnknownDevice
	}
	if dev.Name == self.Name {
		return panel.PingResult{}, errors.New("bu cihazın kendisine ping atılamaz")
	}
	res := panel.PingResult{Schema: panel.DiagSchema, Peer: dev.Name, IPv4: dev.IPv4.String()}
	stats, _ := e.PeerStats()
	s, have := stats[dev.WireGuardKey]
	if !have {
		return res, errors.New("bu cihazla tünel yok: kurallar iki cihazın birbirine ulaşmasına izin vermiyor olabilir")
	}
	ping := d.Ping
	if ping == nil {
		ping = PingICMPv4
	}
	rtt, perr := ping(ctx, self.IPv4, dev.IPv4)
	// The path is read after the echo: the packet itself may have started
	// a handshake.
	if st2, err := e.PeerStats(); err == nil {
		if s2, ok := st2[dev.WireGuardKey]; ok {
			s = s2
		}
	}
	res.Path = pathOf(s, true)
	if s.Endpoint.IsValid() && !s.Relayed {
		res.Endpoint = s.Endpoint.String()
	}
	if perr == nil {
		ms := panel.Millis(rtt)
		res.RTTMS, res.Method = &ms, panel.PingICMP
		return res, nil
	}
	switch res.Path {
	case panel.PathRelay:
		if rtt, err := e.TestRelay(ctx, dev.Name); err == nil {
			ms := panel.Millis(rtt)
			res.RTTMS, res.Method = &ms, panel.PingRelay
			return res, nil
		}
	case panel.PathDirect:
		paths, _ := e.PeerPaths()
		for _, p := range paths {
			if p.Name == dev.Name && p.ProbeRTT > 0 {
				ms := panel.Millis(p.ProbeRTT)
				res.RTTMS, res.Method = &ms, panel.PingProbe
				return res, nil
			}
		}
	}
	res.Error = "yanıt yok: " + perr.Error()
	return res, nil
}

// lookupMagicDNS asks the MagicDNS resolver directly over UDP.
func lookupMagicDNS(ctx context.Context, server netip.AddrPort, name string) ([]netip.Addr, error) {
	res := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var dl net.Dialer
		return dl.DialContext(ctx, "udp", server.String())
	}}
	return res.LookupNetIP(ctx, "ip", name)
}

// DiagDNSQuery implements panel.Diagnostics: the name is asked from this
// device's MagicDNS resolver through the tunnel interface.
func (d *EngineDiag) DiagDNSQuery(ctx context.Context, name string) (panel.DNSQueryResult, error) {
	e, err := d.engine()
	if err != nil {
		return panel.DNSQueryResult{}, err
	}
	resolver, domain := e.DNSResolver()
	server, err := netip.ParseAddr(resolver)
	if err != nil {
		return panel.DNSQueryResult{}, errors.New("MagicDNS çözücü adresi yok")
	}
	fqdn := strings.TrimSuffix(name, ".")
	if !strings.Contains(fqdn, ".") {
		fqdn += "." + domain
	}
	out := panel.DNSQueryResult{Schema: panel.DiagSchema, Name: fqdn, Resolver: resolver, Addrs: []string{}}
	lookup := d.Lookup
	if lookup == nil {
		lookup = lookupMagicDNS
	}
	start := time.Now()
	addrs, err := lookup(ctx, netip.AddrPortFrom(server, 53), fqdn)
	out.RTTMS = panel.Millis(time.Since(start))
	if err != nil {
		out.Error = err.Error()
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			out.Error = "ad bulunamadı (NXDOMAIN)"
		}
		return out, nil
	}
	for _, a := range addrs {
		out.Addrs = append(out.Addrs, a.Unmap().String())
	}
	return out, nil
}

// KeyFingerprint is a short, stable label of a public key.
func KeyFingerprint(k trust.Key) string {
	sum := sha256.Sum256(k[:])
	return hex.EncodeToString(sum[:6])
}

// groupsOf lists the groups a device belongs to.
func groupsOf(doc *trust.Document, dev trust.Device) []string {
	out := []string{}
	for _, g := range doc.Groups {
		for _, m := range g.Members {
			tag, isTag := strings.CutPrefix(m, trust.TagPrefix)
			if (isTag && slices.Contains(dev.Tags, tag)) || (!isTag && m == dev.Name) {
				out = append(out, g.Name)
				break
			}
		}
	}
	return out
}

// Whois describes a device of doc (F-110); q "" is self. stats may be nil.
func Whois(doc *trust.Document, self trust.Device, q string, stats map[trust.Key]wgconf.PeerStatus, now time.Time) (panel.WhoisResult, error) {
	res := panel.WhoisResult{Schema: panel.DiagSchema, Query: q}
	dev := self
	if q != "" {
		if c := doc.Coordinator; c != nil {
			if a, err := netip.ParseAddr(q); err == nil && (a.Unmap() == c.IPv4 || a.Unmap() == c.IPv6) {
				res.Coordinator = true
				return res, nil
			}
		}
		found, ok := FindDevice(doc, q)
		if !ok {
			return res, errUnknownDevice
		}
		dev = found
	}
	w := &panel.WhoisDevice{Name: dev.Name, FQDN: dev.Name + "." + doc.DNSDomain, IPv4: dev.IPv4.String(), IPv6: dev.IPv6.String(),
		Tags: append([]string{}, dev.Tags...), Groups: groupsOf(doc, dev), Roles: roleNames(dev.Roles), AddedAt: dev.AddedAt,
		Self: dev.Name == self.Name, Fingerprint: KeyFingerprint(dev.WireGuardKey)}
	if !dev.ExpiresAt.IsZero() {
		t := dev.ExpiresAt
		w.ExpiresAt = &t
	}
	if s, ok := stats[dev.WireGuardKey]; ok && !w.Self {
		w.Path = pathOf(s, true)
		w.Online = s.LastHandshakeUnix > 0 && now.Sub(time.Unix(s.LastHandshakeUnix, 0)) < onlineWindow
	}
	res.Device = w
	return res, nil
}

// DiagWhois implements panel.Diagnostics.
func (d *EngineDiag) DiagWhois(q string) (panel.WhoisResult, error) {
	e, err := d.engine()
	if err != nil {
		return panel.WhoisResult{}, err
	}
	self, err := e.Self()
	if err != nil {
		return panel.WhoisResult{}, err
	}
	stats, _ := e.PeerStats()
	return Whois(e.Document(), self, q, stats, d.now())
}

// DiagWireGuard implements panel.Diagnostics: WireGuard's state without
// any secret (F-208). The UAPI socket itself is never exposed.
func (d *EngineDiag) DiagWireGuard() (panel.WGShow, error) {
	e, err := d.engine()
	if err != nil {
		return panel.WGShow{}, err
	}
	doc := e.Document()
	self, err := e.Self()
	if err != nil {
		return panel.WGShow{}, err
	}
	stats, err := e.PeerStats()
	if err != nil {
		return panel.WGShow{}, err
	}
	paths, _ := e.PeerPaths()
	pq := map[string]string{}
	for _, p := range paths {
		pq[p.Name] = p.PostQuantum
	}
	out := panel.WGShow{Schema: panel.DiagSchema, PublicKey: self.WireGuardKey.String(), Peers: []panel.WGPeer{}}
	if d.Interface != nil {
		out.Interface = d.Interface()
	}
	add := func(name string, key trust.Key, allowed []string) {
		p := panel.WGPeer{Name: name, PublicKey: key.String(), AllowedIPs: allowed}
		if s, ok := stats[key]; ok {
			p.Relayed, p.RxBytes, p.TxBytes = s.Relayed, s.RxBytes, s.TxBytes
			if s.Endpoint.IsValid() && !s.Relayed {
				p.Endpoint = s.Endpoint.String()
			}
			if s.LastHandshakeUnix > 0 {
				t := time.Unix(s.LastHandshakeUnix, 0)
				p.LastHandshake = &t
			}
		}
		p.PostQuantum = pq[name]
		out.Peers = append(out.Peers, p)
	}
	if c := doc.Coordinator; c != nil {
		var allowed []string
		for _, a := range []netip.Addr{c.IPv4, c.IPv6} {
			if a.IsValid() {
				allowed = append(allowed, netip.PrefixFrom(a, a.BitLen()).String())
			}
		}
		add("koordinatör", c.WireGuardKey, allowed)
	}
	exit := e.ExitNode()
	for _, dev := range doc.TunnelPeersOf(self.Name) {
		allowed := []string{netip.PrefixFrom(dev.IPv4, 32).String(), netip.PrefixFrom(dev.IPv6, 128).String()}
		if exit != "" && exit == dev.Name {
			allowed = append(allowed, "0.0.0.0/0", "::/0")
		}
		add(dev.Name, dev.WireGuardKey, allowed)
	}
	return out, nil
}
