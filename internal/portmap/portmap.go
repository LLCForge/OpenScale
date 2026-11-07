// Package portmap asks the local Internet gateway (the home router) to
// forward a UDP port to this device, so that other devices can reach its
// WireGuard port directly (ADR-0042, #55, F-003). It speaks PCP (RFC 6887),
// NAT-PMP (RFC 6886) and UPnP-IGD, in that order, and talks to nothing but
// the gateway: PCP and NAT-PMP go to its UDP port 5351, SSDP discovery is
// sent to the gateway and with TTL 2 to the local multicast group, and only
// HTTP URLs on the gateway's own IP address are followed.
//
// A mapping is renewed at half its lifetime, checked every two minutes for
// a gateway restart (the PCP/NAT-PMP epoch; for UPnP whether the entry still
// exists) and deleted when the client closes.
package portmap

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/netip"
	"strings"
	"sync"
	"time"
	"unicode"
)

// Protocol is a port mapping protocol.
type Protocol uint8

// The protocols, in the order they are tried.
const (
	ProtoNone Protocol = iota
	ProtoPCP
	ProtoNATPMP
	ProtoUPnP
)

func (p Protocol) String() string {
	switch p {
	case ProtoPCP:
		return "PCP"
	case ProtoNATPMP:
		return "NAT-PMP"
	case ProtoUPnP:
		return "UPnP-IGD"
	default:
		return "yok"
	}
}

// Lifetime bounds and defaults.
const (
	DefaultLifetime = 2 * time.Hour
	MinLifetime     = 2 * time.Minute
	MaxLifetime     = 24 * time.Hour
	// checkEvery is how often a mapping is checked for a gateway restart
	// or an external address change.
	checkEvery = 2 * time.Minute
	// Retry backoff after a failed mapping round.
	retryFirst = 30 * time.Second
	retryMax   = 15 * time.Minute
	// closeTimeout bounds deleting the mapping on close.
	closeTimeout = 3 * time.Second
	// pcpPort is the PCP and NAT-PMP server port (RFC 6887 §19.1).
	pcpPort = 5351
	// upnpPortTries is how many random external ports are tried after
	// the internal port conflicts.
	upnpPortTries = 3
	// maxDescriptionLen bounds the UPnP mapping description.
	maxDescriptionLen = 64
)

// Errors.
var (
	// ErrGatewayNotAllowed is returned for a gateway or local address that
	// is not a private, link-local or shared (100.64/10) IPv4 address.
	ErrGatewayNotAllowed = errors.New("ağ geçidi ya da yerel adres yerel ağda değil")
	// ErrNotPublic is returned when the gateway's external address is not
	// a public address (double NAT): the mapping would be useless.
	ErrNotPublic = errors.New("ağ geçidinin dış adresi genel bir adres değil (çift NAT)")
	// ErrPermanentOnly is returned for a UPnP gateway that only grants
	// mappings without expiry, which are refused (ADR-0042).
	ErrPermanentOnly = errors.New("ağ geçidi yalnızca süresiz eşleme veriyor; kullanılmadı")
	// ErrAllDisabled is returned when every protocol is turned off.
	ErrAllDisabled = errors.New("bütün port eşleme protokolleri kapalı")
)

// Options configures a Client.
type Options struct {
	// DisablePCP, DisableNATPMP and DisableUPnP turn single protocols off.
	DisablePCP    bool
	DisableNATPMP bool
	DisableUPnP   bool
	// Lifetime is the requested mapping lifetime; zero uses
	// DefaultLifetime. Allowed: MinLifetime to MaxLifetime.
	Lifetime time.Duration
	// Description names the UPnP mapping on the router; "" uses
	// "OpenScale". Printable, at most 64 bytes.
	Description string
	Logger      *slog.Logger
	Now         func() time.Time

	// Test hooks.
	pcpPort       int
	ssdpPort      int
	noMulticast   bool
	allowLoopback bool
	retries       []time.Duration
	checkEvery    time.Duration
	retryFirst    time.Duration
}

// Mapping is a port mapping the gateway granted.
type Mapping struct {
	Protocol Protocol
	// External is the public address and port other devices use.
	External netip.AddrPort
	// Internal is this device's local address and port.
	Internal netip.AddrPort
	// Lifetime is what the gateway granted.
	Lifetime time.Duration
	// Obtained is when it was granted or last renewed.
	Obtained time.Time
}

// RenewAt is when the mapping is renewed: half its lifetime.
func (m Mapping) RenewAt() time.Time { return m.Obtained.Add(m.Lifetime / 2) }

// Expires is when the gateway drops the mapping unless renewed.
func (m Mapping) Expires() time.Time { return m.Obtained.Add(m.Lifetime) }

// Client maps one UDP port of this device on one gateway.
type Client struct {
	gw, local netip.Addr
	port      uint16
	opts      Options
	logger    *slog.Logger

	// op serializes network operations; mu guards the state below.
	op    sync.Mutex
	mu    sync.Mutex
	cur   Mapping
	have  bool
	nonce [pcpNonceLen]byte
	epoch epochState
	upnp  *upnpService
	// skip remembers protocols the gateway does not speak until the next
	// failure of the others.
	skip map[Protocol]bool
}

// allowedLocal reports whether a is an address port mapping may be done
// from or to: private, link-local or shared address space IPv4.
func allowedLocal(a netip.Addr, loopback bool) bool {
	a = a.Unmap()
	if !a.Is4() {
		return false
	}
	if loopback && a.IsLoopback() {
		return true
	}
	return a.IsPrivate() || a.IsLinkLocalUnicast() || sharedAddressSpace.Contains(a)
}

var sharedAddressSpace = netip.MustParsePrefix("100.64.0.0/10")

// IsPublic reports whether a is a public unicast IPv4 address, the only
// kind of external address a mapping is useful with.
func IsPublic(a netip.Addr) bool {
	a = a.Unmap()
	return a.Is4() && a.IsGlobalUnicast() && !a.IsPrivate() && !sharedAddressSpace.Contains(a) &&
		!netip.MustParsePrefix("192.0.0.0/24").Contains(a) && !netip.MustParsePrefix("198.18.0.0/15").Contains(a) &&
		!netip.MustParsePrefix("240.0.0.0/4").Contains(a)
}

// New prepares a client that maps internalPort of local on gateway.
func New(gateway, local netip.Addr, internalPort uint16, opts Options) (*Client, error) {
	gateway, local = gateway.Unmap(), local.Unmap()
	if !allowedLocal(gateway, opts.allowLoopback) || !allowedLocal(local, opts.allowLoopback) {
		return nil, ErrGatewayNotAllowed
	}
	if internalPort == 0 {
		return nil, errors.New("iç port 0 olamaz")
	}
	if opts.DisablePCP && opts.DisableNATPMP && opts.DisableUPnP {
		return nil, ErrAllDisabled
	}
	if opts.Lifetime == 0 {
		opts.Lifetime = DefaultLifetime
	}
	if opts.Lifetime < MinLifetime || opts.Lifetime > MaxLifetime {
		return nil, fmt.Errorf("eşleme süresi %s ile %s arasında olmalı", MinLifetime, MaxLifetime)
	}
	if opts.Description == "" {
		opts.Description = "OpenScale"
	}
	if len(opts.Description) > maxDescriptionLen || strings.IndexFunc(opts.Description, func(r rune) bool { return !unicode.IsPrint(r) }) >= 0 {
		return nil, errors.New("eşleme açıklaması en fazla 64 yazdırılabilir karakter olmalı")
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.pcpPort == 0 {
		opts.pcpPort = pcpPort
	}
	if opts.ssdpPort == 0 {
		opts.ssdpPort = ssdpPort
	}
	if opts.retries == nil {
		opts.retries = defaultRetries
	}
	if opts.checkEvery == 0 {
		opts.checkEvery = checkEvery
	}
	if opts.retryFirst == 0 {
		opts.retryFirst = retryFirst
	}
	c := &Client{gw: gateway, local: local, port: internalPort, opts: opts, logger: opts.Logger, skip: map[Protocol]bool{}}
	if _, err := rand.Read(c.nonce[:]); err != nil {
		return nil, err
	}
	return c, nil
}

// Gateway returns the gateway address.
func (c *Client) Gateway() netip.Addr { return c.gw }

// Current returns the mapping in effect, if any.
func (c *Client) Current() (Mapping, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cur, c.have
}

func (c *Client) set(m Mapping) {
	c.mu.Lock()
	c.cur, c.have = m, true
	c.mu.Unlock()
}

func (c *Client) clear() {
	c.mu.Lock()
	c.cur, c.have = Mapping{}, false
	c.mu.Unlock()
}

// Map creates the mapping, or renews the one in effect with the same
// protocol. A failed renewal forgets the mapping and tries every enabled
// protocol again.
func (c *Client) Map(ctx context.Context) (Mapping, error) {
	c.op.Lock()
	defer c.op.Unlock()
	cur, have := c.Current()
	if have {
		m, err := c.mapWith(ctx, cur.Protocol, cur.External)
		if err == nil {
			return m, nil
		}
		c.logger.Debug("port mapping renewal failed", "protocol", cur.Protocol.String(), "error", err.Error())
		c.clear()
	}
	var errs []error
	for _, p := range []Protocol{ProtoPCP, ProtoNATPMP, ProtoUPnP} {
		if c.disabled(p) || c.skip[p] {
			continue
		}
		m, err := c.mapWith(ctx, p, netip.AddrPort{})
		if err == nil {
			return m, nil
		}
		if ctx.Err() != nil {
			return Mapping{}, ctx.Err()
		}
		if errors.Is(err, errNATPMPOnly) {
			c.skip[ProtoPCP] = true
		}
		errs = append(errs, fmt.Errorf("%s: %w", p, err))
		if errors.Is(err, ErrNotPublic) {
			break // another protocol sees the same external address
		}
	}
	// Next round tries the skipped protocols again.
	clear(c.skip)
	if len(errs) == 0 {
		return Mapping{}, ErrAllDisabled
	}
	return Mapping{}, errors.Join(errs...)
}

func (c *Client) disabled(p Protocol) bool {
	switch p {
	case ProtoPCP:
		return c.opts.DisablePCP
	case ProtoNATPMP:
		return c.opts.DisableNATPMP
	case ProtoUPnP:
		return c.opts.DisableUPnP
	}
	return true
}

// mapWith maps with one protocol; prev is the external address to ask for
// again when renewing.
func (c *Client) mapWith(ctx context.Context, p Protocol, prev netip.AddrPort) (Mapping, error) {
	var (
		m   Mapping
		err error
	)
	switch p {
	case ProtoPCP:
		m, err = c.mapPCP(ctx, prev, uint32(c.opts.Lifetime/time.Second))
	case ProtoNATPMP:
		m, err = c.mapNATPMP(ctx, prev.Port(), uint32(c.opts.Lifetime/time.Second))
	case ProtoUPnP:
		m, err = c.mapUPnP(ctx, prev.Port())
	default:
		return Mapping{}, errors.New("bilinmeyen protokol")
	}
	if err != nil {
		return Mapping{}, err
	}
	if m.Lifetime < MinLifetime {
		c.deleteWith(ctx, m)
		return Mapping{}, fmt.Errorf("ağ geçidi çok kısa süre verdi (%s)", m.Lifetime)
	}
	if !IsPublic(m.External.Addr()) && !(c.opts.allowLoopback && m.External.Addr().IsLoopback()) {
		c.deleteWith(ctx, m)
		return Mapping{}, ErrNotPublic
	}
	c.set(m)
	return m, nil
}

func (c *Client) mapPCP(ctx context.Context, prev netip.AddrPort, lifetime uint32) (Mapping, error) {
	suggest := prev
	if !suggest.IsValid() {
		suggest = netip.AddrPortFrom(netip.IPv4Unspecified(), c.port)
	}
	req := pcpMapRequest(c.local, c.nonce, c.port, suggest, lifetime)
	var resp pcpResponse
	var perr error
	_, err := c.exchange(ctx, c.opts.pcpPort, req, func(b []byte) bool {
		r, err := parsePCPResponse(b)
		if errors.Is(err, errNATPMPOnly) {
			perr = err
			return true
		}
		if err != nil || r.op != pcpOpMap {
			return false
		}
		if r.result == pcpSuccess && (r.nonce != c.nonce || r.proto != protoUDP || r.internal != c.port) {
			return false
		}
		resp = r
		return true
	})
	if err != nil {
		return Mapping{}, err
	}
	if perr != nil {
		return Mapping{}, perr
	}
	c.noteEpoch(resp.epoch)
	if resp.result != pcpSuccess {
		return Mapping{}, pcpError(resp.result)
	}
	if !resp.external.IsValid() || resp.external.Port() == 0 || resp.lifetime == 0 {
		return Mapping{}, errMalformed
	}
	return Mapping{Protocol: ProtoPCP, External: resp.external, Internal: netip.AddrPortFrom(c.local, c.port),
		Lifetime: time.Duration(resp.lifetime) * time.Second, Obtained: c.opts.Now()}, nil
}

func (c *Client) mapNATPMP(ctx context.Context, prevPort uint16, lifetime uint32) (Mapping, error) {
	ext, err := c.natpmpExternal(ctx)
	if err != nil {
		return Mapping{}, err
	}
	suggest := prevPort
	if suggest == 0 {
		suggest = c.port
	}
	var resp natpmpResponse
	_, err = c.exchange(ctx, c.opts.pcpPort, natpmpMapRequest(c.port, suggest, lifetime), func(b []byte) bool {
		r, err := parseNATPMPResponse(b)
		if err != nil || r.op != natpmpOpMapUDP || (r.result == 0 && r.internal != c.port) {
			return false
		}
		resp = r
		return true
	})
	if err != nil {
		return Mapping{}, err
	}
	c.noteEpoch(resp.epoch)
	if resp.result != 0 {
		return Mapping{}, natpmpError(resp.result)
	}
	if resp.mapped == 0 || resp.lifetime == 0 {
		return Mapping{}, errMalformed
	}
	return Mapping{Protocol: ProtoNATPMP, External: netip.AddrPortFrom(ext, resp.mapped), Internal: netip.AddrPortFrom(c.local, c.port),
		Lifetime: time.Duration(resp.lifetime) * time.Second, Obtained: c.opts.Now()}, nil
}

// natpmpExternal asks for the external address (and notes the epoch).
func (c *Client) natpmpExternal(ctx context.Context) (netip.Addr, error) {
	var resp natpmpResponse
	_, err := c.exchange(ctx, c.opts.pcpPort, natpmpExternalRequest(), func(b []byte) bool {
		r, err := parseNATPMPResponse(b)
		if err != nil || r.op != natpmpOpExternal {
			return false
		}
		resp = r
		return true
	})
	if err != nil {
		return netip.Addr{}, err
	}
	c.noteEpoch(resp.epoch)
	if resp.result != 0 {
		return netip.Addr{}, natpmpError(resp.result)
	}
	return resp.external, nil
}

func (c *Client) mapUPnP(ctx context.Context, prevPort uint16) (Mapping, error) {
	c.mu.Lock()
	svc := c.upnp
	c.mu.Unlock()
	if svc == nil {
		var err error
		if svc, err = c.discover(ctx); err != nil {
			return Mapping{}, err
		}
		c.mu.Lock()
		c.upnp = svc
		c.mu.Unlock()
	}
	ext, err := c.upnpExternalIP(ctx, svc)
	if err != nil {
		c.forgetUPnP()
		return Mapping{}, err
	}
	if !IsPublic(ext) && !(c.opts.allowLoopback && ext.IsLoopback()) {
		return Mapping{}, ErrNotPublic
	}
	ports := []uint16{c.port}
	if prevPort != 0 && prevPort != c.port {
		ports = []uint16{prevPort, c.port}
	}
	for range upnpPortTries {
		ports = append(ports, randomPort())
	}
	for i, port := range ports {
		err = c.upnpAdd(ctx, svc, port, c.opts.Lifetime)
		switch faultCode(err) {
		case 0:
		case upnpOnlyPermanent:
			return Mapping{}, ErrPermanentOnly
		case upnpConflict:
			continue
		case upnpSamePortRequired:
			if i == 0 {
				return Mapping{}, err
			}
			continue
		default:
			return Mapping{}, err
		}
		if err != nil {
			c.forgetUPnP()
			return Mapping{}, err
		}
		return Mapping{Protocol: ProtoUPnP, External: netip.AddrPortFrom(ext, port), Internal: netip.AddrPortFrom(c.local, c.port),
			Lifetime: c.opts.Lifetime, Obtained: c.opts.Now()}, nil
	}
	return Mapping{}, err
}

func (c *Client) forgetUPnP() {
	c.mu.Lock()
	c.upnp = nil
	c.mu.Unlock()
}

// randomPort returns a random port in 1024-65535.
func randomPort() uint16 {
	n, err := rand.Int(rand.Reader, big.NewInt(65536-1024))
	if err != nil {
		return 0
	}
	return uint16(1024 + n.Int64())
}

// noteEpoch records an epoch value; a gateway restart forgets the mapping
// so that the next round asks for it again.
func (c *Client) noteEpoch(epoch uint32) {
	c.mu.Lock()
	reset := c.epoch.observe(epoch, c.opts.Now())
	if reset {
		c.cur, c.have = Mapping{}, false
	}
	c.mu.Unlock()
	if reset {
		c.logger.Info("gateway restarted (epoch reset); port mapping requested again")
	}
}

// Check looks for a gateway restart or a change of the external address.
// It returns lost when the mapping must be requested again and changed
// when the external address changed (the mapping is updated).
func (c *Client) Check(ctx context.Context) (lost, changed bool, err error) {
	c.op.Lock()
	defer c.op.Unlock()
	cur, have := c.Current()
	if !have {
		return true, false, nil
	}
	switch cur.Protocol {
	case ProtoPCP:
		var resp pcpResponse
		_, err = c.exchange(ctx, c.opts.pcpPort, pcpAnnounceRequest(c.local), func(b []byte) bool {
			r, err := parsePCPResponse(b)
			if err != nil || r.op != pcpOpAnnounce {
				return false
			}
			resp = r
			return true
		})
		if err != nil {
			return false, false, err
		}
		c.noteEpoch(resp.epoch)
	case ProtoNATPMP:
		var ext netip.Addr
		if ext, err = c.natpmpExternal(ctx); err != nil {
			return false, false, err
		}
		if _, still := c.Current(); still && ext != cur.External.Addr() {
			cur.External = netip.AddrPortFrom(ext, cur.External.Port())
			c.set(cur)
			changed = true
		}
	case ProtoUPnP:
		c.mu.Lock()
		svc := c.upnp
		c.mu.Unlock()
		if svc == nil {
			c.clear()
			return true, false, nil
		}
		owned, err := c.upnpOwned(ctx, svc, cur.External.Port())
		if err != nil {
			return false, false, err
		}
		if !owned {
			c.logger.Info("UPnP port mapping disappeared from the gateway; requesting it again")
			c.clear()
			return true, false, nil
		}
		ext, err := c.upnpExternalIP(ctx, svc)
		if err != nil {
			return false, false, err
		}
		if ext != cur.External.Addr() {
			cur.External = netip.AddrPortFrom(ext, cur.External.Port())
			c.set(cur)
			changed = true
		}
	}
	_, have = c.Current()
	return !have, changed, nil
}

// Close deletes the mapping in effect.
func (c *Client) Close(ctx context.Context) error {
	c.op.Lock()
	defer c.op.Unlock()
	cur, have := c.Current()
	if !have {
		return nil
	}
	c.clear()
	return c.deleteWith(ctx, cur)
}

// deleteWith removes m from the gateway.
func (c *Client) deleteWith(ctx context.Context, m Mapping) error {
	switch m.Protocol {
	case ProtoPCP:
		_, err := c.exchange(ctx, c.opts.pcpPort, pcpMapRequest(c.local, c.nonce, c.port, m.External, 0), func(b []byte) bool {
			r, err := parsePCPResponse(b)
			return err == nil && r.op == pcpOpMap
		})
		return err
	case ProtoNATPMP:
		_, err := c.exchange(ctx, c.opts.pcpPort, natpmpMapRequest(c.port, 0, 0), func(b []byte) bool {
			r, err := parseNATPMPResponse(b)
			return err == nil && r.op == natpmpOpMapUDP
		})
		return err
	case ProtoUPnP:
		c.mu.Lock()
		svc := c.upnp
		c.mu.Unlock()
		if svc == nil {
			return nil
		}
		return c.upnpDelete(ctx, svc, m.External.Port())
	}
	return nil
}

// Run keeps the mapping alive until ctx ends, then deletes it. onChange is
// called with the new mapping when the external address changes and with
// ok false when the mapping is lost.
func (c *Client) Run(ctx context.Context, onChange func(m Mapping, ok bool)) {
	defer func() {
		cctx, cancel := context.WithTimeout(context.Background(), closeTimeout)
		defer cancel()
		if err := c.Close(cctx); err != nil {
			c.logger.Debug("delete port mapping", "error", err.Error())
		}
		if onChange != nil {
			onChange(Mapping{}, false)
		}
	}()
	var (
		last    netip.AddrPort
		backoff = c.opts.retryFirst
	)
	report := func() {
		m, ok := c.Current()
		ext := netip.AddrPort{}
		if ok {
			ext = m.External
		}
		if ext == last {
			return
		}
		last = ext
		if onChange != nil {
			onChange(m, ok)
		}
	}
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		now := c.opts.Now()
		cur, have := c.Current()
		var wait time.Duration
		switch {
		case !have || !now.Before(cur.RenewAt()):
			m, err := c.Map(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				c.logger.Debug("port mapping", "error", err.Error())
				report()
				wait = backoff
				backoff = min(2*backoff, retryMax)
				break
			}
			if !have || m.External != cur.External {
				c.logger.Info("port mapped", "protocol", m.Protocol.String(), "external", m.External.String(), "lifetime", m.Lifetime.String())
			}
			backoff = c.opts.retryFirst
			report()
			wait = min(c.opts.checkEvery, m.RenewAt().Sub(c.opts.Now()))
		default:
			lost, _, err := c.Check(ctx)
			if ctx.Err() != nil {
				return
			}
			if err != nil {
				c.logger.Debug("port mapping check", "error", err.Error())
			}
			report()
			if lost {
				wait = 0
				break
			}
			wait = min(c.opts.checkEvery, cur.RenewAt().Sub(c.opts.Now()))
		}
		timer.Reset(max(wait, 0))
	}
}
