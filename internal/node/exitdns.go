package node

import (
	"bytes"
	"container/list"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/openscale/openscale/internal/magicdns"
)

// Exit node DNS forwarder (ADR-0018, ADR-0024): members' queries go to the
// exit node's resolver, by plain DNS, DNS over TLS or DNS over HTTPS.
const (
	maxDNSMessage    = 65535
	exitDNSCacheSize = 1024
	exitDNSMaxTTL    = time.Hour
	exitDNSNegTTL    = 60 * time.Second
	// maxCachedMessage keeps the cache small: 1024 entries of at most
	// 4 KiB each.
	maxCachedMessage = 4096
	defaultDoTPort   = "853"
	dnsMediaType     = "application/dns-message"
)

type upstreamKind int

const (
	upstreamUDP       upstreamKind = iota // plain DNS: UDP, TCP when truncated
	upstreamDoT                           // RFC 7858
	upstreamDoH                           // RFC 8484
	upstreamRecursive                     // own recursive resolver (#88)
)

// dnsUpstream is a parsed ExitDNSUpstream value.
type dnsUpstream struct {
	kind upstreamKind
	// addr is host:port for plain DNS and DoT; empty plain addr means the
	// first nameserver in /etc/resolv.conf.
	addr       string
	serverName string
	url        string
	// dnssec validates the recursive resolver's answers (#89, ADR-0102).
	dnssec bool
	// local is the source address of plain DNS queries: the upstream
	// tunnel address of an upstream exit (ADR-0142); zero lets the OS pick.
	local netip.Addr
}

// ValidateExitDNSUpstream checks an exit node upstream resolver setting:
// an IP address with an optional port, "tls://host[:port]" or
// "https://host[:port]/path", or "recursive" for the exit node's own
// recursive resolver (#88), "recursive-dnssec" for the same with DNSSEC
// validation (#89). Empty means the system resolver.
func ValidateExitDNSUpstream(s string) error {
	_, err := parseDNSUpstream(s)
	return err
}

func parseDNSUpstream(s string) (dnsUpstream, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return dnsUpstream{kind: upstreamUDP}, nil
	}
	if strings.EqualFold(s, UpstreamRecursive) {
		return dnsUpstream{kind: upstreamRecursive}, nil
	}
	if strings.EqualFold(s, UpstreamRecursiveDNSSEC) {
		return dnsUpstream{kind: upstreamRecursive, dnssec: true}, nil
	}
	if len(s) > 2048 {
		return dnsUpstream{}, errors.New("üst çözücü adresi çok uzun")
	}
	if !strings.Contains(s, "://") {
		if ap, err := netip.ParseAddrPort(s); err == nil && ap.Port() != 0 {
			return dnsUpstream{kind: upstreamUDP, addr: ap.String()}, nil
		}
		if a, err := netip.ParseAddr(s); err == nil && a.Zone() == "" {
			return dnsUpstream{kind: upstreamUDP, addr: netip.AddrPortFrom(a, dnsPort).String()}, nil
		}
		return dnsUpstream{}, fmt.Errorf("üst çözücü %q geçersiz: IP adresi, tls://sunucu veya https://sunucu/yol olmalı", s)
	}
	u, err := url.Parse(s)
	if err != nil {
		return dnsUpstream{}, fmt.Errorf("üst çözücü adresi çözümlenemedi: %w", err)
	}
	if u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return dnsUpstream{}, errors.New("üst çözücü adresinde kullanıcı bilgisi veya parça (#) olamaz")
	}
	host := u.Hostname()
	if host == "" {
		return dnsUpstream{}, errors.New("üst çözücü adresinde sunucu adı zorunlu")
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return dnsUpstream{}, errors.New("üst çözücü portu geçersiz")
		}
	}
	switch u.Scheme {
	case "https":
		return dnsUpstream{kind: upstreamDoH, url: u.String()}, nil
	case "tls":
		if (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
			return dnsUpstream{}, errors.New("tls:// adresinde yol veya sorgu olamaz")
		}
		port := u.Port()
		if port == "" {
			port = defaultDoTPort
		}
		return dnsUpstream{kind: upstreamDoT, addr: net.JoinHostPort(host, port), serverName: host}, nil
	}
	return dnsUpstream{}, fmt.Errorf("üst çözücü şeması %q desteklenmiyor: yalnızca https:// ve tls://", u.Scheme)
}

// dnsForwarder sends queries upstream and caches the answers.
type dnsForwarder struct {
	up      dnsUpstream
	timeout time.Duration
	// tlsConfig returns the client TLS settings for DoT and DoH; servers
	// are always verified (system roots outside tests).
	tlsConfig func(serverName string) *tls.Config
	http      *http.Client
	// recursive resolves from the root servers (upstreamRecursive).
	recursive *recursiveResolver
	// validator checks DNSSEC on the recursive resolver's answers
	// ("recursive-dnssec"); nil otherwise.
	validator *dnssecValidator
	cache     *dnsCache
	now       func() time.Time
	systemDNS func() string
}

var (
	forwardersMu sync.Mutex
	// forwarders holds one forwarder (and cache) per upstream setting; a
	// process has one or, in tests, a few.
	forwarders = map[string]*dnsForwarder{}
)

const maxForwarders = 16

// exitForwarder returns the shared forwarder for an upstream setting.
func exitForwarder(spec string) (*dnsForwarder, error) {
	forwardersMu.Lock()
	defer forwardersMu.Unlock()
	if f, ok := forwarders[spec]; ok {
		return f, nil
	}
	up, err := parseDNSUpstream(spec)
	if err != nil {
		return nil, err
	}
	f := newDNSForwarder(up, nil)
	if len(forwarders) >= maxForwarders {
		clear(forwarders)
	}
	forwarders[spec] = f
	return f, nil
}

func newDNSForwarder(up dnsUpstream, tlsCfg func(serverName string) *tls.Config) *dnsForwarder {
	if tlsCfg == nil {
		tlsCfg = func(serverName string) *tls.Config {
			return &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12}
		}
	}
	f := &dnsForwarder{
		up:        up,
		timeout:   exitDNSTimeout,
		tlsConfig: tlsCfg,
		cache:     newDNSCache(exitDNSCacheSize),
		now:       time.Now,
		systemDNS: systemResolver,
	}
	if up.kind == upstreamRecursive {
		f.recursive = newRecursiveResolver()
		if up.dnssec {
			f.validator = newDNSSECValidator(f.recursive)
		}
		// A cold walk from the root takes a few round trips.
		f.timeout = 2 * exitDNSTimeout
	}
	if up.kind == upstreamDoH {
		host := ""
		if u, err := url.Parse(up.url); err == nil {
			host = u.Hostname()
		}
		f.http = &http.Client{
			Timeout: exitDNSTimeout,
			Transport: &http.Transport{
				// Straight to the resolver the owner chose: no proxy
				// from the environment.
				Proxy:                 nil,
				TLSClientConfig:       tlsCfg(host),
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          4,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   exitDNSTimeout,
				ResponseHeaderTimeout: exitDNSTimeout,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	return f
}

// clientQuery is what the forwarder needs from a member's query.
type clientQuery struct {
	id       uint16
	question dnsmessage.Question
	key      cacheKey
	limit    int
}

func parseClientQuery(msg []byte) (clientQuery, error) {
	var p dnsmessage.Parser
	hdr, err := p.Start(msg)
	if err != nil {
		return clientQuery{}, err
	}
	if hdr.Response || hdr.OpCode != 0 {
		return clientQuery{}, errors.New("not a standard query")
	}
	q, err := p.Question()
	if err != nil {
		return clientQuery{}, err
	}
	if _, err := p.Question(); !errors.Is(err, dnsmessage.ErrSectionDone) {
		return clientQuery{}, errors.New("query must have exactly one question")
	}
	key := cacheKey{name: strings.ToLower(q.Name.String()), qtype: q.Type, class: q.Class, cd: hdr.CheckingDisabled}
	if p.SkipAllAnswers() == nil && p.SkipAllAuthorities() == nil {
		for {
			h, err := p.AdditionalHeader()
			if err != nil {
				break
			}
			if h.Type == dnsmessage.TypeOPT {
				key.edns, key.do = true, h.DNSSECAllowed()
				break
			}
			if p.SkipAdditional() != nil {
				break
			}
		}
	}
	// The answer travels back in one IPv4 UDP packet.
	limit := min(magicdns.UDPLimit(msg), maxDNSPacket-28)
	return clientQuery{id: hdr.ID, question: q, key: key, limit: limit}, nil
}

// forward answers query (a member's DNS message) from the cache or the
// upstream resolver. The answer carries the member's own ID and fits the
// member's UDP limit.
// Blocked names and the DoH canary never leave (#91, #94); the guards of
// exitdns_guard.go apply (P05).
func (f *dnsForwarder) forward(ctx context.Context, query []byte) ([]byte, error) {
	return f.forwardFrom(ctx, exitClient{}, query, false)
}

// forwardStream answers a member's TCP query: the answer is not cut to a
// UDP size (F-066).
func (f *dnsForwarder) forwardStream(ctx context.Context, query []byte) ([]byte, error) {
	return f.forwardFrom(ctx, exitClient{}, query, true)
}

// fitUDP truncates msg (TC bit) when it exceeds the member's UDP limit.
func fitUDP(msg []byte, limit int) []byte {
	if len(msg) <= limit {
		return msg
	}
	return magicdns.Truncate(msg)
}

// exchange sends query upstream under a fresh, random ID and returns the
// matching response (F-136).
func (f *dnsForwarder) exchange(ctx context.Context, query []byte, q dnsmessage.Question) ([]byte, error) {
	msg := bytes.Clone(query)
	var id uint16
	if f.up.kind != upstreamDoH {
		// DoH uses ID 0 (RFC 8484 4.1); TLS already authenticates it.
		var b [2]byte
		if _, err := rand.Read(b[:]); err != nil {
			return nil, err
		}
		id = binary.BigEndian.Uint16(b[:])
	}
	binary.BigEndian.PutUint16(msg, id)
	// No EDNS Client Subnet upstream; DoT and DoH queries padded (#413, #414).
	msg = prepareUpstream(msg, f.up.kind)

	if f.validator != nil {
		return f.validator.resolve(ctx, msg, id, q)
	}
	if f.up.kind == upstreamRecursive && f.recursive != nil {
		return f.recursive.resolve(ctx, msg, id, q)
	}
	switch f.up.kind {
	case upstreamDoH:
		return f.exchangeDoH(ctx, msg, id, q)
	case upstreamDoT:
		d := tls.Dialer{Config: f.tlsConfig(f.up.serverName)}
		c, err := d.DialContext(ctx, "tcp", f.up.addr)
		if err != nil {
			return nil, err
		}
		defer c.Close()
		return exchangeStream(ctx, c, msg, id, q)
	}
	addr := f.up.addr
	if addr == "" {
		sys := f.systemDNS()
		if sys == "" {
			return nil, errors.New("no upstream resolver")
		}
		addr = net.JoinHostPort(sys, strconv.Itoa(dnsPort))
	}
	var d net.Dialer
	if f.up.local.IsValid() {
		d.LocalAddr = net.UDPAddrFromAddrPort(netip.AddrPortFrom(f.up.local, 0))
	}
	resp, err := exchangeUDPWith(ctx, &d, addr, msg, id, q)
	if err != nil {
		return nil, err
	}
	if len(resp) > 2 && resp[2]&0x02 != 0 {
		// Truncated: ask the same question again over TCP (F-066).
		var d net.Dialer
		if f.up.local.IsValid() {
			d.LocalAddr = net.TCPAddrFromAddrPort(netip.AddrPortFrom(f.up.local, 0))
		}
		c, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, err
		}
		defer c.Close()
		return exchangeStream(ctx, c, msg, id, q)
	}
	return resp, nil
}

// exchangeUDP sends from a new socket, so every query has its own random
// source port. Packets that do not match the ID and the question are
// ignored rather than accepted: a spoofer must guess both.
func exchangeUDP(ctx context.Context, addr string, msg []byte, id uint16, q dnsmessage.Question) ([]byte, error) {
	return exchangeUDPWith(ctx, &net.Dialer{}, addr, msg, id, q)
}

// exchangeUDPWith is exchangeUDP with the caller's dialer; a dialer with a
// local address keeps it (the upstream tunnel address, ADR-0142).
func exchangeUDPWith(ctx context.Context, d *net.Dialer, addr string, msg []byte, id uint16, q dnsmessage.Question) ([]byte, error) {
	// A loopback upstream gets a loopback source address. Windows otherwise
	// binds the socket to the wildcard address, which can make the firewall
	// ask the user about the program.
	if ap, perr := netip.ParseAddrPort(addr); perr == nil && ap.Addr().IsLoopback() && d.LocalAddr == nil {
		d.LocalAddr = net.UDPAddrFromAddrPort(netip.AddrPortFrom(ap.Addr(), 0))
	}
	c, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	if _, err := c.Write(msg); err != nil {
		return nil, err
	}
	buf := make([]byte, maxDNSMessage)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return nil, err
		}
		if matchesQuery(buf[:n], id, q) {
			return bytes.Clone(buf[:n]), nil
		}
	}
}

// exchangeStream speaks DNS over a stream (TCP or TLS): each message has
// a two-byte length prefix (RFC 1035 4.2.2).
func exchangeStream(ctx context.Context, c net.Conn, msg []byte, id uint16, q dnsmessage.Question) ([]byte, error) {
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	if len(msg) > maxDNSMessage {
		return nil, errors.New("query too large")
	}
	out := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(out, uint16(len(msg)))
	copy(out[2:], msg)
	if _, err := c.Write(out); err != nil {
		return nil, err
	}
	var lenBuf [2]byte
	if _, err := io.ReadFull(c, lenBuf[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(lenBuf[:]))
	if n < 12 {
		return nil, errors.New("short DNS response")
	}
	resp := make([]byte, n)
	if _, err := io.ReadFull(c, resp); err != nil {
		return nil, err
	}
	if !matchesQuery(resp, id, q) {
		return nil, errors.New("DNS response does not match the query")
	}
	return resp, nil
}

func (f *dnsForwarder) exchangeDoH(ctx context.Context, msg []byte, id uint16, q dnsmessage.Question) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.up.url, bytes.NewReader(msg))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", dnsMediaType)
	req.Header.Set("Accept", dnsMediaType)
	resp, err := f.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("DoH server answered HTTP %d", resp.StatusCode)
	}
	if mt, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type")); err != nil || mt != dnsMediaType {
		return nil, errors.New("DoH server sent a non-DNS response")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDNSMessage+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxDNSMessage {
		return nil, errors.New("DoH response too large")
	}
	if !matchesQuery(body, id, q) {
		return nil, errors.New("DNS response does not match the query")
	}
	return body, nil
}

// matchesQuery accepts a response only with the expected ID and exactly
// the question that was asked (names compared without case).
func matchesQuery(resp []byte, id uint16, q dnsmessage.Question) bool {
	var p dnsmessage.Parser
	h, err := p.Start(resp)
	if err != nil || !h.Response || h.ID != id {
		return false
	}
	got, err := p.Question()
	if err != nil || got.Type != q.Type || got.Class != q.Class || !strings.EqualFold(got.Name.String(), q.Name.String()) {
		return false
	}
	_, err = p.Question()
	return errors.Is(err, dnsmessage.ErrSectionDone)
}

// cacheKey identifies one question; EDNS, DO and CD change the answer.
type cacheKey struct {
	name   string
	qtype  dnsmessage.Type
	class  dnsmessage.Class
	edns   bool
	do, cd bool
}

type cacheEntry struct {
	key     cacheKey
	msg     dnsmessage.Message
	stored  time.Time
	expires time.Time
	// hits and prefetching drive the prefetch of busy entries (#415).
	hits        int
	prefetching bool
}

// dnsCache is a bounded LRU of upstream answers (F-067).
type dnsCache struct {
	mu    sync.Mutex
	max   int
	order *list.List // front is the most recently used
	items map[cacheKey]*list.Element
}

func newDNSCache(max int) *dnsCache {
	return &dnsCache{max: max, order: list.New(), items: map[cacheKey]*list.Element{}}
}

// cacheTTL is how long m may be cached: the smallest record TTL (at most an
// hour) for answers, the SOA-derived TTL (at most 60 s) for negative
// answers. Zero means not cacheable.
func cacheTTL(m *dnsmessage.Message) time.Duration {
	if m.Truncated {
		return 0
	}
	negative := m.RCode == dnsmessage.RCodeNameError || (m.RCode == dnsmessage.RCodeSuccess && len(m.Answers) == 0)
	if !negative && m.RCode != dnsmessage.RCodeSuccess {
		return 0
	}
	if negative {
		for _, rr := range m.Authorities {
			if soa, ok := rr.Body.(*dnsmessage.SOAResource); ok {
				ttl := min(rr.Header.TTL, soa.MinTTL)
				return min(time.Duration(ttl)*time.Second, exitDNSNegTTL)
			}
		}
		return 0 // no SOA: RFC 2308 says do not cache
	}
	ttl := exitDNSMaxTTL
	for _, section := range [][]dnsmessage.Resource{m.Answers, m.Authorities, m.Additionals} {
		for _, rr := range section {
			if rr.Header.Type == dnsmessage.TypeOPT {
				continue // its TTL field holds flags
			}
			ttl = min(ttl, time.Duration(rr.Header.TTL)*time.Second)
		}
	}
	return ttl
}

func (c *dnsCache) put(key cacheKey, m dnsmessage.Message, size int, now time.Time) {
	ttl := cacheTTL(&m)
	if ttl <= 0 || size > maxCachedMessage {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		c.order.Remove(el)
		delete(c.items, key)
	}
	c.items[key] = c.order.PushFront(&cacheEntry{key: key, msg: m, stored: now, expires: now.Add(ttl)})
	for c.order.Len() > c.max {
		last := c.order.Back()
		c.order.Remove(last)
		delete(c.items, last.Value.(*cacheEntry).key)
	}
}

// get returns a copy of the cached answer with every TTL reduced by the
// time it spent in the cache.
func (c *dnsCache) get(key cacheKey, now time.Time) (dnsmessage.Message, bool) {
	m, ok, _ := c.lookup(key, now)
	return m, ok
}

// lookup is get that also reports, once per entry, that a busy entry is
// close to expiry and should be refreshed (#415). Expired entries stay
// for staleWindow so serve-stale can use them; the LRU bound holds.
func (c *dnsCache) lookup(key cacheKey, now time.Time) (dnsmessage.Message, bool, bool) {
	c.mu.Lock()
	el, ok := c.items[key]
	if !ok {
		c.mu.Unlock()
		return dnsmessage.Message{}, false, false
	}
	e := el.Value.(*cacheEntry)
	if !now.Before(e.expires) {
		if !now.Before(e.expires.Add(staleWindow)) {
			c.order.Remove(el)
			delete(c.items, key)
		}
		c.mu.Unlock()
		return dnsmessage.Message{}, false, false
	}
	c.order.MoveToFront(el)
	e.hits++
	refresh := false
	if life := e.expires.Sub(e.stored); !e.prefetching && e.hits >= 2 && e.expires.Sub(now) <= max(life/10, time.Second) {
		e.prefetching, refresh = true, true
	}
	m := e.msg
	age := uint32(now.Sub(e.stored) / time.Second)
	c.mu.Unlock()
	return agedCopy(m, age), true, refresh
}

// stale returns an expired entry of at most staleWindow with every TTL set
// to 30 seconds (RFC 8767).
func (c *dnsCache) stale(key cacheKey, now time.Time) (dnsmessage.Message, bool) {
	c.mu.Lock()
	el, ok := c.items[key]
	if !ok {
		c.mu.Unlock()
		return dnsmessage.Message{}, false
	}
	e := el.Value.(*cacheEntry)
	if now.Before(e.expires) || !now.Before(e.expires.Add(staleWindow)) {
		c.mu.Unlock()
		return dnsmessage.Message{}, false
	}
	m := e.msg
	c.mu.Unlock()
	m = agedCopy(m, 0)
	for _, rrs := range [][]dnsmessage.Resource{m.Answers, m.Authorities, m.Additionals} {
		for i := range rrs {
			if rrs[i].Header.Type != dnsmessage.TypeOPT {
				rrs[i].Header.TTL = staleAnswerTTL
			}
		}
	}
	return m, true
}

// agedCopy copies the parts of a shared cached message whose headers
// change, with every TTL reduced by age seconds.
func agedCopy(m dnsmessage.Message, age uint32) dnsmessage.Message {

	// The cached message is shared and never modified: copy the sections
	// whose headers change. Record bodies are not touched.
	age32 := func(rrs []dnsmessage.Resource) []dnsmessage.Resource {
		out := make([]dnsmessage.Resource, len(rrs))
		for i, rr := range rrs {
			if rr.Header.Type != dnsmessage.TypeOPT {
				rr.Header.TTL -= min(age, rr.Header.TTL)
			}
			out[i] = rr
		}
		return out
	}
	m.Questions = append([]dnsmessage.Question(nil), m.Questions...)
	m.Answers, m.Authorities, m.Additionals = age32(m.Answers), age32(m.Authorities), age32(m.Additionals)
	return m
}

// len reports the number of cached answers.
func (c *dnsCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}
