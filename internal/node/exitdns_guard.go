package node

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/openscale/openscale/internal/dnsblock"
	"github.com/openscale/openscale/internal/filter"
	"github.com/openscale/openscale/internal/trust"
)

// Exit node resolver hardening (P05, ADR-0102 additions, ADR-0150):
//
//   - #412 DNS rebinding: public names answered with private, CGNAT, ULA,
//     loopback or link-local addresses are refused unless the owner
//     allows the name.
//   - #413 EDNS Client Subnet is removed from every upstream query.
//   - #414 DoT and DoH queries are padded to 128-byte blocks (RFC 8467).
//   - #415 serve-stale (RFC 8767) and prefetch of busy records.
//   - #416/#417 per-device filter profiles from the signed document and
//     safe search mapping.
//   - #418 timed block list exceptions, #419 an opt-in, memory-only query
//     log of at most an hour.
//   - #421 per-device query rate limit, #422 DNS tunnelling detection,
//     #423 AAAA filtering on an exit node without IPv6.

// ExitDNSGuardConfig are the owner's settings of the hardening above. The
// zero value is the default: rebinding protection, rate limit and tunnel
// detection (event only) on, AAAA filtering automatic, serve-stale off.
type ExitDNSGuardConfig struct {
	// RebindOff turns rebinding protection off; RebindAllow lists domains
	// (and their subdomains) that may resolve to private addresses.
	RebindOff   bool     `json:"rebind_off,omitempty"`
	RebindAllow []string `json:"rebind_allow,omitempty"`
	// ServeStale answers from expired cache entries while the upstream
	// fails, and refreshes busy entries before they expire.
	ServeStale bool `json:"serve_stale,omitempty"`
	// RateLimit is queries per second per device: 0 the default, -1 off.
	RateLimit int `json:"rate_limit,omitempty"`
	// TunnelDetectOff turns tunnelling detection off; TunnelBlock refuses
	// the suspicious queries of a flagged device (default: event only).
	TunnelDetectOff bool `json:"tunnel_detect_off,omitempty"`
	TunnelBlock     bool `json:"tunnel_block,omitempty"`
	// AAAA is "auto" (or empty: filter when this host has no global IPv6
	// address), "keep" or "filter".
	AAAA string `json:"aaaa,omitempty"`
	// ProfileLists maps a document DNS profile name to a local block list
	// file used for its members instead of the exit node's default list.
	ProfileLists map[string]string `json:"profile_lists,omitempty"`
	// SafeSearchMap is a local file mapping search engine names to their
	// safe search names for profiles with safe_search (#417,
	// exitdns_safesearch.go). OpenScale ships no built-in names
	// (ADR-0008); without the file safe search is not enforced.
	SafeSearchMap string `json:"safe_search_map,omitempty"`
}

// Limits and defaults of the guard.
const (
	DefaultExitDNSRate   = 50
	MaxExitDNSRate       = 10000
	exitDNSBurstFactor   = 4
	maxRebindAllow       = 256
	maxProfileLists      = trust.MaxDNSProfiles
	maxExitDNSExceptions = 256
	MinExitDNSException  = time.Minute
	MaxExitDNSException  = 24 * time.Hour
	MaxExitDNSQueryLog   = time.Hour
	maxQueryLogEntries   = 5000
	staleAnswerTTL       = 30 // seconds, RFC 8767 section 4
	staleWindow          = time.Hour
	maxLimiterEntries    = 4096
	rateEventEvery       = 5 * time.Minute
	tunnelWindow         = time.Minute
	tunnelThreshold      = 40
	tunnelFlagFor        = 10 * time.Minute
	tunnelMinSub         = 30
	tunnelMinEntropy     = 3.6
	maxTunnelBases       = 64
	maxDNSThreatEvents   = 64
	maxPrefetch          = 8
	ipv6CheckEvery       = time.Minute
	optionECS            = 8
	optionPadding        = 12
	paddingBlock         = 128
)

// Threat kinds of the resolver (shown with the port scan detections).
const (
	ThreatDNSRateLimit filter.ThreatKind = "dns_rate_limit"
	ThreatDNSTunnel    filter.ThreatKind = "dns_tunnel"
)

// Query log decisions.
const (
	DecisionAllowed    = "allowed"
	DecisionCached     = "cached"
	DecisionStale      = "stale"
	DecisionBlocked    = "blocked"
	DecisionException  = "exception"
	DecisionCanary     = "canary"
	DecisionRebind     = "rebind"
	DecisionAAAA       = "aaaa_filtered"
	DecisionSafeSearch = "safe_search"
	DecisionTunnel     = "tunnel"
	DecisionLimited    = "rate_limited"
	DecisionFailed     = "failed"
)

var errExitDNSRateLimited = errors.New("exit DNS rate limit")

// Validate checks the settings without touching files.
func (c ExitDNSGuardConfig) Validate() error {
	if len(c.RebindAllow) > maxRebindAllow {
		return fmt.Errorf("yeniden bağlama istisnası en fazla %d alan olabilir", maxRebindAllow)
	}
	for _, d := range c.RebindAllow {
		if _, ok := normalizeDomain(d); !ok {
			return fmt.Errorf("yeniden bağlama istisnası %q geçerli bir alan adı değil", d)
		}
	}
	if c.RateLimit < -1 || c.RateLimit > MaxExitDNSRate {
		return fmt.Errorf("DNS hız sınırı -1 (kapalı), 0 (varsayılan %d) veya 1-%d sorgu/sn olmalı", DefaultExitDNSRate, MaxExitDNSRate)
	}
	switch c.AAAA {
	case "", "auto", "keep", "filter":
	default:
		return fmt.Errorf("AAAA ayarı %q geçersiz; auto, keep veya filter yazın", c.AAAA)
	}
	if len(c.ProfileLists) > maxProfileLists {
		return fmt.Errorf("en fazla %d profil listesi olabilir", maxProfileLists)
	}
	for name, path := range c.ProfileLists {
		if !trust.ValidDNSProfileName(name) {
			return fmt.Errorf("profil adı %q küçük harfli bir DNS etiketi olmalı", name)
		}
		if path == "" || len(path) > 1024 || !filepath.IsAbs(path) || strings.ContainsAny(path, "\x00\r\n") {
			return fmt.Errorf("profil %s listesi mutlak bir dosya yolu olmalı", name)
		}
	}
	if p := c.SafeSearchMap; p != "" && (len(p) > 1024 || !filepath.IsAbs(p) || strings.ContainsAny(p, "\x00\r\n")) {
		return errors.New("güvenli arama eşlemesi mutlak bir dosya yolu olmalı")
	}
	return nil
}

// exitDNSGuard is an applied configuration.
type exitDNSGuard struct {
	cfg          ExitDNSGuardConfig
	rebindAllow  []string
	profileLists map[string]*dnsblock.List
	// safeSearch maps names to safe search names (lowercase, absolute).
	safeSearch map[string]string
}

var exitGuard atomic.Pointer[exitDNSGuard]

// defaultGuard applies while no configuration was set.
var defaultGuard = &exitDNSGuard{}

func currentExitGuard() *exitDNSGuard {
	if g := exitGuard.Load(); g != nil {
		return g
	}
	return defaultGuard
}

// ApplyExitDNSGuard installs the settings for every exit node forwarder in
// this process and reads the profile block lists; onEvent receives rate
// limit and tunnelling detections.
func ApplyExitDNSGuard(c ExitDNSGuardConfig, onEvent func(filter.ThreatEvent)) error {
	if err := c.Validate(); err != nil {
		return err
	}
	g := &exitDNSGuard{cfg: c, profileLists: map[string]*dnsblock.List{}}
	for _, d := range c.RebindAllow {
		n, _ := normalizeDomain(d)
		g.rebindAllow = append(g.rebindAllow, n)
	}
	for name, path := range c.ProfileLists {
		l, err := dnsblock.Load(path)
		if err != nil {
			return fmt.Errorf("profil %s: %w", name, err)
		}
		g.profileLists[name] = l
	}
	if c.SafeSearchMap != "" {
		m, err := LoadSafeSearchMap(c.SafeSearchMap)
		if err != nil {
			return err
		}
		g.safeSearch = m
	}
	exitGuard.Store(g)
	if onEvent != nil {
		exitDNSRT.hook.Store(&onEvent)
	} else {
		exitDNSRT.hook.Store(nil)
	}
	return nil
}

func (g *exitDNSGuard) rate() int {
	switch {
	case g.cfg.RateLimit < 0:
		return 0
	case g.cfg.RateLimit == 0:
		return DefaultExitDNSRate
	}
	return g.cfg.RateLimit
}

func (g *exitDNSGuard) rebindAllowed(name string) bool {
	if localSuffix(name) {
		return true
	}
	for _, d := range g.rebindAllow {
		if name == d || strings.HasSuffix(name, "."+d) {
			return true
		}
	}
	return false
}

func (g *exitDNSGuard) filterAAAA(now time.Time) bool {
	switch g.cfg.AAAA {
	case "keep":
		return false
	case "filter":
		return true
	}
	return !exitDNSRT.hasIPv6(now)
}

// exitClient is the member that sent a query, with its document profile.
type exitClient struct {
	name        string
	profile     string
	safeSearch  bool
	noBlocklist bool
}

// exitClientFor describes the named member of doc.
func exitClientFor(doc *trust.Document, name string) exitClient {
	c := exitClient{name: name}
	if p, ok := doc.DNSProfileFor(name); ok {
		c.profile, c.safeSearch, c.noBlocklist = p.Name, p.SafeSearch, p.NoBlocklist
	}
	return c
}

// --- process state: rate limiter, detector, log, exceptions, events ---

type rateBucket struct {
	tokens    float64
	last      time.Time
	lastEvent time.Time
}

type tunnelState struct {
	start   time.Time
	counts  map[string]int
	flagged map[string]time.Time
	event   time.Time
}

// ExitDNSLogEntry is one logged query (#419).
type ExitDNSLogEntry struct {
	At       time.Time `json:"at"`
	Device   string    `json:"device"`
	Name     string    `json:"name"`
	Type     string    `json:"type"`
	Decision string    `json:"decision"`
}

// ExitDNSException is a timed block list exception (#418).
type ExitDNSException struct {
	Name  string    `json:"name"`
	Until time.Time `json:"until"`
}

// ExitDNSGuardStats counts the guard's decisions.
type ExitDNSGuardStats struct {
	RateLimited  uint64 `json:"rate_limited"`
	Rebind       uint64 `json:"rebind"`
	AAAAFiltered uint64 `json:"aaaa_filtered"`
	SafeSearch   uint64 `json:"safe_search"`
	Stale        uint64 `json:"stale"`
	Prefetched   uint64 `json:"prefetched"`
	TunnelFlags  uint64 `json:"tunnel_flags"`
	Exceptions   uint64 `json:"exceptions"`
}

type exitDNSRuntime struct {
	hook atomic.Pointer[func(filter.ThreatEvent)]

	rateLimited, rebind, aaaa, safeSearch, stale, prefetched, tunnelFlags, exceptionHits atomic.Uint64

	mu         sync.Mutex
	buckets    map[string]*rateBucket
	tunnels    map[string]*tunnelState
	exceptions map[string]time.Time
	logUntil   time.Time
	logEntries []ExitDNSLogEntry
	events     []filter.ThreatEvent
	v6At       time.Time
	v6         bool
}

var exitDNSRT = &exitDNSRuntime{
	buckets:    map[string]*rateBucket{},
	tunnels:    map[string]*tunnelState{},
	exceptions: map[string]time.Time{},
}

// exitGlobalIPv6 reports whether this host has a global IPv6 address;
// tests replace it.
var exitGlobalIPv6 = hostHasGlobalIPv6

var prefetchSem = make(chan struct{}, maxPrefetch)

func (rt *exitDNSRuntime) emit(ev filter.ThreatEvent) {
	rt.mu.Lock()
	rt.events = append(rt.events, ev)
	if len(rt.events) > maxDNSThreatEvents {
		rt.events = rt.events[len(rt.events)-maxDNSThreatEvents:]
	}
	rt.mu.Unlock()
	if h := rt.hook.Load(); h != nil && *h != nil {
		(*h)(ev)
	}
}

// allowRate takes one token of the device's bucket.
func (rt *exitDNSRuntime) allowRate(device string, rate int, now time.Time) bool {
	if rate <= 0 || device == "" {
		return true
	}
	burst := float64(rate * exitDNSBurstFactor)
	rt.mu.Lock()
	b, ok := rt.buckets[device]
	if !ok {
		if len(rt.buckets) >= maxLimiterEntries {
			for k, v := range rt.buckets {
				if now.Sub(v.last) > time.Minute {
					delete(rt.buckets, k)
				}
			}
			if len(rt.buckets) >= maxLimiterEntries {
				clear(rt.buckets)
			}
		}
		b = &rateBucket{tokens: burst, last: now}
		rt.buckets[device] = b
	}
	if el := now.Sub(b.last).Seconds(); el > 0 {
		b.tokens = math.Min(burst, b.tokens+el*float64(rate))
	}
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		rt.mu.Unlock()
		return true
	}
	report := b.lastEvent.IsZero() || now.Sub(b.lastEvent) >= rateEventEvery
	if report {
		b.lastEvent = now
	}
	rt.mu.Unlock()
	rt.rateLimited.Add(1)
	if report {
		rt.emit(filter.ThreatEvent{Kind: ThreatDNSRateLimit, Peer: device, Count: rate, At: now.Truncate(time.Minute)})
	}
	return false
}

// tunnelCheck counts suspicious queries per device and base domain; it
// reports whether the query must be refused (TunnelBlock and a flagged
// base domain).
func (rt *exitDNSRuntime) tunnelCheck(g *exitDNSGuard, device, name string, now time.Time) bool {
	if g.cfg.TunnelDetectOff || device == "" {
		return false
	}
	base, ok := suspiciousName(name)
	if !ok {
		return false
	}
	rt.mu.Lock()
	st, found := rt.tunnels[device]
	if !found {
		if len(rt.tunnels) >= maxLimiterEntries {
			clear(rt.tunnels)
		}
		st = &tunnelState{start: now, counts: map[string]int{}, flagged: map[string]time.Time{}}
		rt.tunnels[device] = st
	}
	if now.Sub(st.start) >= tunnelWindow {
		st.start = now
		clear(st.counts)
	}
	for b, until := range st.flagged {
		if !now.Before(until) {
			delete(st.flagged, b)
		}
	}
	if _, ok := st.counts[base]; ok || len(st.counts) < maxTunnelBases {
		st.counts[base]++
	}
	flaggedNow := false
	if st.counts[base] >= tunnelThreshold {
		if _, already := st.flagged[base]; !already && len(st.flagged) < maxTunnelBases {
			st.flagged[base] = now.Add(tunnelFlagFor)
			flaggedNow = true
		}
	}
	_, flagged := st.flagged[base]
	n := st.counts[base]
	report := flaggedNow && (st.event.IsZero() || now.Sub(st.event) >= tunnelFlagFor)
	if report {
		st.event = now
	}
	rt.mu.Unlock()
	if flaggedNow {
		rt.tunnelFlags.Add(1)
	}
	if report {
		// The domain is not part of the event (ADR-0008); the owner can
		// turn the query log on to see it.
		ev := filter.ThreatEvent{Kind: ThreatDNSTunnel, Peer: device, Count: n, At: now.Truncate(time.Minute)}
		if g.cfg.TunnelBlock {
			ev.BlockedUntil = now.Add(tunnelFlagFor)
		}
		rt.emit(ev)
	}
	return flagged && g.cfg.TunnelBlock
}

// suspiciousName returns the base domain of a name whose subdomain part
// is long and random looking, as DNS tunnels encode data.
func suspiciousName(name string) (string, bool) {
	n := strings.TrimSuffix(name, ".")
	labels := strings.Split(n, ".")
	keep := 2
	if len(labels) >= 3 && len(labels[len(labels)-1]) == 2 {
		switch labels[len(labels)-2] {
		case "co", "com", "net", "org", "gov", "edu", "ac", "gen", "web", "bel", "k12":
			keep = 3
		}
	}
	if len(labels) <= keep {
		return "", false
	}
	sub := strings.Join(labels[:len(labels)-keep], "")
	if len(sub) < tunnelMinSub || shannon(sub) < tunnelMinEntropy || !encodedLooking(sub) {
		return "", false
	}
	return strings.Join(labels[len(labels)-keep:], ".") + ".", true
}

// encodedLooking tells encoded data (hex, base32, base64) from long but
// readable host names: encodings mix in digits or have few vowels, and
// hardly ever hyphens.
func encodedLooking(s string) bool {
	digits, vowels, letters, hyphens := 0, 0, 0, 0
	for i := 0; i < len(s); i++ {
		switch c := s[i] | 0x20; {
		case '0' <= s[i] && s[i] <= '9':
			digits++
		case s[i] == '-':
			hyphens++
		case 'a' <= c && c <= 'z':
			letters++
			if strings.IndexByte("aeiou", c) >= 0 {
				vowels++
			}
		}
	}
	if hyphens*20 > len(s) {
		return false
	}
	return digits*10 >= len(s) || (letters > 0 && vowels*5 < letters)
}

// shannon is the entropy of s in bits per byte.
func shannon(s string) float64 {
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	h, n := 0.0, float64(len(s))
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / n
			h -= p * math.Log2(p)
		}
	}
	return h
}

// excepted reports whether a timed exception covers name.
func (rt *exitDNSRuntime) excepted(name string, now time.Time) bool {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if len(rt.exceptions) == 0 {
		return false
	}
	for s := name; s != "" && s != "."; {
		if until, ok := rt.exceptions[s]; ok {
			if now.Before(until) {
				return true
			}
			delete(rt.exceptions, s)
		}
		i := strings.IndexByte(s, '.')
		if i < 0 || i == len(s)-1 {
			break
		}
		s = s[i+1:]
	}
	return false
}

// ExitDNSAllowFor opens a blocked name (and the names below it) for d,
// without changing the block list (#418).
func ExitDNSAllowFor(name string, d time.Duration, now time.Time) (ExitDNSException, error) {
	n, ok := normalizeDomain(name)
	if !ok {
		return ExitDNSException{}, fmt.Errorf("%q geçerli bir alan adı değil", name)
	}
	if d < MinExitDNSException || d > MaxExitDNSException {
		return ExitDNSException{}, fmt.Errorf("istisna süresi %v ile %v arasında olmalı", MinExitDNSException, MaxExitDNSException)
	}
	rt := exitDNSRT
	rt.mu.Lock()
	defer rt.mu.Unlock()
	for k, until := range rt.exceptions {
		if !now.Before(until) {
			delete(rt.exceptions, k)
		}
	}
	if _, ok := rt.exceptions[n]; !ok && len(rt.exceptions) >= maxExitDNSExceptions {
		return ExitDNSException{}, fmt.Errorf("en fazla %d süreli istisna olabilir", maxExitDNSExceptions)
	}
	until := now.Add(d).Truncate(time.Second)
	rt.exceptions[n] = until
	return ExitDNSException{Name: n, Until: until}, nil
}

// ExitDNSRevokeException closes a timed exception early.
func ExitDNSRevokeException(name string) bool {
	n, ok := normalizeDomain(name)
	if !ok {
		return false
	}
	exitDNSRT.mu.Lock()
	defer exitDNSRT.mu.Unlock()
	_, found := exitDNSRT.exceptions[n]
	delete(exitDNSRT.exceptions, n)
	return found
}

// ExitDNSExceptions lists the exceptions still in force.
func ExitDNSExceptions(now time.Time) []ExitDNSException {
	rt := exitDNSRT
	rt.mu.Lock()
	defer rt.mu.Unlock()
	out := []ExitDNSException{}
	for k, until := range rt.exceptions {
		if !now.Before(until) {
			delete(rt.exceptions, k)
			continue
		}
		out = append(out, ExitDNSException{Name: k, Until: until})
	}
	sortExceptions(out)
	return out
}

func sortExceptions(out []ExitDNSException) {
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].Name < out[j-1].Name; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
}

// SetExitDNSQueryLog turns the memory-only query log on for d (at most an
// hour) or, with d == 0, off; turning it off deletes every entry (#419).
func SetExitDNSQueryLog(d time.Duration, now time.Time) (time.Time, error) {
	if d < 0 || d > MaxExitDNSQueryLog {
		return time.Time{}, fmt.Errorf("sorgu günlüğü süresi 0 (kapalı) ile %v arasında olmalı", MaxExitDNSQueryLog)
	}
	rt := exitDNSRT
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if d == 0 {
		rt.logUntil = time.Time{}
		rt.logEntries = nil
		return time.Time{}, nil
	}
	rt.logUntil = now.Add(d)
	return rt.logUntil, nil
}

// expireLogLocked drops the log once its time is over, and entries older
// than an hour.
func (rt *exitDNSRuntime) expireLogLocked(now time.Time) {
	if !rt.logUntil.IsZero() && !now.Before(rt.logUntil) {
		rt.logUntil = time.Time{}
		rt.logEntries = nil
		return
	}
	cut := 0
	for cut < len(rt.logEntries) && now.Sub(rt.logEntries[cut].At) > MaxExitDNSQueryLog {
		cut++
	}
	if cut > 0 {
		rt.logEntries = append([]ExitDNSLogEntry(nil), rt.logEntries[cut:]...)
	}
}

// ExitDNSQueryLog returns a copy of the log and until when it runs (zero:
// off).
func ExitDNSQueryLog(now time.Time) ([]ExitDNSLogEntry, time.Time) {
	rt := exitDNSRT
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.expireLogLocked(now)
	return append([]ExitDNSLogEntry{}, rt.logEntries...), rt.logUntil
}

func (rt *exitDNSRuntime) record(now time.Time, device string, q dnsmessage.Question, decision string) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.logUntil.IsZero() {
		return
	}
	rt.expireLogLocked(now)
	if rt.logUntil.IsZero() {
		return
	}
	if len(rt.logEntries) >= maxQueryLogEntries {
		rt.logEntries = append(rt.logEntries[:0], rt.logEntries[1:]...)
	}
	rt.logEntries = append(rt.logEntries, ExitDNSLogEntry{
		At: now.Truncate(time.Second), Device: device, Name: strings.ToLower(q.Name.String()),
		Type: strings.TrimPrefix(q.Type.String(), "Type"), Decision: decision,
	})
}

// ExitDNSThreatEvents returns the resolver's recent detections.
func ExitDNSThreatEvents() []filter.ThreatEvent {
	exitDNSRT.mu.Lock()
	defer exitDNSRT.mu.Unlock()
	return append([]filter.ThreatEvent(nil), exitDNSRT.events...)
}

// ExitDNSStats returns the guard counters.
func ExitDNSStats() ExitDNSGuardStats {
	rt := exitDNSRT
	return ExitDNSGuardStats{
		RateLimited: rt.rateLimited.Load(), Rebind: rt.rebind.Load(), AAAAFiltered: rt.aaaa.Load(),
		SafeSearch: rt.safeSearch.Load(), Stale: rt.stale.Load(), Prefetched: rt.prefetched.Load(),
		TunnelFlags: rt.tunnelFlags.Load(), Exceptions: rt.exceptionHits.Load(),
	}
}

func (rt *exitDNSRuntime) hasIPv6(now time.Time) bool {
	rt.mu.Lock()
	if !rt.v6At.IsZero() && now.Sub(rt.v6At) < ipv6CheckEvery && now.After(rt.v6At) {
		v := rt.v6
		rt.mu.Unlock()
		return v
	}
	rt.mu.Unlock()
	v := exitGlobalIPv6()
	rt.mu.Lock()
	rt.v6, rt.v6At = v, now
	rt.mu.Unlock()
	return v
}

// hostHasGlobalIPv6 looks for a global unicast IPv6 address (not unique
// local) on any interface: without one, members' IPv6 cannot leave.
func hostHasGlobalIPv6() bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return true // unknown: keep AAAA records
	}
	for _, a := range addrs {
		p, err := netip.ParsePrefix(a.String())
		if err != nil {
			continue
		}
		ip := p.Addr()
		if ip.Is6() && !ip.Is4In6() && ip.IsGlobalUnicast() && !ip.IsPrivate() {
			return true
		}
	}
	return false
}

// --- answers ---

// localAnswer is an answer built here: rcode, no records, and an EDNS
// record (with an Extended DNS Error when ede >= 0) if the member speaks
// EDNS.
func localAnswer(cq clientQuery, rcode dnsmessage.RCode, ede int) ([]byte, error) {
	m := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID: cq.id, Response: true, RecursionDesired: true, RecursionAvailable: true, RCode: rcode,
		},
		Questions: []dnsmessage.Question{cq.question},
	}
	if cq.key.edns {
		var opt dnsmessage.ResourceHeader
		if err := opt.SetEDNS0(recEDNSSize, dnsmessage.RCodeSuccess, cq.key.do); err != nil {
			return nil, err
		}
		var body dnsmessage.OPTResource
		if ede >= 0 {
			body.Options = []dnsmessage.Option{{Code: optionEDE, Data: []byte{byte(ede >> 8), byte(ede)}}}
		}
		m.Additionals = []dnsmessage.Resource{{Header: opt, Body: &body}}
	}
	return m.Pack()
}

// exitPolicyAnswerFor answers the canary and blocked names for client.
func exitPolicyAnswerFor(g *exitDNSGuard, client exitClient, cq clientQuery, now time.Time) ([]byte, string, bool) {
	name := cq.key.name
	if name == dohCanary || strings.HasSuffix(name, "."+dohCanary) {
		exitDNSCanaryCount.Add(1)
		out, err := nxdomainAnswer(cq, false)
		return out, DecisionCanary, err == nil
	}
	if out, d, ok, skip := g7PolicyAnswer(client, cq, now); ok || skip { // ADR-0220
		return out, d, ok
	}
	if client.noBlocklist {
		return nil, "", false
	}
	l := exitBlocklist.Load()
	if client.profile != "" {
		if pl, ok := g.profileLists[client.profile]; ok {
			l = pl
		}
	}
	if l == nil || !l.Blocked(name) {
		return nil, "", false
	}
	if exitDNSRT.excepted(name, now) {
		exitDNSRT.exceptionHits.Add(1)
		return nil, DecisionException, false
	}
	exitDNSBlockedCount.Add(1)
	out, err := nxdomainAnswer(cq, true)
	return out, DecisionBlocked, err == nil
}

// forwardFrom answers a member's query with every guard applied. An empty
// client (tests, internal callers) skips the per-device parts.
func (f *dnsForwarder) forwardFrom(ctx context.Context, client exitClient, query []byte, stream bool) ([]byte, error) {
	cq, err := parseClientQuery(query)
	if err != nil {
		return nil, err
	}
	now := f.now()
	g := currentExitGuard()
	q := cq.question
	limit := cq.limit
	if stream {
		limit = maxDNSMessage
	}
	done := func(out []byte, decision string) ([]byte, error) {
		exitDNSRT.record(now, client.name, q, decision)
		return fitUDP(out, limit), nil
	}
	if client.name != "" {
		if !exitDNSRT.allowRate(client.name, g.rate(), now) {
			exitDNSRT.record(now, client.name, q, DecisionLimited)
			return nil, errExitDNSRateLimited
		}
		if exitDNSRT.tunnelCheck(g, client.name, cq.key.name, now) {
			out, err := localAnswer(cq, dnsmessage.RCodeRefused, edeBlocked)
			if err != nil {
				return nil, err
			}
			return done(out, DecisionTunnel)
		}
	}
	out, decision, ok := exitPolicyAnswerFor(g, client, cq, now)
	if ok {
		return done(out, decision)
	}
	if client.safeSearch {
		if target, ok := g.safeSearch[cq.key.name]; ok {
			out, err := f.safeSearchAnswer(ctx, cq, target)
			if err != nil {
				exitDNSRT.record(now, client.name, q, DecisionFailed)
				return nil, err
			}
			exitDNSRT.safeSearch.Add(1)
			return done(out, DecisionSafeSearch)
		}
	}
	if client.name != "" && q.Type == dnsmessage.TypeAAAA && g.filterAAAA(now) {
		exitDNSRT.aaaa.Add(1)
		out, err := localAnswer(cq, dnsmessage.RCodeSuccess, -1)
		if err != nil {
			return nil, err
		}
		return done(out, DecisionAAAA)
	}
	out, how, err := f.resolveCached(ctx, query, cq, g)
	if err != nil {
		exitDNSRT.record(now, client.name, q, DecisionFailed)
		return nil, err
	}
	if decision == DecisionException {
		how = DecisionException
	}
	if !g.cfg.RebindOff && !g.rebindAllowed(cq.key.name) && privateAnswer(out) {
		exitDNSRT.rebind.Add(1)
		blocked, err := nxdomainAnswer(cq, true)
		if err != nil {
			return nil, err
		}
		return done(blocked, DecisionRebind)
	}
	return done(out, how)
}

// resolveCached answers from the cache or the upstream resolver, with
// serve-stale and prefetch when the owner turned them on. The answer has
// the member's ID and is not fitted to its UDP limit.
func (f *dnsForwarder) resolveCached(ctx context.Context, query []byte, cq clientQuery, g *exitDNSGuard) ([]byte, string, error) {
	now := f.now()
	if m, ok, refresh := f.cache.lookup(cq.key, now); ok {
		if refresh && g.cfg.ServeStale {
			f.prefetch(query, cq)
		}
		m.Header.ID = cq.id
		out, err := m.Pack()
		return out, DecisionCached, err
	}
	cctx, cancel := context.WithTimeout(ctx, f.timeout)
	defer cancel()
	resp, err := f.exchange(cctx, query, cq.question)
	failed := err != nil || (len(resp) > 3 && dnsmessage.RCode(resp[3]&0x0f) == dnsmessage.RCodeServerFailure)
	if failed && g.cfg.ServeStale {
		if m, ok := f.cache.stale(cq.key, now); ok {
			exitDNSRT.stale.Add(1)
			m.Header.ID = cq.id
			out, perr := m.Pack()
			return out, DecisionStale, perr
		}
	}
	if err != nil {
		return nil, "", err
	}
	var m dnsmessage.Message
	if err := m.Unpack(resp); err == nil {
		f.cache.put(cq.key, m, len(resp), f.now())
	}
	out := bytes.Clone(resp)
	out[0], out[1] = byte(cq.id>>8), byte(cq.id)
	return out, DecisionAllowed, nil
}

// prefetch refreshes a busy cache entry in the background.
func (f *dnsForwarder) prefetch(query []byte, cq clientQuery) {
	select {
	case prefetchSem <- struct{}{}:
	default:
		return
	}
	q := bytes.Clone(query)
	go func() {
		defer func() { <-prefetchSem }()
		ctx, cancel := context.WithTimeout(context.Background(), f.timeout)
		defer cancel()
		resp, err := f.exchange(ctx, q, cq.question)
		if err != nil {
			return
		}
		var m dnsmessage.Message
		if m.Unpack(resp) == nil && m.RCode != dnsmessage.RCodeServerFailure {
			f.cache.put(cq.key, m, len(resp), f.now())
			exitDNSRT.prefetched.Add(1)
		}
	}()
}

// privateAnswer reports an A or AAAA record with an address that must not
// come from a public name (#412).
func privateAnswer(msg []byte) bool {
	var p dnsmessage.Parser
	if _, err := p.Start(msg); err != nil {
		return false
	}
	if err := p.SkipAllQuestions(); err != nil {
		return false
	}
	for {
		h, err := p.AnswerHeader()
		if err != nil {
			return false
		}
		switch h.Type {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return false
			}
			if rebindAddr(netip.AddrFrom4(r.A)) {
				return true
			}
		case dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return false
			}
			if rebindAddr(netip.AddrFrom16(r.AAAA)) {
				return true
			}
		default:
			if err := p.SkipAnswer(); err != nil {
				return false
			}
		}
	}
}

var (
	cgnatRange    = netip.MustParsePrefix("100.64.0.0/10")
	thisNetRange  = netip.MustParsePrefix("0.0.0.0/8")
	nat64Range    = netip.MustParsePrefix("64:ff9b::/96")
	siteLocal6    = netip.MustParsePrefix("fec0::/10")
	localSuffixes = []string{
		"lan.", "local.", "localhost.", "localdomain.", "home.arpa.", "internal.",
		"home.", "corp.", "intranet.", "private.", "in-addr.arpa.", "ip6.arpa.",
	}
)

// rebindAddr is an address of the member's own or the exit node's local
// networks.
func rebindAddr(a netip.Addr) bool {
	a = a.Unmap()
	if a.Is6() && nat64Range.Contains(a) {
		b := a.As16()
		a = netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
	}
	return a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsUnspecified() ||
		a.IsMulticast() || cgnatRange.Contains(a) || thisNetRange.Contains(a) || siteLocal6.Contains(a)
}

// localSuffix reports names that are local by design: single labels and
// special-use or commonly private domains.
func localSuffix(name string) bool {
	n := strings.TrimSuffix(name, ".")
	if !strings.Contains(n, ".") {
		return true
	}
	for _, s := range localSuffixes {
		if name == s || strings.HasSuffix(name, "."+s) {
			return true
		}
	}
	return false
}

// normalizeDomain returns a lowercase absolute domain name of at least two
// labels.
func normalizeDomain(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
	s = strings.TrimPrefix(s, "*.")
	if s == "" || len(s) > 253 {
		return "", false
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return "", false
	}
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return "", false
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return "", false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !('a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-' || c == '_') {
				return "", false
			}
		}
	}
	return s + ".", true
}

// --- upstream query preparation (#413, #414) ---

// prepareUpstream removes EDNS Client Subnet from the query and, for DoT
// and DoH, pads it to a multiple of 128 bytes (RFC 7830, RFC 8467). A
// query without EDNS is sent unchanged: adding EDNS would change what the
// member receives.
func prepareUpstream(msg []byte, kind upstreamKind) []byte {
	var m dnsmessage.Message
	if err := m.Unpack(msg); err != nil {
		return msg
	}
	optIdx := -1
	for i, rr := range m.Additionals {
		if rr.Header.Type == dnsmessage.TypeOPT {
			optIdx = i
			break
		}
	}
	if optIdx < 0 {
		return msg
	}
	body, ok := m.Additionals[optIdx].Body.(*dnsmessage.OPTResource)
	if !ok {
		return msg
	}
	opts := make([]dnsmessage.Option, 0, len(body.Options))
	changed := false
	for _, o := range body.Options {
		if o.Code == optionECS || o.Code == optionPadding {
			changed = true
			continue
		}
		opts = append(opts, o)
	}
	pad := kind == upstreamDoT || kind == upstreamDoH
	if !changed && !pad {
		return msg
	}
	m.Additionals[optIdx].Body = &dnsmessage.OPTResource{Options: opts}
	out, err := m.Pack()
	if err != nil {
		return msg
	}
	if !pad {
		return out
	}
	// The padding option adds 4 bytes of header.
	n := len(out) + 4
	padLen := (paddingBlock - n%paddingBlock) % paddingBlock
	m.Additionals[optIdx].Body = &dnsmessage.OPTResource{Options: append(opts, dnsmessage.Option{Code: optionPadding, Data: make([]byte, padLen)})}
	padded, err := m.Pack()
	if err != nil || len(padded) > maxDNSMessage {
		return out
	}
	return padded
}

// --- safe search (#417) ---

// safeSearchAnswer answers an A or AAAA query with a CNAME to target and
// target's records; other types get an empty answer so a browser does not
// learn another way in (for example HTTPS records).
func (f *dnsForwarder) safeSearchAnswer(ctx context.Context, cq clientQuery, target string) ([]byte, error) {
	q := cq.question
	if q.Type != dnsmessage.TypeA && q.Type != dnsmessage.TypeAAAA {
		return localAnswer(cq, dnsmessage.RCodeSuccess, -1)
	}
	tname, err := dnsmessage.NewName(target)
	if err != nil {
		return nil, err
	}
	sub := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: cq.id, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: tname, Type: q.Type, Class: q.Class}},
	}
	if cq.key.edns {
		var opt dnsmessage.ResourceHeader
		if err := opt.SetEDNS0(recEDNSSize, dnsmessage.RCodeSuccess, cq.key.do); err != nil {
			return nil, err
		}
		sub.Additionals = []dnsmessage.Resource{{Header: opt, Body: &dnsmessage.OPTResource{}}}
	}
	sub.Header.CheckingDisabled = cq.key.cd
	subQuery, err := sub.Pack()
	if err != nil {
		return nil, err
	}
	scq, err := parseClientQuery(subQuery)
	if err != nil {
		return nil, err
	}
	resp, _, err := f.resolveCached(ctx, subQuery, scq, currentExitGuard())
	if err != nil {
		return nil, err
	}
	var m dnsmessage.Message
	if err := m.Unpack(resp); err != nil {
		return nil, err
	}
	cname := dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 300},
		Body:   &dnsmessage.CNAMEResource{CNAME: tname},
	}
	m.Header.ID = cq.id
	m.Header.Authoritative = false
	m.Header.AuthenticData = false
	m.Questions = []dnsmessage.Question{q}
	m.Answers = append([]dnsmessage.Resource{cname}, m.Answers...)
	return m.Pack()
}
