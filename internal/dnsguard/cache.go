package dnsguard

import (
	"container/list"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Cache limits and defaults (#765).
const (
	DefaultCacheEntries = 4096
	MaxCacheEntries     = 1 << 20
	DefaultCacheBytes   = 4 << 20
	MaxCacheBytes       = 256 << 20
	DefaultMaxTTL       = 24 * time.Hour
	DefaultNegTTL       = 15 * time.Minute
	MaxNegTTL           = 3 * time.Hour // RFC 2308 5
	DefaultPrefetchHits = 3
	maxCachedMessage    = 64 << 10
)

// CacheOptions configure a Cache; zero values take the defaults.
type CacheOptions struct {
	MaxEntries int
	MaxBytes   int
	// MinTTL raises short positive TTLs (0 keeps them); MaxTTL caps them.
	MinTTL time.Duration
	MaxTTL time.Duration
	// NegTTL caps negative answers (RFC 2308); answers without an SOA are
	// never cached negatively.
	NegTTL time.Duration
	// PrefetchHits is how many hits make an entry popular enough to be
	// refreshed before it expires; PrefetchFraction is the remaining part
	// of its TTL at which that happens (default 0.1).
	PrefetchHits     int
	PrefetchFraction float64
}

func (o CacheOptions) withDefaults() (CacheOptions, error) {
	if o.MaxEntries == 0 {
		o.MaxEntries = DefaultCacheEntries
	}
	if o.MaxBytes == 0 {
		o.MaxBytes = DefaultCacheBytes
	}
	if o.MaxTTL == 0 {
		o.MaxTTL = DefaultMaxTTL
	}
	if o.NegTTL == 0 {
		o.NegTTL = DefaultNegTTL
	}
	if o.PrefetchHits == 0 {
		o.PrefetchHits = DefaultPrefetchHits
	}
	if o.PrefetchFraction == 0 {
		o.PrefetchFraction = 0.1
	}
	switch {
	case o.MaxEntries < 1 || o.MaxEntries > MaxCacheEntries:
		return o, fmt.Errorf("önbellek kayıt sayısı 1 ile %d arasında olmalı", MaxCacheEntries)
	case o.MaxBytes < 1024 || o.MaxBytes > MaxCacheBytes:
		return o, fmt.Errorf("önbellek boyutu 1 KiB ile %d MiB arasında olmalı", MaxCacheBytes>>20)
	case o.MinTTL < 0 || o.MinTTL > time.Hour || o.MaxTTL < time.Second || o.MaxTTL > 7*24*time.Hour || o.MinTTL > o.MaxTTL:
		return o, errors.New("önbellek TTL sınırları geçersiz")
	case o.NegTTL < 0 || o.NegTTL > MaxNegTTL:
		return o, fmt.Errorf("olumsuz önbellek süresi en fazla %s olabilir", MaxNegTTL)
	case o.PrefetchHits < 1 || o.PrefetchFraction <= 0 || o.PrefetchFraction >= 1:
		return o, errors.New("önceden çözme ayarları geçersiz")
	}
	return o, nil
}

// Key identifies a cached answer. DNSSEC marks answers fetched with the
// DO or CD bit; the caller keeps them apart from plain answers.
type Key struct {
	Name   string
	Type   dnsmessage.Type
	Class  dnsmessage.Class
	DNSSEC bool
}

// KeyOf builds the key of a question.
func KeyOf(q dnsmessage.Question, dnssec bool) Key {
	return Key{Name: strings.ToLower(q.Name.String()), Type: q.Type, Class: q.Class, DNSSEC: dnssec}
}

type cacheEntry struct {
	key         Key
	msg         dnsmessage.Message
	size        int
	stored      time.Time
	expires     time.Time
	ttl         time.Duration
	hits        int
	negative    bool
	prefetching bool
}

// Cache is a TTL-respecting LRU answer cache; safe for concurrent use.
// It holds answers only in memory and never logs a name.
type Cache struct {
	opt   CacheOptions
	mu    sync.Mutex
	ll    *list.List
	m     map[Key]*list.Element
	bytes int
	st    CacheStats
}

// CacheStats are counters.
type CacheStats struct {
	Entries   int    `json:"entries"`
	Bytes     int    `json:"bytes"`
	Hits      uint64 `json:"hits"`
	NegHits   uint64 `json:"negative_hits"`
	Misses    uint64 `json:"misses"`
	Evictions uint64 `json:"evictions"`
	Prefetch  uint64 `json:"prefetch"`
}

// NewCache returns an empty cache.
func NewCache(o CacheOptions) (*Cache, error) {
	o, err := o.withDefaults()
	if err != nil {
		return nil, err
	}
	return &Cache{opt: o, ll: list.New(), m: map[Key]*list.Element{}}, nil
}

// Put stores a response under its question's key. Truncated answers,
// failures, answers with a zero TTL and negative answers without an SOA
// are not stored (stored is false). OPT records are not kept: EDNS is
// per query and the caller adds its own.
func (c *Cache) Put(resp []byte, dnssec bool, now time.Time) (stored bool, err error) {
	if len(resp) > maxCachedMessage {
		return false, nil
	}
	var m dnsmessage.Message
	if err := m.Unpack(resp); err != nil {
		return false, fmt.Errorf("DNS yanıtı okunamadı: %w", err)
	}
	if !m.Header.Response || m.Header.Truncated || len(m.Questions) != 1 {
		return false, nil
	}
	adds := m.Additionals[:0:0]
	for _, r := range m.Additionals {
		if r.Header.Type != dnsmessage.TypeOPT {
			adds = append(adds, r)
		}
	}
	m.Additionals = adds
	var ttl time.Duration
	negative := false
	switch {
	case m.Header.RCode == dnsmessage.RCodeSuccess && len(m.Answers) > 0:
		ttl = minTTL(m.Answers, m.Additionals)
		if ttl <= 0 {
			return false, nil
		}
		ttl = max(ttl, c.opt.MinTTL)
		ttl = min(ttl, c.opt.MaxTTL)
	case m.Header.RCode == dnsmessage.RCodeSuccess || m.Header.RCode == dnsmessage.RCodeNameError:
		negative = true
		ttl = negativeTTL(m.Authorities)
		if ttl <= 0 {
			return false, nil
		}
		ttl = min(ttl, c.opt.NegTTL)
	default:
		return false, nil
	}
	k := KeyOf(m.Questions[0], dnssec)
	e := &cacheEntry{key: k, msg: m, size: len(resp) + len(k.Name), stored: now, expires: now.Add(ttl), ttl: ttl, negative: negative}
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.m[k]; ok {
		old := el.Value.(*cacheEntry)
		e.hits = old.hits // popularity survives a refresh
		c.removeLocked(el)
	}
	if e.size > c.opt.MaxBytes {
		return false, nil
	}
	c.m[k] = c.ll.PushFront(e)
	c.bytes += e.size
	for c.ll.Len() > c.opt.MaxEntries || c.bytes > c.opt.MaxBytes {
		c.removeLocked(c.ll.Back())
		c.st.Evictions++
	}
	return true, nil
}

func (c *Cache) removeLocked(el *list.Element) {
	e := el.Value.(*cacheEntry)
	c.ll.Remove(el)
	delete(c.m, e.key)
	c.bytes -= e.size
}

func minTTL(sets ...[]dnsmessage.Resource) time.Duration {
	best := time.Duration(-1)
	for _, set := range sets {
		for _, r := range set {
			d := time.Duration(r.Header.TTL) * time.Second
			if best < 0 || d < best {
				best = d
			}
		}
	}
	return best
}

// negativeTTL is min(SOA TTL, SOA minimum) of the authority section
// (RFC 2308 5), or 0 without an SOA.
func negativeTTL(auth []dnsmessage.Resource) time.Duration {
	for _, r := range auth {
		if soa, ok := r.Body.(*dnsmessage.SOAResource); ok {
			return time.Duration(min(r.Header.TTL, soa.MinTTL)) * time.Second
		}
	}
	return 0
}

// Get returns the cached answer to q with id and every TTL lowered by the
// time spent in the cache. Expired entries are removed.
func (c *Cache) Get(q dnsmessage.Question, dnssec bool, id uint16, now time.Time) ([]byte, bool) {
	k := KeyOf(q, dnssec)
	c.mu.Lock()
	el, ok := c.m[k]
	if !ok {
		c.st.Misses++
		c.mu.Unlock()
		return nil, false
	}
	e := el.Value.(*cacheEntry)
	if !now.Before(e.expires) {
		c.removeLocked(el)
		c.st.Misses++
		c.mu.Unlock()
		return nil, false
	}
	e.hits++
	c.ll.MoveToFront(el)
	if e.negative {
		c.st.NegHits++
	} else {
		c.st.Hits++
	}
	m := e.msg
	elapsed := uint32(now.Sub(e.stored) / time.Second)
	c.mu.Unlock()

	m.Header.ID = id
	m.Questions = []dnsmessage.Question{q} // the client's spelling
	m.Answers = aged(m.Answers, elapsed)
	m.Authorities = aged(m.Authorities, elapsed)
	m.Additionals = aged(m.Additionals, elapsed)
	out, err := m.Pack()
	if err != nil {
		return nil, false
	}
	return out, true
}

func aged(in []dnsmessage.Resource, elapsed uint32) []dnsmessage.Resource {
	if len(in) == 0 {
		return nil
	}
	out := make([]dnsmessage.Resource, len(in))
	copy(out, in)
	for i := range out {
		if out[i].Header.TTL > elapsed {
			out[i].Header.TTL -= elapsed
		} else {
			out[i].Header.TTL = 0
		}
	}
	return out
}

// PrefetchCandidates returns at most n keys of popular positive entries
// in the last PrefetchFraction of their TTL, most popular first, and
// marks them so they are returned once until refreshed with Put. The
// caller resolves them again in the background, within its own limits.
func (c *Cache) PrefetchCandidates(now time.Time, n int) []Key {
	if n <= 0 {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	type cand struct {
		k    Key
		hits int
		e    *cacheEntry
	}
	var cs []cand
	for el := c.ll.Front(); el != nil; el = el.Next() {
		e := el.Value.(*cacheEntry)
		if e.negative || e.prefetching || e.hits < c.opt.PrefetchHits || !now.Before(e.expires) {
			continue
		}
		left := e.expires.Sub(now)
		if float64(left) <= float64(e.ttl)*c.opt.PrefetchFraction {
			cs = append(cs, cand{e.key, e.hits, e})
		}
	}
	sort.SliceStable(cs, func(i, j int) bool { return cs[i].hits > cs[j].hits })
	if len(cs) > n {
		cs = cs[:n]
	}
	out := make([]Key, len(cs))
	for i, x := range cs {
		x.e.prefetching = true
		out[i] = x.k
	}
	c.st.Prefetch += uint64(len(out))
	return out
}

// Purge empties the cache (for example when the upstream changes).
func (c *Cache) Purge() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ll.Init()
	c.m = map[Key]*list.Element{}
	c.bytes = 0
}

// Stats reports the counters.
func (c *Cache) Stats() CacheStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.st
	s.Entries, s.Bytes = c.ll.Len(), c.bytes
	return s
}
