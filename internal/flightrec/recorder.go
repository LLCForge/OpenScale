// Package flightrec is the connection flight recorder (#836): a bounded
// in-memory ring of detailed log records, kept at debug level whatever the
// service's own log level is, so the minutes before a dropout can be looked
// at after the fact without running with debug logging all the time.
//
// Nothing in the ring is written to disk until it is frozen. Every record
// is masked when it enters the ring (ADR-0008): secret-named attributes and
// key-like values are removed, IP addresses are shortened with the same
// rules as the service log (internal/privacy), and device names are
// replaced by a short salted digest that stays the same within one ring, so
// the records of one peer can still be followed. A frozen ring is only ever
// stored sealed (internal/bundlecrypt, store.go).
package flightrec

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/openscale/openscale/internal/privacy"
)

// Defaults of a Recorder.
const (
	// DefaultMaxBytes bounds the ring's text.
	DefaultMaxBytes = 4 << 20
	// DefaultMaxAge drops records older than this.
	DefaultMaxAge = 30 * time.Minute
	// MinMaxBytes and MaxMaxBytes bound Config.MaxBytes.
	MinMaxBytes = 64 << 10
	MaxMaxBytes = 32 << 20
	// maxMsg and maxAttrs bound one record's parts.
	maxMsg   = 1 << 10
	maxAttrs = 2 << 10
	// entryOverhead is the bookkeeping charged per record.
	entryOverhead = 48
	// maxNames bounds the names given to SetNames.
	maxNames = 4096
	// minNameLen: shorter names are not replaced inside free text (they
	// would match ordinary words); name-like attributes are always masked.
	minNameLen = 3
)

// Entry is one masked record.
type Entry struct {
	At    time.Time `json:"at"`
	Level string    `json:"level"`
	Msg   string    `json:"msg"`
	Attrs string    `json:"attrs,omitempty"`
}

func (e Entry) size() int { return len(e.Level) + len(e.Msg) + len(e.Attrs) + entryOverhead }

// Stats describes the ring.
type Stats struct {
	Entries  int       `json:"entries"`
	Bytes    int       `json:"bytes"`
	MaxBytes int       `json:"max_bytes"`
	MaxAgeS  int       `json:"max_age_s"`
	Oldest   time.Time `json:"oldest,omitzero"`
	Newest   time.Time `json:"newest,omitzero"`
	// Dropped counts records pushed out by the size bound.
	Dropped uint64 `json:"dropped"`
	// Total counts every record seen since start.
	Total uint64 `json:"total"`
}

// Config configures a Recorder.
type Config struct {
	MaxBytes int
	MaxAge   time.Duration
	Now      func() time.Time
	// Random seeds the name digest salt; nil uses crypto/rand.
	Random io.Reader
}

// Recorder is the ring. It is safe for concurrent use.
type Recorder struct {
	maxBytes int
	maxAge   time.Duration
	now      func() time.Time
	salt     [16]byte

	mu      sync.Mutex
	buf     []Entry
	head    int
	bytes   int
	dropped uint64
	total   uint64
	names   *strings.Replacer
}

// New returns an empty ring.
func New(cfg Config) *Recorder {
	if cfg.MaxBytes == 0 {
		cfg.MaxBytes = DefaultMaxBytes
	}
	cfg.MaxBytes = min(max(cfg.MaxBytes, MinMaxBytes), MaxMaxBytes)
	if cfg.MaxAge <= 0 {
		cfg.MaxAge = DefaultMaxAge
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Random == nil {
		cfg.Random = rand.Reader
	}
	r := &Recorder{maxBytes: cfg.MaxBytes, maxAge: cfg.MaxAge, now: cfg.Now}
	if _, err := io.ReadFull(cfg.Random, r.salt[:]); err != nil {
		// A fixed salt still masks the names; it only makes the digests
		// comparable between computers.
		copy(r.salt[:], "openscale-flight")
	}
	return r
}

// SetNames gives the device names to replace inside free text (messages
// and string values). Names shorter than three characters are skipped.
func (r *Recorder) SetNames(names []string) {
	seen := map[string]bool{}
	var list []string
	for _, n := range names {
		n = strings.TrimSpace(n)
		if utf8.RuneCountInString(n) < minNameLen || seen[n] || len(list) >= maxNames {
			continue
		}
		seen[n] = true
		list = append(list, n)
	}
	// Longest first, so "nas-backup" is replaced before "nas".
	sort.Slice(list, func(i, j int) bool {
		if len(list[i]) != len(list[j]) {
			return len(list[i]) > len(list[j])
		}
		return list[i] < list[j]
	})
	var rep *strings.Replacer
	if len(list) > 0 {
		pairs := make([]string, 0, 2*len(list))
		for _, n := range list {
			pairs = append(pairs, n, r.MaskName(n))
		}
		rep = strings.NewReplacer(pairs...)
	}
	r.mu.Lock()
	r.names = rep
	r.mu.Unlock()
}

// MaskName is the stable masked form of a device name in this ring.
func (r *Recorder) MaskName(name string) string {
	if name == "" {
		return ""
	}
	h := sha256.New()
	h.Write(r.salt[:])
	h.Write([]byte(name))
	return "ad-" + hex.EncodeToString(h.Sum(nil)[:4])
}

// nameKeys are attribute names whose value is a device or user name.
var nameKeys = map[string]bool{
	"name": true, "peer": true, "device": true, "host": true, "hostname": true,
	"fqdn": true, "user": true, "username": true, "owner": true, "from": true, "to": true,
	"exit": true, "exit_node": true, "target": true,
}

func isNameKey(key string) bool {
	k := strings.ToLower(key)
	if i := strings.LastIndexByte(k, '.'); i >= 0 {
		k = k[i+1:]
	}
	return nameKeys[k] || strings.HasSuffix(k, "_name") || strings.HasSuffix(k, "name")
}

// cleanText masks addresses and secrets, replaces known names and control
// characters, and bounds the length.
func (r *Recorder) cleanText(s string, names *strings.Replacer, limit int) string {
	s = privacy.RedactSecrets(privacy.MaskText(s))
	if names != nil {
		s = names.Replace(s)
	}
	s = strings.Map(func(c rune) rune {
		if unicode.IsControl(c) || c == utf8.RuneError {
			return ' '
		}
		return c
	}, s)
	return cut(s, limit)
}

func cut(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	s = s[:limit]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s + "…"
}

// formatAttr appends one masked attribute as key=value.
func (r *Recorder) formatAttr(b *strings.Builder, prefix string, a slog.Attr, names *strings.Replacer) {
	if a.Equal(slog.Attr{}) {
		return
	}
	key := a.Key
	if prefix != "" {
		key = prefix + "." + key
	}
	a = privacy.MaskAttr(a, true)
	v := a.Value.Resolve()
	if v.Kind() == slog.KindGroup {
		for _, g := range v.Group() {
			r.formatAttr(b, key, g, names)
		}
		return
	}
	var val string
	if v.Kind() == slog.KindString && isNameKey(key) && v.String() != privacy.Redacted {
		val = r.MaskName(v.String())
	} else {
		val = r.cleanText(v.String(), names, 256)
	}
	if b.Len() > 0 {
		b.WriteByte(' ')
	}
	b.WriteString(key)
	b.WriteByte('=')
	if strings.ContainsAny(val, " =\"") {
		b.WriteByte('"')
		b.WriteString(strings.ReplaceAll(val, `"`, `'`))
		b.WriteByte('"')
	} else {
		b.WriteString(val)
	}
}

// Add records one log record. attrs are masked here.
func (r *Recorder) Add(at time.Time, level slog.Level, msg string, attrs []slog.Attr) {
	r.mu.Lock()
	names := r.names
	r.mu.Unlock()
	var b strings.Builder
	for _, a := range attrs {
		r.formatAttr(&b, "", a, names)
		if b.Len() > maxAttrs {
			break
		}
	}
	if at.IsZero() {
		at = r.now()
	}
	e := Entry{At: at.UTC(), Level: levelName(level), Msg: r.cleanText(msg, names, maxMsg), Attrs: cut(b.String(), maxAttrs)}
	r.push(e)
}

func levelName(l slog.Level) string {
	switch {
	case l < slog.LevelInfo:
		return "debug"
	case l < slog.LevelWarn:
		return "info"
	case l < slog.LevelError:
		return "warn"
	}
	return "error"
}

func (r *Recorder) push(e Entry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.total++
	r.buf = append(r.buf, e)
	r.bytes += e.size()
	for r.bytes > r.maxBytes && r.head < len(r.buf) {
		r.popLocked()
		r.dropped++
	}
	r.pruneLocked(r.now())
}

func (r *Recorder) popLocked() {
	r.bytes -= r.buf[r.head].size()
	r.buf[r.head] = Entry{}
	r.head++
	// Compact once the dead front is half the slice.
	if r.head > 1024 && r.head*2 > len(r.buf) {
		n := copy(r.buf, r.buf[r.head:])
		clear(r.buf[n:])
		r.buf = r.buf[:n]
		r.head = 0
	}
}

func (r *Recorder) pruneLocked(now time.Time) {
	limit := now.Add(-r.maxAge)
	for r.head < len(r.buf) && r.buf[r.head].At.Before(limit) {
		r.popLocked()
	}
}

// Snapshot returns a copy of the records, oldest first.
func (r *Recorder) Snapshot() []Entry {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pruneLocked(r.now())
	return append([]Entry(nil), r.buf[r.head:]...)
}

// Stats describes the ring now.
func (r *Recorder) Stats() Stats {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pruneLocked(r.now())
	st := Stats{Entries: len(r.buf) - r.head, Bytes: r.bytes, MaxBytes: r.maxBytes, MaxAgeS: int(r.maxAge / time.Second), Dropped: r.dropped, Total: r.total}
	if st.Entries > 0 {
		st.Oldest, st.Newest = r.buf[r.head].At, r.buf[len(r.buf)-1].At
	}
	return st
}
