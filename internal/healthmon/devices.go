package healthmon

import (
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/trust"
)

// ScopeFromDocument returns the tunnel's prefixes plus the owner's extra
// prefixes (for example a home LAN behind an approved subnet router).
// Extra prefixes must be private: a public range is never probed.
func ScopeFromDocument(doc *trust.Document, extra []netip.Prefix) (Scope, error) {
	var s Scope
	if doc != nil {
		if doc.IPv4Prefix.IsValid() {
			s.Prefixes = append(s.Prefixes, doc.IPv4Prefix)
		}
		if doc.IPv6Prefix.IsValid() {
			s.Prefixes = append(s.Prefixes, doc.IPv6Prefix)
		}
	}
	for _, p := range extra {
		p = p.Masked()
		if !p.IsValid() || !(p.Addr().IsPrivate() || p.Addr().Unmap().IsLoopback()) {
			return Scope{}, fmt.Errorf("ek ağ özel bir aralık olmalı: %s", p)
		}
		s.Prefixes = append(s.Prefixes, p)
	}
	return s, nil
}

// Presence defaults.
const (
	DefaultOfflineAfter = 5 * time.Minute
	maxWatched          = 1024
)

// Presence turns "last seen" times into device offline and online events
// for the devices the owner chose to watch (servers, the NAS); laptops
// that sleep at night are not watched unless the owner asks.
type Presence struct {
	mu      sync.Mutex
	after   time.Duration
	watched map[string]*presenceState
}

type presenceState struct {
	offline bool
	since   time.Time
	last    time.Time
}

// NewPresence watches names; offlineAfter is the silence that counts as
// offline (zero means DefaultOfflineAfter).
func NewPresence(names []string, offlineAfter time.Duration) *Presence {
	if offlineAfter <= 0 {
		offlineAfter = DefaultOfflineAfter
	}
	p := &Presence{after: offlineAfter, watched: map[string]*presenceState{}}
	for _, n := range names {
		if len(p.watched) >= maxWatched {
			break
		}
		p.watched[n] = &presenceState{}
	}
	return p
}

// Watched reports whether name is watched.
func (p *Presence) Watched(name string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok := p.watched[name]
	return ok
}

// Observe records the last time each device was seen (a WireGuard
// handshake or a status reply; zero when never) and returns transitions.
// Devices missing from lastSeen are left as they are.
func (p *Presence) Observe(lastSeen map[string]time.Time, now time.Time) []Event {
	p.mu.Lock()
	defer p.mu.Unlock()
	names := make([]string, 0, len(p.watched))
	for n := range p.watched {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []Event
	for _, n := range names {
		seen, ok := lastSeen[n]
		if !ok {
			continue
		}
		st := p.watched[n]
		if seen.After(st.last) {
			st.last = seen
		}
		silent := st.last.IsZero() || now.Sub(st.last) >= p.after
		switch {
		case silent && !st.offline:
			st.offline, st.since = true, now
			detail := "Cihaz hiç görülmedi."
			if !st.last.IsZero() {
				detail = fmt.Sprintf("Son görülme: %s önce.", now.Sub(st.last).Round(time.Minute))
			}
			out = append(out, Event{Kind: KindDeviceOffline, Severity: SeverityCritical, Subject: n, At: now,
				Title: n + " çevrimdışı", Detail: detail})
		case !silent && st.offline:
			down := now.Sub(st.since).Round(time.Minute)
			st.offline, st.since = false, now
			out = append(out, Event{Kind: KindDeviceOnline, Severity: SeverityInfo, Subject: n, At: now,
				Title: n + " yeniden çevrimiçi", Detail: fmt.Sprintf("Yaklaşık %s erişilemedi.", down)})
		}
	}
	return out
}

// Offline lists watched devices currently offline with the time since.
func (p *Presence) Offline(now time.Time) map[string]time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := map[string]time.Duration{}
	for n, st := range p.watched {
		if st.offline {
			out[n] = now.Sub(st.since)
		}
	}
	return out
}

// MemberChanges compares two signed documents by device ID and returns
// joined, left and renamed devices (#783). Ephemeral devices are
// reported with info severity so short-lived guests do not page anyone.
func MemberChanges(prev, next *trust.Document, now time.Time) []Event {
	if next == nil {
		return nil
	}
	old := map[string]trust.Device{}
	if prev != nil {
		for _, d := range prev.Devices {
			old[d.ID] = d
		}
	}
	var out []Event
	cur := map[string]bool{}
	for _, d := range next.Devices {
		cur[d.ID] = true
		o, ok := old[d.ID]
		switch {
		case prev == nil:
		case !ok:
			sev := SeverityWarning
			if d.Ephemeral {
				sev = SeverityInfo
			}
			out = append(out, Event{Kind: KindDeviceJoined, Severity: sev, Subject: d.Name, At: now,
				Title: d.Name + " ağa katıldı", Detail: fmt.Sprintf("Belge sürümü %d ile eklendi.", next.Version)})
		case o.Name != d.Name:
			out = append(out, Event{Kind: KindDeviceRenamed, Severity: SeverityInfo, Subject: d.Name, At: now,
				Title: o.Name + " cihazının adı " + d.Name + " oldu"})
		}
	}
	if prev != nil {
		for _, d := range prev.Devices {
			if !cur[d.ID] {
				out = append(out, Event{Kind: KindDeviceLeft, Severity: SeverityWarning, Subject: d.Name, At: now,
					Title: d.Name + " ağdan çıkarıldı", Detail: fmt.Sprintf("Belge sürümü %d ile kaldırıldı.", next.Version)})
			}
		}
	}
	return out
}
