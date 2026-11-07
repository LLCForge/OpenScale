// Package enrollkit holds the enrollment conveniences of package P02:
// nearby pairing on the local network (#358, ADR-0156) and the invite
// launcher file (#360).
package enrollkit

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/trust"
)

// Nearby pairing (#358, ADR-0156). A new device broadcasts its signed
// enrollment request on the local network for a short window; an admin
// device that the owner switched to listening collects the requests and
// lists them as "nearby requests". The announcement proves only that the
// sender holds the keys it names: anyone on the LAN can announce. The
// owner still approves each request by typing the short code read from the
// new device's screen (ADR-0062), so a forged announcement cannot be
// approved by accident. Listening is off by default and stops by itself.

const (
	// NearbyPort is the UDP port of nearby announcements.
	NearbyPort = 41823
	// NearbyWindow is how long an announcer sends and a listener listens.
	NearbyWindow = 5 * time.Minute
	// NearbyInterval is the gap between two announcements.
	NearbyInterval = 2 * time.Second
	// MaxNearby bounds the listed requests.
	MaxNearby    = 32
	nearbyMagic  = "OSNEAR1\n"
	maxNearbyPkt = 1400
	maxPerSource = 4
)

// ErrNotAnnouncement is returned for packets that are not announcements.
var ErrNotAnnouncement = errors.New("not a nearby announcement")

// NearbyPacket returns the announcement packet for an encoded enrollment
// request line (trust.EncodeEnrollment).
func NearbyPacket(line string) ([]byte, error) {
	env, err := trust.DecodeEnrollment(line)
	if err != nil {
		return nil, err
	}
	if _, err := trust.OpenEnrollmentRequest(env, time.Now()); err != nil {
		return nil, err
	}
	pkt := append([]byte(nearbyMagic), line...)
	if len(pkt) > maxNearbyPkt {
		return nil, errors.New("enrollment request is too large to announce")
	}
	return pkt, nil
}

// Announce sends pkt to dst every interval until ctx ends or window passes.
// It returns the number of packets sent.
func Announce(ctx context.Context, conn net.PacketConn, dst net.Addr, pkt []byte, interval, window time.Duration) (int, error) {
	if interval <= 0 {
		interval = NearbyInterval
	}
	if window <= 0 {
		window = NearbyWindow
	}
	ctx, cancel := context.WithTimeout(ctx, window)
	defer cancel()
	t := time.NewTicker(interval)
	defer t.Stop()
	sent := 0
	for {
		if _, err := conn.WriteTo(pkt, dst); err != nil {
			return sent, err
		}
		sent++
		select {
		case <-ctx.Done():
			return sent, nil
		case <-t.C:
		}
	}
}

// BroadcastAddr is the IPv4 limited broadcast address on NearbyPort.
func BroadcastAddr() *net.UDPAddr {
	return &net.UDPAddr{IP: net.IPv4bcast, Port: NearbyPort}
}

// NearbyRequest is one verified announcement. The short code is
// deliberately absent: the owner reads it on the new device.
type NearbyRequest struct {
	Line      string    `json:"request"`
	Hostname  string    `json:"hostname"`
	DeviceID  string    `json:"deviceId"`
	From      string    `json:"from"`
	FirstSeen time.Time `json:"firstSeen"`
	LastSeen  time.Time `json:"lastSeen"`
}

// Listener collects nearby announcements.
type Listener struct {
	now func() time.Time

	mu    sync.Mutex
	until time.Time
	byID  map[string]*NearbyRequest
}

// NewListener returns a listener; now may be nil.
func NewListener(now func() time.Time) *Listener {
	if now == nil {
		now = time.Now
	}
	return &Listener{now: now, byID: map[string]*NearbyRequest{}}
}

// Handle verifies one packet from src and records it.
func (l *Listener) Handle(pkt []byte, src netip.AddrPort) error {
	if len(pkt) > maxNearbyPkt || !bytes.HasPrefix(pkt, []byte(nearbyMagic)) {
		return ErrNotAnnouncement
	}
	line := string(pkt[len(nearbyMagic):])
	env, err := trust.DecodeEnrollment(line)
	if err != nil {
		return err
	}
	now := l.now()
	req, err := trust.OpenEnrollmentRequest(env, now)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pruneLocked(now)
	key := req.DeviceID + "/" + req.Fingerprint()
	if r, ok := l.byID[key]; ok {
		r.LastSeen = now
		return nil
	}
	if len(l.byID) >= MaxNearby {
		return errors.New("too many nearby requests")
	}
	from := src.Addr().Unmap().String()
	same := 0
	for _, r := range l.byID {
		if r.From == from {
			same++
		}
	}
	if same >= maxPerSource {
		return errors.New("too many nearby requests from one address")
	}
	id := req.DeviceID
	if len(id) > 8 {
		id = id[:8]
	}
	l.byID[key] = &NearbyRequest{Line: line, Hostname: req.Hostname, DeviceID: id, From: from, FirstSeen: now, LastSeen: now}
	return nil
}

func (l *Listener) pruneLocked(now time.Time) {
	for k, r := range l.byID {
		if now.Sub(r.LastSeen) > NearbyWindow {
			delete(l.byID, k)
		}
	}
}

// Requests returns the current requests, newest first.
func (l *Listener) Requests() []NearbyRequest {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pruneLocked(l.now())
	out := make([]NearbyRequest, 0, len(l.byID))
	for _, r := range l.byID {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FirstSeen.After(out[j].FirstSeen) })
	return out
}

// Until is the end of the current listening window (zero when idle).
func (l *Listener) Until() time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.until
}

// Serve reads packets from conn until ctx ends or the window passes, then
// closes conn. Invalid packets are dropped silently.
func (l *Listener) Serve(ctx context.Context, conn net.PacketConn, window time.Duration) {
	if window <= 0 {
		window = NearbyWindow
	}
	ctx, cancel := context.WithTimeout(ctx, window)
	defer cancel()
	l.mu.Lock()
	l.until = l.now().Add(window)
	l.mu.Unlock()
	defer func() {
		l.mu.Lock()
		l.until = time.Time{}
		l.mu.Unlock()
	}()
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()
	buf := make([]byte, maxNearbyPkt+1)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		var src netip.AddrPort
		if ua, ok := addr.(*net.UDPAddr); ok {
			src = ua.AddrPort()
		}
		_ = l.Handle(buf[:n], src)
	}
}
