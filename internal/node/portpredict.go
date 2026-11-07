package node

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	mrand "math/rand/v2"
	"net/netip"
	"slices"
	"time"
)

// Port prediction (ADR-0042 §3, #54). Many NATs that map each destination
// to a new port (hard, symmetric NATs) hand out ports in sequence: while
// both sides ping at once after a call, the peer's mapping toward this
// device is likely just above the one the coordinator saw. For a relayed
// peer whose first probe round failed, a few ports above its observed
// public IPv4 endpoint are pinged too.
//
// Birthday scan (ADR-0231). NATs that pick a random port per destination
// defeat that. When both devices sit behind such NATs (each says so in its
// sealed candidates, ADR-0230), no direct path is known and the plain probe
// rounds failed, each side pings a bounded number of random ports of the
// other's public IPv4 address from its WireGuard socket. Every ping opens a
// mapping on the sender's NAT toward the peer's address; a ping of the peer
// that lands on one of those mappings passes a NAT that filters by address
// (not by address and port), and its pong validates the path. With n pings
// on each side and r possible ports the chance of at least one hit is about
// 1 - exp(-n*n/r): 64% for n = 256.
//
// Bounds: at most MaxBirthdayProbes pings per scan, paced at
// birthdayRate per second, at most one scan per peer every birthdayEvery and
// birthdayBudget pings per hour for the whole device. Scans never run for
// a peer that has a direct path, for IPv6 or private addresses, or when the
// owner turned them off (Config.DisableBirthdayScan).

// portPredictionSpan is how many ports above the observed one are tried.
const portPredictionSpan = 4

// Birthday scan limits.
const (
	// DefaultBirthdayProbes, MinBirthdayProbes and MaxBirthdayProbes bound
	// the pings of one scan (Config.BirthdayProbes).
	DefaultBirthdayProbes = 256
	MinBirthdayProbes     = 64
	MaxBirthdayProbes     = 256
	// birthdayRate is the pacing of scan pings (per second).
	birthdayRate = 64
	// birthdayEvery is the shortest interval between two scans of a peer.
	birthdayEvery = 10 * time.Minute
	// birthdayBudget bounds all scan pings of the device per hour.
	birthdayBudget = 4 * MaxBirthdayProbes
	// birthdayAfter: a scan starts only after this many failed rounds.
	birthdayAfter = 2
	// birthdayLenient is how long after a scan pongs from another port of
	// the probed address still count (the peer's NAT answers from a new
	// mapping).
	birthdayLenient = 30 * time.Second
	// birthdayMinPort is the lowest port tried: NATs rarely map below.
	birthdayMinPort = 1024
)

// predictedPorts returns up to span endpoints above observed, only for a
// public IPv4 endpoint.
func predictedPorts(observed netip.AddrPort, span int) []netip.AddrPort {
	if !scannable(observed) {
		return nil
	}
	a := observed.Addr().Unmap()
	var out []netip.AddrPort
	for i := 1; i <= span; i++ {
		p := int(observed.Port()) + i
		if p > 65535 {
			break
		}
		out = append(out, netip.AddrPortFrom(a, uint16(p)))
	}
	return out
}

// scannable accepts only a public IPv4 endpoint: private, shared (CGN) and
// IPv6 addresses are never scanned.
func scannable(ap netip.AddrPort) bool {
	a := ap.Addr().Unmap()
	return ap.IsValid() && ap.Port() != 0 && a.Is4() && a.IsGlobalUnicast() && !a.IsPrivate() && !sharedAddressSpace.Contains(a)
}

// birthdayPorts returns n distinct random endpoints of addr's address,
// leaving out the ones in skip.
func birthdayPorts(rng *mrand.Rand, addr netip.Addr, n int, skip []netip.AddrPort) []netip.AddrPort {
	a := addr.Unmap()
	span := 65536 - birthdayMinPort
	n = min(n, span-len(skip))
	seen := make(map[uint16]bool, n+len(skip))
	for _, s := range skip {
		if s.Addr().Unmap() == a {
			seen[s.Port()] = true
		}
	}
	out := make([]netip.AddrPort, 0, n)
	for len(out) < n {
		p := uint16(birthdayMinPort + rng.IntN(span)) //nolint:gosec // below 65536
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, netip.AddrPortFrom(a, p))
	}
	return out
}

// newScanRand seeds the scan's port choice from the system's random source.
func newScanRand() *mrand.Rand {
	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		binary.LittleEndian.PutUint64(seed[:], uint64(time.Now().UnixNano())) //nolint:gosec // fallback only
	}
	return mrand.New(mrand.NewChaCha8(seed))
}

// configureBirthday applies the owner's choice.
func (p *prober) configureBirthday(off bool, probes int) error {
	if probes == 0 {
		probes = DefaultBirthdayProbes
	}
	if probes < MinBirthdayProbes || probes > MaxBirthdayProbes {
		return fmt.Errorf("doğum günü taraması %d ile %d port arasında olmalı", MinBirthdayProbes, MaxBirthdayProbes)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.scanOff, p.scanProbes = off, probes
	return nil
}

// scanEligibleLocked reports whether a birthday scan of pp may start now.
// selfHard is this device's own NAT estimate, taken before p.mu.
func (p *prober) scanEligibleLocked(pp *peerProbe, selfHard bool, now time.Time) bool {
	if p.scanOff || !selfHard || !pp.peerHard || !pp.peerScan || !scannable(pp.observed) {
		return false
	}
	if !pp.lastScan.IsZero() && now.Sub(pp.lastScan) < birthdayEvery {
		return false
	}
	p.refillScanLocked(now)
	return p.scanTokens >= float64(p.scanProbes)
}

func (p *prober) refillScanLocked(now time.Time) {
	if !p.scanAt.IsZero() {
		p.scanTokens = min(birthdayBudget, p.scanTokens+now.Sub(p.scanAt).Hours()*birthdayBudget)
	}
	p.scanAt = now
}

// scanPingsLocked builds the pings of one scan of pp and records them as
// pending at the time each will be sent (they are paced).
func (p *prober) scanPingsLocked(pp *peerProbe, now time.Time) []outPing {
	p.expireLocked(now)
	targets := birthdayPorts(p.scanRand, pp.observed.Addr(), p.scanProbes, pp.probeTargets())
	pp.lastScan, pp.scanUntil = now, now.Add(time.Duration(len(targets))*p.scanPace+birthdayLenient)
	p.scanTokens -= float64(len(targets))
	var out []outPing
	for i, to := range targets {
		if len(p.pending) >= maxPendingPings {
			break
		}
		pkt, txid, err := p.newPingLocked(pp, now)
		if err != nil {
			continue
		}
		p.pending[txid] = &pendingPing{peer: pp.dev.ID, to: to, sent: now.Add(time.Duration(i) * p.scanPace), lenient: true}
		out = append(out, outPing{pkt: pkt, to: to})
	}
	p.scans++
	return out
}

// sendPaced sends scan pings at the scan rate, in the background so the
// sync is not held up; with no pacing (tests) at once.
func (p *prober) sendPaced(pings []outPing) {
	if len(pings) == 0 {
		return
	}
	if p.scanPace <= 0 {
		p.send(pings)
		return
	}
	go func() {
		t := time.NewTicker(p.scanPace)
		defer t.Stop()
		for i := range pings {
			if i > 0 {
				<-t.C
			}
			p.send(pings[i : i+1])
		}
	}()
}

// probeTargets are the targets of a probe round: the candidates and, when
// prediction is on for this peer, the predicted ports.
func (pp *peerProbe) probeTargets() []netip.AddrPort {
	t := pp.targets()
	if !pp.predict {
		return t
	}
	for _, ap := range predictedPorts(pp.observed, portPredictionSpan) {
		if !slices.Contains(t, ap) {
			t = append(t, ap)
		}
	}
	return t
}

// selfNATHard estimates whether this device's NAT maps ports per
// destination (ADR-0231): what diag.go reports as "zor", or, before any
// peer saw this device directly, a coordinator-observed port that differs
// from the WireGuard port while no router mapping exists.
func (e *Engine) selfNATHard(listen uint16) bool {
	if _, ok := e.mappedCandidate(); ok {
		return false // the router forwards the port: the NAT is not in the way
	}
	e.mu.Lock()
	var mapped netip.AddrPort
	if n := len(e.mapping); n > 0 {
		mapped = e.mapping[n-1].ep
	}
	e.mu.Unlock()
	if !mapped.IsValid() || e.probe == nil {
		return false
	}
	local := map[netip.Addr]bool{}
	if addrs, err := listInterfaceAddrs(); err == nil {
		for _, ia := range addrs {
			local[ia.addr] = true
		}
	}
	switch estimateNAT(mapped, local, e.probe.seenAsAll(observationFresh)) {
	case NATHard:
		return true
	case NATUnknown:
		return listen != 0 && mapped.Port() != listen
	}
	return false
}
