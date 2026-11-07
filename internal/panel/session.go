package panel

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"sync"
	"time"
)

const (
	sessionCookie   = "openscale_session"
	sessionIdle     = 15 * time.Minute
	maxSessions     = 8
	tokenBytes      = 32
	lockoutFailures = 5
	lockoutWindow   = 5 * time.Minute
	maxLoginSources = 32               // distinct sign-in lockout counters, then a shared one
	ticketLife      = 30 * time.Second // tray sign-in ticket (W2)
	maxTickets      = 8
)

var errTooManyTickets = errors.New("too many unused sign-in tickets")

type session struct {
	csrf     string
	lastSeen time.Time
	// g5 holds the context binding, second factor, re-authentication and
	// administrator mode state (ADR-0199, g5_session.go).
	g5 g5Session
}

// auth holds sessions and the passphrase failure counters. failures counts
// what only a signed-in session can reach (signing, re-authentication,
// unlock); loginFailures counts sign-in attempts by source (lockout.go).
// All methods are safe for concurrent use.
type auth struct {
	mu       sync.Mutex
	random   io.Reader
	now      func() time.Time
	sessions map[string]*session
	failures []time.Time
	tickets  map[string]time.Time
	// loginFailures is created on the first failure (lockout.go).
	loginFailures map[string][]time.Time
	loginPending  map[string]int // attempts being checked, by counter
}

func newAuth(random io.Reader, now func() time.Time) *auth {
	return &auth{random: random, now: now, sessions: map[string]*session{}, tickets: map[string]time.Time{}}
}

// create starts a new session after a successful sign-in.
func (a *auth) create() (string, error) {
	id, err := randomToken(a.random)
	if err != nil {
		return "", err
	}
	csrf, err := randomToken(a.random)
	if err != nil {
		return "", err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pruneLocked()
	if len(a.sessions) >= maxSessions {
		a.evictOldestLocked()
	}
	a.sessions[id] = &session{csrf: csrf, lastSeen: a.now()}
	return id, nil
}

// lookup returns the session for id and refreshes its idle timer.
func (a *auth) lookup(id string) (*session, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pruneLocked()
	s, ok := a.sessions[id]
	if !ok {
		return nil, false
	}
	if s.g5.isPending() {
		// A sign-in waiting for its second factor opens nothing else.
		return nil, false
	}
	s.lastSeen = a.now()
	return s, true
}

// issueTicket returns a one-time sign-in ticket for the tray app.
func (a *auth) issueTicket() (string, error) {
	t, err := randomToken(a.random)
	if err != nil {
		return "", err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	for k, exp := range a.tickets {
		if !now.Before(exp) {
			delete(a.tickets, k)
		}
	}
	if len(a.tickets) >= maxTickets {
		return "", errTooManyTickets
	}
	a.tickets[t] = now.Add(ticketLife)
	return t, nil
}

// redeemTicket consumes a ticket; it works once and only before it expires.
func (a *auth) redeemTicket(t string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	exp, ok := a.tickets[t]
	delete(a.tickets, t)
	return ok && a.now().Before(exp)
}

func (a *auth) logout(id string) {
	a.logoutSession(id) // wipes G5 secrets too (g5_session.go)
}

// passphraseLocked reports whether too many wrong passphrases were entered
// recently by a signed-in session. Argon2id already makes each guess slow;
// this caps the rate. Sign-in has its own counters (lockout.go).
func (a *auth) passphraseLocked() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.trimFailuresLocked()
	return len(a.failures) >= lockoutFailures
}

func (a *auth) recordPassphraseFailure() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.trimFailuresLocked()
	a.failures = append(a.failures, a.now())
}

func (a *auth) trimFailuresLocked() {
	cutoff := a.now().Add(-lockoutWindow)
	kept := a.failures[:0]
	for _, t := range a.failures {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	a.failures = kept
}

func (a *auth) pruneLocked() {
	now := a.now()
	cutoff := now.Add(-sessionIdle)
	for id, s := range a.sessions {
		if s.lastSeen.Before(cutoff) || s.g5.pendingExpired(now) {
			s.g5.wipe()
			delete(a.sessions, id)
		}
	}
}

func (a *auth) evictOldestLocked() {
	var oldestID string
	var oldest time.Time
	for id, s := range a.sessions {
		if oldestID == "" || s.lastSeen.Before(oldest) {
			oldestID, oldest = id, s.lastSeen
		}
	}
	if s, ok := a.sessions[oldestID]; ok {
		s.g5.wipe()
	}
	delete(a.sessions, oldestID)
}

func randomToken(random io.Reader) (string, error) {
	b := make([]byte, tokenBytes)
	if _, err := io.ReadFull(random, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// defaultRandom is the system CSPRNG.
var defaultRandom io.Reader = rand.Reader
