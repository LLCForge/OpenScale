package panel

import (
	"errors"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/openscale/openscale/internal/peercred"
	"github.com/openscale/openscale/internal/trust"
)

// Sign-in lockout by source. POST /api/login needs no session, and a tool
// can set any Origin, so with one shared counter every local process could
// keep the owner locked out of sign-in and signing for good. Each source
// now has its own counter, and a source that fails locks only itself:
//
//   - the OpenScale window (the requesting process descends from this
//     program, peercred #646);
//   - each local account: elsewhere the system names the account, not a
//     process id, because a process id would give a new budget of guesses
//     to every process started;
//   - the tray's panic item;
//   - everything that cannot be identified, together.
//
// Signing and the other session paths keep auth.failures: a process
// without a session never reaches that counter. Remote sign-in has its own
// server and counters already (remote_access.go, startRemote).
//
// The number of guesses per window stays bounded: the table has at most
// maxLoginSources entries and further sources share lockSourceOverflow.

const (
	lockSourceWindow   = "pencere"
	lockSourceTray     = "tepsi"
	lockSourceUnknown  = "bilinmeyen"
	lockSourceOverflow = "taşma"
)

// windowProcesser is the part of peercred.WindowBinding used to name the
// source; test bindings without it name no window.
type windowProcesser interface {
	WindowProcess(pid int) int
}

// loginSource names the source of a sign-in request. It never fails: what
// cannot be identified counts as lockSourceUnknown, which is limited too.
func (s *Server) loginSource(r *http.Request) string {
	if f := s.g5.desk.lockSource; f != nil {
		return f(r)
	}
	client, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil || !client.Addr().Unmap().IsLoopback() {
		return lockSourceUnknown
	}
	server, err := netip.ParseAddrPort(localAddrOf(r))
	if err != nil {
		return lockSourceUnknown
	}
	id, err := peercred.Lookup(netip.AddrPortFrom(client.Addr().Unmap(), client.Port()), netip.AddrPortFrom(server.Addr().Unmap(), server.Port()))
	if err != nil {
		return lockSourceUnknown
	}
	if id.PID <= 0 {
		if id.UID >= 0 {
			return "yerel:" + strconv.Itoa(id.UID)
		}
		return lockSourceUnknown
	}
	if b, ok := s.windowBinding().(windowProcesser); ok && b.WindowProcess(id.PID) != 0 {
		return lockSourceWindow
	}
	user, err := peercred.ProcessUser(id.PID)
	if err != nil {
		return lockSourceUnknown
	}
	return "yerel:" + user
}

// failLogin answers a failed sign-in; only a wrong passphrase counts.
func (s *Server) failLogin(w http.ResponseWriter, source string, err error) {
	if errors.Is(err, trust.ErrWrongPassphrase) {
		s.auth.recordLoginFailure(source)
		s.logger.Warn("wrong root key passphrase in panel sign-in", "source_kind", lockSourceKind(source))
	}
	s.fail(w, err)
}

// lockSourceKind is the source without the account, for the log.
func lockSourceKind(source string) string {
	switch source {
	case lockSourceWindow, lockSourceTray, lockSourceUnknown, lockSourceOverflow:
		return source
	}
	return "yerel"
}

// loginLocked reports whether source used up its failures.
func (a *auth) loginLocked(source string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.trimLoginFailuresLocked()
	return len(a.loginFailures[a.loginKeyLocked(source)]) >= lockoutFailures
}

// reserveLoginAttempt lets one attempt of source start; release ends it and
// must run after the failure is recorded.
//
// SECURITY FIX: CWE-307 A failure is counted only after the slow passphrase
// check, so a check of the count alone would let every parallel request
// through. Attempts under way use up the budget too.
func (a *auth) reserveLoginAttempt(source string) (release func(), ok bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.trimLoginFailuresLocked()
	key := a.loginKeyLocked(source)
	if len(a.loginFailures[key])+a.loginPending[key] >= lockoutFailures {
		return nil, false
	}
	if a.loginPending == nil {
		a.loginPending = map[string]int{}
	}
	a.loginPending[key]++
	return func() {
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.loginPending[key]--; a.loginPending[key] <= 0 {
			delete(a.loginPending, key)
		}
	}, true
}

// recordLoginFailure counts a wrong passphrase for source.
func (a *auth) recordLoginFailure(source string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.trimLoginFailuresLocked()
	if a.loginFailures == nil {
		a.loginFailures = map[string][]time.Time{}
	}
	key := a.loginKeyLocked(source)
	a.loginFailures[key] = append(a.loginFailures[key], a.now())
}

// loginKeyLocked is the counter of source: a known one, a free slot, or
// the shared overflow counter when the table is full.
func (a *auth) loginKeyLocked(source string) string {
	if _, ok := a.loginFailures[source]; ok {
		return source
	}
	used := len(a.loginFailures)
	if _, ok := a.loginFailures[lockSourceOverflow]; ok {
		used--
	}
	if used >= maxLoginSources {
		return lockSourceOverflow
	}
	return source
}

func (a *auth) trimLoginFailuresLocked() {
	cutoff := a.now().Add(-lockoutWindow)
	for source, times := range a.loginFailures {
		kept := times[:0]
		for _, t := range times {
			if t.After(cutoff) {
				kept = append(kept, t)
			}
		}
		if len(kept) == 0 {
			delete(a.loginFailures, source)
			continue
		}
		a.loginFailures[source] = kept
	}
}
