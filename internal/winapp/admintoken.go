package winapp

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/piv"
)

// Administrator mode on hardware token insertion (ADR-0197, with #678).
// The tray polls the smart-card readers with piv.Prober (no PIN, no
// signing, the card is not reset). When a token holding one of the
// network's root or administrator keys appears, it asks the service to
// open a token administrator session; when the token is pulled out it
// closes that session at once. A session also ends after MaxSession (15
// minutes, #678) and is not reopened until the token is removed and
// inserted again.
//
// Presence alone proves nothing: a card emulator can report any public
// key. The session API behind AdminSessionAPI (group G1) must therefore
// verify possession with a fresh challenge signed by the token (PIN or
// touch) before it grants anything. This watcher only decides when to ask
// and when to drop.

// PresenceChecker reports the current token; *piv.Prober implements it.
type PresenceChecker interface {
	Check(ctx context.Context) (piv.PresenceResult, error)
}

// AdminSessionAPI is the service's token administrator session API (G1).
type AdminSessionAPI interface {
	// OpenTokenSession starts the challenge and opens the session when
	// the token signs it. It returns when the session is open or refused.
	OpenTokenSession(ctx context.Context, token piv.PresenceResult) error
	// CloseTokenSession ends the session; reason is Turkish, for the log.
	CloseTokenSession(ctx context.Context, reason string) error
}

// Defaults.
const (
	DefaultTokenPoll       = 2 * time.Second
	DefaultTokenMaxSession = 15 * time.Minute
)

// Close reasons.
const (
	ReasonTokenRemoved = "donanım anahtarı çekildi"
	ReasonSessionLimit = "yönetici oturumu süresi doldu (15 dakika)"
	ReasonStopped      = "tepsi kapandı"
)

// AdminTokenState is what the tray shows.
type AdminTokenState struct {
	// Present: a reader matching the filter has a card.
	Present bool `json:"present"`
	// Admin: the card holds a root or administrator key of the network.
	Admin bool `json:"admin"`
	// SessionOpen: the service granted the token session.
	SessionOpen bool      `json:"session_open"`
	Reader      string    `json:"reader,omitempty"`
	OpenedAt    time.Time `json:"opened_at,omitzero"`
	// Message is a Turkish status line for the tray tooltip or menu.
	Message string `json:"message"`
	// Err is the last error (reader or session API), Turkish.
	Err string `json:"error,omitempty"`
}

// AdminTokenWatcher runs the loop. Set the fields before Run.
type AdminTokenWatcher struct {
	Checker    PresenceChecker
	API        AdminSessionAPI
	Poll       time.Duration
	MaxSession time.Duration
	// OnChange is called after every state change (from the Run goroutine).
	OnChange func(AdminTokenState)
	// Now is for tests.
	Now func() time.Time

	mu    sync.Mutex
	state AdminTokenState
	// spent is set when a session ended by time while the token stayed in;
	// the token must be removed before a new session.
	spent bool
	// refused is set when the API refused the current insertion.
	refused bool
}

// ErrNoChecker: the watcher has no presence checker or API.
var ErrNoChecker = errors.New("yönetici jetonu izleyicisi eksik yapılandırılmış")

func (w *AdminTokenWatcher) now() time.Time {
	if w.Now != nil {
		return w.Now()
	}
	return time.Now()
}

// State returns the current state.
func (w *AdminTokenWatcher) State() AdminTokenState {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.state
}

// Run polls until ctx ends; on return an open session is closed.
func (w *AdminTokenWatcher) Run(ctx context.Context) error {
	if w.Checker == nil || w.API == nil {
		return ErrNoChecker
	}
	poll := w.Poll
	if poll <= 0 {
		poll = DefaultTokenPoll
	}
	t := time.NewTicker(poll)
	defer t.Stop()
	for {
		w.Step(ctx)
		select {
		case <-ctx.Done():
			w.closeSession(context.WithoutCancel(ctx), ReasonStopped)
			return ctx.Err()
		case <-t.C:
		}
	}
}

// Step runs one poll and returns the new state.
func (w *AdminTokenWatcher) Step(ctx context.Context) AdminTokenState {
	res, err := w.Checker.Check(ctx)
	w.mu.Lock()
	prev := w.state
	maxSession := w.MaxSession
	if maxSession <= 0 {
		maxSession = DefaultTokenMaxSession
	}
	next := prev
	next.Err = ""
	if err != nil {
		// A reader error counts as "no token": fail closed.
		res = piv.PresenceResult{Match: -1}
		next.Err = "kart okuyucu okunamadı: " + err.Error()
	}
	next.Present, next.Admin, next.Reader = res.Present, res.Admin(), res.Reader
	if !next.Admin {
		w.spent, w.refused = false, false
	}
	open := prev.SessionOpen
	expired := open && w.now().Sub(prev.OpenedAt) >= maxSession
	w.mu.Unlock()

	switch {
	case open && !next.Admin:
		w.closeSession(ctx, ReasonTokenRemoved)
		next.SessionOpen, next.OpenedAt = false, time.Time{}
	case expired:
		w.closeSession(ctx, ReasonSessionLimit)
		next.SessionOpen, next.OpenedAt = false, time.Time{}
		w.mu.Lock()
		w.spent = true
		w.mu.Unlock()
	case !open && next.Admin && !w.blocked():
		if err := w.API.OpenTokenSession(ctx, res); err != nil {
			next.Err = "yönetici oturumu açılamadı: " + err.Error()
			w.mu.Lock()
			w.refused = true
			w.mu.Unlock()
		} else {
			next.SessionOpen, next.OpenedAt = true, w.now()
		}
	}
	next.Message = tokenMessage(next, w.blocked())
	w.mu.Lock()
	w.state = next
	cb := w.OnChange
	w.mu.Unlock()
	if cb != nil && next != prev {
		cb(next)
	}
	return next
}

func (w *AdminTokenWatcher) blocked() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.spent || w.refused
}

func (w *AdminTokenWatcher) closeSession(ctx context.Context, reason string) {
	w.mu.Lock()
	open := w.state.SessionOpen
	w.mu.Unlock()
	if !open {
		return
	}
	// The session is dropped locally whatever the API answers; the
	// service also ends it on its own timer (#678).
	_ = w.API.CloseTokenSession(ctx, reason)
	w.mu.Lock()
	w.state.SessionOpen, w.state.OpenedAt = false, time.Time{}
	w.mu.Unlock()
}

func tokenMessage(s AdminTokenState, blocked bool) string {
	switch {
	case s.SessionOpen:
		return "Yönetici kipi açık (donanım anahtarı takılı)"
	case s.Admin && blocked:
		return "Donanım anahtarı takılı; yeni yönetici oturumu için çıkarıp yeniden takın"
	case s.Admin:
		return "Donanım anahtarı takılı"
	case s.Present:
		return "Kart takılı, bu ağın yönetici anahtarı değil"
	}
	return "Yönetici anahtarı takılı değil (salt okunur)"
}
