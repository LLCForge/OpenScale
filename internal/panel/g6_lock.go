package panel

import (
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Idle privacy lock (#661, ADR-0206). The server keeps the time of the
// last user action. When the configured idle time passes, the panel is
// locked: every API request other than the lock endpoints, the tray's
// own endpoints and sign-in answers 423 until the user unlocks it with
// the network passphrase (owner device) or the app's unlock method
// (PanelUnlocker: operating system password or a YubiKey touch). The
// browser blurs the page as soon as it sees 423 or a locked status; the
// server side makes the lock real even if the page is changed.
//
// Background polling (status, screen share) does not count as activity;
// the page reports real input with POST /api/app/privacy/activity.
//
// The lock is off until the user sets a time, because a panel build that
// does not know the lock screen would only see failing requests.

// PanelUnlocker is implemented by an app that can unlock without the
// network passphrase (member devices). The secret is wiped by the caller.
type PanelUnlocker interface {
	UnlockPanel(secret []byte) error
}

// PanelLockStore persists the idle minutes; optional.
type PanelLockStore interface {
	PanelLockMinutes() int
	SetPanelLockMinutes(int) error
}

// LockStatus is GET /api/app/privacy/lock.
type LockStatus struct {
	Schema      int  `json:"schema"`
	Locked      bool `json:"locked"`
	Minutes     int  `json:"minutes"`
	IdleSeconds int  `json:"idle_seconds"`
	// RemainingSeconds is the time until the lock (0 when off or locked).
	RemainingSeconds int `json:"remaining_seconds"`
	// Method is how to unlock: "passphrase" (network passphrase), "app"
	// (operating system password or YubiKey through the app) or "none".
	Method string `json:"method"`
}

// LockSettings sets the idle minutes (0 turns the lock off).
type LockSettings struct {
	Minutes int `json:"minutes"`
}

// UnlockRequest carries the secret; it is never logged.
type UnlockRequest struct {
	Secret string `json:"secret"`
}

const maxLockMinutes = 240

type idleLock struct {
	mu      sync.Mutex
	minutes int
	last    time.Time
	locked  bool
	loaded  bool
}

var idleLocks sync.Map // *Server -> *idleLock

func (s *Server) idle() *idleLock {
	if v, ok := idleLocks.Load(s); ok {
		return v.(*idleLock)
	}
	v, _ := idleLocks.LoadOrStore(s, &idleLock{last: s.now()})
	l := v.(*idleLock)
	l.mu.Lock()
	if !l.loaded {
		l.loaded = true
		if st, ok := s.app.(PanelLockStore); ok {
			if m := st.PanelLockMinutes(); m > 0 && m <= maxLockMinutes {
				l.minutes = m
			}
		}
	}
	l.mu.Unlock()
	return l
}

// lockedNow updates the lock from the idle time and reports it.
func (l *idleLock) lockedNow(now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.locked && l.minutes > 0 && now.Sub(l.last) >= time.Duration(l.minutes)*time.Minute {
		l.locked = true
	}
	return l.locked
}

func (l *idleLock) touch(now time.Time) {
	l.mu.Lock()
	if !l.locked {
		l.last = now
	}
	l.mu.Unlock()
}

func (s *Server) unlockMethod() string {
	if s.network() != nil {
		return "passphrase"
	}
	if _, ok := s.app.(PanelUnlocker); ok {
		return "app"
	}
	return "none"
}

// lockExempt lists paths that work while locked.
func lockExempt(r *http.Request) bool {
	p := r.URL.Path
	switch {
	case !strings.HasPrefix(p, "/api/"):
		return true // static files; the page itself shows the lock
	case strings.HasPrefix(p, "/api/app/privacy/"):
		return true
	case strings.HasPrefix(p, "/api/app/tray"):
		return true // tray app token, not the panel session
	case p == "/api/login", p == "/api/logout", p == "/api/session", p == "/api/app/info", p == "/api/app/ticket":
		return true
	}
	return false
}

// passive lists polling endpoints that are not user activity.
func passive(r *http.Request) bool {
	p := r.URL.Path
	return strings.HasPrefix(p, "/api/app/privacy/") || strings.HasPrefix(p, "/api/app/tray") || p == "/api/session" ||
		p == "/api/app/status" || p == "/api/app/e2e"
}

// lockGate enforces the idle lock in front of every handler.
func (s *Server) lockGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l := s.idle()
		now := s.now()
		if l.lockedNow(now) && !lockExempt(r) {
			writeJSON(w, http.StatusLocked, map[string]any{"error": "Panel boşta kaldığı için kilitlendi. Devam etmek için kilidi açın.", "locked": true})
			return
		}
		if !passive(r) && r.Method != http.MethodGet {
			l.touch(now)
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) lockStatus() LockStatus {
	l := s.idle()
	now := s.now()
	locked := l.lockedNow(now)
	l.mu.Lock()
	defer l.mu.Unlock()
	st := LockStatus{Schema: 1, Locked: locked, Minutes: l.minutes, IdleSeconds: int(now.Sub(l.last) / time.Second), Method: s.unlockMethod()}
	if !locked && l.minutes > 0 {
		if rem := time.Duration(l.minutes)*time.Minute - now.Sub(l.last); rem > 0 {
			st.RemainingSeconds = int(rem / time.Second)
		}
	}
	return st
}

// checkUnlock verifies the secret with the network passphrase or the app.
func (s *Server) checkUnlock(secret []byte) error {
	if n := s.network(); n != nil {
		return n.CheckPassphrase(secret)
	}
	if u, ok := s.app.(PanelUnlocker); ok {
		return u.UnlockPanel(secret)
	}
	return errors.New("no unlock method")
}

func (s *Server) g6LockRoutes(mux *http.ServeMux) {
	write := func(h http.HandlerFunc) http.HandlerFunc { return s.requireSession(s.requireCSRF(h)) }
	mux.HandleFunc("GET /api/app/privacy/lock", s.requireSession(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, s.lockStatus())
	}))
	mux.HandleFunc("POST /api/app/privacy/lock", write(func(w http.ResponseWriter, _ *http.Request) {
		if s.unlockMethod() == "none" {
			writeError(w, http.StatusConflict, "Bu cihazda kilidi açacak bir yöntem yok; panel kilitlenmedi.")
			return
		}
		l := s.idle()
		l.mu.Lock()
		l.locked = true
		l.mu.Unlock()
		s.logger.Info("panel locked by user")
		writeJSON(w, http.StatusOK, s.lockStatus())
	}))
	mux.HandleFunc("POST /api/app/privacy/activity", write(func(w http.ResponseWriter, _ *http.Request) {
		s.idle().touch(s.now())
		writeJSON(w, http.StatusOK, s.lockStatus())
	}))
	mux.HandleFunc("POST /api/app/privacy/lock/settings", write(func(w http.ResponseWriter, r *http.Request) {
		if s.isReadOnly() {
			writeError(w, http.StatusForbidden, "Panel salt okunur modda; değişiklik yapılamaz.")
			return
		}
		var req LockSettings
		if !decodeBody(w, r, &req) {
			return
		}
		if req.Minutes < 0 || req.Minutes > maxLockMinutes {
			writeError(w, http.StatusBadRequest, "Süre 0 ile 240 dakika arasında olmalı (0: kapalı).")
			return
		}
		if req.Minutes > 0 && s.unlockMethod() == "none" {
			writeError(w, http.StatusConflict, "Bu cihazda kilidi açacak bir yöntem yok; boşta kilidi açılamaz.")
			return
		}
		l := s.idle()
		if l.lockedNow(s.now()) {
			writeError(w, http.StatusLocked, "Panel kilitli.")
			return
		}
		if st, ok := s.app.(PanelLockStore); ok {
			if err := st.SetPanelLockMinutes(req.Minutes); err != nil {
				writeError(w, http.StatusInternalServerError, "Ayar kaydedilemedi.")
				return
			}
		}
		l.mu.Lock()
		l.minutes, l.last = req.Minutes, s.now()
		l.mu.Unlock()
		writeJSON(w, http.StatusOK, s.lockStatus())
	}))
	mux.HandleFunc("POST /api/app/privacy/unlock", write(func(w http.ResponseWriter, r *http.Request) {
		if s.auth.passphraseLocked() {
			writeError(w, http.StatusTooManyRequests, "Çok fazla yanlış deneme. 5 dakika sonra tekrar deneyin.")
			return
		}
		var req UnlockRequest
		if !decodeBody(w, r, &req) {
			return
		}
		secret := []byte(req.Secret)
		defer wipe(secret)
		if len(secret) == 0 || len(secret) > 1024 {
			writeError(w, http.StatusBadRequest, "Parola gerekli.")
			return
		}
		if err := s.checkUnlock(secret); err != nil {
			s.auth.recordPassphraseFailure()
			s.logger.Warn("panel unlock failed")
			writeError(w, http.StatusUnauthorized, "Kilit açılamadı. Parolayı kontrol edin.")
			return
		}
		l := s.idle()
		l.mu.Lock()
		l.locked, l.last = false, s.now()
		l.mu.Unlock()
		s.logger.Info("panel unlocked")
		writeJSON(w, http.StatusOK, s.lockStatus())
	}))
}
