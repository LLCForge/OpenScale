package support

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"sync"
	"time"
)

// Mode is what a request needs from the signed rules.
type Mode string

// Modes.
const (
	ModeRead Mode = "read"
	ModeKill Mode = "kill"
)

// Decision is the answer of the signed rules for one request.
type Decision struct {
	Allowed bool
	// Peer is the source device's name in the signed document.
	Peer   string
	Reason string
}

// AuthorizeFunc decides from the root-signed document whether the device
// behind remote may use the toolbox in mode. It is called for every
// request, so a withdrawn rule takes effect at once.
type AuthorizeFunc func(remote netip.Addr, mode Mode) Decision

// Request is a consent request shown to the person at the device.
type Request struct {
	ID   string    `json:"id"`
	Peer string    `json:"peer"`
	Kill bool      `json:"kill"`
	At   time.Time `json:"at"`
}

// ConsentFunc asks the person at the device; true means approved. It must
// return when ctx ends.
type ConsentFunc func(ctx context.Context, req Request) (bool, error)

// SessionInfo describes an approved session.
type SessionInfo struct {
	ID      string    `json:"id"`
	Peer    string    `json:"peer"`
	Kill    bool      `json:"kill"`
	Started time.Time `json:"started"`
	LastUse time.Time `json:"lastUse"`
}

// Indicator is the visible "remotely connected" notice of one session.
type Indicator interface{ Close() error }

// IndicatorFunc shows the notice; a session whose notice cannot be shown
// does not start.
type IndicatorFunc func(SessionInfo) (Indicator, error)

// LogEvent is one line of the device's support log.
type LogEvent struct {
	Kind   string    `json:"kind"`
	Peer   string    `json:"peer"`
	Detail string    `json:"detail,omitempty"`
	At     time.Time `json:"at"`
}

// Log event kinds.
const (
	EventStart    = "start"
	EventEnd      = "end"
	EventDenied   = "denied"
	EventRefused  = "refused"
	EventKill     = "kill"
	EventSnapshot = "snapshot"
)

// Defaults.
const (
	DefaultIdle           = 10 * time.Minute
	DefaultConsentTimeout = 60 * time.Second
	rateWindow            = time.Minute
	rateLimit             = 60
	maxKillBody           = 1 << 10
	reapInterval          = 5 * time.Second
)

// Config configures a Server. Authorize, Consent and Indicator are
// mandatory.
type Config struct {
	Authorize      AuthorizeFunc
	Consent        ConsentFunc
	Indicator      IndicatorFunc
	Collector      Collector
	OnEvent        func(LogEvent)
	Idle           time.Duration
	ConsentTimeout time.Duration
	Now            func() time.Time
	Logger         *slog.Logger
}

type session struct {
	info   SessionInfo
	remote netip.Addr
	ind    Indicator
}

// Server answers support requests on the tunnel.
type Server struct {
	cfg Config

	consentMu sync.Mutex // one consent question at a time

	mu       sync.Mutex
	sessions map[string]*session
	rate     map[string][]time.Time
}

// New checks cfg and returns a server.
func New(cfg Config) (*Server, error) {
	switch {
	case cfg.Authorize == nil:
		return nil, errors.New("support: yetkilendirme (Authorize) zorunlu")
	case cfg.Consent == nil:
		return nil, errors.New("support: hedefte onay (Consent) zorunlu")
	case cfg.Indicator == nil:
		return nil, errors.New("support: uzaktan bağlı göstergesi (Indicator) zorunlu")
	}
	if cfg.Collector == nil {
		cfg.Collector = System()
	}
	if cfg.Idle <= 0 {
		cfg.Idle = DefaultIdle
	}
	if cfg.ConsentTimeout <= 0 {
		cfg.ConsentTimeout = DefaultConsentTimeout
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	return &Server{cfg: cfg, sessions: map[string]*session{}, rate: map[string][]time.Time{}}, nil
}

// Serve answers requests on ln until ctx ends. A listener on every
// interface is refused: the toolbox only ever listens on a tunnel address.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	if ta, ok := ln.Addr().(*net.TCPAddr); ok && ta.IP.IsUnspecified() {
		return errors.New("support: bütün arayüzlerde dinlenmez; tünel adresi gerekir")
	}
	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      s.cfg.ConsentTimeout + collectTimeout + 15*time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 << 10,
		ErrorLog:          slog.NewLogLogger(s.cfg.Logger.Handler(), slog.LevelDebug),
	}
	done := make(chan struct{})
	go func() {
		t := time.NewTicker(reapInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				_ = srv.Close()
				close(done)
				return
			case <-t.C:
				s.reap()
			}
		}
	}()
	err := srv.Serve(ln)
	<-done
	s.EndAll("servis durdu")
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Handler is the HTTP handler; Serve uses it, tests may too.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/snapshot", s.handleSnapshot)
	mux.HandleFunc("POST /v1/kill", s.handleKill)
	mux.HandleFunc("POST /v1/end", s.handleEnd)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Cache-Control", "no-store")
		h.Set("Content-Security-Policy", "default-src 'none'")
		mux.ServeHTTP(w, r)
	})
}

// Sessions lists the approved sessions.
func (s *Server) Sessions() []SessionInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]SessionInfo, 0, len(s.sessions))
	for _, sess := range s.sessions {
		out = append(out, sess.info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Started.Before(out[j].Started) })
	return out
}

// EndAll ends every session (the local "disconnect" button) and returns
// how many ended.
func (s *Server) EndAll(reason string) int {
	s.mu.Lock()
	list := make([]*session, 0, len(s.sessions))
	for peer, sess := range s.sessions {
		list = append(list, sess)
		delete(s.sessions, peer)
	}
	s.mu.Unlock()
	for _, sess := range list {
		s.close(sess, reason)
	}
	return len(list)
}

func (s *Server) close(sess *session, reason string) {
	if sess.ind != nil {
		if err := sess.ind.Close(); err != nil {
			s.cfg.Logger.Warn("support indicator close failed", "peer", sess.info.Peer, "err", err)
		}
	}
	s.emit(EventEnd, sess.info.Peer, reason)
}

// reap ends idle sessions and sessions whose rule was withdrawn.
func (s *Server) reap() {
	now := s.cfg.Now()
	s.mu.Lock()
	var ended []*session
	var reasons []string
	for peer, sess := range s.sessions {
		reason := ""
		if now.Sub(sess.info.LastUse) > s.cfg.Idle {
			reason = "boşta kaldı"
		} else if d := s.cfg.Authorize(sess.remote, ModeRead); !d.Allowed || d.Peer != peer {
			reason = "kural geri çekildi"
		}
		if reason != "" {
			ended = append(ended, sess)
			reasons = append(reasons, reason)
			delete(s.sessions, peer)
		}
	}
	s.mu.Unlock()
	for i, sess := range ended {
		s.close(sess, reasons[i])
	}
}

func (s *Server) emit(kind, peer, detail string) {
	ev := LogEvent{Kind: kind, Peer: peer, Detail: detail, At: s.cfg.Now().UTC()}
	s.cfg.Logger.Info("support", "kind", kind, "peer", peer, "detail", detail)
	if s.cfg.OnEvent != nil {
		s.cfg.OnEvent(ev)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// admit authorizes the request, applies the rate limit and makes sure an
// approved session exists for the peer. It writes the error itself.
func (s *Server) admit(w http.ResponseWriter, r *http.Request, mode Mode) (string, bool) {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		writeErr(w, http.StatusForbidden, "kaynak adres okunamadı")
		return "", false
	}
	remote := ap.Addr().Unmap()
	d := s.cfg.Authorize(remote, mode)
	if !d.Allowed || d.Peer == "" {
		s.emit(EventDenied, d.Peer, string(mode)+": "+d.Reason)
		writeErr(w, http.StatusForbidden, "imzalı kurallar buna izin vermiyor")
		return "", false
	}
	if !s.allowRate(d.Peer) {
		writeErr(w, http.StatusTooManyRequests, "çok fazla istek; biraz bekleyin")
		return "", false
	}
	if err := s.ensureSession(r.Context(), d.Peer, remote, mode == ModeKill); err != nil {
		var se statusError
		if errors.As(err, &se) {
			writeErr(w, se.status, se.msg)
		} else {
			writeErr(w, http.StatusServiceUnavailable, "oturum açılamadı")
		}
		return "", false
	}
	return d.Peer, true
}

type statusError struct {
	status int
	msg    string
}

func (e statusError) Error() string { return e.msg }

func (s *Server) allowRate(peer string) bool {
	now := s.cfg.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	list := s.rate[peer][:0]
	for _, t := range s.rate[peer] {
		if now.Sub(t) < rateWindow {
			list = append(list, t)
		}
	}
	if len(list) >= rateLimit {
		s.rate[peer] = list
		return false
	}
	s.rate[peer] = append(list, now)
	if len(s.rate) > 1024 {
		for p, l := range s.rate {
			if len(l) == 0 || now.Sub(l[len(l)-1]) >= rateWindow {
				delete(s.rate, p)
			}
		}
	}
	return true
}

func (s *Server) current(peer string, kill bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := s.sessions[peer]
	if sess == nil || (kill && !sess.info.Kill) {
		return false
	}
	sess.info.LastUse = s.cfg.Now()
	return true
}

// ensureSession asks for consent when the peer has no approved session,
// or only a read session and wants to end a process, and opens the
// indicator before anything is collected.
func (s *Server) ensureSession(ctx context.Context, peer string, remote netip.Addr, kill bool) error {
	if s.current(peer, kill) {
		return nil
	}
	s.consentMu.Lock()
	defer s.consentMu.Unlock()
	if s.current(peer, kill) {
		return nil
	}
	req := Request{ID: newID(), Peer: peer, Kill: kill, At: s.cfg.Now().UTC()}
	cctx, cancel := context.WithTimeout(ctx, s.cfg.ConsentTimeout)
	ok, err := s.cfg.Consent(cctx, req)
	cancel()
	if err != nil || !ok {
		s.emit(EventRefused, peer, "onay verilmedi")
		return statusError{http.StatusForbidden, "cihazdaki kişi isteği onaylamadı"}
	}
	now := s.cfg.Now()
	s.mu.Lock()
	if sess := s.sessions[peer]; sess != nil {
		// A read session gains the kill permission; the indicator stays.
		sess.info.Kill = sess.info.Kill || kill
		sess.info.LastUse = now
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()
	info := SessionInfo{ID: req.ID, Peer: peer, Kill: kill, Started: now, LastUse: now}
	ind, err := s.cfg.Indicator(info)
	if err != nil {
		s.cfg.Logger.Warn("support indicator failed", "peer", peer, "err", err)
		s.emit(EventRefused, peer, "uzaktan bağlı göstergesi açılamadı")
		return statusError{http.StatusServiceUnavailable, "cihazda uzaktan bağlı göstergesi açılamadı; oturum başlatılmadı"}
	}
	s.mu.Lock()
	s.sessions[peer] = &session{info: info, remote: remote, ind: ind}
	s.mu.Unlock()
	s.emit(EventStart, peer, map[bool]string{false: "salt okunur", true: "süreç sonlandırma dahil"}[kill])
	return nil
}

func newID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func (s *Server) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	kind := r.URL.Query().Get("kind")
	if !ValidKind(kind) {
		writeErr(w, http.StatusBadRequest, "bilinmeyen tür")
		return
	}
	peer, ok := s.admit(w, r, ModeRead)
	if !ok {
		return
	}
	snap, err := Collect(r.Context(), s.cfg.Collector, kind, s.cfg.Now())
	if err != nil {
		msg := "bilgi toplanamadı"
		if errors.Is(err, ErrUnsupported) {
			msg = ErrUnsupported.Error()
		}
		s.cfg.Logger.Warn("support collect failed", "kind", kind, "err", err)
		writeErr(w, http.StatusServiceUnavailable, msg)
		return
	}
	s.emit(EventSnapshot, peer, kind)
	writeJSON(w, http.StatusOK, snap)
}

// KillRequest is the body of POST /v1/kill.
type KillRequest struct {
	PID  int    `json:"pid"`
	Name string `json:"name"`
}

func (s *Server) handleKill(w http.ResponseWriter, r *http.Request) {
	var req KillRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxKillBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || req.PID <= 0 || req.Name == "" || len(req.Name) > MaxNameLen {
		writeErr(w, http.StatusBadRequest, "istek geçersiz")
		return
	}
	peer, ok := s.admit(w, r, ModeKill)
	if !ok {
		return
	}
	if err := s.cfg.Collector.Kill(r.Context(), req.PID, req.Name); err != nil {
		switch {
		case errors.Is(err, ErrProtected):
			writeErr(w, http.StatusForbidden, ErrProtected.Error())
		case errors.Is(err, ErrNoProcess):
			writeErr(w, http.StatusNotFound, ErrNoProcess.Error())
		default:
			writeErr(w, http.StatusInternalServerError, "süreç sonlandırılamadı")
		}
		return
	}
	s.emit(EventKill, peer, fmt.Sprintf("%s (%d)", clean(req.Name, MaxNameLen), req.PID))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleEnd lets the helper end its own session at once. It needs no
// consent: it only gives something up.
func (s *Server) handleEnd(w http.ResponseWriter, r *http.Request) {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		writeErr(w, http.StatusForbidden, "kaynak adres okunamadı")
		return
	}
	d := s.cfg.Authorize(ap.Addr().Unmap(), ModeRead)
	if d.Peer == "" {
		writeErr(w, http.StatusForbidden, "imzalı kurallar buna izin vermiyor")
		return
	}
	s.mu.Lock()
	sess := s.sessions[d.Peer]
	delete(s.sessions, d.Peer)
	s.mu.Unlock()
	if sess != nil {
		s.close(sess, "yardım eden oturumu kapattı")
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
