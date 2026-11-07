package panel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/trust"
)

// YubiKey administrator mode through the tray (ADR-0223, with #678).
//
// The tray (user's process) watches the smart-card readers, asks the PIN
// itself and opens admin.TokenSession there; the PIN and the token never
// reach this service. Over the app-token local API (loopback, elevated
// caller, same OpenScale program, #645) the tray reports only the
// session's state (open, role, key fingerprint, end) and serves signing
// requests: the panel sends the exact document payload, the tray checks it,
// asks the user and lets the token sign. The panel then verifies the
// signature against the root key like any other hardware signature
// (admin.Network.CommitWith).
//
// Fail closed: a state not refreshed within trayAdminStale counts as
// closed; a closed session drops the #678 elevation of every panel session.

const (
	trayAdminStale    = 15 * time.Second
	trayAdminLongPoll = 25 * time.Second
	trayAdminSignWait = 90 * time.Second
	maxTrayAdminField = 128
)

// TrayAdminState is what the tray reports (POST /api/app/tray/admin-mode)
// and, without the internal fields, what the panel shows.
type TrayAdminState struct {
	// Open: a token session is open in the tray.
	Open bool `json:"open"`
	// Offer: a token holding a root or administrator key is plugged in but
	// no session is open (the tray offers "Yönetici kipini aç").
	Offer bool `json:"offer"`
	// Role is admin.SessionRoot or admin.SessionAdmin.
	Role string `json:"role,omitempty"`
	// Name is the administrator grant's name (admin role).
	Name string `json:"name,omitempty"`
	// Key is admin.KeyFingerprint of the token key.
	Key       string    `json:"key,omitempty"`
	Reader    string    `json:"reader,omitempty"`
	Started   time.Time `json:"started,omitzero"`
	Ends      time.Time `json:"ends,omitzero"`
	IdleUntil time.Time `json:"idle_until,omitzero"`
	// Reason is why the last session ended (Turkish).
	Reason string `json:"reason,omitempty"`
}

// validate bounds the tray's report.
func (st *TrayAdminState) validate() error {
	for _, f := range []string{st.Role, st.Name, st.Key, st.Reader, st.Reason} {
		if len(f) > maxTrayAdminField {
			return errors.New("field too long")
		}
	}
	if st.Open {
		if st.Role != admin.SessionRoot && st.Role != admin.SessionAdmin {
			return errors.New("unknown role")
		}
		if st.Ends.IsZero() {
			return errors.New("open session without an end")
		}
	}
	if st.Key != "" {
		if _, err := hex.DecodeString(st.Key); err != nil {
			return errors.New("bad key fingerprint")
		}
	}
	return nil
}

// TrayAdminTrust is what the tray needs to open a session: public data.
type TrayAdminTrust struct {
	NetworkID string   `json:"network_id"`
	Root      []byte   `json:"root"`
	Revoked   []string `json:"revoked,omitempty"`
}

// TraySignRequest is one signing request for the tray's token session.
type TraySignRequest struct {
	ID      string    `json:"id"`
	Context string    `json:"context"`
	Payload []byte    `json:"payload"`
	Version uint64    `json:"version"`
	Summary string    `json:"summary"`
	Expires time.Time `json:"expires"`
}

// TraySignResult is the tray's answer.
type TraySignResult struct {
	ID        string `json:"id"`
	Signature []byte `json:"signature,omitempty"`
	// Error is a Turkish reason (user said no, token pulled, wrong PIN).
	Error string `json:"error,omitempty"`
}

type traySignJob struct {
	req  TraySignRequest
	done chan TraySignResult
}

// trayAdminRelay is the panel side of the channel.
type trayAdminRelay struct {
	mu         sync.Mutex
	state      TrayAdminState
	reportedAt time.Time
	queue      chan *traySignJob
	jobs       map[string]*traySignJob
}

var trayAdminRelays sync.Map // *Server -> *trayAdminRelay

func (s *Server) trayAdmin() *trayAdminRelay {
	if v, ok := trayAdminRelays.Load(s); ok {
		return v.(*trayAdminRelay)
	}
	v, _ := trayAdminRelays.LoadOrStore(s, &trayAdminRelay{queue: make(chan *traySignJob, 1), jobs: map[string]*traySignJob{}})
	return v.(*trayAdminRelay)
}

// current returns the state, closed when the tray went quiet.
func (r *trayAdminRelay) current(now time.Time) (TrayAdminState, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.reportedAt.IsZero() || now.Sub(r.reportedAt) > trayAdminStale || now.Before(r.reportedAt) {
		return TrayAdminState{}, false
	}
	st := r.state
	if st.Open && (!now.Before(st.Ends) || (!st.IdleUntil.IsZero() && !now.Before(st.IdleUntil))) {
		st.Open = false
	}
	return st, true
}

// report stores the tray's state; it returns true when an open session
// just closed.
func (r *trayAdminRelay) report(st TrayAdminState, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	closed := r.state.Open && !st.Open
	r.state, r.reportedAt = st, now
	if !st.Open {
		// Requests waiting for a closed session fail at once.
		for id, j := range r.jobs {
			delete(r.jobs, id)
			j.done <- TraySignResult{ID: id, Error: "Yönetici oturumu kapandı."}
		}
	}
	return closed
}

var errTrayAdminClosed error = trayRelayError("YubiKey yönetici oturumu açık değil; tepside \"Yönetici kipini aç\" seçeneğini kullanın veya parolayla imzalayın.")

// sign sends one request to the tray and waits for the token.
func (r *trayAdminRelay) sign(ctx context.Context, req TraySignRequest, now time.Time) ([]byte, error) {
	if st, ok := r.current(now); !ok || !st.Open {
		return nil, errTrayAdminClosed
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	req.ID = hex.EncodeToString(id)
	req.Expires = now.Add(trayAdminSignWait)
	job := &traySignJob{req: req, done: make(chan TraySignResult, 1)}
	r.mu.Lock()
	r.jobs[req.ID] = job
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		delete(r.jobs, req.ID)
		r.mu.Unlock()
	}()
	select {
	case r.queue <- job:
	default:
		return nil, trayRelayError("Başka bir YubiKey imzası bekleniyor; önce onu tamamlayın.")
	}
	t := time.NewTimer(trayAdminSignWait)
	defer t.Stop()
	select {
	case res := <-job.done:
		if res.Error != "" {
			return nil, trayRelayError(res.Error)
		}
		return res.Signature, nil
	case <-t.C:
		r.drain(job)
		return nil, trayRelayError("YubiKey imzası zaman aşımına uğradı.")
	case <-ctx.Done():
		r.drain(job)
		return nil, ctx.Err()
	}
}

// drain removes job from the queue when the tray never took it.
func (r *trayAdminRelay) drain(job *traySignJob) {
	select {
	case j := <-r.queue:
		if j != job {
			select {
			case r.queue <- j:
			default:
			}
		}
	default:
	}
}

// next waits for a request (long poll).
func (r *trayAdminRelay) next(ctx context.Context, wait time.Duration) (*TraySignRequest, bool) {
	t := time.NewTimer(wait)
	defer t.Stop()
	for {
		select {
		case job := <-r.queue:
			r.mu.Lock()
			_, live := r.jobs[job.req.ID]
			r.mu.Unlock()
			if !live {
				continue
			}
			req := job.req
			return &req, true
		case <-t.C:
			return nil, false
		case <-ctx.Done():
			return nil, false
		}
	}
}

// deliver hands the tray's answer to the waiting request.
func (r *trayAdminRelay) deliver(res TraySignResult) bool {
	r.mu.Lock()
	job, ok := r.jobs[res.ID]
	delete(r.jobs, res.ID)
	r.mu.Unlock()
	if !ok {
		return false
	}
	job.done <- res
	return true
}

// trayRelayError is a Turkish message for the owner.
type trayRelayError string

func (e trayRelayError) Error() string { return string(e) }

// tokenChange is the signing step of Server.change for "YubiKey ile
// imzala" (signRequest.Token).
func (s *Server) tokenChange(w http.ResponseWriter, plan *admin.Plan, resp changeResponse) {
	lines := resp.Lines
	if len(lines) > 12 {
		lines = append(lines[:12:12], "...")
	}
	err := s.commitWithTrayToken(context.Background(), plan, strings.Join(lines, "\n"))
	var te trayRelayError
	switch {
	case errors.As(err, &te):
		writeErrorCode(w, http.StatusConflict, string(te), err)
		return
	case err != nil:
		s.fail(w, err)
		return
	}
	s.logger.Info("network document signed with the tray's token session", "version", plan.Next.Version)
	writeJSON(w, http.StatusOK, resp)
}

// relaySigner is a trust.DigestSigner that signs exactly one payload
// through the tray. SignMessage refuses any other message.
type relaySigner struct {
	ctx     context.Context
	s       *Server
	pub     ed25519.PublicKey
	context string
	payload []byte
	version uint64
	summary string
}

func (p *relaySigner) PublicKey() ed25519.PublicKey { return p.pub }

func (p *relaySigner) SignMessage(msg []byte) ([]byte, error) {
	want, err := trust.DigestMessage(p.context, p.payload)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(want, msg) {
		return nil, errors.New("unexpected message for the token")
	}
	return p.s.trayAdmin().sign(p.ctx, TraySignRequest{Context: p.context, Payload: p.payload, Version: p.version, Summary: p.summary}, p.s.now())
}

// commitWithTrayToken signs plan with the root key on the token through
// the tray's session (the "YubiKey ile imzala" choice of the sign dialog).
func (s *Server) commitWithTrayToken(ctx context.Context, plan *admin.Plan, summary string) error {
	n := s.network()
	if n == nil {
		return errors.New("Bu bilgisayar ağın yöneticisi değil.")
	}
	st, ok := s.trayAdmin().current(s.now())
	if !ok || !st.Open {
		return errTrayAdminClosed
	}
	if st.Role != admin.SessionRoot {
		return trayRelayError("Takılı jeton kök anahtarı taşımıyor; ağ belgesi kök anahtarla imzalanır.")
	}
	payload, err := trust.DocumentPayload(plan.Next)
	if err != nil {
		return err
	}
	signer := &relaySigner{ctx: ctx, s: s, pub: n.RootPublicKey(), context: trust.DocumentContext, payload: payload, version: plan.Next.Version, summary: summary}
	return n.CommitWith(plan, signer)
}

// ---- routes ----

func (s *Server) trayAdminRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/admin-mode/token", s.requireSession(s.handleTokenModeStatus))
	mux.HandleFunc("POST /api/app/tray/admin-mode", s.handleTrayAdminReport)
	mux.HandleFunc("GET /api/app/tray/admin-mode/trust", s.handleTrayAdminTrust)
	mux.HandleFunc("GET /api/app/tray/admin-mode/next", s.handleTrayAdminNext)
	mux.HandleFunc("POST /api/app/tray/admin-mode/result", s.handleTrayAdminResult)
}

// TokenModeStatus is the panel's view (GET /api/admin-mode/token).
type TokenModeStatus struct {
	// Tray: the tray reported within the last 15 seconds.
	Tray bool `json:"tray"`
	TrayAdminState
	// CanSign: a root session is open, "YubiKey ile imzala" works.
	CanSign bool `json:"can_sign"`
	LeftSec int  `json:"left_sec"`
}

func (s *Server) handleTokenModeStatus(w http.ResponseWriter, _ *http.Request) {
	now := s.now()
	st, ok := s.trayAdmin().current(now)
	out := TokenModeStatus{Tray: ok, TrayAdminState: st}
	if st.Open {
		end := st.Ends
		if !st.IdleUntil.IsZero() && st.IdleUntil.Before(end) {
			end = st.IdleUntil
		}
		out.LeftSec = int(end.Sub(now) / time.Second)
		out.CanSign = st.Role == admin.SessionRoot && s.network() != nil
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleTrayAdminReport(w http.ResponseWriter, r *http.Request) {
	if !s.trayAuthorized(w, r) {
		return
	}
	var st TrayAdminState
	if !decodeBody(w, r, &st) {
		return
	}
	if err := st.validate(); err != nil {
		writeError(w, http.StatusBadRequest, "Yönetici kipi durumu geçersiz.")
		return
	}
	st.Reason = strings.TrimSpace(st.Reason)
	if s.trayAdmin().report(st, s.now()) {
		// Token pulled, idle or expired: the #678 elevation ends too.
		s.auth.dropElevation()
		s.logger.Info("token administrator session closed in the tray", "reason", st.Reason)
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleTrayAdminTrust(w http.ResponseWriter, r *http.Request) {
	if !s.trayAuthorized(w, r) {
		return
	}
	n := s.network()
	if n == nil {
		writeError(w, http.StatusConflict, "Bu bilgisayar ağın yöneticisi değil.")
		return
	}
	doc, err := n.Document()
	if err != nil || doc == nil {
		writeError(w, http.StatusConflict, "Ağ belgesi okunamadı.")
		return
	}
	writeJSON(w, http.StatusOK, TrayAdminTrust{NetworkID: doc.NetworkID, Root: n.RootPublicKey(), Revoked: doc.RevokedAdmins})
}

func (s *Server) handleTrayAdminNext(w http.ResponseWriter, r *http.Request) {
	if !s.trayAuthorized(w, r) {
		return
	}
	req, ok := s.trayAdmin().next(r.Context(), trayAdminLongPoll)
	if !ok {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeJSON(w, http.StatusOK, req)
}

func (s *Server) handleTrayAdminResult(w http.ResponseWriter, r *http.Request) {
	if !s.trayAuthorized(w, r) {
		return
	}
	var res TraySignResult
	if !decodeBody(w, r, &res) {
		return
	}
	if len(res.ID) != 32 || len(res.Error) > 512 || (res.Error == "" && len(res.Signature) != ed25519.SignatureSize) {
		writeError(w, http.StatusBadRequest, "İmza yanıtı geçersiz.")
		return
	}
	if !s.trayAdmin().deliver(res) {
		writeError(w, http.StatusNotFound, "Bu imza isteği artık beklenmiyor.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
