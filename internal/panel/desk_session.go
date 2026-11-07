package panel

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"sync"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/peercred"
	"github.com/openscale/openscale/internal/trust"
)

// Desktop sign-in (W2, ADR-0195): the tray's one-time ticket becomes a
// session bound to the panel window process (#646), the duress
// passphrase of the panel sign-in (#592) and the tray's panic item.
//
// A ticket session is an automatic sign-in: it can view and make local
// changes, but it never starts the administrator mode (elevatedAt stays
// zero) and every root key signature still asks for the passphrase or
// the hardware key.

// deskState is the per-server desktop sign-in state (a field of g5State).
type deskState struct {
	once sync.Once
	bind *peercred.WindowBinding
	// bindOverride replaces the binding in tests.
	bindOverride windowBinder
	// lockSource replaces the sign-in lockout source in tests (lockout.go).
	lockSource func(*http.Request) string
}

// windowBinder is the part of peercred.WindowBinding the panel uses.
type windowBinder interface {
	Bind(session, remote, local string) (int, error)
	Check(session, remote, local string) error
	Forget(session string)
}

// windowBinding returns the binding of the window processes, nil when
// this program's path cannot be read (then no session is bound).
func (s *Server) windowBinding() windowBinder {
	d := &s.g5.desk
	if d.bindOverride != nil {
		return d.bindOverride
	}
	d.once.Do(func() {
		policy, err := peercred.SelfProgramPolicy()
		if err != nil {
			s.logger.Warn("panel window binding unavailable", "error", err.Error())
			return
		}
		d.bind = peercred.NewWindowBinding(policy)
	})
	if d.bind == nil {
		return nil
	}
	return d.bind
}

// localAddrOf is the panel's side of the request's connection.
func localAddrOf(r *http.Request) string {
	if a, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok && a != nil {
		return a.String()
	}
	return ""
}

// loopbackRemote reports whether the request comes from this computer.
func loopbackRemote(r *http.Request) bool {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	if _, remote := remoteDevice(r); remote {
		return false
	}
	return ap.Addr().Unmap().IsLoopback()
}

// windowCheck enforces #646 for a session; unbound sessions pass.
func (s *Server) windowCheck(r *http.Request, id string) bool {
	b := s.windowBinding()
	if b == nil {
		return true
	}
	if err := b.Check(id, r.RemoteAddr, localAddrOf(r)); err != nil {
		s.logger.Warn("panel session refused: bound to another window")
		b.Forget(id)
		return false
	}
	return true
}

// forgetWindow drops the binding of a signed-out session.
func (s *Server) forgetWindow(id string) {
	if b := s.windowBinding(); b != nil && id != "" {
		b.Forget(id)
	}
}

// openSession creates a full session bound to this request's context
// (#675); setup marks it before the cookie is set. It returns "" after
// answering.
func (s *Server) openSession(w http.ResponseWriter, r *http.Request, setup func(*g5Session)) string {
	id, err := s.auth.create()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Oturum açılamadı.")
		return ""
	}
	s.auth.mu.Lock()
	sess := s.auth.sessions[id]
	s.auth.mu.Unlock()
	if sess == nil {
		writeError(w, http.StatusInternalServerError, "Oturum açılamadı.")
		return ""
	}
	rc := contextOf(r)
	sess.g5.mu.Lock()
	sess.g5.bound, sess.g5.device, sess.g5.addr, sess.g5.webview = true, rc.device, rc.addr, rc.webview
	setup(&sess.g5)
	sess.g5.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: id, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
	return id
}

// startTicketSession opens the automatic session of a redeemed ticket,
// bound on Windows to the window process that made the request (#646).
// It never starts the administrator mode. It returns false after
// answering.
func (s *Server) startTicketSession(w http.ResponseWriter, r *http.Request) bool {
	id := s.openSession(w, r, func(g *g5Session) { g.viaTray = true })
	if id == "" {
		return false
	}
	if b := s.windowBinding(); b != nil {
		// A browser sign-in (not an OpenScale window) stays unbound.
		if pid, err := b.Bind(id, r.RemoteAddr, localAddrOf(r)); err != nil {
			s.logger.Warn("panel window binding failed", "error", err.Error())
		} else if pid != 0 {
			s.logger.Info("panel session bound to the window process")
		}
	}
	return true
}

// signInKind classifies the sign-in passphrase (#592): the duress check
// runs only where a duress passphrase is set, and then both checks always
// run so the time taken does not tell them apart.
// The error is set for every result other than LoginRoot and LoginDuress.
func signInKind(n *admin.Network, pass []byte) (admin.LoginKind, error) {
	if !admin.DuressConfigured(n.Dir()) {
		if err := n.CheckPassphrase(pass); err != nil {
			return admin.LoginWrong, err
		}
		return admin.LoginRoot, nil
	}
	switch k := n.CheckLogin(pass); k {
	case admin.LoginRoot, admin.LoginDuress:
		return k, nil
	}
	return admin.LoginWrong, trust.ErrWrongPassphrase
}

// duressSignIn handles the duress passphrase: the root key is overwritten
// and removed, the silent alarm is queued, and the sign-in looks like a
// normal one; the session it opens cannot change anything.
func (s *Server) duressSignIn(w http.ResponseWriter, r *http.Request, n *admin.Network) {
	networkID := ""
	if doc, err := n.Document(); err == nil && doc != nil {
		networkID = doc.NetworkID
	}
	// Detached from the request: a closed connection must not stop it.
	res := admin.TriggerDuress(context.WithoutCancel(r.Context()), n.Dir(), nil, nil, networkID, s.now())
	// Same wording as an ordinary sign-in in the log.
	s.logger.Info("panel sign-in")
	s.logger.Debug("duress sign-in", "wiped", len(res.Wiped), "alarm_queued", res.AlarmQueued)
	now := s.now()
	if s.openSession(w, r, func(g *g5Session) { g.duress, g.elevatedAt = true, now }) == "" {
		return
	}
	writeJSON(w, http.StatusOK, loginResponse{OK: true})
}

// duressReadOnlyMessage answers every change of a duress session; it
// reads like the ordinary read-only refusal.
const duressReadOnlyMessage = "Panel salt okunur modda; değişiklik yapılamaz."

// isDuress reports a session opened with the duress passphrase.
func (g *g5Session) isDuress() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.duress
}

// ---- tray panic (panel side of the G1 panic button) ----

// TrayPanicRequest is the tray's panic item: the prepared lockdown
// document is published. The passphrase opens the sealed document; the
// tray reads it on the secure desktop.
type TrayPanicRequest struct {
	Passphrase string `json:"passphrase"`
}

func (s *Server) deskRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/app/tray/panic", s.handleTrayPanic)
}

func (s *Server) handleTrayPanic(w http.ResponseWriter, r *http.Request) {
	if !s.trayAuthorized(w, r) {
		return
	}
	n := s.network()
	if n == nil {
		writeError(w, http.StatusConflict, "Bu bilgisayar ağın yöneticisi değil; panik düğmesi yönetici bilgisayarda çalışır.")
		return
	}
	var req TrayPanicRequest
	if !decodeBody(w, r, &req) {
		return
	}
	pass := []byte(req.Passphrase)
	defer clear(pass)
	if len(pass) == 0 {
		writeError(w, http.StatusBadRequest, "Parola gerekli.")
		return
	}
	// The panic button has its own counter: no other path can lock it.
	release, ok := s.auth.reserveLoginAttempt(lockSourceTray)
	if !ok {
		writeError(w, http.StatusTooManyRequests, "Çok fazla yanlış parola denemesi. 5 dakika sonra tekrar dene.")
		return
	}
	defer release()
	_, doc, err := n.PublishEmergency(admin.EmergencyLockdown, "", pass, s.now())
	switch {
	case errors.Is(err, trust.ErrWrongPassphrase):
		s.failLogin(w, lockSourceTray, err)
		return
	case errors.Is(err, admin.ErrNoEmergency):
		writeError(w, http.StatusNotFound, "Hazır kilitleme belgesi yok. Hazırlamak için: openscale admin emergency prepare")
		return
	case errors.Is(err, admin.ErrEmergencyOutdated):
		writeError(w, http.StatusConflict, "Ağ hazır kilitleme belgesinden ileri gitti; belgeyi yeniden hazırlayın.")
		return
	case err != nil:
		s.fail(w, err)
		return
	}
	s.logger.Warn("panic: lockdown document published from the tray", "version", doc.Version)
	writeJSON(w, http.StatusOK, map[string]any{"schema": 1, "version": doc.Version})
}
