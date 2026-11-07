package panel

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/rdesk"
	"github.com/openscale/openscale/internal/sshclient"
	"golang.org/x/net/websocket"
)

// Terminal to a Linux device's own OpenSSH through the tunnel (ADR-0203).
//
// The panel opens the terminal in two steps. POST /api/ssh/open (session,
// CSRF token, Origin) names the device and the account and returns a
// one-time ticket that is valid for a minute. The browser then opens the
// WebSocket /api/ssh/ws?ticket=...; the handshake checks the Origin, the
// session cookie and that the ticket belongs to that session. The first
// message carries the password, which never appears in a URL or a log.
// Output goes to the browser as binary messages; keystrokes and window
// sizes come back as small JSON text messages. Only this computer's panel
// serves the terminal: the remote panel refuses it.

const (
	sshTicketLife   = time.Minute
	maxSSHTickets   = 16
	sshMaxMessage   = 64 << 10
	sshAuthTimeout  = 2 * time.Minute
	sshKnownHosts   = "ssh_known_hosts.json"
	sshDefaultPort  = 22
	sshOutputBuffer = 32 << 10
)

type sshTicket struct {
	sessionID string
	addr      netip.AddrPort
	host      string
	user      string
	until     time.Time
}

// SetSSHResolver replaces how a device name becomes its tunnel address
// (default: the network document of this computer).
func (s *Server) SetSSHResolver(resolve func(name string) (netip.Addr, bool)) {
	s.g5.mu.Lock()
	s.g5.sshResolve = resolve
	s.g5.mu.Unlock()
}

func (s *Server) resolveDevice(name string) (netip.Addr, bool) {
	s.g5.mu.Lock()
	resolve := s.g5.sshResolve
	s.g5.mu.Unlock()
	if resolve != nil {
		return resolve(name)
	}
	n := s.network()
	if n == nil {
		return netip.Addr{}, false
	}
	doc, err := n.Document()
	if err != nil {
		return netip.Addr{}, false
	}
	d, ok := doc.DeviceByName(name)
	if !ok || !d.IPv4.IsValid() {
		return netip.Addr{}, false
	}
	return d.IPv4, true
}

// sshGuard slows down password guessing through the panel (#665 applied
// to the terminal); keyed by target.
var sshGuard = rdesk.NewLoginGuard(rdesk.LoginGuardConfig{})

func (s *Server) knownHosts() (*sshclient.KnownHosts, error) {
	dir := s.panelDir()
	if dir == "" {
		return nil, errors.New("bu bilgisayarda yönetilen bir ağ yok")
	}
	return sshclient.OpenKnownHosts(filepath.Join(dir, sshKnownHosts)), nil
}

func (s *Server) g5SSHRoutes(mux *http.ServeMux) {
	write := func(h http.HandlerFunc) http.HandlerFunc {
		return s.requireSession(s.requireCSRF(s.requireWritable(s.localOnly(h))))
	}
	mux.HandleFunc("POST /api/ssh/open", write(s.handleSSHOpen))
	mux.HandleFunc("GET /api/ssh/ws", s.handleSSHSocket)
	mux.HandleFunc("GET /api/ssh/hostkeys", s.requireSession(s.localOnly(s.handleSSHHostKeys)))
	mux.HandleFunc("POST /api/ssh/hostkeys/forget", write(s.handleSSHForget))
}

type sshOpenRequest struct {
	Device string `json:"device"`
	Port   int    `json:"port,omitempty"`
	User   string `json:"user"`
}

func (s *Server) handleSSHOpen(w http.ResponseWriter, r *http.Request) {
	var req sshOpenRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if req.Port == 0 {
		req.Port = sshDefaultPort
	}
	if req.Port < 1 || req.Port > 65535 || req.User == "" || len(req.User) > 64 || strings.ContainsAny(req.User, " /\\:\x00") {
		writeError(w, http.StatusBadRequest, "Cihaz, port veya kullanıcı adı geçersiz.")
		return
	}
	addr, ok := s.resolveDevice(req.Device)
	if !ok {
		writeError(w, http.StatusNotFound, "Cihaz ağ belgesinde bulunamadı.")
		return
	}
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "Oturum yok.")
		return
	}
	ticket, err := randomToken(s.random)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Bilet üretilemedi.")
		return
	}
	now := s.now()
	s.g5.mu.Lock()
	if s.g5.tickets == nil {
		s.g5.tickets = map[string]*sshTicket{}
	}
	for k, t := range s.g5.tickets {
		if !now.Before(t.until) {
			delete(s.g5.tickets, k)
		}
	}
	if len(s.g5.tickets) >= maxSSHTickets {
		s.g5.mu.Unlock()
		writeError(w, http.StatusTooManyRequests, "Çok fazla açık terminal isteği.")
		return
	}
	s.g5.tickets[ticket] = &sshTicket{sessionID: c.Value, addr: netip.AddrPortFrom(addr, uint16(req.Port)), host: req.Device, user: req.User, until: now.Add(sshTicketLife)}
	s.g5.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"ticket": ticket, "expires_sec": int(sshTicketLife / time.Second), "address": addr.String()})
}

// sshSessionCheck is how often an open terminal checks that its panel
// session still exists and the panel is not locked.
const sshSessionCheck = 5 * time.Second

// alive reports whether the session exists, without counting the check as
// use (lookup would keep an idle session alive).
func (a *auth) alive(id string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pruneLocked()
	sess, ok := a.sessions[id]
	return ok && !sess.g5.isPending()
}

// takeTicket returns and forgets a ticket of the session id.
func (s *Server) takeTicket(ticket, sessionID string) (*sshTicket, bool) {
	s.g5.mu.Lock()
	defer s.g5.mu.Unlock()
	t, ok := s.g5.tickets[ticket]
	delete(s.g5.tickets, ticket)
	if !ok || t.sessionID != sessionID || !s.now().Before(t.until) {
		return nil, false
	}
	return t, true
}

// wsOriginOK checks the WebSocket's Origin like sameOrigin does for POST.
func (s *Server) wsOriginOK(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	u, err := url.Parse(origin)
	return origin != "" && err == nil && u.Scheme == "http" && s.allowedHost(u.Host)
}

func (s *Server) handleSSHSocket(w http.ResponseWriter, r *http.Request) {
	if _, remote := remoteDevice(r); remote {
		writeError(w, http.StatusForbidden, "Terminal uzak panelden açılamaz.")
		return
	}
	if !s.wsOriginOK(r) {
		writeError(w, http.StatusForbidden, "İstek kaynağı doğrulanamadı.")
		return
	}
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		writeError(w, http.StatusUnauthorized, "Oturum yok.")
		return
	}
	if _, ok := s.sessionFrom(r); !ok {
		writeError(w, http.StatusUnauthorized, "Oturum yok veya süresi doldu.")
		return
	}
	t, ok := s.takeTicket(r.URL.Query().Get("ticket"), c.Value)
	if !ok {
		writeError(w, http.StatusForbidden, "Terminal bileti geçersiz veya süresi doldu.")
		return
	}
	srv := websocket.Server{
		// Origin and session were checked above; the library's own
		// check would only repeat the Origin test.
		Handshake: func(*websocket.Config, *http.Request) error { return nil },
		Handler:   func(ws *websocket.Conn) { s.bridgeSSH(r.Context(), ws, t) },
	}
	srv.ServeHTTP(w, r)
}

// wsMessage is a text message in either direction.
type wsMessage struct {
	Type        string `json:"type"`
	Data        string `json:"data,omitempty"`
	Cols        int    `json:"cols,omitempty"`
	Rows        int    `json:"rows,omitempty"`
	Code        string `json:"code,omitempty"`
	Message     string `json:"message,omitempty"`
	Status      string `json:"status,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Pinned      string `json:"pinned,omitempty"`
}

// wsAuth is the first message: the password (base64) and terminal size.
type wsAuth struct {
	Type     string `json:"type"`
	Password []byte `json:"password"`
	Cols     int    `json:"cols"`
	Rows     int    `json:"rows"`
}

func sendWS(ws *websocket.Conn, mu *sync.Mutex, m wsMessage) {
	b, _ := json.Marshal(m)
	mu.Lock()
	_ = websocket.Message.Send(ws, string(b))
	mu.Unlock()
}

func hostStatus(st sshclient.HostKeyStatus) string {
	switch st {
	case sshclient.HostKeyPinned:
		return "pinned"
	case sshclient.HostKeyCertified:
		return "certified"
	}
	return "known"
}

func (s *Server) bridgeSSH(ctx context.Context, ws *websocket.Conn, t *sshTicket) {
	defer ws.Close()
	ws.MaxPayloadBytes = sshMaxMessage
	var wmu sync.Mutex
	fail := func(code, msg string) { sendWS(ws, &wmu, wsMessage{Type: "error", Code: code, Message: msg}) }
	key := t.addr.Addr().String()
	if _, blocked := sshGuard.Blocked(key); blocked {
		fail("blocked", "Çok fazla hatalı parola; bu cihaz için bir süre bekleyin.")
		return
	}
	_ = ws.SetReadDeadline(time.Now().Add(sshAuthTimeout))
	// The password arrives base64 encoded so it decodes into a byte slice
	// that can be wiped; it never becomes a string here.
	var first []byte
	if err := websocket.Message.Receive(ws, &first); err != nil {
		return
	}
	var auth wsAuth
	err := json.Unmarshal(first, &auth)
	wipe(first)
	if err != nil || auth.Type != "auth" || len(auth.Password) == 0 {
		wipe(auth.Password)
		fail("bad_request", "İlk ileti parola olmalı.")
		return
	}
	pw := auth.Password
	kh, err := s.knownHosts()
	if err != nil {
		wipe(pw)
		fail("unavailable", err.Error())
		return
	}
	client, err := sshclient.Dial(ctx, sshclient.Config{
		Addr: t.addr, HostName: t.host + ":" + strconv.Itoa(int(t.addr.Port())), User: t.user, KnownHosts: kh,
		Password: func() ([]byte, error) { return pw, nil },
	})
	wipe(pw)
	var changed *sshclient.HostKeyChangedError
	switch {
	case errors.As(err, &changed):
		s.logger.Warn("SSH host key changed; terminal refused", "device", t.host)
		sendWS(ws, &wmu, wsMessage{Type: "error", Code: "host_key_changed", Message: "Sunucu anahtarı değişti; ortadaki saldırı olabilir. Beklenen bir değişiklikse kaydı silip yeniden deneyin.",
			Pinned: changed.Pinned, Fingerprint: changed.Received})
		return
	case errors.Is(err, sshclient.ErrAuth):
		delay, _ := sshGuard.Failure(key)
		time.Sleep(delay)
		fail("auth_failed", "Kullanıcı adı veya parola kabul edilmedi.")
		return
	case err != nil:
		fail("connect_failed", "Cihaza bağlanılamadı.")
		return
	}
	defer client.Close()
	sshGuard.Success(key)
	sendWS(ws, &wmu, wsMessage{Type: "hostkey", Status: hostStatus(client.Host.Status), Fingerprint: client.Host.Fingerprint})
	sh, err := client.Shell("xterm-256color", auth.Cols, auth.Rows)
	if err != nil {
		fail("shell_failed", "Kabuk açılamadı.")
		return
	}
	defer sh.Close()
	s.logger.Info("SSH terminal opened from the panel", "device", t.host)
	sendWS(ws, &wmu, wsMessage{Type: "ready"})
	_ = ws.SetReadDeadline(time.Time{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, sshOutputBuffer)
		for {
			n, err := sh.Read(buf)
			if n > 0 {
				wmu.Lock()
				werr := websocket.Message.Send(ws, buf[:n])
				wmu.Unlock()
				if werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	go func() {
		for {
			var msg string
			if err := websocket.Message.Receive(ws, &msg); err != nil {
				_ = sh.Close()
				return
			}
			var m wsMessage
			if json.Unmarshal([]byte(msg), &m) != nil {
				continue
			}
			switch m.Type {
			case "data":
				if _, err := io.WriteString(sh, m.Data); err != nil {
					return
				}
			case "resize":
				_ = sh.Resize(m.Cols, m.Rows)
			}
		}
	}()
	// The terminal ends with the panel session: sign-out, session expiry
	// and the idle lock (#661) close it too.
	check := time.NewTicker(sshSessionCheck)
	defer check.Stop()
wait:
	for {
		select {
		case <-done:
			break wait
		case <-sh.Done():
			<-done
			break wait
		case <-ctx.Done():
			break wait
		case <-check.C:
			if !s.auth.alive(t.sessionID) || s.idle().lockedNow(s.now()) {
				s.logger.Info("SSH terminal closed with the panel session", "device", t.host)
				break wait
			}
		}
	}
	sendWS(ws, &wmu, wsMessage{Type: "exit"})
	s.logger.Info("SSH terminal closed", "device", t.host)
}

func (s *Server) handleSSHHostKeys(w http.ResponseWriter, _ *http.Request) {
	kh, err := s.knownHosts()
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	list, err := kh.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Kayıtlı sunucu anahtarları okunamadı.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"hosts": list})
}

type sshForgetRequest struct {
	Host string `json:"host"`
}

func (s *Server) handleSSHForget(w http.ResponseWriter, r *http.Request) {
	var req sshForgetRequest
	if !decodeBody(w, r, &req) {
		return
	}
	kh, err := s.knownHosts()
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	ok, err := kh.Forget(req.Host)
	if err != nil || !ok {
		writeError(w, http.StatusNotFound, "Kayıt bulunamadı.")
		return
	}
	s.logger.Warn("SSH host key forgotten by the owner", "host", req.Host)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
