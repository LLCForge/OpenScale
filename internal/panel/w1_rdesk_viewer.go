package panel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"image/jpeg"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/openscale/openscale/internal/rdesk"
	"github.com/openscale/openscale/internal/trust"
	"golang.org/x/net/websocket"
)

// Remote desktop viewer in the panel (W1, ADR-0198, ADR-0201).
//
// POST /api/app/rdesk/connect (session, CSRF token, Origin, local panel
// only) names the device, the mode, the channels the person wants for this
// session and, for a target that asks for it, an account of the target's
// operating system. The panel dials the device's rdesk server itself, so a
// wrong password, a block or a refusal by the signed rule is answered on
// this request. The open session waits a minute for its viewer under a
// one-time ticket; the viewer page (/remote-viewer/#t=...) opens the
// WebSocket /api/rdesk/ws?ticket=..., whose handshake checks the Origin,
// the session cookie and that the ticket belongs to that session. Frames
// go to the browser as JPEG binary messages; pointer, wheel and keys come
// back as small JSON messages. The target still checks every channel
// against its own rules: asking here only narrows a session, it never
// widens one.

const (
	rdeskViewerLife    = time.Minute
	maxRDeskViewers    = 4
	rdeskDialTimeout   = 3 * time.Minute
	rdeskWSMaxMessage  = 16 << 10
	rdeskJPEGQuality   = 70
	rdeskViewerMaxFPS  = 15
	rdeskMaxUserLen    = 256
	rdeskMaxPassword   = 1024
	rdeskViewerPrefix  = "/remote-viewer/#t="
	rdeskClipboardSize = 8 << 10
)

// errRDeskWrongAccount ends the sign-in loop after one wrong password: the
// panel asks the person again instead of resending the same password.
var errRDeskWrongAccount = errors.New("hesap kabul edilmedi")

type rdeskViewer struct {
	sessionID string
	device    string
	mode      rdesk.Mode
	input     bool
	client    *rdesk.Client
	until     time.Time
	timer     *time.Timer
}

// w1State holds the sessions waiting for their viewer.
type w1State struct {
	mu      sync.Mutex
	viewers map[string]*rdeskViewer
	target  func(name string) (netip.AddrPort, bool)
}

// SetRDeskTarget replaces how a device name becomes its remote desktop
// address (default: the tunnel address of the device in the network
// document and the rdesk port).
func (s *Server) SetRDeskTarget(resolve func(name string) (netip.AddrPort, bool)) {
	s.w1.mu.Lock()
	s.w1.target = resolve
	s.w1.mu.Unlock()
}

func (s *Server) rdeskTarget(name string) (netip.AddrPort, bool) {
	s.w1.mu.Lock()
	resolve := s.w1.target
	s.w1.mu.Unlock()
	if resolve != nil {
		return resolve(name)
	}
	addr, ok := s.resolveDevice(name)
	if !ok {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(addr, trust.RemoteDesktopPort), true
}

func (s *Server) w1Routes(mux *http.ServeMux) {
	write := func(h http.HandlerFunc) http.HandlerFunc {
		return s.requireSession(s.requireCSRF(s.requireWritable(s.localOnly(h))))
	}
	mux.HandleFunc("POST /api/app/rdesk/connect", write(s.handleRDeskConnect))
	mux.HandleFunc("GET /api/rdesk/ws", s.handleRDeskSocket)
}

type rdeskConnectRequest struct {
	Device   string   `json:"device"`
	Mode     string   `json:"mode"`
	Channels []string `json:"channels,omitempty"`
	User     string   `json:"user,omitempty"`
	// Password is base64 so it decodes into bytes that can be wiped.
	Password []byte `json:"password,omitempty"`
	// Monitor is the first monitor: "primary" (default), "all" or a number (#120).
	Monitor string `json:"monitor,omitempty"`
}

var rdeskChannelNames = map[string]bool{"video": true, "input": true, "clipboard": true, "files": true, "audio": true, "curtain": true}

func validAccountName(u string) bool {
	if len(u) > rdeskMaxUserLen {
		return false
	}
	for _, r := range u {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func writeCoded(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]string{"error": message, "code": code})
}

func (s *Server) handleRDeskConnect(w http.ResponseWriter, r *http.Request) {
	var req rdeskConnectRequest
	if !decodeBody(w, r, &req) {
		return
	}
	defer wipe(req.Password)
	var mode rdesk.Mode
	switch req.Mode {
	case "view":
		mode = rdesk.ModeView
	case "control":
		mode = rdesk.ModeControl
	default:
		writeError(w, http.StatusBadRequest, "Oturum türü geçersiz.")
		return
	}
	want := map[string]bool{}
	for _, c := range req.Channels {
		if !rdeskChannelNames[c] {
			writeError(w, http.StatusBadRequest, "Bilinmeyen oturum izni: "+c)
			return
		}
		want[c] = true
	}
	req.User = strings.TrimSpace(req.User)
	if !validAccountName(req.User) || len(req.Password) > rdeskMaxPassword || (req.User == "") != (len(req.Password) == 0) {
		writeError(w, http.StatusBadRequest, "Hesap adı veya parola geçersiz.")
		return
	}
	addr, ok := s.rdeskTarget(req.Device)
	if req.Device == "" || !ok {
		writeError(w, http.StatusNotFound, "Cihaz ağ belgesinde bulunamadı.")
		return
	}
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "Oturum yok.")
		return
	}
	s.w1.mu.Lock()
	n := len(s.w1.viewers)
	s.w1.mu.Unlock()
	if n >= maxRDeskViewers {
		writeError(w, http.StatusTooManyRequests, "Çok fazla bekleyen uzak masaüstü oturumu.")
		return
	}

	monitor, ok := rdeskMonitorOption(req.Monitor) // #120, f3_rdesk_monitors.go
	if !ok {
		writeError(w, http.StatusBadRequest, "Monitör seçimi geçersiz.")
		return
	}
	opts := rdesk.DialOptions{Mode: mode, Monitor: monitor, MaxFPS: rdeskViewerMaxFPS,
		Clipboard: mode == rdesk.ModeControl && want["clipboard"]}
	if req.User != "" {
		pw := append([]byte(nil), req.Password...)
		used := false
		opts.Credentials = func(_ context.Context, lr rdesk.LoginRequest) (rdesk.LoginCredentials, error) {
			if used || lr.Retry {
				return rdesk.LoginCredentials{}, errRDeskWrongAccount
			}
			used = true
			// Dial wipes the password after sending it.
			return rdesk.LoginCredentials{User: req.User, Password: pw}, nil
		}
		defer wipe(pw)
	}
	ctx, cancel := context.WithTimeout(r.Context(), rdeskDialTimeout)
	defer cancel()
	client, err := rdesk.Dial(ctx, addr, opts)
	switch {
	case errors.Is(err, rdesk.ErrLoginRequired):
		writeCoded(w, http.StatusUnauthorized, "os_login_required", "Hedef cihaz işletim sistemi hesabıyla giriş istiyor; kullanıcı adı ve parola girin.")
		return
	case errors.Is(err, errRDeskWrongAccount):
		writeCoded(w, http.StatusUnauthorized, "os_login_failed", "Kullanıcı adı veya parola yanlış.")
		return
	case errors.Is(err, rdesk.ErrLoginBlocked):
		writeCoded(w, http.StatusTooManyRequests, "os_login_blocked", "Çok fazla hatalı deneme; hedef cihaz bu bilgisayarı bir süre engelledi.")
		return
	case errors.Is(err, rdesk.ErrControlTaken): // #853
		writeCoded(w, http.StatusConflict, "control_busy", "Bu cihazı başka bir yönetici denetliyor; yalnızca izleyici olarak katılabilirsiniz.")
		return
	case errors.Is(err, rdesk.ErrLoginRejected):
		writeCoded(w, http.StatusForbidden, "os_login_failed", "Hedef cihaz girişi kabul etmedi.")
		return
	case err != nil:
		s.logger.Info("remote desktop connection from the panel failed", "device", req.Device, "error", err.Error())
		writeCoded(w, http.StatusBadGateway, "connect_failed", "Uzak masaüstüne bağlanılamadı. Kural izin vermiyor, karşıda onay verilmedi veya cihaz çevrim dışı olabilir.")
		return
	}
	if mode == rdesk.ModeControl && want["curtain"] {
		// The target refuses it without the curtain channel; the session
		// goes on without it.
		_ = client.SetLocalLock(ctx, rdesk.LockState{Blank: true, Input: true})
	}
	ticket, err := randomToken(s.random)
	if err != nil {
		_ = client.Close()
		writeError(w, http.StatusInternalServerError, "Bilet üretilemedi.")
		return
	}
	v := &rdeskViewer{sessionID: c.Value, device: req.Device, mode: mode, input: mode == rdesk.ModeControl && want["input"],
		client: client, until: s.now().Add(rdeskViewerLife)}
	s.w1.mu.Lock()
	if s.w1.viewers == nil {
		s.w1.viewers = map[string]*rdeskViewer{}
	}
	s.w1.viewers[ticket] = v
	// A session nobody opens within the minute is closed.
	v.timer = time.AfterFunc(rdeskViewerLife, func() {
		if s.takeRDeskViewer(ticket, "") != nil {
			_ = client.Close()
		}
	})
	s.w1.mu.Unlock()
	s.logger.Info("remote desktop session opened from the panel", "device", req.Device, "mode", req.Mode)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "session": ticket, "viewer": rdeskViewerPrefix + ticket, "expires_sec": int(rdeskViewerLife / time.Second),
		"code": client.VerificationCode(), "recorded": client.Recorded(),
	})
}

// takeRDeskViewer returns and forgets the waiting session of ticket; an
// empty sessionID takes it regardless of the owner (expiry).
func (s *Server) takeRDeskViewer(ticket, sessionID string) *rdeskViewer {
	s.w1.mu.Lock()
	defer s.w1.mu.Unlock()
	v, ok := s.w1.viewers[ticket]
	if !ok {
		return nil
	}
	if sessionID != "" && v.sessionID != sessionID {
		return nil
	}
	delete(s.w1.viewers, ticket)
	if v.timer != nil {
		v.timer.Stop()
	}
	return v
}

func (s *Server) handleRDeskSocket(w http.ResponseWriter, r *http.Request) {
	if _, remote := remoteDevice(r); remote {
		writeError(w, http.StatusForbidden, "Uzak masaüstü uzak panelden açılamaz.")
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
	ticket := r.URL.Query().Get("ticket")
	if ticket == "" {
		writeError(w, http.StatusForbidden, "Görüntüleyici bileti geçersiz veya süresi doldu.")
		return
	}
	v := s.takeRDeskViewer(ticket, c.Value)
	if v == nil {
		writeError(w, http.StatusForbidden, "Görüntüleyici bileti geçersiz veya süresi doldu.")
		return
	}
	if !s.now().Before(v.until) {
		_ = v.client.Close()
		writeError(w, http.StatusForbidden, "Görüntüleyici bileti geçersiz veya süresi doldu.")
		return
	}
	srv := websocket.Server{
		Handshake: func(*websocket.Config, *http.Request) error { return nil },
		Handler:   func(ws *websocket.Conn) { s.bridgeRDesk(r.Context(), ws, v) },
	}
	srv.ServeHTTP(w, r)
}

// rdeskMessage is a text message in either direction.
type rdeskMessage struct {
	Type      string `json:"type"`
	X         int    `json:"x,omitempty"`
	Y         int    `json:"y,omitempty"`
	Buttons   uint8  `json:"buttons,omitempty"`
	DX        int    `json:"dx,omitempty"`
	DY        int    `json:"dy,omitempty"`
	Code      string `json:"code,omitempty"`
	Down      bool   `json:"down,omitempty"`
	Data      string `json:"data,omitempty"`
	Message   string `json:"message,omitempty"`
	Width     int    `json:"width,omitempty"`
	Height    int    `json:"height,omitempty"`
	Mode      string `json:"mode,omitempty"`
	Input     bool   `json:"input,omitempty"`
	Recorded  bool   `json:"recorded,omitempty"`
	Clipboard bool   `json:"clipboard,omitempty"`
	Device    string `json:"device,omitempty"`
	// Monitor picker (#120, f3_rdesk_monitors.go).
	Monitors []rdeskMonitorView `json:"monitors,omitempty"`
	Selected *int               `json:"selected,omitempty"`
	Index    int                `json:"index,omitempty"`
}

func sendRDesk(ws *websocket.Conn, mu *sync.Mutex, m rdeskMessage) error {
	b, _ := json.Marshal(m)
	mu.Lock()
	defer mu.Unlock()
	return websocket.Message.Send(ws, string(b))
}

func (s *Server) bridgeRDesk(ctx context.Context, ws *websocket.Conn, v *rdeskViewer) {
	defer ws.Close()
	defer v.client.Close()
	ws.MaxPayloadBytes = rdeskWSMaxMessage
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wmu sync.Mutex
	d := v.client.Desktop()
	var mons rdeskMonitorState // #120: used only here and by the frame goroutine
	first, _ := mons.message(v.client)
	_ = sendRDesk(ws, &wmu, rdeskMessage{Type: "ready", Device: v.device, Mode: v.mode.String(), Input: v.input,
		Code: v.client.VerificationCode(), Recorded: v.client.Recorded(), Clipboard: v.client.ClipboardShared(),
		Width: d.Width, Height: d.Height, Monitors: first.Monitors, Selected: first.Selected})
	done := make(chan struct{})
	go func() {
		defer close(done)
		var buf bytes.Buffer
		for {
			img, err := v.client.NextFrame(ctx)
			if err != nil {
				return
			}
			buf.Reset()
			if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: rdeskJPEGQuality}); err != nil {
				return
			}
			wmu.Lock()
			err = websocket.Message.Send(ws, buf.Bytes())
			wmu.Unlock()
			if err != nil {
				return
			}
			mons.notify(ws, &wmu, v.client)
		}
	}()
	go func() {
		defer cancel()
		for {
			var msg string
			if err := websocket.Message.Receive(ws, &msg); err != nil {
				return
			}
			var m rdeskMessage
			if json.Unmarshal([]byte(msg), &m) != nil {
				continue
			}
			if m.Type == "close" {
				return
			}
			if rdeskViewerCommand(v, m) { // #120: monitor choice, any session
				continue
			}
			if !v.input {
				// A view session, or one without the input channel, never
				// sends input (the target refuses it anyway).
				continue
			}
			var err error
			switch m.Type {
			case "pointer":
				err = v.client.SendPointer(m.X, m.Y, m.Buttons&(rdesk.ButtonLeft|rdesk.ButtonRight|rdesk.ButtonMiddle))
			case "wheel":
				err = v.client.SendWheel(clampNotches(m.DX), clampNotches(m.DY))
			case "key":
				if usage, ok := hidUsage(m.Code); ok {
					err = v.client.SendKey(usage, m.Down)
				}
			case "clipboard":
				if len(m.Data) <= rdeskClipboardSize {
					err = v.client.SendClipboard(m.Data)
				}
			}
			if err != nil {
				return
			}
		}
	}()
	check := time.NewTicker(sshSessionCheck)
	defer check.Stop()
	reason := "Oturum kapandı."
wait:
	for {
		select {
		case <-done:
			if err := v.client.Err(); err != nil {
				reason = "Bağlantı kesildi: " + err.Error()
			}
			break wait
		case <-ctx.Done():
			break wait
		case <-check.C:
			if !s.auth.alive(v.sessionID) || s.idle().lockedNow(s.now()) {
				reason = "Panel oturumu kapandığı veya kilitlendiği için uzak masaüstü kapatıldı."
				break wait
			}
		}
	}
	_ = sendRDesk(ws, &wmu, rdeskMessage{Type: "exit", Message: reason})
	s.logger.Info("remote desktop session from the panel closed", "device", v.device)
}

func clampNotches(n int) int {
	return max(-10, min(10, n))
}

// hidUsage maps a browser KeyboardEvent.code to a USB HID usage (keyboard
// page 0x07); the layout does not matter, the target maps the usage.
func hidUsage(code string) (uint16, bool) {
	switch {
	case len(code) == 4 && strings.HasPrefix(code, "Key") && code[3] >= 'A' && code[3] <= 'Z':
		return 0x04 + uint16(code[3]-'A'), true
	case len(code) == 6 && strings.HasPrefix(code, "Digit") && code[5] >= '0' && code[5] <= '9':
		if code[5] == '0' {
			return 0x27, true
		}
		return 0x1E + uint16(code[5]-'1'), true
	case len(code) == 7 && strings.HasPrefix(code, "Numpad") && code[6] >= '0' && code[6] <= '9':
		if code[6] == '0' {
			return 0x62, true
		}
		return 0x59 + uint16(code[6]-'1'), true
	case strings.HasPrefix(code, "F") && len(code) <= 3:
		n := 0
		for _, ch := range code[1:] {
			if ch < '0' || ch > '9' {
				return 0, false
			}
			n = n*10 + int(ch-'0')
		}
		if n >= 1 && n <= 12 {
			return 0x3A + uint16(n-1), true
		}
		return 0, false
	}
	u, ok := hidNamed[code]
	return u, ok
}

var hidNamed = map[string]uint16{
	"Enter": 0x28, "Escape": 0x29, "Backspace": 0x2A, "Tab": 0x2B, "Space": 0x2C, "Minus": 0x2D, "Equal": 0x2E,
	"BracketLeft": 0x2F, "BracketRight": 0x30, "Backslash": 0x31, "Semicolon": 0x33, "Quote": 0x34, "Backquote": 0x35,
	"Comma": 0x36, "Period": 0x37, "Slash": 0x38, "CapsLock": 0x39, "PrintScreen": 0x46, "ScrollLock": 0x47,
	"Pause": 0x48, "Insert": 0x49, "Home": 0x4A, "PageUp": 0x4B, "Delete": 0x4C, "End": 0x4D, "PageDown": 0x4E,
	"ArrowRight": 0x4F, "ArrowLeft": 0x50, "ArrowDown": 0x51, "ArrowUp": 0x52, "NumLock": 0x53,
	"NumpadDivide": 0x54, "NumpadMultiply": 0x55, "NumpadSubtract": 0x56, "NumpadAdd": 0x57, "NumpadEnter": 0x58,
	"NumpadDecimal": 0x63, "IntlBackslash": 0x64, "ContextMenu": 0x65,
	"ControlLeft": 0xE0, "ShiftLeft": 0xE1, "AltLeft": 0xE2, "MetaLeft": 0xE3,
	"ControlRight": 0xE4, "ShiftRight": 0xE5, "AltRight": 0xE6, "MetaRight": 0xE7,
}
