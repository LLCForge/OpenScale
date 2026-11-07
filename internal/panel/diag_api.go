package panel

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/node"
)

// Time limits of the diagnostics that wait for the network.
const (
	diagNetCheckTimeout = 10 * time.Second
	diagRelayTimeout    = 10 * time.Second
	diagPingTimeout     = 5 * time.Second
	diagDNSTimeout      = 5 * time.Second
	// maxDiagQuery bounds names and addresses accepted from a request.
	maxDiagQuery = 253
)

// LocalAPIPrefix is where the command line finds the diagnostics API.
const LocalAPIPrefix = "/api/local"

// ErrNeedsService is returned by diagnostics only the desktop service has.
var ErrNeedsService = errors.New("bu işlem yalnızca OpenScale servisinde var; ön planda çalışan 'openscale up' bunu desteklemez")

// diagAPI serves the diagnostics handlers for one Diagnostics source.
type diagAPI struct {
	diag   func() (Diagnostics, bool)
	logger *slog.Logger
}

type peerRequest struct {
	Peer string `json:"peer"`
}

type nameRequest struct {
	Name string `json:"name"`
}

type levelRequest struct {
	Level string `json:"level"`
}

type prefsRequest struct {
	Set map[string]string `json:"set"`
}

type netCheckReply struct {
	Schema int `json:"schema"`
	node.NetReport
}

type pathsReply struct {
	Schema int             `json:"schema"`
	Peers  []node.PeerPath `json:"peers"`
}

type eventsReply struct {
	Schema int         `json:"schema"`
	Events []DiagEvent `json:"events"`
}

type relayReply struct {
	Schema int     `json:"schema"`
	Peer   string  `json:"peer"`
	RTTMS  float64 `json:"rtt_ms"`
}

type levelReply struct {
	Schema int    `json:"schema"`
	Level  string `json:"level"`
}

type prefsReply struct {
	Schema int    `json:"schema"`
	Prefs  []Pref `json:"prefs"`
}

type okReply struct {
	Schema int  `json:"schema"`
	OK     bool `json:"ok"`
}

// validDiagQuery accepts device names, FQDNs and IP addresses only, so
// nothing else reaches the service.
func validDiagQuery(q string) bool {
	if q == "" || len(q) > maxDiagQuery {
		return false
	}
	for _, c := range q {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '-', c == ':', c == '_':
		default:
			return false
		}
	}
	return true
}

// routes registers the handlers under prefix. read wraps reads, write
// wraps actions; full adds the command-line-only handlers.
func (a *diagAPI) routes(mux *http.ServeMux, prefix string, read, write func(http.HandlerFunc) http.HandlerFunc, full bool) {
	mux.HandleFunc("GET "+prefix+"/status", read(a.with(a.status)))
	mux.HandleFunc("GET "+prefix+"/netcheck", read(a.with(a.netCheck)))
	mux.HandleFunc("GET "+prefix+"/paths", read(a.with(a.paths)))
	mux.HandleFunc("GET "+prefix+"/events", read(a.with(a.events)))
	mux.HandleFunc("GET "+prefix+"/dns", read(a.with(a.dns)))
	mux.HandleFunc("POST "+prefix+"/reconnect", write(a.with(a.reconnect)))
	mux.HandleFunc("POST "+prefix+"/relay-test", write(a.with(a.relayTest)))
	mux.HandleFunc("POST "+prefix+"/ping", write(a.with(a.ping)))
	a.observeRoutes(mux, prefix, read, write, full) // ADR-0105, observe_api.go
	if !full {
		return
	}
	mux.HandleFunc("POST "+prefix+"/dns/query", read(a.with(a.dnsQuery)))
	mux.HandleFunc("GET "+prefix+"/whois", read(a.with(a.whois)))
	mux.HandleFunc("GET "+prefix+"/wg", read(a.with(a.wireGuard)))
	mux.HandleFunc("POST "+prefix+"/trace", read(a.with(a.trace)))
	mux.HandleFunc("GET "+prefix+"/health", read(a.with(a.health)))
	mux.HandleFunc("GET "+prefix+"/log-level", read(a.with(a.logLevel)))
	mux.HandleFunc("POST "+prefix+"/log-level", write(a.with(a.setLogLevel)))
	mux.HandleFunc("GET "+prefix+"/prefs", read(a.with(a.prefs)))
	mux.HandleFunc("POST "+prefix+"/prefs", write(a.with(a.setPrefs)))
	a.threatRoutes(mux, prefix, read, write) // ADR-0102, ADR-0110
	// Exit node resolver controls (P05, exitdns_api.go).
	a.exitDNSRoutes(mux, prefix, read, write)
}

// with resolves the Diagnostics source or answers 404.
func (a *diagAPI) with(h func(http.ResponseWriter, *http.Request, Diagnostics)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		d, ok := a.diag()
		if !ok {
			writeError(w, http.StatusNotFound, "Tanı işlemleri yalnızca masaüstü servisinde veya 'openscale up' çalışırken var.")
			return
		}
		h(w, r, d)
	}
}

func diagFailed(w http.ResponseWriter, err error) {
	writeError(w, http.StatusConflict, err.Error())
}

func (a *diagAPI) status(w http.ResponseWriter, _ *http.Request, d Diagnostics) {
	st, err := d.DiagStatus()
	if err != nil {
		diagFailed(w, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (a *diagAPI) netCheck(w http.ResponseWriter, r *http.Request, d Diagnostics) {
	ctx, cancel := context.WithTimeout(r.Context(), diagNetCheckTimeout)
	defer cancel()
	rep, err := d.DiagNetCheck(ctx)
	if err != nil {
		diagFailed(w, err)
		return
	}
	writeJSON(w, http.StatusOK, netCheckReply{Schema: DiagSchema, NetReport: rep})
}

func (a *diagAPI) paths(w http.ResponseWriter, _ *http.Request, d Diagnostics) {
	p, err := d.DiagPaths()
	if err != nil {
		diagFailed(w, err)
		return
	}
	if p == nil {
		p = []node.PeerPath{}
	}
	writeJSON(w, http.StatusOK, pathsReply{Schema: DiagSchema, Peers: p})
}

func (a *diagAPI) events(w http.ResponseWriter, _ *http.Request, d Diagnostics) {
	ev := d.DiagEvents()
	if ev == nil {
		ev = []DiagEvent{}
	}
	writeJSON(w, http.StatusOK, eventsReply{Schema: DiagSchema, Events: ev})
}

func (a *diagAPI) dns(w http.ResponseWriter, _ *http.Request, d Diagnostics) {
	st, err := d.DiagDNS()
	if err != nil {
		diagFailed(w, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (a *diagAPI) reconnect(w http.ResponseWriter, r *http.Request, d Diagnostics) {
	var req struct{}
	if !decodeBody(w, r, &req) {
		return
	}
	if err := d.DiagReconnect(); err != nil {
		diagFailed(w, err)
		return
	}
	a.logger.Info("forced reconnect from diagnostics")
	writeJSON(w, http.StatusOK, okReply{Schema: DiagSchema, OK: true})
}

func (a *diagAPI) peerFrom(w http.ResponseWriter, r *http.Request) (string, bool) {
	var req peerRequest
	if !decodeBody(w, r, &req) {
		return "", false
	}
	peer := strings.TrimSpace(req.Peer)
	if !validDiagQuery(peer) {
		writeError(w, http.StatusBadRequest, "Cihaz adı veya adresi geçersiz.")
		return "", false
	}
	return peer, true
}

func (a *diagAPI) relayTest(w http.ResponseWriter, r *http.Request, d Diagnostics) {
	peer, ok := a.peerFrom(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), diagRelayTimeout)
	defer cancel()
	rtt, err := d.DiagRelayTest(ctx, peer)
	if err != nil {
		diagFailed(w, err)
		return
	}
	writeJSON(w, http.StatusOK, relayReply{Schema: DiagSchema, Peer: peer, RTTMS: Millis(rtt)})
}

func (a *diagAPI) ping(w http.ResponseWriter, r *http.Request, d Diagnostics) {
	peer, ok := a.peerFrom(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), diagPingTimeout)
	defer cancel()
	res, err := d.DiagPing(ctx, peer)
	if err != nil {
		diagFailed(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (a *diagAPI) dnsQuery(w http.ResponseWriter, r *http.Request, d Diagnostics) {
	var req nameRequest
	if !decodeBody(w, r, &req) {
		return
	}
	name := strings.TrimSpace(req.Name)
	if !validDiagQuery(name) {
		writeError(w, http.StatusBadRequest, "Ad geçersiz.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), diagDNSTimeout)
	defer cancel()
	res, err := d.DiagDNSQuery(ctx, name)
	if err != nil {
		diagFailed(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (a *diagAPI) whois(w http.ResponseWriter, r *http.Request, d Diagnostics) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q != "" && !validDiagQuery(q) {
		writeError(w, http.StatusBadRequest, "Sorgu geçersiz.")
		return
	}
	res, err := d.DiagWhois(q)
	if err != nil {
		diagFailed(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (a *diagAPI) wireGuard(w http.ResponseWriter, _ *http.Request, d Diagnostics) {
	res, err := d.DiagWireGuard()
	if err != nil {
		diagFailed(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (a *diagAPI) trace(w http.ResponseWriter, r *http.Request, d Diagnostics) {
	var req TraceRequest
	if !decodeBody(w, r, &req) {
		return
	}
	req.Src, req.Dst, req.Proto = strings.TrimSpace(req.Src), strings.TrimSpace(req.Dst), strings.ToLower(strings.TrimSpace(req.Proto))
	if !validDiagQuery(req.Src) || !validDiagQuery(req.Dst) || !validDiagQuery(req.Proto) || req.Port < 0 || req.Port > 65535 {
		writeError(w, http.StatusBadRequest, "Paket tanımı geçersiz.")
		return
	}
	res, err := d.DiagPacketTrace(req)
	if err != nil {
		diagFailed(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (a *diagAPI) health(w http.ResponseWriter, _ *http.Request, d Diagnostics) {
	writeJSON(w, http.StatusOK, d.DiagHealth())
}

func (a *diagAPI) logLevel(w http.ResponseWriter, _ *http.Request, d Diagnostics) {
	writeJSON(w, http.StatusOK, levelReply{Schema: DiagSchema, Level: d.DiagLogLevel()})
}

func (a *diagAPI) setLogLevel(w http.ResponseWriter, r *http.Request, d Diagnostics) {
	var req levelRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if err := d.DiagSetLogLevel(strings.ToLower(strings.TrimSpace(req.Level))); err != nil {
		diagFailed(w, err)
		return
	}
	a.logger.Info("log level changed", "level", d.DiagLogLevel())
	writeJSON(w, http.StatusOK, levelReply{Schema: DiagSchema, Level: d.DiagLogLevel()})
}

func (a *diagAPI) prefs(w http.ResponseWriter, _ *http.Request, d Diagnostics) {
	p, err := d.DiagPrefs()
	if err != nil {
		diagFailed(w, err)
		return
	}
	writeJSON(w, http.StatusOK, prefsReply{Schema: DiagSchema, Prefs: p})
}

// maxPrefChanges bounds one "openscale set".
const maxPrefChanges = 32

func (a *diagAPI) setPrefs(w http.ResponseWriter, r *http.Request, d Diagnostics) {
	var req prefsRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if len(req.Set) == 0 || len(req.Set) > maxPrefChanges {
		writeError(w, http.StatusBadRequest, "Değiştirilecek ayar gönderilmeli.")
		return
	}
	for k, v := range req.Set {
		if !validDiagQuery(k) || len(v) > 1024 {
			writeError(w, http.StatusBadRequest, "Ayar adı veya değeri geçersiz.")
			return
		}
	}
	p, err := d.DiagSetPrefs(req.Set)
	if err != nil {
		diagFailed(w, err)
		return
	}
	a.logger.Info("preferences changed from the command line", "count", len(req.Set))
	writeJSON(w, http.StatusOK, prefsReply{Schema: DiagSchema, Prefs: p})
}

// Millis converts a duration to milliseconds with microsecond precision.
func Millis(d time.Duration) float64 {
	return float64(d.Microseconds()) / 1000
}

// diagRoutes adds the diagnostics API to the panel server: the panel's
// "Tanı" page under /api/app/diag with a session (actions refused while the
// panel is read-only), the command line under LocalAPIPrefix with the app
// token.
func (s *Server) diagRoutes(mux *http.ServeMux) {
	api := &diagAPI{logger: s.logger, diag: func() (Diagnostics, bool) {
		d, ok := s.app.(Diagnostics)
		return d, ok
	}}
	session := func(h http.HandlerFunc) http.HandlerFunc { return s.requireSession(s.requireApp(h)) }
	sessionWrite := func(h http.HandlerFunc) http.HandlerFunc {
		return s.requireSession(s.requireCSRF(s.requireWritable(s.requireApp(h))))
	}
	api.routes(mux, "/api/app/diag", session, sessionWrite, false)
	token := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if !s.trayAuthorized(w, r) {
				return
			}
			h(w, r)
		}
	}
	api.routes(mux, LocalAPIPrefix, token, token, true)
}

// LocalAPIConfig configures the diagnostics API of a foreground tunnel.
type LocalAPIConfig struct {
	Diag   Diagnostics
	Token  string
	Logger *slog.Logger
	// PeerCheck, when set, must also accept the calling process
	// (ADR-0050).
	PeerCheck func(remote, local string) error
}

// ServeLocalAPI serves only the command line diagnostics API on a loopback
// listener until ctx ends ("openscale up"). Requests need the token, the
// listener's own Host and no Origin header (browsers always send one on
// cross-site requests).
func ServeLocalAPI(ctx context.Context, ln net.Listener, cfg LocalAPIConfig) error {
	tcp, ok := ln.Addr().(*net.TCPAddr)
	if !ok || !tcp.IP.IsLoopback() {
		return errors.New("local API must listen on a loopback address")
	}
	if cfg.Diag == nil || len(cfg.Token) < 32 {
		return errors.New("local API needs diagnostics and a token")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	host := ln.Addr().String()
	_, port, _ := net.SplitHostPort(host)
	api := &diagAPI{logger: cfg.Logger, diag: func() (Diagnostics, bool) { return cfg.Diag, true }}
	auth := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Host != host && r.Host != net.JoinHostPort("localhost", port) {
				writeError(w, http.StatusMisdirectedRequest, "Geçersiz Host başlığı.")
				return
			}
			got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			if r.Header.Get("Origin") != "" || !ok || subtle.ConstantTimeCompare([]byte(got), []byte(cfg.Token)) != 1 {
				writeError(w, http.StatusUnauthorized, "İzin verilmedi.")
				return
			}
			if !callerAllowed(cfg.PeerCheck, r, cfg.Logger) {
				writeError(w, http.StatusForbidden, "İzin verilmedi: bu tünelin yerel API'si yalnızca root, tüneli başlatan kullanıcı veya openscale grubu içindir.")
				return
			}
			h(w, r)
		}
	}
	mux := http.NewServeMux()
	api.routes(mux, LocalAPIPrefix, auth, auth, true)
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, "Bulunamadı.")
	})
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
			h.Set("Cache-Control", "no-store")
			defer func() {
				if v := recover(); v != nil {
					if v == http.ErrAbortHandler {
						panic(v)
					}
					cfg.Logger.Error("local API panic", "path", r.URL.Path, "panic", fmt.Sprint(v))
					writeError(w, http.StatusInternalServerError, "Beklenmeyen bir hata oluştu.")
				}
			}()
			mux.ServeHTTP(w, r)
		}),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		return nil
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}
