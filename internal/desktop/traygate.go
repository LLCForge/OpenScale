package desktop

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/peercred"
)

// The tray gateway (ADR-0227). On macOS the menu bar app runs as the
// logged-in user while the service runs as root. The app token stays in
// the root-only data folder; instead the service listens on a Unix
// socket, asks the kernel who connected (LOCAL_PEERCRED, LOCAL_PEERPID)
// and forwards a fixed list of tray requests to its own panel with the
// token added. The caller must be root or a member of the admin group
// (the Windows tray must be an elevated administrator) and must run
// exactly the program the service runs (the Windows tray must run this
// OpenScale program, #645). Everything else is refused.

const (
	// adminGroupID is the macOS "admin" group: the users who may
	// administer the computer.
	adminGroupID = 80
	// maxGateBody bounds a forwarded request body; tray requests are
	// small JSON objects.
	maxGateBody = 64 << 10
	// maxGateReply bounds a forwarded answer (the event stream reply is
	// the largest).
	maxGateReply = 1 << 20
	// maxGateQuery bounds the query string of the event poll.
	maxGateQuery = 64
	// gateUpstreamTimeout covers the event poll's long wait.
	gateUpstreamTimeout = eventTimeout
)

// gateRoutes are the only requests the gateway forwards: what the menu
// bar app uses (desktop.go, events.go, panic).
var gateRoutes = map[string]bool{
	http.MethodGet + " /api/app/tray":                            true,
	http.MethodPost + " /api/app/tray/connect":                   true,
	http.MethodPost + " /api/app/tray/exit":                      true,
	http.MethodPost + " /api/app/tray/exit/options":              true,
	http.MethodPost + " /api/app/tray/disconnect":                true,
	http.MethodPost + " /api/app/tray/panic":                     true,
	http.MethodPost + " /api/app/ticket":                         true,
	http.MethodGet + " " + panel.LocalAPIPrefix + "/events/poll": true,
}

// gateQueryAllowed lists the routes that may carry a query string.
var gateQueryAllowed = map[string]bool{
	panel.LocalAPIPrefix + "/events/poll": true,
}

// trayGate forwards allowed tray requests to the panel with the token.
type trayGate struct {
	upstream string
	token    func() (string, error)
	client   *http.Client
	logger   *slog.Logger
}

func newTrayGate(upstream string, token func() (string, error), logger *slog.Logger) *trayGate {
	return &trayGate{
		upstream: upstream,
		token:    token,
		logger:   logger,
		client: &http.Client{
			Timeout:       gateUpstreamTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

func gateError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, "{\"error\":%q}\n", msg)
}

func (g *trayGate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if !gateRoutes[r.Method+" "+path] {
		gateError(w, http.StatusNotFound, "bu istek tepsi kanalında yok")
		return
	}
	query := ""
	if r.URL.RawQuery != "" {
		if !gateQueryAllowed[path] || len(r.URL.RawQuery) > maxGateQuery {
			gateError(w, http.StatusBadRequest, "geçersiz sorgu")
			return
		}
		query = "?" + r.URL.RawQuery
	}
	var body io.Reader
	if r.Method == http.MethodPost {
		if ct := r.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(ct, "application/json") {
			gateError(w, http.StatusUnsupportedMediaType, "yalnızca JSON")
			return
		}
		data, err := io.ReadAll(io.LimitReader(r.Body, maxGateBody+1))
		if err != nil {
			gateError(w, http.StatusBadRequest, "istek okunamadı")
			return
		}
		if len(data) > maxGateBody {
			gateError(w, http.StatusRequestEntityTooLarge, "istek çok büyük")
			return
		}
		body = bytes.NewReader(data)
	}
	token, err := g.token()
	if err != nil {
		g.logger.Warn("tray gateway: app token unavailable", "error", err.Error())
		gateError(w, http.StatusServiceUnavailable, "servis henüz hazır değil")
		return
	}
	req, err := http.NewRequestWithContext(r.Context(), r.Method, g.upstream+path+query, body)
	if err != nil {
		gateError(w, http.StatusBadRequest, "geçersiz istek")
		return
	}
	// Only what the panel needs goes on: no cookies, origin or the
	// caller's own authorization header.
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := g.client.Do(req)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			g.logger.Warn("tray gateway: panel unreachable", "error", err.Error())
		}
		gateError(w, http.StatusBadGateway, "servis yanıt vermedi")
		return
	}
	defer resp.Body.Close()
	reply, err := io.ReadAll(io.LimitReader(resp.Body, maxGateReply+1))
	if err != nil || len(reply) > maxGateReply {
		gateError(w, http.StatusBadGateway, "servis yanıtı okunamadı")
		return
	}
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(reply)
}

// errGatePeer explains a refused caller (logged, never sent).
var errGatePeer = errors.New("tray gateway: caller refused")

// gatePeerPolicy decides who may use the tray socket.
type gatePeerPolicy struct {
	// want is the SHA-256 of the program the service runs.
	want [sha256.Size]byte
	// image returns the program file of a process.
	image func(pid int) (string, error)
	// hash returns the SHA-256 of a program file.
	hash func(path string) ([sha256.Size]byte, error)
	// inGroup asks the directory service whether uid is a member of gid;
	// used when the kernel's list may be incomplete (macOS: at most 16
	// groups; Linux: SO_PEERCRED has the primary group only). Nil skips
	// it.
	inGroup func(uid, gid int) bool
	// group is the group whose members may connect besides root: the
	// macOS admin group (the zero value) or, on Linux, the openscale
	// group (ADR-0234); noGroup lets only root in.
	group int
	// partialGroups: the kernel never lists supplementary groups, so
	// inGroup is always asked (Linux).
	partialGroups bool
}

// maxPeerGroups is the size of the group list in struct xucred.
const maxPeerGroups = 16

// noGroup: no group besides root may use the tray socket (Linux without
// an openscale group).
const noGroup = -1

// check allows root and members of the admin group that run the
// service's own program.
func (p gatePeerPolicy) check(id peercred.Identity) error {
	g := p.group
	if g == 0 {
		g = adminGroupID
	}
	admin := id.Admin || (g != noGroup && (id.HasGroup(g) ||
		((len(id.Groups) >= maxPeerGroups || p.partialGroups) && p.inGroup != nil && p.inGroup(id.UID, g))))
	if !admin {
		return fmt.Errorf("%w: uid %d is neither root nor in the allowed group", errGatePeer, id.UID)
	}
	if id.PID <= 0 {
		return fmt.Errorf("%w: no process id", errGatePeer)
	}
	exe, err := p.image(id.PID)
	if err != nil {
		return fmt.Errorf("%w: program of pid %d: %v", errGatePeer, id.PID, err)
	}
	sum, err := p.hash(exe)
	if err != nil {
		return fmt.Errorf("%w: program of pid %d: %v", errGatePeer, id.PID, err)
	}
	if sum != p.want {
		return fmt.Errorf("%w: pid %d runs another program (%s)", errGatePeer, id.PID, exe)
	}
	return nil
}

// programHashes caches file digests by path, size and modification time,
// so a long-running menu bar app costs one hash per update.
type programHashes struct {
	mu    sync.Mutex
	cache map[string]programHash
}

type programHash struct {
	size int64
	mod  time.Time
	sum  [sha256.Size]byte
}

// maxProgramSize bounds what is hashed.
const maxProgramSize = 512 << 20

func (h *programHashes) sum(path string) ([sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	f, err := os.Open(path)
	if err != nil {
		return zero, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return zero, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxProgramSize {
		return zero, errors.New("not a regular program file")
	}
	h.mu.Lock()
	if c, ok := h.cache[path]; ok && c.size == info.Size() && c.mod.Equal(info.ModTime()) {
		h.mu.Unlock()
		return c.sum, nil
	}
	h.mu.Unlock()
	d := sha256.New()
	if _, err := io.Copy(d, io.LimitReader(f, maxProgramSize+1)); err != nil {
		return zero, err
	}
	var sum [sha256.Size]byte
	copy(sum[:], d.Sum(nil))
	h.mu.Lock()
	if h.cache == nil {
		h.cache = map[string]programHash{}
	}
	if len(h.cache) > 64 {
		clear(h.cache)
	}
	h.cache[path] = programHash{size: info.Size(), mod: info.ModTime(), sum: sum}
	h.mu.Unlock()
	return sum, nil
}
