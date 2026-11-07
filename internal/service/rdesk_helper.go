package service

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/rdesk"
	"github.com/openscale/openscale/internal/securefile"
)

// The Windows desktop helper (ADR-0110). The service (LocalSystem, session
// 0) starts "openscale rdesk-helper" in the active console session with
// the logged-in user's token. The helper gets a bootstrap over an
// inherited pipe: a fresh random token, the local API address and the
// owner's switches (and the recording key only when recording is on). It
// runs the screen server on the tunnel address and asks the service for
// every decision; the service accepts the token only from the process it
// started (caller check by process id, ADR-0050). Closing the pipe tells
// the helper to stop; it ends its sessions (releasing held keys) and exits.

// HelperBootstrapVersion is the bootstrap format.
const HelperBootstrapVersion = 1

// HelperBootstrap is the first line the helper reads from its stdin.
type HelperBootstrap struct {
	Version   int    `json:"v"`
	API       string `json:"api"`
	Token     string `json:"token"`
	Listen    string `json:"listen"`
	Device    string `json:"device"`
	LocalLock bool   `json:"local_lock,omitempty"`
	Power     bool   `json:"power,omitempty"`
	// RecordingKey is the key file's contents, only while recording is on.
	RecordingKey  string `json:"recording_key,omitempty"`
	RecordingDays int    `json:"recording_days,omitempty"`
	// FileRoots are the owner's folders for the session file browser
	// (ADR-0146).
	FileRoots []string `json:"file_roots,omitempty"`
}

// Validate checks a bootstrap before the helper uses it.
func (b HelperBootstrap) Validate() error {
	if b.Version != HelperBootstrapVersion {
		return errors.New("desteklenmeyen yardımcı başlangıç biçimi")
	}
	ap, err := netip.ParseAddrPort(b.API)
	if err != nil || !ap.Addr().IsLoopback() {
		return errors.New("yerel API adresi geçersiz")
	}
	if len(b.Token) < 32 || len(b.Token) > 128 {
		return errors.New("yardımcı anahtarı geçersiz")
	}
	l, err := netip.ParseAddrPort(b.Listen)
	if err != nil {
		return errors.New("dinleme adresi geçersiz")
	}
	if err := ValidateRDeskFileRoots(b.FileRoots); err != nil {
		return err
	}
	return rdesk.ValidateListenAddr(l)
}

// helperProc is one started helper process.
type helperProc interface {
	PID() uint32
	// Done is closed when the process exited.
	Done() <-chan struct{}
	// Stop closes the bootstrap pipe, waits up to grace and then ends the
	// process.
	Stop(grace time.Duration)
}

// helperLauncher starts helpers in the console session.
type helperLauncher interface {
	// ConsoleSession is the active console session (a change restarts the
	// helper in the new session).
	ConsoleSession() uint32
	Launch(bootstrap []byte) (helperProc, error)
}

var errNoConsoleUser = errors.New("masaüstünde oturum açmış kullanıcı yok; uzak masaüstü bekliyor")

// errSessionChanged restarts the helper at once in the new session.
var errSessionChanged = errors.New("konsol oturumu değişti")

const (
	helperRestartDelay = 5 * time.Second
	helperStopGrace    = 5 * time.Second
	helperPoll         = 2 * time.Second
	helperTokenBytes   = 32
)

// helperHost is the RemoteDesktopHost of the Windows service.
type helperHost struct {
	launcher helperLauncher
	apiAddr  func() string
	// lookupPID returns the process behind a loopback connection.
	lookupPID func(remote, local string) (uint32, error)
	events    func(source string, ev rdesk.SessionEvent)
	endSource func(source, reason string)
	restart   func(ctx context.Context, peer string) error

	gen atomic.Uint64
	seq atomic.Uint64

	mu      sync.Mutex
	token   string
	pid     uint32
	source  string
	env     RemoteDesktopEnv
	serving bool
	stop    bool
	lastErr string
}

// Kind implements RemoteDesktopHost.
func (h *helperHost) Kind() string { return "helper" }

// Revalidate implements RemoteDesktopHost: the helper sees a new
// generation at its next poll and checks its sessions again.
func (h *helperHost) Revalidate() { h.gen.Add(1) }

func newHelperToken() (string, error) {
	b := make([]byte, helperTokenBytes)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// bootstrap builds the helper's first line for env.
func (h *helperHost) bootstrap(env RemoteDesktopEnv, token string) ([]byte, error) {
	b := HelperBootstrap{Version: HelperBootstrapVersion, API: h.apiAddr(), Token: token, Listen: env.Addr.String(), Device: env.Device,
		LocalLock: env.Settings.LocalLock, Power: env.Settings.Power, FileRoots: env.Settings.FileRoots}
	if env.Settings.Recording {
		// The key stays in the data directory; the helper gets its value
		// over the pipe and keeps recordings in the user's local folder.
		if _, err := rdesk.LoadOrCreateRecordingKey(RecordingKeyPath(env.Dir)); err != nil {
			return nil, err
		}
		data, err := securefile.ReadPrivate(RecordingKeyPath(env.Dir), 4096)
		if err != nil {
			return nil, err
		}
		b.RecordingKey, b.RecordingDays = string(data), int(env.Settings.RecordingKeep()/(24*time.Hour))
	}
	if err := b.Validate(); err != nil {
		return nil, err
	}
	out, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

// Serve implements RemoteDesktopHost. The tunnel listener is closed: the
// helper binds the same address in the user's session.
func (h *helperHost) Serve(ctx context.Context, ln net.Listener, env RemoteDesktopEnv) error {
	_ = ln.Close()
	h.mu.Lock()
	if h.serving {
		h.mu.Unlock()
		return errors.New("uzak masaüstü yardımcısı zaten çalışıyor")
	}
	h.serving, h.env, h.stop = true, env, false
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		h.serving, h.token, h.pid = false, "", 0
		h.mu.Unlock()
	}()
	for ctx.Err() == nil {
		err := h.runOnce(ctx, env)
		h.mu.Lock()
		if err != nil {
			h.lastErr = err.Error()
		} else {
			h.lastErr = ""
		}
		h.mu.Unlock()
		if errors.Is(err, errSessionChanged) {
			h.mu.Lock()
			h.lastErr = ""
			h.mu.Unlock()
			continue
		}
		if err != nil && !errors.Is(err, errNoConsoleUser) && env.Logger != nil {
			env.Logger.Warn("remote desktop helper stopped", "error", err.Error())
		}
		select {
		case <-ctx.Done():
		case <-time.After(helperRestartDelay):
		}
	}
	return nil
}

// runOnce starts one helper and waits until it exits, the console session
// changes or ctx ends.
func (h *helperHost) runOnce(ctx context.Context, env RemoteDesktopEnv) error {
	token, err := newHelperToken()
	if err != nil {
		return err
	}
	boot, err := h.bootstrap(env, token)
	if err != nil {
		return err
	}
	session := h.launcher.ConsoleSession()
	source := "h" + strconv.FormatUint(h.seq.Add(1), 10)
	// The token is valid before the process runs; the process check below
	// still refuses anyone else until the pid is known.
	h.mu.Lock()
	h.token, h.pid, h.source = token, 0, source
	h.mu.Unlock()
	proc, err := h.launcher.Launch(boot)
	clear(boot)
	if err != nil {
		h.mu.Lock()
		h.token = ""
		h.mu.Unlock()
		return err
	}
	h.mu.Lock()
	h.pid = proc.PID()
	h.mu.Unlock()
	if env.Logger != nil {
		env.Logger.Info("remote desktop helper started in the console session", "session", session)
	}
	defer func() {
		h.mu.Lock()
		h.token, h.pid = "", 0
		h.mu.Unlock()
		if h.endSource != nil {
			h.endSource(source, "yardımcı durdu")
		}
	}()
	t := time.NewTicker(helperPoll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			h.mu.Lock()
			h.stop = true
			h.mu.Unlock()
			proc.Stop(helperStopGrace)
			return nil
		case <-proc.Done():
			return errors.New("uzak masaüstü yardımcısı kapandı; yeniden başlatılacak")
		case <-t.C:
			if s := h.launcher.ConsoleSession(); s != session {
				proc.Stop(helperStopGrace)
				return errSessionChanged
			}
		}
	}
}

// Allowed reports whether a request carries the current token and comes
// from the helper process the service started.
func (h *helperHost) Allowed(token, remote, local string) bool {
	h.mu.Lock()
	want, pid := h.token, h.pid
	h.mu.Unlock()
	if want == "" || pid == 0 || subtle.ConstantTimeCompare([]byte(token), []byte(want)) != 1 {
		return false
	}
	if h.lookupPID == nil {
		return false
	}
	got, err := h.lookupPID(remote, local)
	return err == nil && got == pid
}

func (h *helperHost) current() (RemoteDesktopEnv, string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.env, h.source
}

// Authorize answers the helper.
func (h *helperHost) Authorize(remote netip.Addr, mode string) panel.RDeskHelperDecision {
	env, _ := h.current()
	m := parseRDeskMode(mode)
	if env.Authorize == nil || m == 0 {
		return panel.RDeskHelperDecision{Reason: "geçersiz istek"}
	}
	d := env.Authorize(remote, m)
	return panel.RDeskHelperDecision{Allowed: d.Allowed, Unattended: d.Unattended, Peer: d.Peer, Reason: d.Reason, Files: d.Files}
}

// State answers the helper's poll.
func (h *helperHost) State() panel.RDeskHelperState {
	h.mu.Lock()
	stop := h.stop
	h.mu.Unlock()
	return panel.RDeskHelperState{Generation: h.gen.Load(), Stop: stop}
}

// Event records a helper's session event.
func (h *helperHost) Event(ev panel.RDeskHelperEvent) {
	_, source := h.current()
	if h.events == nil || source == "" {
		return
	}
	var kind rdesk.EventKind
	switch ev.Kind {
	case "start":
		kind = rdesk.EventStart
	case "end":
		kind = rdesk.EventEnd
	case "change":
		kind = rdesk.EventChange
	case "fatal":
		h.mu.Lock()
		h.lastErr = ev.Reason
		h.mu.Unlock()
		return
	default:
		return
	}
	h.events(source, rdesk.SessionEvent{Kind: kind, ID: ev.ID, Peer: ev.Peer, Mode: parseRDeskMode(ev.Mode), Unattended: ev.Unattended,
		Code: ev.Code, Recording: ev.Recording, Clipboard: ev.Clipboard, LocalLock: rdesk.LockState{Blank: ev.Blank, Input: ev.InputLock},
		Reason: ev.Reason, Time: time.Now()})
}

// Power restarts this computer for a control session, only when the owner
// allowed it. Safe mode is refused (ADR-0110: the boot configuration is not
// changed by this version).
func (h *helperHost) Power(req panel.RDeskHelperPower) error {
	env, _ := h.current()
	if !env.Settings.Power {
		return errors.New("uzaktan yeniden başlatma kapalı")
	}
	if req.SafeMode {
		return errors.New("güvenli modda yeniden başlatma bu sürümde desteklenmiyor")
	}
	if h.restart == nil {
		return errors.New("bu sistemde yeniden başlatma desteklenmiyor")
	}
	if env.Logger != nil {
		env.Logger.Warn("remote restart requested by a remote desktop session", "peer", req.Peer)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return h.restart(ctx, req.Peer)
}

func (h *helperHost) lastError() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.lastErr
}

// helperRecordingDir is where the helper keeps recordings: the user's
// local application data (the service's data directory is not writable
// from the user's session). Files are encrypted with the service's key.
func helperRecordingDir() (string, error) {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		var err error
		if base, err = os.UserCacheDir(); err != nil {
			return "", err
		}
	}
	return base + string(os.PathSeparator) + "OpenScale" + string(os.PathSeparator) + "rdesk-recordings", nil
}

// HelperRecordingDir is exported for the helper command.
func HelperRecordingDir() (string, error) { return helperRecordingDir() }
