package service

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/netip"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/rdesk"
	"github.com/openscale/openscale/internal/trust"
)

// Remote desktop service connection (ADR-0055, ADR-0103, ADR-0110).
//
// Apps decides every session from the signed rules (authorizeRDesk); a
// RemoteDesktopHost runs the screen server. On Windows the service runs in
// session 0 and cannot see the user's desktop, so its host starts a desktop
// helper ("openscale rdesk-helper") in the console session with the user's
// token; the helper asks the service for every decision over the local
// API. "openscale up" on Linux runs the server in the same process when an
// X11 display is available.

// Owner settings of the remote desktop; every switch is off by default.
const (
	rdeskSettingsFn       = "rdesk.json"
	rdeskRecordingKeyFile = "rdesk-recording.key"
	rdeskRecordingsDir    = "recordings"
	defaultRecordingDays  = 30
	maxRecordingDays      = 3650
	maxRecentSessions     = 20
)

// RemoteDesktopSettings are saved in apps/rdesk.json.
type RemoteDesktopSettings struct {
	Recording     bool `json:"recording,omitempty"`
	RecordingDays int  `json:"recording_days,omitempty"`
	LocalLock     bool `json:"local_lock,omitempty"`
	Power         bool `json:"power,omitempty"`
	// FileRoots are the folders a control session with a files rule may
	// browse and fetch from (ADR-0146 #435); empty refuses every request.
	FileRoots []string `json:"file_roots,omitempty"`
}

// Equal reports whether two settings are the same.
func (s RemoteDesktopSettings) Equal(o RemoteDesktopSettings) bool {
	return s.Recording == o.Recording && s.RecordingDays == o.RecordingDays && s.LocalLock == o.LocalLock &&
		s.Power == o.Power && slices.Equal(s.FileRoots, o.FileRoots)
}

// RecordingKeep is how long recordings are kept.
func (s RemoteDesktopSettings) RecordingKeep() time.Duration {
	d := s.RecordingDays
	if d <= 0 {
		d = defaultRecordingDays
	}
	return time.Duration(d) * 24 * time.Hour
}

// LoadRemoteDesktopSettings reads the owner's switches; a missing file is
// the defaults (everything off).
func LoadRemoteDesktopSettings(dir string) (RemoteDesktopSettings, error) {
	var s RemoteDesktopSettings
	err := loadJSON(filepath.Join(dir, AppsDir, rdeskSettingsFn), &s)
	if errors.Is(err, fs.ErrNotExist) {
		return RemoteDesktopSettings{}, nil
	}
	return s, err
}

// SaveRemoteDesktopSettings writes the switches (owner only).
func SaveRemoteDesktopSettings(dir string, s RemoteDesktopSettings) error {
	if s.RecordingDays < 0 || s.RecordingDays > maxRecordingDays {
		return fmt.Errorf("kayıt saklama süresi 1 ile %d gün arasında olmalı", maxRecordingDays)
	}
	if err := ValidateRDeskFileRoots(s.FileRoots); err != nil {
		return err
	}
	return saveJSON(filepath.Join(dir, AppsDir, rdeskSettingsFn), s)
}

// RecordingKeyPath is the device-local recording key under the data
// directory (never sent anywhere).
func RecordingKeyPath(dir string) string { return filepath.Join(dir, "keys", rdeskRecordingKeyFile) }

// RemoteDesktopEnv is what Apps gives a host for one run.
type RemoteDesktopEnv struct {
	Addr      netip.AddrPort
	Device    string
	Authorize rdesk.AuthorizeFunc
	OnEvent   func(rdesk.SessionEvent)
	Settings  RemoteDesktopSettings
	// Dir is the data (service) or state (openscale up) directory.
	Dir    string
	Logger *slog.Logger
}

// RemoteDesktopHost runs the remote desktop server for Apps.
type RemoteDesktopHost interface {
	// Serve runs until ctx ends or the server fails. ln listens on the
	// tunnel address; a host that serves from another process closes it.
	Serve(ctx context.Context, ln net.Listener, env RemoteDesktopEnv) error
	// Revalidate asks the server to check its sessions against the rules
	// again (the signed document changed).
	Revalidate()
	// Kind is "helper" or "inprocess".
	Kind() string
}

// RemoteDesktopServerOptions build an rdesk.Config for the helper and the
// in-process host.
type RemoteDesktopServerOptions struct {
	Addr      netip.AddrPort
	Authorize rdesk.AuthorizeFunc
	Consent   rdesk.ConsentFunc
	Indicator rdesk.IndicatorFunc
	Power     rdesk.PowerFunc
	// RecordingKey and RecordingDir turn recording on (both or neither).
	RecordingKey *rdesk.RecordingKey
	RecordingDir string
	LocalLock    bool
	// FileRoots are the owner's folders for the session file browser.
	FileRoots []string
	// Annotate shows viewers' marks; nil ignores them.
	Annotate rdesk.AnnotateFunc
	Logger   *slog.Logger
}

// BuildRemoteDesktopConfig returns the server configuration. Power and
// local lock are only set when the owner turned them on; recording only
// with a key and an absolute folder.
func BuildRemoteDesktopConfig(o RemoteDesktopServerOptions) (rdesk.Config, error) {
	if o.Authorize == nil || o.Indicator == nil {
		return rdesk.Config{}, errors.New("uzak masaüstü: yetkilendirme ve gösterge zorunlu")
	}
	if err := rdesk.ValidateListenAddr(o.Addr); err != nil {
		return rdesk.Config{}, err
	}
	cfg := rdesk.Config{
		ListenAddr: o.Addr,
		Authorize:  o.Authorize,
		Consent:    o.Consent,
		Indicator:  o.Indicator,
		Logger:     o.Logger,
		Power:      o.Power,
		Annotate:   o.Annotate,
	}
	if err := ValidateRDeskFileRoots(o.FileRoots); err != nil {
		return rdesk.Config{}, err
	}
	cfg.FileRoots = rdesk.FileRootsFromPaths(o.FileRoots)
	if o.LocalLock {
		cfg.NewLocalLock = rdesk.NewSystemLocalLock
	}
	if (o.RecordingKey == nil) != (o.RecordingDir == "") {
		return rdesk.Config{}, errors.New("uzak masaüstü: kayıt için anahtar ve klasör birlikte gerekli")
	}
	if o.RecordingKey != nil {
		if !filepath.IsAbs(o.RecordingDir) {
			return rdesk.Config{}, errors.New("uzak masaüstü: kayıt klasörü mutlak yol olmalı")
		}
		cfg.Recording = &rdesk.RecordingConfig{Dir: o.RecordingDir, Key: o.RecordingKey}
	}
	return cfg, nil
}

// rdeskDecision applies the rdesk rules to a session from dev on self.
func rdeskDecision(doc *trust.Document, self string, dev trust.Device, mode rdesk.Mode) rdesk.Decision {
	var m trust.RemoteDesktopMode
	switch mode {
	case rdesk.ModeView:
		m = trust.RemoteDesktopView
	case rdesk.ModeControl:
		m = trust.RemoteDesktopControl
	default:
		return rdesk.Decision{Peer: dev.Name, Reason: "geçersiz kip"}
	}
	if !doc.AllowsRemoteDesktop(dev.Name, self, m) {
		return rdesk.Decision{Peer: dev.Name, Reason: "kural izin vermiyor"}
	}
	return rdesk.Decision{Allowed: true, Peer: dev.Name, Unattended: doc.RemoteDesktopUnattended(dev.Name, self, m),
		// The session file browser needs a control session and a files
		// rule from the viewer (ADR-0146 #435).
		Files: mode == rdesk.ModeControl && doc.AllowsFileSend(dev.Name, self)}
}

func parseRDeskMode(s string) rdesk.Mode {
	switch s {
	case "view":
		return rdesk.ModeView
	case "control":
		return rdesk.ModeControl
	}
	return 0
}

// authorizeRDesk is the AuthorizeFunc of every host: the session's source
// must be a device of the current document other than this one.
func (a *Apps) authorizeRDesk(remote netip.Addr, mode rdesk.Mode) rdesk.Decision {
	doc, self, dev, ok := a.peer(remote)
	if !ok {
		return rdesk.Decision{Reason: "kaynak adres ağdaki bir cihaz değil"}
	}
	return rdeskDecision(doc, self.Name, dev, mode)
}

// rdeskTracker keeps the sessions for the panel and the log.
type rdeskTracker struct {
	mu     sync.Mutex
	active map[string]panel.RDeskSession
	recent []panel.RDeskSession
	now    func() time.Time
	log    *slog.Logger
}

func newRDeskTracker(now func() time.Time, log *slog.Logger) *rdeskTracker {
	return &rdeskTracker{active: map[string]panel.RDeskSession{}, now: now, log: log}
}

func sessionView(id string, ev rdesk.SessionEvent, at time.Time) panel.RDeskSession {
	return panel.RDeskSession{ID: id, Peer: ev.Peer, Mode: ev.Mode.String(), Unattended: ev.Unattended, Code: ev.Code,
		Recording: ev.Recording, Clipboard: ev.Clipboard, Blank: ev.LocalLock.Blank, InputLock: ev.LocalLock.Input, Started: at}
}

// event records a session event; source tells sessions of different
// helper runs apart.
func (t *rdeskTracker) event(source string, ev rdesk.SessionEvent) {
	id := source + "-" + strconv.FormatUint(ev.ID, 10)
	now := t.now().UTC()
	t.mu.Lock()
	defer t.mu.Unlock()
	switch ev.Kind {
	case rdesk.EventStart:
		t.active[id] = sessionView(id, ev, now)
		// Device name, mode, attended or not and the code go to the local
		// log; tunnel addresses never do (ADR-0055, ADR-0008).
		t.log.Info("remote desktop session started", "peer", ev.Peer, "mode", ev.Mode.String(), "unattended", ev.Unattended,
			"recording", ev.Recording, "code", ev.Code)
	case rdesk.EventChange:
		if s, ok := t.active[id]; ok {
			s.Clipboard, s.Blank, s.InputLock = ev.Clipboard, ev.LocalLock.Blank, ev.LocalLock.Input
			t.active[id] = s
		}
	case rdesk.EventEnd:
		s, ok := t.active[id]
		if !ok {
			s = sessionView(id, ev, now)
		}
		delete(t.active, id)
		s.Ended, s.Reason = &now, ev.Reason
		t.recent = append(t.recent, s)
		if len(t.recent) > maxRecentSessions {
			t.recent = t.recent[len(t.recent)-maxRecentSessions:]
		}
		t.log.Info("remote desktop session ended", "peer", s.Peer, "mode", s.Mode, "unattended", s.Unattended,
			"duration", now.Sub(s.Started).Round(time.Second).String(), "reason", ev.Reason)
	}
}

// endSource closes every session of a helper run that stopped.
func (t *rdeskTracker) endSource(source, reason string) {
	t.mu.Lock()
	var ids []string
	for id := range t.active {
		if len(id) > len(source) && id[:len(source)+1] == source+"-" {
			ids = append(ids, id)
		}
	}
	t.mu.Unlock()
	for _, id := range ids {
		n, _ := strconv.ParseUint(id[len(source)+1:], 10, 64)
		t.event(source, rdesk.SessionEvent{Kind: rdesk.EventEnd, ID: n, Reason: reason})
	}
}

func (t *rdeskTracker) snapshot() (active, recent []panel.RDeskSession) {
	t.mu.Lock()
	defer t.mu.Unlock()
	active = make([]panel.RDeskSession, 0, len(t.active))
	for _, s := range t.active {
		active = append(active, s)
	}
	slices.SortFunc(active, func(a, b panel.RDeskSession) int {
		if c := a.Started.Compare(b.Started); c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	})
	recent = make([]panel.RDeskSession, 0, len(t.recent))
	for i := len(t.recent) - 1; i >= 0; i-- {
		recent = append(recent, t.recent[i])
	}
	return active, recent
}

// InProcessRemoteDesktop runs the server in this process ("openscale up"
// with an X11 display). Consent nil refuses every attended session.
type InProcessRemoteDesktop struct {
	Consent   rdesk.ConsentFunc
	Indicator rdesk.IndicatorFunc

	mu  sync.Mutex
	srv *rdesk.Server
}

// Kind implements RemoteDesktopHost.
func (h *InProcessRemoteDesktop) Kind() string { return "inprocess" }

// Serve implements RemoteDesktopHost.
func (h *InProcessRemoteDesktop) Serve(ctx context.Context, ln net.Listener, env RemoteDesktopEnv) error {
	opts := RemoteDesktopServerOptions{
		Addr:      env.Addr,
		Authorize: env.Authorize,
		Consent:   h.Consent,
		Indicator: func(ev rdesk.SessionEvent) {
			if env.OnEvent != nil {
				env.OnEvent(ev)
			}
			if h.Indicator != nil {
				h.Indicator(ev)
			}
		},
		LocalLock: env.Settings.LocalLock,
		FileRoots: env.Settings.FileRoots,
		Logger:    env.Logger,
	}
	if env.Settings.Recording {
		key, err := rdesk.LoadOrCreateRecordingKey(RecordingKeyPath(env.Dir))
		if err != nil {
			_ = ln.Close()
			return err
		}
		opts.RecordingKey, opts.RecordingDir = key, filepath.Join(env.Dir, rdeskRecordingsDir)
		pruneRecordings(env.Logger, opts.RecordingDir, env.Settings.RecordingKeep())
	}
	cfg, err := BuildRemoteDesktopConfig(opts)
	if err != nil {
		_ = ln.Close()
		return err
	}
	srv, err := rdesk.New(cfg)
	if err != nil {
		_ = ln.Close()
		return err
	}
	h.mu.Lock()
	h.srv = srv
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		h.srv = nil
		h.mu.Unlock()
	}()
	return srv.Serve(ctx, ln)
}

// Revalidate implements RemoteDesktopHost.
func (h *InProcessRemoteDesktop) Revalidate() {
	h.mu.Lock()
	srv := h.srv
	h.mu.Unlock()
	if srv != nil {
		srv.Revalidate()
	}
}

// pruneRecordings removes recordings older than keep.
func pruneRecordings(log *slog.Logger, dir string, keep time.Duration) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if n, err := rdesk.PruneRecordings(dir, keep, time.Now()); err != nil && !errors.Is(err, fs.ErrNotExist) {
		log.Warn("remote desktop recordings could not be pruned", "error", err.Error())
	} else if n > 0 {
		log.Info("old remote desktop recordings removed", "count", n)
	}
}
