package openscale

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/node"
)

// Tunnel is one running OpenScale connection inside the app's VpnService.
// Its methods are safe for concurrent use.
type Tunnel struct {
	stateDir string
	platform Platform

	mu      sync.Mutex
	engine  *node.Engine
	cancel  context.CancelFunc
	done    chan struct{}
	lastErr string
	exit    string
}

// NewTunnel prepares a tunnel for a joined state directory.
func NewTunnel(stateDir string, platform Platform) (*Tunnel, error) {
	if err := checkStateDir(stateDir); err != nil {
		return nil, err
	}
	if platform == nil {
		return nil, errors.New("platform gerekli")
	}
	return &Tunnel{stateDir: stateDir, platform: platform}, nil
}

// platformWriter turns the engine's JSON log records into Platform.Log
// calls; slog's JSON handler writes one record per Write.
type platformWriter struct{ p Platform }

func (w platformWriter) Write(b []byte) (int, error) {
	var rec struct {
		Level string `json:"level"`
	}
	level := LogInfo
	if json.Unmarshal(b, &rec) == nil {
		switch rec.Level {
		case "DEBUG":
			level = LogDebug
		case "WARN":
			level = LogWarn
		case "ERROR":
			level = LogError
		}
	}
	line := string(b)
	if n := len(line); n > 0 && line[n-1] == '\n' {
		line = line[:n-1]
	}
	w.p.Log(level, line)
	return len(b), nil
}

// Start runs the engine on the VPN interface tunFD. This package owns
// tunFD from the call on (the app detaches it from its
// ParcelFileDescriptor) and closes it on every error and on Stop. secrets
// is the decrypted device key file; options must be the string Plan was
// called with.
func (t *Tunnel) Start(tunFD int, secrets []byte, options string) (err error) {
	owned := true
	defer func() {
		if owned && tunFD >= 0 {
			closeFD(tunFD)
		}
	}()
	if tunFD < 0 {
		return errors.New("geçersiz VPN arayüzü")
	}
	o, err := parseOptions(options)
	if err != nil {
		return err
	}
	t.mu.Lock()
	running := t.engine != nil
	t.mu.Unlock()
	if running {
		return errors.New("tünel zaten çalışıyor")
	}
	store, err := member.Open(t.stateDir)
	if err != nil {
		return err
	}
	s, err := parseSecrets(secrets)
	if err != nil {
		return err
	}
	keep := false
	defer func() {
		if !keep {
			wipeSecrets(s)
		}
	}()
	doc := store.Document()
	self, err := selfDevice(doc, s)
	if err != nil {
		return err
	}
	if doc.Coordinator == nil {
		return errors.New("ağ belgesinde koordinatör yok")
	}
	// The routes the app installed came from the same options; refuse an
	// exit node the document no longer allows rather than run without it.
	if _, err := planFor(doc, self, o, time.Now()); err != nil {
		return err
	}
	dev, err := tunFromFD(tunFD)
	if err != nil {
		return fmt.Errorf("VPN arayüzü açılamadı: %w", err)
	}
	owned = false // dev owns the descriptor now
	level := slog.LevelInfo
	if o.Debug {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewJSONHandler(platformWriter{t.platform}, &slog.HandlerOptions{Level: level}))
	cfg := node.Config{
		Store:      store,
		Secrets:    s,
		TUN:        dev,
		Bind:       &protectBind{Bind: node.DefaultBind(), protect: t.platform.Protect},
		Logger:     logger,
		ExitNode:   o.ExitNode,
		MTU:        o.MTU,
		ForceRelay: o.ForceRelay,
		// Android has no gateway table to read without privileges, and
		// the system's own captive portal handling runs before the VPN.
		DisableCaptiveCheck: true,
		// The phone's LAN and mobile addresses change all the time and
		// say where the owner is; only the coordinator-observed endpoint
		// is reported.
		HideLocalCandidates: true,
	}
	profileFor(o.batterySaver()).apply(&cfg)
	engine, err := node.New(cfg)
	if err != nil {
		_ = dev.Close()
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	t.mu.Lock()
	if t.engine != nil {
		t.mu.Unlock()
		cancel()
		_ = dev.Close()
		return errors.New("tünel zaten çalışıyor")
	}
	t.engine, t.cancel, t.done, t.lastErr, t.exit = engine, cancel, done, "", o.ExitNode
	t.mu.Unlock()
	keep = true
	go func() {
		defer close(done)
		runErr := engine.Run(ctx)
		wipeSecrets(s)
		t.mu.Lock()
		if runErr != nil && !errors.Is(runErr, context.Canceled) {
			t.lastErr = runErr.Error()
		}
		t.engine, t.cancel = nil, nil
		t.mu.Unlock()
		t.platform.StatusChanged(t.Status())
	}()
	t.platform.StatusChanged(t.Status())
	return nil
}

// Stop ends the tunnel and waits until the engine has released the VPN
// interface. Stopping a stopped tunnel does nothing.
func (t *Tunnel) Stop() {
	t.mu.Lock()
	cancel, done := t.cancel, t.done
	t.mu.Unlock()
	if cancel == nil {
		return
	}
	cancel()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
	}
}

// Running reports whether the engine runs.
func (t *Tunnel) Running() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.engine != nil
}

// NetworkChanged tells the engine the phone switched networks (Wi-Fi to
// mobile data and back), so paths are probed again at once instead of at
// the next keepalive.
func (t *Tunnel) NetworkChanged() {
	t.mu.Lock()
	e := t.engine
	t.mu.Unlock()
	if e != nil {
		e.ForceReconnect()
	}
}

type tunnelStatus struct {
	Running         bool      `json:"running"`
	ExitNode        string    `json:"exit_node,omitempty"`
	Peers           int       `json:"peers"`
	DocumentVersion uint64    `json:"document_version,omitempty"`
	DocumentExpired bool      `json:"document_expired,omitempty"`
	LastSync        time.Time `json:"last_sync,omitzero"`
	LastSyncError   string    `json:"last_sync_error,omitempty"`
	Error           string    `json:"error,omitempty"`
}

// Status returns the tunnel state as JSON.
func (t *Tunnel) Status() string {
	t.mu.Lock()
	e, lastErr, exit := t.engine, t.lastErr, t.exit
	t.mu.Unlock()
	st := tunnelStatus{Running: e != nil, Error: lastErr}
	if e != nil {
		s := e.Status()
		st.ExitNode, st.Peers, st.DocumentVersion, st.DocumentExpired = s.ExitNode, s.Peers, s.DocumentVersion, s.Expired
		st.LastSync, st.LastSyncError = s.LastSync, s.LastSyncError
		if st.ExitNode == "" {
			st.ExitNode = exit
		}
	}
	out, err := json.Marshal(st)
	if err != nil {
		return `{"running":false}`
	}
	return string(out)
}
