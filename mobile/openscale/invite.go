package openscale

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/node"
	"github.com/openscale/openscale/internal/trust"
)

// InviteObserver is implemented by the app while it joins with an invite
// code (scanned from the owner's screen, #182).
type InviteObserver interface {
	// Waiting is called once the coordinator holds the enrollment: the
	// owner approves it in the panel after comparing shortCode, and may
	// also compare the 20-digit sas (ADR-0062).
	Waiting(shortCode, sas string)
	// Log receives one JSON log line; level is LogDebug..LogError.
	Log(level int, line string)
}

// inviteJoinTimeout bounds a join; an invite lives at most 7 days but the
// owner approves while the phone waits on screen.
const inviteJoinTimeout = 30 * time.Minute

// InviteJoin joins a network with an invite code (ADR-0014) without a
// VPN interface: only the coordinator is reachable, through a userspace
// WireGuard tunnel keyed by the invite. The app runs Run on a background
// thread and may Cancel it from another.
type InviteJoin struct {
	stateDir string
	observer InviteObserver

	mu       sync.Mutex
	cancel   context.CancelFunc
	canceled bool
}

// NewInviteJoin prepares a join into stateDir (not yet joined).
func NewInviteJoin(stateDir string, observer InviteObserver) (*InviteJoin, error) {
	if err := checkStateDir(stateDir); err != nil {
		return nil, err
	}
	if observer == nil {
		return nil, errors.New("gözlemci gerekli")
	}
	return &InviteJoin{stateDir: stateDir, observer: observer}, nil
}

// Run submits the enrollment and blocks until the owner approved it (the
// join summary JSON is returned, as Join does), the invite is gone, the
// join timed out or Cancel was called.
func (j *InviteJoin) Run(secrets []byte, inviteCode, hostname string) (string, error) {
	if len(hostname) > maxHostname {
		return "", errors.New("cihaz adı çok uzun")
	}
	if IsJoined(j.stateDir) {
		return "", errors.New("bu uygulama zaten bir ağa katılmış")
	}
	code, err := trust.DecodeInviteCode(strings.TrimSpace(inviteCode))
	if err != nil {
		return "", err
	}
	s, err := parseSecrets(secrets)
	if err != nil {
		return "", err
	}
	defer wipeSecrets(s)
	sas, err := s.SAS()
	if err != nil {
		return "", err
	}

	ctx, cancel := context.WithTimeout(context.Background(), inviteJoinTimeout)
	defer cancel()
	j.mu.Lock()
	if j.canceled {
		j.mu.Unlock()
		return "", context.Canceled
	}
	j.cancel = cancel
	j.mu.Unlock()

	logger := slog.New(slog.NewJSONHandler(platformWriter{logOnly{j.observer}}, &slog.HandlerOptions{Level: slog.LevelInfo}))
	store, err := node.JoinWithInvite(ctx, node.InviteJoinConfig{
		Code:     code,
		Secrets:  s,
		Hostname: hostname,
		StateDir: j.stateDir,
		Logger:   logger,
		OnWaiting: func(req *trust.EnrollmentRequest) {
			j.observer.Waiting(req.ShortCode(), sas)
		},
	})
	if err != nil {
		return "", err
	}
	doc := store.Document()
	out, err := json.Marshal(joinSummary{NetworkID: doc.NetworkID, Version: doc.Version, Domain: doc.DNSDomain})
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// Cancel stops a running or upcoming Run.
func (j *InviteJoin) Cancel() {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.canceled = true
	if j.cancel != nil {
		j.cancel()
	}
}

// logOnly adapts an InviteObserver to the Platform the log writer needs.
type logOnly struct{ o InviteObserver }

func (l logOnly) Protect(int) bool        { return true }
func (l logOnly) Log(level int, s string) { l.o.Log(level, s) }
func (l logOnly) StatusChanged(string)    {}
