package admin

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"errors"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/trust"
)

// Token administrator session (ADR-0172). When the owner plugs in a token
// that holds the root key or a granted administrator key, the tray and the
// desktop window (G4) open a session through this API and switch to
// administrator mode; pulling the token, idling or the grant's end closes
// it. The session holds only the open token handle: every signature still
// goes to the token (PIN and touch as the token is configured), and no key
// material is ever in this process.

// TokenSigner is a key on a hardware token; piv.CardToken satisfies it.
type TokenSigner interface {
	trust.DigestSigner
	Close() error
}

// TokenOpener connects to the token (G4 passes a piv.OpenToken wrapper).
type TokenOpener func(ctx context.Context) (TokenSigner, error)

// Session roles.
const (
	SessionRoot  = "root"
	SessionAdmin = "admin"
)

// Session errors.
var (
	ErrSessionClosed = errors.New("the token session has ended")
	ErrSessionRole   = errors.New("the token session cannot do this")
)

// SessionOptions bounds a session.
type SessionOptions struct {
	// Idle ends the session after this long without use (default 10m).
	Idle time.Duration
	// MaxLife ends it this long after it started (default 8h).
	MaxLife time.Duration
	// Now is the clock (default time.Now).
	Now func() time.Time
}

// SessionInfo describes an open session for the tray and the panel.
type SessionInfo struct {
	Role       string          `json:"role"`
	Name       string          `json:"name,omitempty"`
	Operations []trust.AdminOp `json:"operations,omitempty"`
	Tags       []string        `json:"tags,omitempty"`
	Started    time.Time       `json:"started"`
	Ends       time.Time       `json:"ends"`
	Active     bool            `json:"active"`
}

// TokenSession is an administrator session bound to a plugged-in token.
type TokenSession struct {
	mu      sync.Mutex
	signer  TokenSigner
	role    string
	grant   *trust.SignedGrant
	started time.Time
	lastUse time.Time
	ends    time.Time
	opts    SessionOptions
	closed  bool
}

// OpenTokenSession opens the token and decides the role: the root key, or
// the key of grantData (verified against root, unexpired, not revoked).
// grantData may be nil when only a root session is wanted.
func OpenTokenSession(ctx context.Context, opener TokenOpener, root ed25519.PublicKey, networkID string, grantData []byte, revoked []string, opts SessionOptions) (*TokenSession, error) {
	if opener == nil {
		return nil, errors.New("no token opener")
	}
	if opts.Idle <= 0 {
		opts.Idle = 10 * time.Minute
	}
	if opts.MaxLife <= 0 {
		opts.MaxLife = 8 * time.Hour
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	signer, err := opener(ctx)
	if err != nil {
		return nil, err
	}
	now := opts.Now()
	s := &TokenSession{signer: signer, started: now, lastUse: now, ends: now.Add(opts.MaxLife), opts: opts}
	pub := signer.PublicKey()
	switch {
	case subtle.ConstantTimeCompare(pub, root) == 1:
		s.role = SessionRoot
	case grantData != nil:
		g, err := trust.CheckAdminGrant(grantData, root, networkID, "", now, revoked)
		if err != nil {
			_ = signer.Close()
			return nil, err
		}
		if subtle.ConstantTimeCompare(pub, g.Key[:]) != 1 || g.Algorithm != trust.AlgEd25519Digest {
			_ = signer.Close()
			return nil, trust.ErrAdminMismatch
		}
		s.role = SessionAdmin
		s.grant = &trust.SignedGrant{Grant: *g, Encoded: append([]byte(nil), grantData...)}
		if g.NotAfter.Before(s.ends) {
			s.ends = g.NotAfter
		}
	default:
		_ = signer.Close()
		return nil, ErrTokenKeyMismatch
	}
	return s, nil
}

// activeLocked ends the session when it idled or passed its end.
func (s *TokenSession) activeLocked() bool {
	if s.closed {
		return false
	}
	now := s.opts.Now()
	if !now.Before(s.ends) || now.Sub(s.lastUse) >= s.opts.Idle {
		s.closeLocked()
		return false
	}
	return true
}

func (s *TokenSession) closeLocked() {
	if !s.closed {
		s.closed = true
		_ = s.signer.Close()
	}
}

// Active reports whether the session can still sign.
func (s *TokenSession) Active() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.activeLocked()
}

// Info describes the session.
func (s *TokenSession) Info() SessionInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	info := SessionInfo{Role: s.role, Started: s.started, Ends: s.ends, Active: s.activeLocked()}
	if s.grant != nil {
		info.Name, info.Operations, info.Tags = s.grant.Grant.Name, s.grant.Grant.Operations, s.grant.Grant.Tags
	}
	return info
}

// Grant returns the administrator grant (nil for a root session).
func (s *TokenSession) Grant() *trust.SignedGrant {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.grant
}

// Close ends the session (token pulled, user logged out).
func (s *TokenSession) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closeLocked()
}

func (s *TokenSession) use(role string) (TokenSigner, error) {
	if !s.activeLocked() {
		return nil, ErrSessionClosed
	}
	if s.role != role {
		return nil, ErrSessionRole
	}
	s.lastUse = s.opts.Now()
	return s.signer, nil
}

// SignAdminPlan signs an administrator plan with the session's token.
func (s *TokenSession) SignAdminPlan(plan *AdminPlan) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	signer, err := s.use(SessionAdmin)
	if err != nil {
		return nil, err
	}
	if plan == nil || plan.ctx == nil || plan.ctx.Grant.Grant.ID != s.grant.Grant.ID {
		return nil, ErrSessionRole
	}
	return SignAdminPlanWith(plan, signer)
}

// CommitRoot signs an owner plan with the root key on the token.
func (s *TokenSession) CommitRoot(n *Network, plan *Plan) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	signer, err := s.use(SessionRoot)
	if err != nil {
		return err
	}
	return n.CommitWith(plan, signer)
}
