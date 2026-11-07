package winapp

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/piv"
	"github.com/openscale/openscale/internal/secmem"
	"github.com/openscale/openscale/internal/trust"
)

// YubiKey administrator mode in the tray (ADR-0223, with #678).
//
// The tray runs in the user's session. It polls the readers (no PIN, no
// signing), and when a token holding the network's root key or an
// administrator grant's key is plugged in it offers "Yönetici kipini aç".
// Only when the user chooses it is the PIN asked (secure desktop), the
// token opened and admin.OpenTokenSession run here, in this process: the
// PIN never goes to the service. A fresh challenge is signed at once, so a
// card that only claims the key cannot open the mode.
//
// The service learns only the state (open, role, key fingerprint, end) and
// sends signing requests; each one is checked (a network document of this
// network under the role's context), shown to the user and signed by the
// token. The session closes at once when the token is pulled, after 15
// minutes without use or at its end; the state is reported on every poll
// so the panel shows real data and treats a silent tray as closed.

// TokenTrust is the public data a session needs (from the service).
type TokenTrust struct {
	NetworkID string
	Root      ed25519.PublicKey
	Revoked   []string
	// Grant is an administrator grant for a non-root token (optional).
	Grant []byte
	// Admins are administrator keys the probe also looks for.
	Admins []ed25519.PublicKey
}

// TokenModeReport is the state the tray reports and shows.
type TokenModeReport struct {
	Open      bool
	Offer     bool
	Role      string
	Name      string
	Key       string
	Reader    string
	Started   time.Time
	Ends      time.Time
	IdleUntil time.Time
	Reason    string
}

// TokenSignRequest is one signing request from the service.
type TokenSignRequest struct {
	ID      string
	Context string
	Payload []byte
	Version uint64
	Summary string
}

// TokenModeChannel is the tray's side of the local channel.
type TokenModeChannel interface {
	Trust(ctx context.Context) (TokenTrust, error)
	Report(ctx context.Context, st TokenModeReport) error
	// NextSign waits for a request; nil with a nil error on timeout.
	NextSign(ctx context.Context) (*TokenSignRequest, error)
	SignResult(ctx context.Context, id string, sig []byte, reason string) error
}

// Close reasons of the token mode.
const (
	ReasonTokenIdle    = "15 dakika işlem yapılmadı"
	ReasonTokenExpired = "yönetici oturumunun süresi doldu"
	ReasonTokenUser    = "kullanıcı yönetici kipini kapattı"
)

// Defaults of the token mode.
const (
	DefaultTokenIdle    = 15 * time.Minute
	DefaultTokenMaxLife = 4 * time.Hour
	tokenTrustRefresh   = time.Minute
	tokenProofContext   = "openscale/token-session-proof/v1"
)

// Token mode errors.
var (
	ErrTokenModeNoToken = errors.New("yönetici anahtarı taşıyan bir jeton takılı değil")
	ErrTokenModeOpen    = errors.New("yönetici kipi zaten açık")
	ErrTokenModeProof   = errors.New("jeton sahiplik sınamasını imzalayamadı")
)

// TokenModeController runs the token mode. Set the fields before use.
type TokenModeController struct {
	// Probe reports the token; keys are the root and administrator keys.
	Probe func(ctx context.Context, keys []ed25519.PublicKey) (piv.PresenceResult, error)
	// Channel talks to the service.
	Channel TokenModeChannel
	// AskPIN asks the PIN (secure desktop in the tray); the controller
	// destroys the buffer when the session ends.
	AskPIN func(ctx context.Context) (*secmem.Buffer, error)
	// OpenToken connects to the token in reader; pin returns a copy of
	// the PIN each time the token needs it.
	OpenToken func(ctx context.Context, reader string, pin func() ([]byte, error)) (admin.TokenSigner, error)
	// Confirm asks the user before each signature.
	Confirm func(text string) bool
	// Notify shows a tray balloon (optional).
	Notify func(msg string)
	// OnChange is called after a state change (optional).
	OnChange func(TokenModeReport)
	Idle     time.Duration
	MaxLife  time.Duration
	Now      func() time.Time

	mu        sync.Mutex
	session   *admin.TokenSession
	pin       *secmem.Buffer
	trust     TokenTrust
	trustAt   time.Time
	trustFail time.Time
	lastProbe piv.PresenceResult
	state     TokenModeReport
}

func (c *TokenModeController) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// State returns the current state.
func (c *TokenModeController) State() TokenModeReport {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

// trustInfo returns the cached trust data, refreshed every minute.
func (c *TokenModeController) trustInfo(ctx context.Context) (TokenTrust, error) {
	c.mu.Lock()
	t, at := c.trust, c.trustAt
	c.mu.Unlock()
	now := c.now()
	if !at.IsZero() && now.Sub(at) < tokenTrustRefresh && !now.Before(at) {
		return t, nil
	}
	c.mu.Lock()
	failed := c.trustFail
	c.mu.Unlock()
	if !failed.IsZero() && now.Sub(failed) < tokenTrustRefresh && !now.Before(failed) {
		// Not an administrator computer (or no service): ask again later.
		return TokenTrust{}, errors.New("ağ güven bilgisi alınamadı")
	}
	t, err := c.Channel.Trust(ctx)
	if err != nil {
		c.mu.Lock()
		c.trustFail = now
		c.mu.Unlock()
		return TokenTrust{}, err
	}
	if len(t.Root) != ed25519.PublicKeySize || t.NetworkID == "" {
		return TokenTrust{}, errors.New("servis geçersiz kök anahtarı bildirdi")
	}
	c.mu.Lock()
	c.trust, c.trustAt, c.trustFail = t, now, time.Time{}
	c.mu.Unlock()
	return t, nil
}

// Step polls once, closes a session that must end, updates the offer and
// reports the state to the service (the report doubles as a heartbeat).
func (c *TokenModeController) Step(ctx context.Context) TokenModeReport {
	var res piv.PresenceResult
	t, err := c.trustInfo(ctx)
	if err == nil {
		keys := append([]ed25519.PublicKey{t.Root}, t.Admins...)
		res, err = c.Probe(ctx, keys)
	}
	if err != nil {
		res = piv.PresenceResult{Match: -1} // fail closed
	}
	c.mu.Lock()
	prev := c.state
	c.lastProbe = res
	sess := c.session
	c.mu.Unlock()

	if sess != nil {
		switch {
		case !res.Admin():
			c.closeSession(ReasonTokenRemoved)
		case !sess.Active():
			reason := ReasonTokenIdle
			if !c.now().Before(sess.Info().Ends) {
				reason = ReasonTokenExpired
			}
			c.closeSession(reason)
		}
	}
	c.mu.Lock()
	next := c.snapshotLocked()
	next.Offer = c.session == nil && res.Admin()
	next.Reader = res.Reader
	c.state = next
	c.mu.Unlock()
	if next.Offer && !prev.Offer && c.Notify != nil {
		c.Notify("Yönetici anahtarı takıldı. Yönetici kipine geçmek için tepsi menüsünden \"Yönetici kipini aç\" seçeneğini kullanın.")
	}
	c.report(ctx, next, prev)
	return next
}

// snapshotLocked builds the state from the session.
func (c *TokenModeController) snapshotLocked() TokenModeReport {
	st := TokenModeReport{Reason: c.state.Reason, Reader: c.state.Reader}
	if c.session == nil {
		return st
	}
	info := c.session.Info()
	st.Open = info.Active
	st.Role, st.Name = info.Role, info.Name
	st.Started, st.Ends = info.Started, info.Ends
	st.IdleUntil = c.session.IdleUntil()
	st.Key = admin.KeyFingerprint(c.session.PublicKey())
	st.Reason = ""
	return st
}

func (c *TokenModeController) report(ctx context.Context, next, prev TokenModeReport) {
	_ = c.Channel.Report(ctx, next) // the service treats a silent tray as closed
	if c.OnChange != nil && !sameReport(next, prev) {
		c.OnChange(next)
	}
}

func sameReport(a, b TokenModeReport) bool {
	return a.Open == b.Open && a.Offer == b.Offer && a.Role == b.Role && a.Key == b.Key && a.Reason == b.Reason && a.Ends.Equal(b.Ends)
}

// Enable is the "Yönetici kipini aç" item: PIN, token session, proof of
// possession, report.
func (c *TokenModeController) Enable(ctx context.Context) error {
	c.mu.Lock()
	open, res := c.session != nil, c.lastProbe
	c.mu.Unlock()
	if open {
		return ErrTokenModeOpen
	}
	if !res.Admin() {
		return ErrTokenModeNoToken
	}
	t, err := c.trustInfo(ctx)
	if err != nil {
		return err
	}
	pin, err := c.AskPIN(ctx)
	if err != nil {
		return err
	}
	pinCopy := func() ([]byte, error) {
		var out []byte
		err := pin.Use(func(b []byte) error { out = slices.Clone(b); return nil })
		return out, err
	}
	var signer admin.TokenSigner
	opener := func(ctx context.Context) (admin.TokenSigner, error) {
		s, err := c.OpenToken(ctx, res.Reader, pinCopy)
		signer = s
		return s, err
	}
	idle, life := c.Idle, c.MaxLife
	if idle <= 0 {
		idle = DefaultTokenIdle
	}
	if life <= 0 {
		life = DefaultTokenMaxLife
	}
	sess, err := admin.OpenTokenSession(ctx, opener, t.Root, t.NetworkID, t.Grant, t.Revoked, admin.SessionOptions{Idle: idle, MaxLife: life, Now: c.now})
	if err != nil {
		pin.Destroy()
		return fmt.Errorf("yönetici oturumu açılamadı: %w", err)
	}
	if err := proveToken(signer); err != nil {
		sess.Close()
		pin.Destroy()
		return err
	}
	c.mu.Lock()
	prev := c.state
	c.session, c.pin = sess, pin
	next := c.snapshotLocked()
	next.Reader = res.Reader
	c.state = next
	c.mu.Unlock()
	c.report(ctx, next, prev)
	return nil
}

// proveToken signs a random challenge: a card that only reports the key
// cannot produce a valid signature.
func proveToken(signer admin.TokenSigner) error {
	if signer == nil {
		return ErrTokenModeProof
	}
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return err
	}
	msg, err := trust.DigestMessage(tokenProofContext, challenge)
	if err != nil {
		return err
	}
	sig, err := signer.SignMessage(msg)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrTokenModeProof, err)
	}
	if len(sig) != ed25519.SignatureSize || !ed25519.Verify(signer.PublicKey(), msg, sig) {
		return ErrTokenModeProof
	}
	return nil
}

// Disable is the "Yönetici kipini kapat" item.
func (c *TokenModeController) Disable(ctx context.Context) {
	c.mu.Lock()
	prev := c.state
	c.mu.Unlock()
	c.closeSession(ReasonTokenUser)
	c.mu.Lock()
	next := c.snapshotLocked()
	next.Offer = c.lastProbe.Admin()
	c.state = next
	c.mu.Unlock()
	c.report(ctx, next, prev)
}

// closeSession ends the session and wipes the PIN.
func (c *TokenModeController) closeSession(reason string) {
	c.mu.Lock()
	sess, pin := c.session, c.pin
	c.session, c.pin = nil, nil
	if sess != nil {
		c.state.Reason = reason
		c.state.Open = false
	}
	c.mu.Unlock()
	if sess != nil {
		sess.Close()
		if c.Notify != nil {
			c.Notify("Yönetici kipi kapandı: " + reason + ".")
		}
	}
	if pin != nil {
		pin.Destroy()
	}
}

// HandleSign answers one request: the request is checked, shown to the
// user and signed by the token.
func (c *TokenModeController) HandleSign(ctx context.Context, req *TokenSignRequest) error {
	sig, reason := c.sign(req)
	return c.Channel.SignResult(ctx, req.ID, sig, reason)
}

func (c *TokenModeController) sign(req *TokenSignRequest) ([]byte, string) {
	c.mu.Lock()
	sess, t := c.session, c.trust
	c.mu.Unlock()
	if sess == nil || !sess.Active() {
		return nil, "Yönetici oturumu açık değil."
	}
	version, err := sess.DescribePayload(req.Context, req.Payload, t.NetworkID)
	if err != nil {
		return nil, "Tepsi bu imza isteğini reddetti: istenen veri bu ağın belgesi değil."
	}
	text := fmt.Sprintf("Ağ belgesi sürüm %d YubiKey ile imzalansın mı?\n\n%s\n\nOnaylarsanız jetona dokunmanız istenebilir.", version, req.Summary)
	if c.Confirm == nil || !c.Confirm(text) {
		return nil, "İmza tepside reddedildi."
	}
	sp, err := sess.SignPayload(req.Context, req.Payload, t.NetworkID)
	if err != nil {
		if errors.Is(err, admin.ErrSessionClosed) {
			return nil, "Yönetici oturumu kapandı."
		}
		return nil, "Jeton imzalayamadı: " + err.Error()
	}
	return sp.Signature, ""
}

// Run polls every poll and serves signing requests until ctx ends; then
// the session is closed and reported.
func (c *TokenModeController) Run(ctx context.Context, poll time.Duration) error {
	if c.Probe == nil || c.Channel == nil || c.AskPIN == nil || c.OpenToken == nil {
		return ErrNoChecker
	}
	if poll <= 0 {
		poll = DefaultTokenPoll
	}
	go c.serveSigning(ctx)
	t := time.NewTicker(poll)
	defer t.Stop()
	for {
		c.Step(ctx)
		select {
		case <-ctx.Done():
			c.closeSession(ReasonStopped)
			c.mu.Lock()
			st := c.snapshotLocked()
			c.mu.Unlock()
			rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
			_ = c.Channel.Report(rctx, st)
			cancel()
			return ctx.Err()
		case <-t.C:
		}
	}
}

func (c *TokenModeController) serveSigning(ctx context.Context) {
	for ctx.Err() == nil {
		req, err := c.Channel.NextSign(ctx)
		if err != nil || req == nil {
			if err != nil {
				select {
				case <-ctx.Done():
					return
				case <-time.After(2 * time.Second):
				}
			}
			continue
		}
		_ = c.HandleSign(ctx, req)
	}
}
