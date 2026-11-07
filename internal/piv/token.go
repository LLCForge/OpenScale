package piv

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"
)

// Kind names the card application that holds the key.
type Kind string

const (
	KindAuto    Kind = ""
	KindPIV     Kind = "piv"     // YubiKey 5.7+, PIV slot with Ed25519
	KindOpenPGP Kind = "openpgp" // YubiKey 5.2.3+, OpenPGP signature key
)

// Token is an Ed25519 signing key on a hardware token, whichever card
// application holds it (ADR-0171). Sign returns only signatures that verify
// under PublicKey; SignMessage is the same call so a Token is a
// trust.DigestSigner.
type Token interface {
	Kind() Kind
	// Version is the firmware version; zero when the card did not tell.
	Version() Version
	PublicKey() ed25519.PublicKey
	Sign(msg []byte) ([]byte, error)
	SignMessage(msg []byte) ([]byte, error)
}

// ErrNoEd25519Key is returned when neither application holds an Ed25519
// key that this package can use.
var ErrNoEd25519Key = errors.New("the token holds no usable Ed25519 key (PIV 5.7+ slot or OpenPGP signature key)")

// TokenOptions selects and unlocks a token key.
type TokenOptions struct {
	// Reader is a reader name or substring; empty picks the first Yubico
	// reader.
	Reader string
	// Kind forces an application; KindAuto prefers PIV when the firmware
	// is 5.7+ and the slot holds Ed25519, else OpenPGP.
	Kind Kind
	// Slot is the PIV slot; zero means SlotSignature (9C).
	Slot byte
	// PIN is asked for before every signature (PIV PIN or OpenPGP PW1).
	PIN func() ([]byte, error)
}

func (o TokenOptions) slot() byte {
	if o.Slot == 0 {
		return SlotSignature
	}
	return o.Slot
}

type pivToken struct {
	s *Signer
	v Version
}

func (p *pivToken) Kind() Kind                             { return KindPIV }
func (p *pivToken) Version() Version                       { return p.v }
func (p *pivToken) PublicKey() ed25519.PublicKey           { return p.s.PublicKey() }
func (p *pivToken) Sign(msg []byte) ([]byte, error)        { return p.s.SignMessage(msg) }
func (p *pivToken) SignMessage(msg []byte) ([]byte, error) { return p.s.SignMessage(msg) }

type openPGPToken struct{ s *OpenPGPSigner }

func (o *openPGPToken) Kind() Kind                             { return KindOpenPGP }
func (o *openPGPToken) Version() Version                       { return o.s.version }
func (o *openPGPToken) PublicKey() ed25519.PublicKey           { return o.s.PublicKey() }
func (o *openPGPToken) Sign(msg []byte) ([]byte, error)        { return o.s.SignMessage(msg) }
func (o *openPGPToken) SignMessage(msg []byte) ([]byte, error) { return o.s.SignMessage(msg) }

// tryPIV returns a PIV token when the firmware is 5.7+ and slot holds an
// Ed25519 key; ok is false (with a nil error) when PIV does not apply.
func tryPIV(t Transport, o TokenOptions) (Token, bool, error) {
	c, err := NewClient(t)
	if err != nil {
		return nil, false, nil // no PIV application
	}
	v, err := c.Version()
	if err != nil || !v.AtLeast(MinEd25519Firmware) {
		return nil, false, nil
	}
	s, err := NewSigner(c, o.slot(), o.PIN)
	if errors.Is(err, ErrNotEd25519Slot) || isNotFound(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return &pivToken{s: s, v: v}, true, nil
}

func tryOpenPGP(t Transport, o TokenOptions) (Token, bool, error) {
	c, err := NewOpenPGPClient(t)
	if err != nil {
		return nil, false, nil
	}
	s, err := NewOpenPGPSigner(c, o.PIN)
	if errors.Is(err, ErrNoSignatureKey) || errors.Is(err, ErrNotEd25519Key) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return &openPGPToken{s: s}, true, nil
}

func isNotFound(err error) bool {
	var se *StatusError
	return errors.As(err, &se) && (se.SW == swFileNotFound || se.SW == swDataNotFound)
}

// NewToken picks the application on an already connected transport.
func NewToken(t Transport, o TokenOptions) (Token, error) {
	if o.Kind != KindOpenPGP {
		tok, ok, err := tryPIV(t, o)
		if err != nil {
			return nil, err
		}
		if ok {
			return tok, nil
		}
		if o.Kind == KindPIV {
			return nil, fmt.Errorf("%w: no Ed25519 key in PIV slot %02X (firmware 5.7+ required)", ErrNoEd25519Key, o.slot())
		}
	}
	tok, ok, err := tryOpenPGP(t, o)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrNoEd25519Key
	}
	return tok, nil
}

// CardToken is a Token on a PC/SC connection; Close ends the session and
// resets the card.
type CardToken struct {
	Token
	Reader string
	card   *Card
}

// Close resets the card and releases the connection.
func (c *CardToken) Close() error {
	if c.card == nil {
		return nil
	}
	err := c.card.Close()
	c.card = nil
	return err
}

// OpenToken connects to a reader and picks the application (TokenOptions).
// The card stays in one PC/SC transaction until Close.
func OpenToken(ctx context.Context, o TokenOptions) (*CardToken, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	readers, err := Readers()
	if err != nil {
		return nil, err
	}
	name, err := pickReader(readers, o.Reader)
	if err != nil {
		return nil, err
	}
	card, err := openCard(name, true)
	if err != nil {
		return nil, err
	}
	tok, err := NewToken(card, o)
	if err != nil {
		card.Close()
		return nil, err
	}
	return &CardToken{Token: tok, Reader: name, card: card}, nil
}

// ChooseImportBackend tells which application a root key should be
// imported into: PIV on 5.7+, OpenPGP on 5.2.3+ (or a card without the
// Yubico version extension), otherwise an error.
func ChooseImportBackend(t Transport) (Kind, Version, error) {
	if c, err := NewClient(t); err == nil {
		if v, err := c.Version(); err == nil && v.AtLeast(MinEd25519Firmware) {
			return KindPIV, v, nil
		}
	}
	c, err := NewOpenPGPClient(t)
	if err != nil {
		return "", Version{}, fmt.Errorf("neither PIV 5.7+ nor OpenPGP is available: %w", err)
	}
	v, err := c.CheckEd25519Support()
	if err != nil {
		return "", v, err
	}
	return KindOpenPGP, v, nil
}

// PresenceResult describes a token found by Presence.
type PresenceResult struct {
	// Present is true when a matching reader exists.
	Present bool
	Reader  string
	// Kind and PublicKey are set when an Ed25519 key was read.
	Kind      Kind
	Version   Version
	PublicKey ed25519.PublicKey
	// Match is the index into PresenceOptions.Keys of the key the token
	// holds, or -1.
	Match int
}

// Admin reports whether the token holds one of the expected keys.
func (r PresenceResult) Admin() bool { return r.Match >= 0 }

// PresenceOptions configures Presence.
type PresenceOptions struct {
	Reader string // substring; empty means "yubico"
	Slot   byte   // PIV slot; zero means 9C
	// Keys are the OpenScale root and administrator public keys to look
	// for.
	Keys []ed25519.PublicKey
}

// ProbeTransport reads, without a PIN, which Ed25519 key the card holds:
// PIV GET VERSION + GET METADATA on 5.7+, otherwise the OpenPGP signature
// public key. It never verifies a PIN or signs.
func ProbeTransport(t Transport, o PresenceOptions) PresenceResult {
	res := PresenceResult{Present: true, Match: -1}
	if c, err := NewClient(t); err == nil {
		if v, err := c.Version(); err == nil {
			res.Version = v
			if v.AtLeast(MinEd25519Firmware) {
				slot := o.Slot
				if slot == 0 {
					slot = SlotSignature
				}
				if pub, err := c.Ed25519PublicKey(slot); err == nil {
					res.Kind, res.PublicKey = KindPIV, pub
				}
			}
		}
	}
	if res.PublicKey == nil {
		if c, err := NewOpenPGPClient(t); err == nil {
			if pub, err := c.SignaturePublicKey(); err == nil {
				res.Kind, res.PublicKey = KindOpenPGP, pub
				if v, ok, err := c.Version(); err == nil && ok {
					res.Version = v
				}
			}
		}
	}
	if res.PublicKey != nil {
		for i, k := range o.Keys {
			if len(k) == ed25519.PublicKeySize && subtle.ConstantTimeCompare(k, res.PublicKey) == 1 {
				res.Match = i
				break
			}
		}
	}
	return res
}

// Presence lists the readers and probes each matching one (at most 8) until
// one holds an expected key; the card is left as it was (no reset, no PIN).
// With no matching reader it returns quickly without touching any card.
func Presence(ctx context.Context, o PresenceOptions) (PresenceResult, error) {
	readers, err := Readers()
	if err != nil {
		return PresenceResult{Match: -1}, err
	}
	return presenceOn(ctx, readers, o)
}

func presenceOn(ctx context.Context, readers []string, o PresenceOptions) (PresenceResult, error) {
	best := PresenceResult{Match: -1}
	for _, name := range matchingReaders(readers, o.Reader) {
		if err := ctx.Err(); err != nil {
			return best, err
		}
		card, err := openCard(name, false)
		if err != nil {
			if !best.Present {
				best = PresenceResult{Present: true, Reader: name, Match: -1}
			}
			continue
		}
		r := ProbeTransport(card, o)
		card.Close()
		r.Reader = name
		if r.Admin() {
			return r, nil
		}
		if !best.Present || (best.PublicKey == nil && r.PublicKey != nil) {
			best = r
		}
	}
	return best, nil
}

// Prober is Presence for a 2-second poll: it probes cards only when the
// reader list changed or MaxAge passed since the last probe, so most polls
// only list readers. It is safe for concurrent use.
type Prober struct {
	Options PresenceOptions
	// MaxAge bounds how long a probe result is reused; zero means 30 s.
	MaxAge time.Duration

	mu      sync.Mutex
	readers []string
	last    PresenceResult
	at      time.Time
	valid   bool
	now     func() time.Time
	list    func() ([]string, error)
	probe   func(context.Context, []string, PresenceOptions) (PresenceResult, error)
}

// Check returns the current presence.
func (p *Prober) Check(ctx context.Context) (PresenceResult, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now, list, probe := time.Now, Readers, presenceOn
	if p.now != nil {
		now = p.now
	}
	if p.list != nil {
		list = p.list
	}
	if p.probe != nil {
		probe = p.probe
	}
	maxAge := p.MaxAge
	if maxAge <= 0 {
		maxAge = 30 * time.Second
	}
	readers, err := list()
	if err != nil {
		p.valid = false
		return PresenceResult{Match: -1}, err
	}
	if p.valid && slices.Equal(readers, p.readers) && now().Sub(p.at) < maxAge {
		return p.last, nil
	}
	r, err := probe(ctx, readers, p.Options)
	if err != nil {
		p.valid = false
		return r, err
	}
	p.readers, p.last, p.at, p.valid = slices.Clone(readers), r, now(), true
	return r, nil
}

// Invalidate forces the next Check to probe the cards again.
func (p *Prober) Invalidate() {
	p.mu.Lock()
	p.valid = false
	p.mu.Unlock()
}
