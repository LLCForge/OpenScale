package admin

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/trust"
)

type signTestToken struct{ priv ed25519.PrivateKey }

func (k signTestToken) PublicKey() ed25519.PublicKey { return k.priv.Public().(ed25519.PublicKey) }
func (k signTestToken) SignMessage(msg []byte) ([]byte, error) {
	return ed25519.Sign(k.priv, msg), nil
}
func (signTestToken) Close() error { return nil }

// TestSessionSignPayloadOnlyOwnDocument: the tray's session signs only a
// valid network document of its own network, under its role's context.
func TestSessionSignPayloadOnlyOwnDocument(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	now := time.Now()
	s, err := OpenTokenSession(context.Background(), func(context.Context) (TokenSigner, error) { return signTestToken{priv}, nil },
		pub, "0123456789abcdef0123456789abcdef", nil, nil, SessionOptions{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := trust.NewDocument("0123456789abcdef0123456789abcdef", trust.DefaultDNSDomain, trust.DefaultIPv4Prefix, netip.MustParsePrefix("fd7a:0:1::/48"), now, trust.DefaultValidity)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := trust.DocumentPayload(doc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SignPayload(trust.AdminDocumentContext, payload, "0123456789abcdef0123456789abcdef"); !errors.Is(err, ErrSignRequest) {
		t.Fatalf("wrong context: %v", err)
	}
	if _, err := s.SignPayload(trust.DocumentContext, payload, "fedcba9876543210fedcba9876543210"); !errors.Is(err, ErrSignRequest) {
		t.Fatalf("other network: %v", err)
	}
	if _, err := s.SignPayload(trust.DocumentContext, []byte(`{"not":"a document"}`), "0123456789abcdef0123456789abcdef"); !errors.Is(err, ErrSignRequest) {
		t.Fatalf("garbage: %v", err)
	}
	sp, err := s.SignPayload(trust.DocumentContext, payload, "0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	env := trust.Envelope{Context: trust.DocumentContext, Payload: payload, Signature: sp.Signature, Algorithm: trust.AlgEd25519Digest}
	if _, err := trust.VerifyDocumentSignature(env, pub); err != nil {
		t.Fatalf("signature does not verify as a root document: %v", err)
	}
	if got := KeyFingerprint(pub); len(got) != 16 || s.IdleUntil().Sub(now) != 10*time.Minute {
		t.Fatalf("fingerprint %q idle %v", got, s.IdleUntil().Sub(now))
	}
	s.Close()
	if _, err := s.SignPayload(trust.DocumentContext, payload, "0123456789abcdef0123456789abcdef"); !errors.Is(err, ErrSessionClosed) {
		t.Fatalf("closed session: %v", err)
	}
}
