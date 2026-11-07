package trust

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func newX25519(t *testing.T) ([]byte, Key) {
	t.Helper()
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		t.Fatal(err)
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	var k Key
	copy(k[:], pub)
	return priv, k
}

func TestPrivatePartRoundTrip(t *testing.T) {
	netID, _ := NewNetworkID(rand.Reader)
	idA, _ := NewNetworkID(rand.Reader)
	idB, _ := NewNetworkID(rand.Reader)
	privA, pubA := newX25519(t)
	privB, pubB := newX25519(t)
	privC, _ := newX25519(t)
	secret := []byte(`{"devices":["laptop"],"rules":[{"from":["laptop"],"to":["nas"]}]}`)
	part, err := SealPrivatePart(secret, []PrivateRecipient{{DeviceID: idB, WireGuardKey: pubB}, {DeviceID: idA, WireGuardKey: pubA}}, netID, 7, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(part.Ciphertext, []byte("laptop")) {
		t.Fatal("plaintext visible")
	}
	for _, c := range []struct {
		id   string
		priv []byte
	}{{idA, privA}, {idB, privB}} {
		got, err := OpenPrivatePart(part, c.id, c.priv, netID, 7)
		if err != nil || !bytes.Equal(got, secret) {
			t.Fatalf("recipient %s: %v", c.id, err)
		}
	}
	// A non-member key, another version or network fails.
	if _, err := OpenPrivatePart(part, idA, privC, netID, 7); !errors.Is(err, ErrPrivatePart) {
		t.Fatalf("foreign key: %v", err)
	}
	if _, err := OpenPrivatePart(part, idA, privA, netID, 8); !errors.Is(err, ErrPrivatePart) {
		t.Fatalf("other version: %v", err)
	}
	other, _ := NewNetworkID(rand.Reader)
	if _, err := OpenPrivatePart(part, idA, privA, other, 7); !errors.Is(err, ErrPrivatePart) {
		t.Fatalf("other network: %v", err)
	}
	// Swapping wrapped keys between recipients fails (device id is bound).
	part.Recipients[0].Wrapped, part.Recipients[1].Wrapped = part.Recipients[1].Wrapped, part.Recipients[0].Wrapped
	if _, err := OpenPrivatePart(part, idA, privA, netID, 7); !errors.Is(err, ErrPrivatePart) {
		t.Fatalf("swapped wrap: %v", err)
	}
}
