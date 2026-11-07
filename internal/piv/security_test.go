package piv

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

// endless61 answers every APDU with 61 00 and no data, as a faulty or
// hostile card could.
type endless61 struct{ calls int }

func (e *endless61) Transmit([]byte) ([]byte, error) {
	e.calls++
	if e.calls > 10*maxGetResponseRounds {
		panic("transmit did not stop")
	}
	return []byte{0x61, 0x00}, nil
}

func TestTransmitStopsEndlessGetResponse(t *testing.T) {
	e := &endless61{}
	if _, err := transmit(e, Command{INS: 0xCA, P1: 0x00, P2: 0x6E, Le: 256}); err == nil {
		t.Fatal("endless 61xx accepted")
	}
	if e.calls > maxGetResponseRounds+1 {
		t.Fatalf("%d APDUs sent, at most %d expected", e.calls, maxGetResponseRounds+1)
	}
}

// pieces61 returns total bytes in GET RESPONSE pieces of n bytes.
type pieces61 struct {
	left, n int
}

func (p *pieces61) Transmit([]byte) ([]byte, error) {
	k := min(p.n, p.left)
	p.left -= k
	out := make([]byte, k, k+2)
	if p.left > 0 {
		return append(out, 0x61, byte(min(p.left, 256))), nil
	}
	return append(out, 0x90, 0x00), nil
}

func TestTransmitLongAnswerStillWorks(t *testing.T) {
	// The largest answer the package accepts, in the smallest full
	// pieces a card normally uses.
	p := &pieces61{left: maxResponse - 256, n: 256}
	data, err := transmit(p, Command{INS: 0xCB, Le: 256})
	if err != nil || len(data) != maxResponse-256 {
		t.Fatalf("long answer: %d bytes, %v", len(data), err)
	}
}

func TestOpenPGPInvalidUIFRefusedBeforeWriting(t *testing.T) {
	f := newFakeOpenPGP(Version{5, 4, 3})
	c, err := NewOpenPGPClient(f)
	if err != nil {
		t.Fatal(err)
	}
	_, root, _ := ed25519.GenerateKey(rand.Reader)
	if err := c.ImportEd25519([]byte("12345678"), root, OpenPGPImportOptions{UIF: 0x05}); err == nil {
		t.Fatal("invalid touch flag accepted")
	}
	if f.seed != nil || f.verified83 || f.pw3Tries != 3 {
		t.Fatalf("card touched before the options were checked: seed %x, admin verified %v", f.seed, f.verified83)
	}
}

func TestPIVImportDataNeverGrows(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for _, pol := range [][2]byte{{PINPolicyDefault, TouchPolicyDefault}, {0x03, 0x02}} {
		data, err := encodeImportEd25519(seed, pol[0], pol[1])
		if err != nil {
			t.Fatal(err)
		}
		// One backing array from the start: a reallocation would leave
		// an uncleared copy of the seed behind.
		if cap(data) != 2+ed25519.SeedSize+6 {
			t.Fatalf("policies %x: cap %d, len %d", pol, cap(data), len(data))
		}
	}
}
