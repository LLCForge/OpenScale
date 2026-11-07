package control

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestRelaySessionSignAndVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s := RelaySession{Expires: time.Unix(1_900_000_000, 0)}
	s.Device[0], s.Coordinator[31] = 7, 9
	payload, sig, err := SignRelaySession(priv, s)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyRelaySession(pub, payload, sig)
	if err != nil {
		t.Fatalf("VerifyRelaySession: %v", err)
	}
	if got.Device != s.Device || got.Coordinator != s.Coordinator || !got.Expires.Equal(s.Expires) {
		t.Fatalf("round trip: %+v", got)
	}
	bad := bytes.Clone(payload)
	bad[1] ^= 1
	if _, err := VerifyRelaySession(pub, bad, sig); err == nil {
		t.Fatal("a changed payload must not verify")
	}
	// A signature for another context (e.g. a path probe) does not verify.
	other, _ := priv.Sign(nil, payload, &ed25519.Options{Context: "openscale/path-probe/v1"})
	if _, err := VerifyRelaySession(pub, payload, other); err == nil {
		t.Fatal("a signature with another context must not verify")
	}
	// The message fits a datagram.
	if _, err := Encode(Message{T: TypeRelaySession, Data: payload, Sig: sig}); err != nil {
		t.Fatal(err)
	}
}

func TestCoordViewsRoundTrip(t *testing.T) {
	views := make([]CoordView, MaxCoordViews)
	for i := range views {
		views[i].Key[0] = byte(i + 1)
		views[i].Version = uint64(i + 10)
		views[i].Digest[5] = byte(i)
		views[i].AgeSec = uint32(i)
	}
	b, err := EncodeCoordViews(views)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseCoordViews(b)
	if err != nil || len(got) != len(views) || got[3] != views[3] {
		t.Fatalf("ParseCoordViews: %v %+v", err, got)
	}
	if _, err := Encode(Message{T: TypeGossipHello, Version: 1, Digest: string(make([]byte, 64)), Size: 1, Data: b}); err != nil {
		t.Fatalf("full views must fit a datagram: %v", err)
	}
	if _, err := EncodeCoordViews(make([]CoordView, MaxCoordViews+1)); err == nil {
		t.Fatal("too many views must be rejected")
	}
	dup := append(bytes.Clone(b[:2+coordViewLen]), b[2:2+coordViewLen]...)
	dup[1] = 2
	if _, err := ParseCoordViews(dup); err == nil {
		t.Fatal("duplicate keys must be rejected")
	}
	if _, err := ParseCoordViews(b[:len(b)-1]); err == nil {
		t.Fatal("truncated views must be rejected")
	}
}

func FuzzParseRelaySession(f *testing.F) {
	s := RelaySession{Expires: time.Unix(1_900_000_000, 0)}
	f.Add(s.Marshal())
	f.Add([]byte{})
	f.Add(make([]byte, RelaySessionLen))
	f.Fuzz(func(t *testing.T, b []byte) {
		got, err := ParseRelaySession(b)
		if err != nil {
			return
		}
		if !bytes.Equal(got.Marshal(), b) {
			t.Fatal("accepted payload does not round trip")
		}
	})
}

func FuzzParseCoordViews(f *testing.F) {
	b, _ := EncodeCoordViews([]CoordView{{Version: 1}, {Key: [8]byte{1}, Version: 2}})
	f.Add(b)
	f.Add([]byte{1, 0})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		views, err := ParseCoordViews(b)
		if err != nil || len(b) == 0 {
			return
		}
		again, err := EncodeCoordViews(views)
		if err != nil || !bytes.Equal(again, b) {
			t.Fatal("accepted views do not round trip")
		}
	})
}
