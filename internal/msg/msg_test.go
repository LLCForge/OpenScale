package msg

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

type device struct {
	name string
	priv []byte
	pub  []byte
}

func newDevice(t *testing.T, name string) device {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return device{name: name, priv: k.Bytes(), pub: k.PublicKey().Bytes()}
}

var t0 = time.Unix(1_800_000_000, 0)

func TestSealOpenRoundTrip(t *testing.T) {
	a, b := newDevice(t, "laptop"), newDevice(t, "phone")
	env, err := Seal(rand.Reader, a.priv, b.pub, a.name, b.name, t0, "merhaba dünya")
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(b.priv, a.pub, env)
	if err != nil || got != "merhaba dünya" {
		t.Fatalf("Open = %q, %v", got, err)
	}
	env2, _ := Seal(rand.Reader, a.priv, b.pub, a.name, b.name, t0, "merhaba dünya")
	if string(env2.Box) == string(env.Box) || env2.ID == env.ID {
		t.Fatal("two messages share a key or id")
	}
}

func TestOpenRejectsWrongKeysAndTampering(t *testing.T) {
	a, b, c := newDevice(t, "laptop"), newDevice(t, "phone"), newDevice(t, "server")
	env, err := Seal(rand.Reader, a.priv, b.pub, a.name, b.name, t0, "gizli")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(c.priv, a.pub, env); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("third device opened it: %v", err)
	}
	// A device that knows only the recipient's public key cannot pose as
	// the sender: the static-static term binds the sender.
	if _, err := Open(b.priv, c.pub, env); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("wrong sender key accepted: %v", err)
	}
	for name, mut := range map[string]func(*Envelope){
		"from": func(e *Envelope) { e.From = "server" },
		"to":   func(e *Envelope) { e.To = "tablet" },
		"time": func(e *Envelope) { e.Time++ },
		"id":   func(e *Envelope) { e.ID = "00000000000000000000000000000000" },
		"box":  func(e *Envelope) { e.Box = append([]byte(nil), e.Box...); e.Box[0] ^= 1 },
		"eph":  func(e *Envelope) { e.Ephemeral = append([]byte(nil), e.Ephemeral...); e.Ephemeral[0] ^= 1 },
	} {
		e := env
		mut(&e)
		if _, err := Open(b.priv, a.pub, e); err == nil {
			t.Errorf("tampered %s accepted", name)
		}
	}
	// A low-order ephemeral point (all zero) must be refused.
	e := env
	e.Ephemeral = make([]byte, 32)
	if _, err := Open(b.priv, a.pub, e); err == nil {
		t.Fatal("zero ephemeral key accepted")
	}
}

func TestSealValidatesInput(t *testing.T) {
	a, b := newDevice(t, "laptop"), newDevice(t, "phone")
	for _, text := range []string{"", string(make([]byte, MaxText+1)), "\xff\xfe"} {
		if _, err := Seal(rand.Reader, a.priv, b.pub, a.name, b.name, t0, text); err == nil {
			t.Errorf("text of %d bytes accepted", len(text))
		}
	}
	for _, names := range [][2]string{{"Laptop", "phone"}, {"laptop", "laptop"}, {"", "phone"}, {"a/b", "phone"}} {
		if _, err := Seal(rand.Reader, a.priv, b.pub, names[0], names[1], t0, "x"); err == nil {
			t.Errorf("names %v accepted", names)
		}
	}
}

func TestStoreDedupAndDelete(t *testing.T) {
	s := OpenStore(t.TempDir())
	m := Message{ID: "0123456789abcdef0123456789abcdef", Peer: "phone", At: t0, Text: "selam"}
	if err := s.AddIncoming(m); err != nil {
		t.Fatal(err)
	}
	if err := s.AddIncoming(m); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate: %v", err)
	}
	if err := s.AddSent(Message{ID: "fedcba9876543210fedcba9876543210", Peer: "phone", At: t0.Add(time.Second), Text: "cevap"}); err != nil {
		t.Fatal(err)
	}
	list, err := s.List("")
	if err != nil || len(list) != 2 || list[0].Out || !list[1].Out {
		t.Fatalf("List = %+v, %v", list, err)
	}
	if ok, err := s.Delete(m.ID); !ok || err != nil {
		t.Fatalf("Delete = %v, %v", ok, err)
	}
	if err := s.AddIncoming(m); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("replay after delete: %v", err)
	}
	if err := s.AddIncoming(Message{ID: "bad", Peer: "phone", At: t0, Text: "x"}); err == nil {
		t.Fatal("bad id stored")
	}
}

func TestSafeText(t *testing.T) {
	in := "a\x1b[31mb‮c\nd\te\x00"
	if got := SafeText(in); got != "a?[31mb?c\nd\te?" {
		t.Fatalf("SafeText = %q", got)
	}
}

func startServer(t *testing.T, self device, peers map[string]device, now time.Time) (netip.AddrPort, *Store) {
	t.Helper()
	store := OpenStore(t.TempDir())
	srv, err := NewServer(ServerConfig{
		Self: func() (string, []byte, error) { return self.name, append([]byte(nil), self.priv...), nil },
		PeerByAddr: func(a netip.Addr) (Peer, bool) {
			d, ok := peers[a.String()]
			return Peer{Name: d.name, WireGuardPublic: d.pub}, ok
		},
		Store: store,
		Now:   func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = srv.Serve(ctx, ln); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return ln.Addr().(*net.TCPAddr).AddrPort(), store
}

func TestServerEndToEnd(t *testing.T) {
	a, b, c := newDevice(t, "laptop"), newDevice(t, "phone"), newDevice(t, "server")
	addr, store := startServer(t, b, map[string]device{"127.0.0.1": a}, t0)
	ctx := context.Background()

	env, _ := Seal(rand.Reader, a.priv, b.pub, a.name, b.name, t0, "tünel içinden")
	if err := Send(ctx, addr, env); err != nil {
		t.Fatal(err)
	}
	// A retry after a lost reply is acknowledged but stored once.
	if err := Send(ctx, addr, env); err != nil {
		t.Fatalf("retry: %v", err)
	}
	list, _ := store.List("")
	if len(list) != 1 || list[0].Text != "tünel içinden" || list[0].Peer != "laptop" {
		t.Fatalf("stored = %+v", list)
	}

	// The source address belongs to "laptop": another name is refused even
	// with a valid seal from that device's key.
	forged, _ := Seal(rand.Reader, c.priv, b.pub, c.name, b.name, t0, "sahte")
	if err := Send(ctx, addr, forged); !errors.Is(err, ErrRejected) {
		t.Fatalf("forged sender: %v", err)
	}
	// Claiming laptop's name with another key fails to open.
	posing, _ := Seal(rand.Reader, c.priv, b.pub, a.name, b.name, t0, "sahte")
	if err := Send(ctx, addr, posing); !errors.Is(err, ErrRejected) {
		t.Fatalf("posing sender: %v", err)
	}
	old, _ := Seal(rand.Reader, a.priv, b.pub, a.name, b.name, t0.Add(-8*24*time.Hour), "eski")
	if err := Send(ctx, addr, old); !errors.Is(err, ErrRejected) {
		t.Fatalf("old message: %v", err)
	}
	wrongTo, _ := Seal(rand.Reader, a.priv, b.pub, a.name, "tablet", t0, "yanlış alıcı")
	if err := Send(ctx, addr, wrongTo); !errors.Is(err, ErrRejected) {
		t.Fatalf("wrong recipient: %v", err)
	}
	if list, _ := store.List(""); len(list) != 1 {
		t.Fatalf("refused messages stored: %+v", list)
	}
}

func TestServerRefusesUnknownSource(t *testing.T) {
	a, b := newDevice(t, "laptop"), newDevice(t, "phone")
	addr, _ := startServer(t, b, map[string]device{}, t0)
	env, _ := Seal(rand.Reader, a.priv, b.pub, a.name, b.name, t0, "x")
	if err := Send(context.Background(), addr, env); !errors.Is(err, ErrRejected) {
		t.Fatalf("unknown source: %v", err)
	}
}
