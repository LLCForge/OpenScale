package webhook

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestDestinationPolicy(t *testing.T) {
	good := []string{"http://127.0.0.1:9000/hook", "http://10.1.2.3/x", "https://192.168.1.10:8443/", "http://100.80.0.5/", "http://[fd00::1]/", "http://ev.lan/hook"}
	for _, u := range good {
		if _, err := ParseURL(u); err != nil {
			t.Errorf("%s refused: %v", u, err)
		}
	}
	bad := []string{"", "ftp://10.0.0.1/", "http://203.0.113.5/", "http://169.254.169.254/latest", "http://0.0.0.0/", "http://[::]/",
		"http://224.0.0.1/", "http://user:pw@10.0.0.1/", "http://10.0.0.1/#x", "http://[fe80::1%25eth0]/", "http://10.0.0.1:0/", "http://bad_host/", "http://10.0.0.1/\n"}
	for _, u := range bad {
		if _, err := ParseURL(u); err == nil {
			t.Errorf("%q accepted", u)
		}
	}
	for _, a := range []string{"8.8.4.4", "169.254.169.254", "fe80::1", "2001:db8::1", "::"} {
		if AllowedAddr(netip.MustParseAddr(a)) {
			t.Errorf("%s allowed", a)
		}
	}
	if !AllowedAddr(netip.MustParseAddr("::ffff:192.168.0.1")) {
		t.Error("mapped private address refused")
	}
}

func TestConfigRoundTripAndFilter(t *testing.T) {
	path := filepath.Join(t.TempDir(), ConfigFile)
	if _, err := Load(path); !errors.Is(err, ErrDisabled) {
		t.Fatalf("missing config = %v", err)
	}
	c, err := NewConfig("http://127.0.0.1:1/h", []string{"peer_offline", "security"}, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := Save(path, c); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil || got.Secret != c.Secret {
		t.Fatalf("load = %+v %v", got, err)
	}
	if !got.Wants(Event{Kind: "peer_offline"}) || !got.Wants(Event{Kind: "x", Category: "security"}) || got.Wants(Event{Kind: "peer_online", Category: "peer"}) {
		t.Fatal("filter")
	}
	if _, err := NewConfig("http://203.0.113.9/", nil, rand.Reader); err == nil {
		t.Fatal("public destination accepted")
	}
	if _, err := NewConfig("http://10.0.0.1/", []string{"Bad Kind"}, rand.Reader); err == nil {
		t.Fatal("bad kind accepted")
	}
}

func TestDeliverySignedAndRetried(t *testing.T) {
	var calls atomic.Int32
	got := make(chan Payload, 1)
	var secret []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		body, _ := io.ReadAll(r.Body)
		if err := Verify(secret, r.Header.Get(HeaderSignature), body, time.Now(), Tolerance); err != nil {
			t.Errorf("signature: %v", err)
		}
		if r.Header.Get(HeaderEvent) != "peer_offline" || r.Header.Get(HeaderDelivery) == "" {
			t.Errorf("headers = %v", r.Header)
		}
		if n < 3 {
			http.Error(w, "busy", http.StatusServiceUnavailable)
			return
		}
		var p Payload
		_ = json.Unmarshal(body, &p)
		got <- p
	}))
	defer srv.Close()
	cfg, err := NewConfig(srv.URL+"/hook", nil, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	secret, _ = hex.DecodeString(cfg.Secret)
	s, err := NewSender(cfg, Options{Device: "masaustu", Backoff: func(int) time.Duration { return 0 }})
	if err != nil {
		t.Fatal(err)
	}
	ev := Event{Seq: 7, At: time.Now(), Kind: "peer_offline", Category: "peer", Severity: "warning", Peer: "laptop", Message: "laptop çevrimdışı"}
	if err := s.Deliver(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	p := <-got
	if p.Device != "masaustu" || p.Event.Seq != 7 || p.Event.Peer != "laptop" || calls.Load() != 3 {
		t.Fatalf("payload = %+v, calls %d", p, calls.Load())
	}

	// Tampered body and stale timestamps fail verification.
	body := []byte(`{"a":1}`)
	sig := Sign(secret, time.Now(), body)
	if Verify(secret, sig, []byte(`{"a":2}`), time.Now(), Tolerance) == nil {
		t.Fatal("tampered body verified")
	}
	if Verify(secret, Sign(secret, time.Now().Add(-time.Hour), body), body, time.Now(), Tolerance) == nil {
		t.Fatal("stale signature verified")
	}
	if Verify([]byte("baska bir sir 0123456789"), sig, body, time.Now(), Tolerance) == nil {
		t.Fatal("wrong secret verified")
	}
}

func TestDeliveryRefusesDisallowedDialAndRedirects(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Redirect(w, r, "http://203.0.113.1/", http.StatusFound)
	}))
	defer srv.Close()
	cfg, err := NewConfig(srv.URL, nil, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// The name resolved to an address the policy refuses: nothing is sent.
	s, err := NewSender(cfg, Options{AllowAddr: func(netip.Addr) bool { return false }, Backoff: func(int) time.Duration { return 0 }})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Deliver(context.Background(), Event{Kind: "x"}); !errors.Is(err, ErrDestination) {
		t.Fatalf("refused dial = %v", err)
	}
	if calls.Load() != 0 {
		t.Fatal("request reached a refused destination")
	}
	// Redirects are not followed.
	s, err = NewSender(cfg, Options{Backoff: func(int) time.Duration { return 0 }})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Deliver(context.Background(), Event{Kind: "x"}); err == nil {
		t.Fatal("a redirect counted as delivered")
	}
	if calls.Load() != Attempts {
		t.Fatalf("calls = %d", calls.Load())
	}
}

func TestQueueBound(t *testing.T) {
	cfg, err := NewConfig("http://127.0.0.1:1/", nil, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSender(cfg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < QueueSize+44; i++ {
		s.Enqueue(Event{Seq: uint64(i), Kind: "x"})
	}
	if s.Dropped() != 44 {
		t.Fatalf("dropped = %d", s.Dropped())
	}
	ev, _ := s.next()
	if ev.Seq != 44 {
		t.Fatalf("oldest kept = %d", ev.Seq)
	}
}
