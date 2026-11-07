package enrollkit

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/trust"
)

func requestLine(t *testing.T, host string) string {
	t.Helper()
	s, err := trust.GenerateDeviceSecrets(rand.Reader, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	env, _, err := s.NewEnrollmentRequest(host, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	line, err := trust.EncodeEnrollment(env)
	if err != nil {
		t.Fatal(err)
	}
	return line
}

func TestNearbyLoopback(t *testing.T) {
	// Loopback only: no broadcast and no firewall prompt in tests.
	lc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := NewListener(nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { l.Serve(ctx, lc, time.Minute); close(done) }()

	sc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()
	pkt, err := NearbyPacket(requestLine(t, "yeni-laptop"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Announce(ctx, sc, lc.LocalAddr(), pkt, 10*time.Millisecond, 60*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	// Junk and a damaged request are ignored.
	_, _ = sc.WriteTo([]byte("hello"), lc.LocalAddr())
	_, _ = sc.WriteTo(append([]byte(nearbyMagic), "osreq-bozuk"...), lc.LocalAddr())
	deadline := time.Now().Add(2 * time.Second)
	for len(l.Requests()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	reqs := l.Requests()
	if len(reqs) != 1 || reqs[0].Hostname != "yeni-laptop" || reqs[0].From != "127.0.0.1" {
		t.Fatalf("requests: %+v", reqs)
	}
	if l.Until().IsZero() {
		t.Fatal("listener reports idle while serving")
	}
	cancel()
	<-done
	if !l.Until().IsZero() {
		t.Fatal("listener still reports a window")
	}
}

func TestNearbyLimitsAndForgery(t *testing.T) {
	now := time.Now()
	l := NewListener(func() time.Time { return now })
	src := netip.MustParseAddrPort("127.0.0.1:5000")
	for i := 0; i < maxPerSource; i++ {
		pkt, _ := NearbyPacket(requestLine(t, "a"))
		if err := l.Handle(pkt, src); err != nil {
			t.Fatal(err)
		}
	}
	pkt, _ := NearbyPacket(requestLine(t, "b"))
	if err := l.Handle(pkt, src); err == nil {
		t.Fatal("per-source limit not applied")
	}
	// A request with a broken signature is refused.
	line := requestLine(t, "c")
	env, _ := trust.DecodeEnrollment(line)
	env.Signature = make([]byte, ed25519.SignatureSize)
	bad, _ := trust.EncodeEnrollment(env)
	if err := l.Handle(append([]byte(nearbyMagic), bad...), netip.MustParseAddrPort("127.0.0.2:1")); err == nil {
		t.Fatal("forged request accepted")
	}
	// Entries age out after the window.
	now = now.Add(NearbyWindow + time.Second)
	if len(l.Requests()) != 0 {
		t.Fatal("old requests kept")
	}
}

func TestLauncher(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	var root, wg trust.Key
	copy(root[:], pub)
	_, _ = rand.Read(wg[:])
	seed, _ := trust.NewInviteSeed(rand.Reader)
	netID, _ := trust.NewNetworkID(rand.Reader)
	invID, _ := trust.NewNetworkID(rand.Reader)
	code := &trust.InviteCode{RootKey: root, NetworkID: netID, InviteID: invID, Seed: seed,
		IPv4:        netip.MustParseAddr("100.64.0.9"),
		Coordinator: trust.InviteCoordinator{Endpoint: "vpn.example.org:41820", WireGuardKey: wg, IPv4: netip.MustParseAddr("100.64.0.1")}}
	line, err := code.Encode()
	if err != nil {
		t.Fatal(err)
	}
	exp := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	for _, p := range []string{PlatformWindows, PlatformLinux} {
		l, err := NewLauncher(p, line, exp)
		if err != nil {
			t.Fatal(err)
		}
		s := string(l.Content)
		if !strings.Contains(s, line) || !strings.Contains(s, "2026-10-30 12:00 UTC") {
			t.Fatalf("%s launcher lacks code or expiry", p)
		}
		if strings.Contains(s, "http") || strings.Contains(s, "curl") || strings.Contains(s, "wget") {
			t.Fatalf("%s launcher downloads", p)
		}
	}
	w, _ := NewLauncher(PlatformWindows, line, exp)
	if !strings.Contains(string(w.Content), "\r\n") || !strings.HasSuffix(w.FileName, ".cmd") {
		t.Fatal("windows launcher format")
	}
	for _, bad := range []string{"", "osinv1.\"&calc", line + "'; rm -rf /"} {
		if _, err := NewLauncher(PlatformLinux, bad, exp); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	a, b, err := trust.SplitInviteCode(code, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewLauncher(PlatformLinux, a+" "+b, exp); err == nil {
		t.Fatal("split code embedded")
	}
	if _, err := NewLauncher("plan9", line, exp); err == nil {
		t.Fatal("unknown platform accepted")
	}
}
