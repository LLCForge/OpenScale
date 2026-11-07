package service

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/openscale/openscale/internal/node"
	"github.com/openscale/openscale/internal/osnet"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/trust"
)

func TestWithTransportOptions(t *testing.T) {
	r, err := New(Config{DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	cfg := r.withTransportOptions(transportOptions{}, node.Config{})
	if cfg.PostQuantum != node.PostQuantumOn || cfg.PSKRotation != 0 || cfg.LazyPeers || cfg.TCPFallback != "" {
		t.Fatalf("defaults: %+v", cfg)
	}
	cfg = r.withTransportOptions(transportOptions{
		PostQuantumOff: true, PSKRotation: time.Hour, TCPFallback: "vpn.example.com:8443", DisableTCPFallback: true,
		Keepalive: 15 * time.Second, AdaptiveKeepalive: true, LazyPeers: true, LazyIdle: 30 * time.Minute,
	}, node.Config{})
	if cfg.PostQuantum != node.PostQuantumOff || cfg.PSKRotation != time.Hour || cfg.TCPFallback != "vpn.example.com:8443" ||
		!cfg.DisableTCPFallback || cfg.Keepalive != 15*time.Second || !cfg.AdaptiveKeepalive || !cfg.LazyPeers || cfg.LazyIdle != 30*time.Minute {
		t.Fatalf("options not copied: %+v", cfg)
	}
	// Unusable saved values fall back to the defaults instead of stopping
	// the tunnel.
	cfg = r.withTransportOptions(transportOptions{PSKRotation: time.Second, TCPFallback: "nohost", Keepalive: 1500 * time.Millisecond, LazyIdle: time.Second}, node.Config{})
	if cfg.PSKRotation != 0 || cfg.TCPFallback != "" || cfg.Keepalive != 0 || cfg.LazyIdle != 0 {
		t.Fatalf("unusable values used: %+v", cfg)
	}
}

func TestTransportPrefs(t *testing.T) {
	var o tunnelOptions
	for k, v := range map[string]string{
		"post-quantum": "false", "psk-rotation": "30m", "tcp-fallback": " 203.0.113.5:443 ", "disable-tcp-fallback": "false",
		"keepalive": "20s", "adaptive-keepalive": "true", "lazy-peers": "true", "lazy-idle": "15m",
	} {
		if ok, err := applyTunnelPref(&o, k, v); !ok || err != nil {
			t.Fatalf("%s=%s: %t %v", k, v, ok, err)
		}
	}
	if err := o.validate(); err != nil {
		t.Fatal(err)
	}
	st := settings{Tunnel: &o}
	got := map[string]string{}
	for _, p := range prefsOf(st) {
		got[p.Key] = p.Value
	}
	if got["post-quantum"] != "false" || got["psk-rotation"] != "30m0s" || got["tcp-fallback"] != "203.0.113.5:443" || got["lazy-idle"] != "15m0s" {
		t.Fatalf("prefs: %v", got)
	}
	for k, v := range map[string]string{"keepalive": "5s", "psk-rotation": "1m", "lazy-idle": "48h", "tcp-fallback": "no-port"} {
		bad := tunnelOptions{}
		if _, err := applyTunnelPref(&bad, k, v); err != nil {
			continue
		}
		if err := bad.validate(); err == nil {
			t.Errorf("%s=%s accepted", k, v)
		}
	}
	if ok, _ := applyTunnelPref(&o, "coordinator-tcp-listen", ":443"); ok {
		t.Fatal("coordinator keys are not tunnel options")
	}
}

func TestValidCoordinatorTCP(t *testing.T) {
	for _, c := range []struct {
		listen          string
		maxConns, perIP int
		ok              bool
	}{
		{"", 0, 0, true},
		{":443", 0, 0, true},
		{"203.0.113.5:443", 512, 4, true},
		{"[2001:db8::1]:443", 0, 0, true},
		{"vpn.example.com:443", 0, 0, false},
		{":0", 0, 0, false},
		{"443", 0, 0, false},
		{":443", 5000, 0, false},
		{":443", 8, 16, false},
		{":443", -1, 0, false},
	} {
		if err := ValidCoordinatorTCP(c.listen, c.maxConns, c.perIP); (err == nil) != c.ok {
			t.Errorf("ValidCoordinatorTCP(%q, %d, %d) = %v", c.listen, c.maxConns, c.perIP, err)
		}
	}
}

func TestApplyAdvancedTransport(t *testing.T) {
	on, off := true, false
	rot, ka := int64(3600), int64(30)
	fallback, listen, conns := "vpn.example.com:443", ":443", 300
	next := settings{}
	err := applyAdvancedTransport(&next, panel.AdvancedSettings{PostQuantum: &off, PSKRotationSec: &rot, TCPFallback: &fallback,
		KeepaliveSec: &ka, LazyPeers: &on, CoordinatorTCPListen: &listen, CoordinatorTCPMaxConns: &conns})
	if err != nil {
		t.Fatal(err)
	}
	ts := transportStatus(next)
	if ts.PostQuantum || ts.PSKRotationSec != 3600 || ts.TCPFallback != fallback || ts.KeepaliveSec != 30 || !ts.LazyPeers {
		t.Fatalf("status: %+v", ts)
	}
	if next.CoordinatorTCPListen != ":443" || next.CoordinatorTCPMaxConns != 300 || !coordinatorTCPChanged(settings{}, next) {
		t.Fatalf("coordinator: %+v", next)
	}
	bad := int64(5)
	if err := applyAdvancedTransport(&settings{}, panel.AdvancedSettings{KeepaliveSec: &bad}); err == nil {
		t.Fatal("5 s keepalive accepted")
	}
	host := "vpn.example.com:443"
	if err := applyAdvancedTransport(&settings{}, panel.AdvancedSettings{CoordinatorTCPListen: &host}); err == nil {
		t.Fatal("a host name for the listener accepted")
	}
}

func TestSetAdvancedTransportNeedsMembership(t *testing.T) {
	r, err := New(Config{DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	on := true
	if err := r.SetAdvanced(panel.AdvancedSettings{LazyPeers: &on}); err == nil {
		t.Fatal("transport option saved without a membership")
	}
	listen := ":443"
	if err := r.SetAdvanced(panel.AdvancedSettings{CoordinatorTCPListen: &listen}); err == nil {
		t.Fatal("coordinator option saved without a coordinator")
	}
	if _, err := r.DiagSetPrefs(map[string]string{"coordinator-tcp-listen": ":443"}); err == nil {
		t.Fatal("openscale set accepted a coordinator option without a coordinator")
	}
}

func TestJournalRecover(t *testing.T) {
	dir := t.TempDir()
	j := OpenJournal(dir, func() time.Time { return time.Date(2026, 10, 30, 7, 0, 0, 0, time.UTC) })
	dns := osnet.DNSConfig{Interface: "OpenScale", Server: netip.MustParseAddr("100.100.100.100"), Domain: "ev.internal"}
	if err := j.Begin(DNSEntry(dns)); err != nil {
		t.Fatal(err)
	}
	if err := j.Begin(JournalEntry{Kind: JournalExitClient, Interface: "OpenScale"}); err != nil {
		t.Fatal(err)
	}
	if err := j.Begin(JournalEntry{Kind: JournalExitNAT}); err != nil {
		t.Fatal(err)
	}
	if err := j.Begin(JournalEntry{Kind: "future-kind"}); err != nil {
		t.Fatal(err)
	}
	if p, _ := j.Pending(); len(p) != 4 {
		t.Fatalf("pending = %v", p)
	}
	var gotDNS osnet.DNSConfig
	var exitIface string
	natFails := errors.New("nft missing")
	done, err := j.Recover(context.Background(), JournalUndo{
		RemoveDNS:  func(_ context.Context, c osnet.DNSConfig) error { gotDNS = c; return nil },
		ExitClient: func(_ context.Context, iface string) error { exitIface = iface; return nil },
		ExitNAT:    func(context.Context) error { return natFails },
	}, nil)
	if !errors.Is(err, natFails) {
		t.Fatalf("error = %v", err)
	}
	if strings.Join(done, ",") != "dns,exit-client" || gotDNS != dns || exitIface != "OpenScale" {
		t.Fatalf("done=%v dns=%+v exit=%q", done, gotDNS, exitIface)
	}
	// The failed undo and the unknown kind stay for the next start.
	p, _ := j.Pending()
	if len(p) != 2 || p[0].Kind != JournalExitNAT || p[1].Kind != "future-kind" {
		t.Fatalf("left = %+v", p)
	}
	if err := j.Done(JournalExitNAT); err != nil {
		t.Fatal(err)
	}
	if err := j.Done("future-kind"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, JournalFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("an empty journal must leave no file")
	}
}

func TestJournalCorruptFileIsReplaced(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, JournalFile), []byte("{bozuk"), 0o600); err != nil {
		t.Fatal(err)
	}
	j := OpenJournal(dir, nil)
	if _, err := j.Recover(context.Background(), JournalUndo{}, nil); err == nil {
		t.Fatal("a corrupt journal must be reported")
	}
	if err := j.Begin(JournalEntry{Kind: JournalDNS, Server: "100.100.100.100"}); err != nil {
		t.Fatal(err)
	}
	if p, err := j.Pending(); err != nil || len(p) != 1 {
		t.Fatalf("pending = %v, %v", p, err)
	}
}

type fakeExitRouter struct{ enabled, disabled int }

func (f *fakeExitRouter) Enable(trust.Device, *trust.Document, string, conn.Bind) error {
	f.enabled++
	return nil
}
func (f *fakeExitRouter) Disable() error { f.disabled++; return nil }

func TestJournaledExitRouter(t *testing.T) {
	j := OpenJournal(t.TempDir(), nil)
	inner := &fakeExitRouter{}
	r := JournaledExitRouter(j, inner)
	if err := r.Enable(trust.Device{}, nil, "OpenScale", nil); err != nil {
		t.Fatal(err)
	}
	if p, _ := j.Pending(); len(p) != 1 || p[0].Kind != JournalExitClient || p[0].Interface != "OpenScale" {
		t.Fatalf("pending = %+v", p)
	}
	if err := r.Disable(); err != nil {
		t.Fatal(err)
	}
	if p, _ := j.Pending(); len(p) != 0 || inner.enabled != 1 || inner.disabled != 1 {
		t.Fatalf("pending = %+v inner = %+v", p, inner)
	}
}

func TestWatchInterface(t *testing.T) {
	var present atomic.Bool
	present.Store(true)
	old := interfaceExists
	interfaceExists = func(string) bool { return present.Load() }
	defer func() { interfaceExists = old }()

	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	watchInterface(ctx, "OpenScale", 5*time.Millisecond, cancel)
	time.Sleep(30 * time.Millisecond)
	if ctx.Err() != nil {
		t.Fatal("a present interface must not stop the tunnel")
	}
	present.Store(false)
	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("a removed interface was not noticed")
	}
	if !errors.Is(context.Cause(ctx), node.ErrTunnelLost) {
		t.Fatalf("cause = %v", context.Cause(ctx))
	}

	// An interface the system never listed (a test device) is not watched.
	present.Store(false)
	ctx2, cancel2 := context.WithCancelCause(context.Background())
	defer cancel2(nil)
	watchInterface(ctx2, "fake0", time.Millisecond, cancel2)
	time.Sleep(20 * time.Millisecond)
	if ctx2.Err() != nil {
		t.Fatal("an unlisted interface was watched")
	}
}
