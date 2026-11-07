package handover

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/internal/wgconf"
)

func key(b byte) trust.Key {
	var k trust.Key
	for i := range k {
		k[i] = b
	}
	return k
}

func stats(now time.Time) map[trust.Key]wgconf.PeerStatus {
	return map[trust.Key]wgconf.PeerStatus{
		key(1): {Endpoint: netip.MustParseAddrPort("127.0.0.1:41641"), LastHandshakeUnix: now.Add(-10 * time.Second).Unix()},
		key(2): {Endpoint: netip.MustParseAddrPort("[::1]:41642"), LastHandshakeUnix: now.Add(-time.Minute).Unix()},
		// Relayed, stale and never handshaken peers are not handed over.
		key(3): {Endpoint: netip.MustParseAddrPort("127.0.0.1:1"), Relayed: true, LastHandshakeUnix: now.Unix()},
		key(4): {Endpoint: netip.MustParseAddrPort("127.0.0.1:2"), LastHandshakeUnix: now.Add(-time.Hour).Unix()},
		key(5): {Endpoint: netip.MustParseAddrPort("127.0.0.1:3")},
		key(9): {Endpoint: netip.MustParseAddrPort("127.0.0.1:51820"), LastHandshakeUnix: now.Unix()},
	}
}

func TestCaptureWriteTakeSeed(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	st := Capture("net1", "OpenScale", "1.0.0", key(9), stats(now), now)
	if len(st.Peers) != 2 || st.Coordinator == nil || st.Coordinator.Endpoint != "127.0.0.1:51820" {
		t.Fatalf("capture %+v", st)
	}
	if err := Write(dir, st); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Join(dir, FileName))
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("handover file mode %v %v", info.Mode(), err)
		}
	}
	// An existing cache of the same network keeps its other entries.
	cache := filepath.Join(dir, EndpointCacheFile)
	other := hexKey(7)
	old := `{"version":1,"network_id":"net1","peers":{"` + other + `":{"endpoint":"127.0.0.1:9","seen":"` + now.Add(-time.Hour).UTC().Format(time.RFC3339) + `"}}}`
	if err := os.WriteFile(cache, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Take(dir, "net1", now.Add(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	n, err := Seed(cache, got, now)
	if err != nil || n != 2 {
		t.Fatalf("seed %d %v", n, err)
	}
	data, err := os.ReadFile(cache)
	if err != nil {
		t.Fatal(err)
	}
	var c endpointCache
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatal(err)
	}
	if c.Version != 1 || c.NetworkID != "net1" || len(c.Peers) != 3 || c.Coordinator == nil || c.Peers[other].Endpoint != "127.0.0.1:9" {
		t.Fatalf("cache %s", data)
	}
	if p := c.Peers[hexKey(2)]; p.Endpoint != "[::1]:41642" || p.Seen.After(now) {
		t.Fatalf("seeded peer %+v", p)
	}
	// Used once: the file is gone.
	if _, err := Take(dir, "net1", now); !errors.Is(err, ErrNone) {
		t.Fatalf("second take: %v", err)
	}
}

func TestTakeRefuses(t *testing.T) {
	now := time.Now()
	write := func(t *testing.T, st State) string {
		dir := t.TempDir()
		if err := Write(dir, st); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	base := Capture("net1", "", "1.0.0", key(9), stats(now), now)
	cases := []struct {
		name string
		dir  func(t *testing.T) string
		at   time.Time
		want error
	}{
		{"too old", func(t *testing.T) string { return write(t, base) }, now.Add(MaxAge + time.Second), ErrStale},
		{"future", func(t *testing.T) string { return write(t, base) }, now.Add(-time.Minute), ErrStale},
		{"another network", func(t *testing.T) string { s := base; s.NetworkID = "net2"; return write(t, s) }, now, ErrCorrupt},
		{"corrupt", func(t *testing.T) string {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, FileName), []byte(`{"format":"openscale-handover-v1","created":`), 0o600); err != nil {
				t.Fatal(err)
			}
			return dir
		}, now, ErrCorrupt},
		{"unknown field", func(t *testing.T) string {
			dir := t.TempDir()
			body := `{"format":"openscale-handover-v1","created":"` + now.UTC().Format(time.RFC3339Nano) + `","from":"x","networkId":"net1","peers":[],"keys":"x"}`
			if err := os.WriteFile(filepath.Join(dir, FileName), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			return dir
		}, now, ErrCorrupt},
		{"other format", func(t *testing.T) string {
			dir := t.TempDir()
			body := `{"format":"v0","created":"` + now.UTC().Format(time.RFC3339Nano) + `","from":"x","networkId":"net1","peers":[]}`
			if err := os.WriteFile(filepath.Join(dir, FileName), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			return dir
		}, now, ErrCorrupt},
		{"too large", func(t *testing.T) string {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, FileName), []byte(strings.Repeat(" ", maxFile+1)), 0o600); err != nil {
				t.Fatal(err)
			}
			return dir
		}, now, ErrCorrupt},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := c.dir(t)
			if _, err := Take(dir, "net1", c.at); !errors.Is(err, c.want) {
				t.Fatalf("err %v, want %v", err, c.want)
			}
			// Refused or not, it is never offered again.
			if _, err := os.Stat(filepath.Join(dir, FileName)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("file left behind: %v", err)
			}
		})
	}
}

// TestTakeRefusesReadableByOthers: a handover file other users could have
// read (or written) is not used (POSIX; on Windows the service folder's
// access list protects it, securefile).
func TestTakeRefusesReadableByOthers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions")
	}
	dir := t.TempDir()
	now := time.Now()
	if err := Write(dir, Capture("net1", "", "1", key(9), stats(now), now)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, FileName), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Take(dir, "net1", now); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("readable file taken: %v", err)
	}
}

// TestSeedReplacesForeignCache: a cache of another network is replaced,
// and endpoints that are not concrete addresses are dropped.
func TestSeedReplacesForeignCache(t *testing.T) {
	dir := t.TempDir()
	cache := filepath.Join(dir, EndpointCacheFile)
	if err := os.WriteFile(cache, []byte(`{"version":1,"network_id":"x","peers":{"aa":{"endpoint":"127.0.0.1:1","seen":"2026-01-01T00:00:00Z"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	st := &State{Format: format, Created: now, NetworkID: "net1", Peers: []Peer{
		{Key: hexKey(1), Endpoint: "127.0.0.1:5", Handshake: now.Add(time.Hour)},
		{Key: hexKey(2), Endpoint: "0.0.0.0:5", Handshake: now},
		{Key: "zz", Endpoint: "127.0.0.1:6", Handshake: now},
	}}
	if n, err := Seed(cache, st, now); err != nil || n != 1 {
		t.Fatalf("seed %d %v", n, err)
	}
	data, _ := os.ReadFile(cache)
	var c endpointCache
	if err := json.Unmarshal(data, &c); err != nil || c.NetworkID != "net1" || len(c.Peers) != 1 {
		t.Fatalf("cache %s", data)
	}
	for _, p := range c.Peers {
		if p.Seen.After(now) {
			t.Fatal("future-dated entry; the engine would drop it")
		}
	}
}

// TestKeeperWritesOnlyOnStop: a tunnel that restarts inside a running
// service writes nothing; a stopping service writes the last snapshot even
// when the tunnel no longer answers.
func TestKeeperWritesOnlyOnStop(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	answering := true
	k := &Keeper{Dir: dir, Capture: func() (State, bool) {
		if !answering {
			return State{}, false
		}
		return Capture("net1", "", "1", key(9), stats(now), now), true
	}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	k.Run(ctx, func() bool { return false })
	if _, err := os.Stat(filepath.Join(dir, FileName)); err == nil {
		t.Fatal("written without a stop")
	}
	stopped := false
	k.OnStop = func() { stopped = true }
	k.Snapshot()
	answering = false
	k.Run(ctx, func() bool { return true })
	st, err := Take(dir, "net1", now)
	if err != nil || !stopped || len(st.Peers) != 2 {
		t.Fatalf("take %+v %v stopped=%v", st, err, stopped)
	}
}

func hexKey(b byte) string { k := key(b); return hex.EncodeToString(k[:]) }
