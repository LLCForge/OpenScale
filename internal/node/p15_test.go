package node

import (
	"crypto/rand"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/control"
	"github.com/openscale/openscale/internal/trust"
)

func p15Key(b byte) trust.Key {
	var k trust.Key
	k[0], k[31] = b, 1
	return k
}

func TestRelayCoordinatorHysteresis(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	e := &Engine{cfg: Config{Now: func() time.Time { return now }}, logger: slog.New(slog.NewTextHandler(io.Discard, nil)), rand: func() float64 { return 0.5 }}
	vps := &coordRuntime{c: trust.Coordinator{WireGuardKey: p15Key(1)}, rtt: 80 * time.Millisecond, okAt: now}
	home := &coordRuntime{c: trust.Coordinator{WireGuardKey: p15Key(2)}, rtt: 70 * time.Millisecond, okAt: now}
	e.p15.mc.list = []*coordRuntime{vps, home}
	e.p15.mc.relay = vps.c.WireGuardKey
	e.p15.mc.mu.Lock()
	e.chooseRelayLocked(now)
	e.p15.mc.mu.Unlock()
	if e.p15.mc.relay != vps.c.WireGuardKey {
		t.Fatal("10 ms (12 %) better must not move the relay")
	}
	home.rtt = 20 * time.Millisecond
	e.p15.mc.mu.Lock()
	e.chooseRelayLocked(now)
	e.p15.mc.mu.Unlock()
	if e.p15.mc.relay != vps.c.WireGuardKey {
		t.Fatal("a much better coordinator must wait relaySwitchAfter")
	}
	now = now.Add(relaySwitchAfter)
	vps.okAt, home.okAt = now, now
	e.p15.mc.mu.Lock()
	e.chooseRelayLocked(now)
	e.p15.mc.mu.Unlock()
	if e.p15.mc.relay != home.c.WireGuardKey {
		t.Fatal("after a minute the faster coordinator must relay")
	}
	// An unhealthy relay is left at once.
	now = now.Add(coordHealthy + time.Second)
	vps.okAt = now
	e.p15.mc.mu.Lock()
	e.chooseRelayLocked(now)
	e.p15.mc.mu.Unlock()
	if e.p15.mc.relay != vps.c.WireGuardKey {
		t.Fatal("a silent relay coordinator must be replaced at once")
	}
}

func TestIntegrityFindings(t *testing.T) {
	base := t.TempDir()
	n, err := admin.Init(filepath.Join(base, "ag"), admin.InitOptions{DNSDomain: trust.DefaultDNSDomain, IPv4Prefix: trust.DefaultIPv4Prefix, Validity: trust.DefaultValidity}, e2ePass, e2eOpts, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cs, _ := trust.GenerateDeviceSecrets(rand.Reader, time.Now())
	_, cwg, _ := cs.PublicKeys()
	commit(t, n, func(doc *trust.Document) error { return doc.SetCoordinator("127.0.0.1:51820", cwg) })
	store := join(t, n, filepath.Join(base, "cihaz"))
	doc, _, digest := store.Snapshot()
	now := time.Now()
	e := &Engine{cfg: Config{Store: store, Now: func() time.Time { return now }}, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}

	// A coordinator that keeps announcing an older version.
	old := hexDigest32([32]byte{9})
	e.noteCoordinatorView(cwg, doc.Version-1, old, now)
	if f := e.CoordinatorIntegrity().Findings; len(f) != 0 {
		t.Fatalf("a coordinator just behind is not yet suspicious: %+v", f)
	}
	now = now.Add(integrityBehindGrace + time.Second)
	e.noteCoordinatorView(cwg, doc.Version-1, old, now)
	rep := e.CoordinatorIntegrity()
	if len(rep.Findings) != 1 || rep.Findings[0].Severity != "uyari" || !strings.Contains(rep.Findings[0].Text, "bölünmüş") {
		t.Fatalf("behind coordinator: %+v", rep.Findings)
	}
	// It catches up; then announces our version with another digest.
	e.noteCoordinatorView(cwg, doc.Version, hexDigest32([32]byte{1}), now)
	rep = e.CoordinatorIntegrity()
	if len(rep.Findings) != 1 || rep.Findings[0].Severity != "kritik" {
		t.Fatalf("different digest: %+v", rep.Findings)
	}
	e.noteCoordinatorView(cwg, doc.Version, hexDigest32(digest), now)
	if f := e.CoordinatorIntegrity().Findings; len(f) != 0 {
		t.Fatalf("an honest coordinator: %+v", f)
	}
	// A peer saw the same coordinator announce the same version with a
	// different digest: split view.
	var v control.CoordView
	copy(v.Key[:], cwg[:control.CoordKeyPrefixLen])
	v.Version, v.Digest, v.AgeSec = doc.Version, [32]byte{7}, 5
	data, _ := control.EncodeCoordViews([]control.CoordView{v})
	e.notePeerView(trust.Device{ID: "p", Name: "telefon"}, control.Message{Version: doc.Version, Digest: hexDigest32(digest), Data: data})
	rep = e.CoordinatorIntegrity()
	if len(rep.Findings) != 1 || rep.Findings[0].Peer != "telefon" || rep.Findings[0].Severity != "kritik" {
		t.Fatalf("split view: %+v", rep.Findings)
	}
	// Own views travel in the gossip hello.
	views, err := control.ParseCoordViews(e.ownCoordViews())
	if err != nil || len(views) != 1 || views[0].Version != doc.Version {
		t.Fatalf("own views: %v %+v", err, views)
	}
	e.noteEquivocation("p")
	if f := e.CoordinatorIntegrity().Findings; !f[0].Verified {
		t.Fatal("a proven equivocation must come first and be verified")
	}
}
