package coordinator

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/control"
	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/trust"
)

// containsAny reports which of secrets occurs in data.
func containsAny(data []byte, secrets []string) string {
	for _, s := range secrets {
		if bytes.Contains(data, []byte(s)) {
			return s
		}
	}
	return ""
}

// TestMembersOnlyBlindCoordinator runs a members-only network (#629,
// ADR-0178) end to end: the owner seals, the coordinator serves the public
// part blind and never holds a device name or rule text in memory, on disk
// or in its log, and a member opens the complete document.
func TestMembersOnlyBlindCoordinator(t *testing.T) {
	r := newMemRig(t)
	const tag, port, display = "gizlietiket", "47123", "Gizli Ev Agi"
	secrets := []string{`"boss"`, tag, port, display}
	if err := r.n.SetMembersOnly(true); err == nil {
		t.Fatal("members-only turned on without a client minimum")
	}
	r.commit(func(doc *trust.Document) error {
		return doc.SetMinClientVersion(trust.MembersOnlyMinClientVersion)
	})
	if err := r.n.SetMembersOnly(true); err != nil {
		t.Fatal(err)
	}
	r.commit(func(doc *trust.Document) error {
		doc.DisplayName = display
		for i := range doc.Devices {
			if doc.Devices[i].Name == "boss" {
				doc.Devices[i].Tags = []string{tag}
			}
		}
		return doc.AddRule(trust.Rule{From: []string{"a"}, To: []string{"b"}, Protocol: trust.ProtocolTCP, Ports: []string{port}})
	})
	// The owner keeps working with the complete document.
	full, err := r.n.Document()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := full.DeviceByName("boss"); !ok || len(full.Rules) == 0 || full.DisplayName != display {
		t.Fatal("owner lost the members part")
	}
	if err := r.n.Reload(); err != nil {
		t.Fatalf("owner reload: %v", err)
	}
	if hit := containsAny(r.networkJSON(), secrets); hit != "" {
		t.Fatalf("published network.json contains %s", hit)
	}

	// Coordinator: accepts the public part and works blind.
	if resp := r.publish(r.boss); !resp.Complete {
		t.Fatalf("publish: %+v", resp)
	}
	var logs bytes.Buffer
	s, err := New(Config{Store: r.s.cfg.Store, Secrets: r.s.cfg.Secrets, Now: func() time.Time { return r.now },
		Logger: slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))})
	if err != nil {
		t.Fatal(err)
	}
	s.tun = newControlTUN(r.s.cfg.Store.Document().Coordinator.IPv4, s.handle)
	s.status, s.statAt = r.s.status, r.s.statAt
	r.s = s
	doc := r.s.cfg.Store.Document()
	if !trust.IsMembersOnly(doc) {
		t.Fatal("coordinator holds an unsealed document")
	}
	// The rule only lets a reach b; blind, a learns every member's endpoint.
	if resp := r.do(r.a, control.Message{T: control.TypeClientVersion, Data: []byte(trust.MembersOnlyMinClientVersion)}); !resp.Complete {
		t.Fatalf("version report: %+v", resp)
	}
	if resp := r.do(r.a, control.Message{T: control.TypePeers}); resp.Total != 2 {
		t.Fatalf("blind coordinator gave a %d peers", resp.Total)
	}
	r.s.relay.mu.Lock()
	r.s.relay.refreshLocked()
	relayOK := r.s.relay.peers[r.a.ID][r.boss.ID]
	r.s.relay.mu.Unlock()
	if !relayOK {
		t.Fatal("blind relay refuses a member")
	}
	inMemory, _ := json.Marshal(doc)
	if hit := containsAny(inMemory, secrets); hit != "" {
		t.Fatalf("coordinator memory contains %s", hit)
	}
	if hit := containsAny(logs.Bytes(), secrets); hit != "" {
		t.Fatalf("coordinator log contains %s", hit)
	}
	err = filepath.WalkDir(r.s.cfg.Store.Dir(), func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if hit := containsAny(data, secrets); hit != "" {
			t.Errorf("coordinator file %s contains %s", filepath.Base(path), hit)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// Member: opens the complete document with its own key.
	bundle, err := r.n.JoinBundle()
	if err != nil {
		t.Fatal(err)
	}
	dev, err := member.Join(filepath.Join(filepath.Dir(r.n.Dir()), "cihaz-a"), bundle, r.n.RootFingerprint(), r.now)
	if err != nil {
		t.Fatal(err)
	}
	if trust.IsMembersOnly(dev.Document()) == false {
		t.Fatal("a store without a key must hold the public part")
	}
	sa := r.secrets["a"]
	dev.SetMembersKey(sa.DeviceID, sa.WireGuardPrivate)
	got := dev.Document()
	if err := dev.MembersPartError(); err != nil {
		t.Fatal(err)
	}
	if boss, ok := got.DeviceByName("boss"); !ok || len(boss.Tags) != 1 || len(got.Rules) != len(full.Rules) {
		t.Fatal("member did not get the complete document")
	}
	want, _ := json.Marshal(full)
	have, _ := json.Marshal(got)
	if !bytes.Equal(want, have) {
		t.Fatal("member and owner hold different documents")
	}
	if peers := got.TunnelPeersOf("a"); len(peers) != len(full.TunnelPeersOf("a")) {
		t.Fatal("member decides differently from the owner")
	}
}
