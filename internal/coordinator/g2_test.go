package coordinator

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/control"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/internal/wgconf"
)

// rootPriv opens the test network's root key.
func (r *memRig) rootPriv() ed25519.PrivateKey {
	r.t.Helper()
	data, err := securefile.ReadPrivate(filepath.Join(r.n.Dir(), "root.key"), trust.MaxSealedKeySize)
	if err != nil {
		r.t.Fatal(err)
	}
	sk, err := trust.UnmarshalSealedRootKey(data)
	if err != nil {
		r.t.Fatal(err)
	}
	priv, err := sk.Open(extPass)
	if err != nil {
		r.t.Fatal(err)
	}
	return priv
}

// restart builds a new server on the same store with h.
func (r *memRig) restart(h *Hardening) error {
	s, err := New(Config{Store: r.s.cfg.Store, Secrets: r.s.cfg.Secrets, Now: func() time.Time { return r.now }, Hardening: h})
	if err != nil {
		return err
	}
	s.tun = newControlTUN(r.s.cfg.Store.Document().Coordinator.IPv4, s.handle)
	s.status, s.statAt = r.s.status, r.s.statAt
	r.s = s
	return nil
}

// upload sends data in chunks with message type t.
func (r *memRig) upload(from trust.Device, t, target string, data []byte) control.Message {
	r.t.Helper()
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	var resp control.Message
	for off := 0; off < len(data); {
		end := min(off+control.ChunkSize, len(data))
		resp = r.do(from, control.Message{T: t, Target: target, Offset: off, Total: len(data), Digest: digest, Data: data[off:end]})
		if resp.T == control.TypeError {
			return resp
		}
		off = end
	}
	return resp
}

// download reads an object with message type t.
func (r *memRig) download(from trust.Device, t, target string) ([]byte, control.Message) {
	r.t.Helper()
	var out []byte
	var digest string
	for {
		resp := r.do(from, control.Message{T: t, Target: target, Offset: len(out), Digest: digest})
		if resp.T == control.TypeError {
			r.t.Fatalf("download: %s", resp.Error)
		}
		out = append(out, resp.Data...)
		digest = resp.Digest
		if resp.Complete || len(out) >= resp.Total {
			return out, resp
		}
	}
}

func TestHardeningFileStrictAndFailClosed(t *testing.T) {
	for _, bad := range []string{`{"schema":2}`, `{"schema":1,"spa":true,"x":1}`, `{"schema":1,"retention_minutes":5}`, `{"schema":1,"no_metadata":true,"retention_minutes":61}`, `{"schema":1}{}`} {
		if _, err := ParseHardening([]byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
	h, err := ParseHardening([]byte(`{"schema":1,"no_metadata":true}`))
	if err != nil || h.Retention() != DefaultMetadataRetention {
		t.Fatalf("%+v %v", h, err)
	}
	r := newMemRig(t)
	dir := r.s.cfg.Store.Dir()
	if err := os.WriteFile(filepath.Join(dir, HardeningFile), []byte(`{"schema":1,"spa":"yes"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := r.restart(nil); err == nil {
		t.Fatal("invalid hardening file did not stop the coordinator")
	}
	if err := SaveHardening(dir, Hardening{SPA: true, NoMetadata: true, RetentionMinutes: 5}); err != nil {
		t.Fatal(err)
	}
	if err := r.restart(nil); err != nil {
		t.Fatal(err)
	}
	if !r.s.g2.hard.SPA || r.s.g2.spa == nil || r.s.g2.hard.Retention() != 5 {
		t.Fatalf("hardening not applied: %+v", r.s.g2.hard)
	}
}

func TestCanaryStoredAndVerified(t *testing.T) {
	r := newMemRig(t)
	root := r.rootPriv()
	doc := r.s.cfg.Store.Document()
	c := Canary{NetworkID: doc.NetworkID, Seq: 1, IssuedAt: r.now, NotAfter: r.now.Add(30 * 24 * time.Hour), Statement: "Bu tarihe kadar hiçbir kurumdan gizli talep almadım.\nİmza: sahip"}
	data, err := SignCanary(root, c)
	if err != nil {
		t.Fatal(err)
	}
	if resp := r.upload(r.a, TypeCanaryPut, "", data); !resp.Complete || resp.Version != 1 {
		t.Fatalf("upload: %+v", resp)
	}
	got, _ := r.download(r.b, TypeCanary, "")
	if !bytes.Equal(got, data) {
		t.Fatal("canary changed in storage")
	}
	pub := root.Public().(ed25519.PublicKey)
	if _, st, err := OpenCanary(got, pub, doc.NetworkID, r.now); err != nil || st != CanaryValid {
		t.Fatalf("state %s %v", st, err)
	}
	if _, st, _ := OpenCanary(got, pub, doc.NetworkID, r.now.Add(25*24*time.Hour)); st != CanaryExpiring {
		t.Fatalf("expiring: %s", st)
	}
	if _, st, _ := OpenCanary(got, pub, doc.NetworkID, r.now.Add(31*24*time.Hour)); st != CanaryExpired {
		t.Fatalf("expired: %s", st)
	}
	if _, st, _ := OpenCanary(nil, pub, doc.NetworkID, r.now); st != CanaryMissing {
		t.Fatalf("missing: %s", st)
	}
	// The same sequence again (rollback/replay of another statement) and a
	// device-signed "canary" are refused.
	c.Statement = "başka"
	same, _ := SignCanary(root, c)
	if resp := r.upload(r.a, TypeCanaryPut, "", same); resp.T != control.TypeError {
		t.Fatalf("same sequence accepted: %+v", resp)
	}
	c.Seq = 2
	forged, _ := SignCanary(r.secrets["boss"].SigningKey(), c)
	if resp := r.upload(r.boss, TypeCanaryPut, "", forged); resp.T != control.TypeError {
		t.Fatalf("non-root canary accepted: %+v", resp)
	}
	if _, st, err := OpenCanary(forged, pub, doc.NetworkID, r.now); err == nil || st != CanaryInvalid {
		t.Fatal("forged canary verified")
	}
	// Tampered payload.
	o, _ := DecodeSignedObject(data)
	o.Payload = bytes.Replace(o.Payload, []byte(`"seq":1`), []byte(`"seq":9`), 1)
	bad, _ := EncodeSignedObject(o)
	if _, _, err := OpenCanary(bad, pub, doc.NetworkID, r.now); err == nil {
		t.Fatal("tampered canary verified")
	}
	// A coordinator restart (state directory) keeps it.
	if err := r.restart(nil); err != nil {
		t.Fatal(err)
	}
	if seq, ok := r.s.g2.objects.has("canary"); !ok || seq != 1 {
		t.Fatalf("canary not reloaded: %d %v", seq, ok)
	}
}

func TestSealedBlobOnlyRootOrAdmin(t *testing.T) {
	r := newMemRig(t)
	doc := r.s.cfg.Store.Document()
	sealed := make([]byte, 3000)
	_, _ = rand.Read(sealed)
	b := SealedBlob{NetworkID: doc.NetworkID, Kind: "emergency", Seq: 1, IssuedAt: r.now, Sealed: sealed}
	byAdmin, err := SignSealedBlob(r.secrets["boss"].SigningKey(), b)
	if err != nil {
		t.Fatal(err)
	}
	byMember, _ := SignSealedBlob(r.secrets["a"].SigningKey(), b)
	if resp := r.upload(r.a, TypeSealedBlobPut, "emergency", byMember); resp.T != control.TypeError {
		t.Fatalf("member-signed blob accepted: %+v", resp)
	}
	// Any member may carry an admin-signed blob (restoring a RAM-mode
	// coordinator), only the signature counts.
	if resp := r.upload(r.a, TypeSealedBlobPut, "emergency", byAdmin); !resp.Complete {
		t.Fatalf("admin blob refused: %+v", resp)
	}
	got, resp := r.download(r.b, TypeSealedBlob, "emergency")
	if !bytes.Equal(got, byAdmin) || resp.Version != 1 {
		t.Fatal("blob changed")
	}
	if _, err := OpenSealedBlob(got, doc, r.s.rootKey(), r.now); err != nil {
		t.Fatal(err)
	}
	// Wrong slot, root-signed newer version, rollback.
	if resp := r.upload(r.a, TypeSealedBlobPut, "other", byAdmin); resp.T != control.TypeError {
		t.Fatal("blob stored under another kind")
	}
	b.Seq = 2
	byRoot, _ := SignSealedBlob(r.rootPriv(), b)
	if resp := r.upload(r.boss, TypeSealedBlobPut, "emergency", byRoot); !resp.Complete || resp.Version != 2 {
		t.Fatalf("root blob refused: %+v", resp)
	}
	if resp := r.upload(r.boss, TypeSealedBlobPut, "emergency", byAdmin); resp.T != control.TypeError {
		t.Fatal("rollback accepted")
	}
	// Size limit and bad kind.
	b.Sealed = make([]byte, MaxSealedBlob+1)
	if _, err := SignSealedBlob(r.rootPriv(), b); err == nil {
		t.Fatal("oversized blob signed")
	}
	if resp := r.do(r.a, control.Message{T: TypeSealedBlob, Target: "../x"}); resp.T != control.TypeError {
		t.Fatal("bad kind accepted")
	}
	// Empty slot answers complete with no data.
	if resp := r.do(r.a, control.Message{T: TypeSealedBlob, Target: "nothing"}); !resp.Complete || resp.Total != 0 {
		t.Fatalf("empty slot: %+v", resp)
	}
}

func TestSPAGate(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	var key [32]byte
	key[0] = 7
	g := newSPAGate(key, func() time.Time { return now })
	src := netip.MustParseAddr("198.51.100.7")
	if g.allow(src) {
		t.Fatal("unknown source allowed")
	}
	k, err := SPAKnock(key, now, rand.Reader)
	if err != nil || len(k) != SPAKnockSize {
		t.Fatal(err)
	}
	if !g.knock(src, k) || !g.allow(src) {
		t.Fatal("valid knock refused")
	}
	if g.knock(netip.MustParseAddr("203.0.113.1"), k) {
		t.Fatal("replayed knock accepted")
	}
	old, _ := SPAKnock(key, now.Add(-2*SPASkew), rand.Reader)
	other, _ := SPAKnock([32]byte{1}, now, rand.Reader)
	if g.knock(src, old) || g.knock(src, other) {
		t.Fatal("stale or foreign knock accepted")
	}
	now = now.Add(SPAOpen + time.Second)
	if g.allow(src) {
		t.Fatal("gate stayed open")
	}
	// Key derivation depends on the coordinator key and the network.
	a := SPAKey(trust.Key{1}, "n1")
	if a == SPAKey(trust.Key{2}, "n1") || a == SPAKey(trust.Key{1}, "n2") {
		t.Fatal("key collision")
	}
}

type fakeEP struct{ s string }

func (e fakeEP) ClearSrc()           {}
func (e fakeEP) SrcToString() string { return "" }
func (e fakeEP) DstToString() string { return e.s }
func (e fakeEP) DstToBytes() []byte  { return []byte(e.s) }
func (e fakeEP) DstIP() netip.Addr   { return netip.MustParseAddrPort(e.s).Addr() }
func (e fakeEP) SrcIP() netip.Addr   { return netip.Addr{} }

func TestSPABindFilters(t *testing.T) {
	now := time.Now()
	g := newSPAGate([32]byte{3}, func() time.Time { return now })
	knock, _ := SPAKnock([32]byte{3}, now, rand.Reader)
	wg := []byte{1, 0, 0, 0, 9, 9}
	in := [][]byte{wg, knock, wg}
	from := []string{"198.51.100.1:1000", "198.51.100.2:2000", "198.51.100.2:2001"}
	recv := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		for i := range in {
			sizes[i] = copy(packets[i], in[i])
			eps[i] = fakeEP{from[i]}
		}
		return len(in), nil
	}
	b := &spaBind{gate: g}
	fn := b.filter(recv)
	packets := make([][]byte, 3)
	for i := range packets {
		packets[i] = make([]byte, 128)
	}
	sizes, eps := make([]int, 3), make([]conn.Endpoint, 3)
	n, err := fn(packets, sizes, eps)
	if err != nil {
		t.Fatal(err)
	}
	// Only the WireGuard packet after the knock (same address, other port)
	// passes; the knock itself never reaches WireGuard.
	if n != 1 || eps[0].DstToString() != "198.51.100.2:2001" || !bytes.Equal(packets[0][:sizes[0]], wg) {
		t.Fatalf("n=%d eps=%v", n, eps[:n])
	}
}

func TestSPATCPKnock(t *testing.T) {
	now := time.Now()
	g := newSPAGate([32]byte{5}, func() time.Time { return now })
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	results := make(chan bool, 2)
	go func() {
		for i := 0; i < 2; i++ {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			b := &tcpBind{knock: g.tcpKnock}
			_, ok := b.readKnock(c)
			results <- ok
			c.Close()
		}
	}()
	k, _ := SPAKnock([32]byte{5}, now, rand.Reader)
	for _, payload := range [][]byte{k, []byte(strings.Repeat("x", SPAKnockSize))} {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		_, _ = c.Write(payload)
		got := <-results
		c.Close()
		if got != bytes.Equal(payload, k) {
			t.Fatalf("knock result %v", got)
		}
	}
}

func TestNoMetadataMode(t *testing.T) {
	var buf bytes.Buffer
	l := slog.New(newRedactHandler(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	l.Debug("endpoint seen", "endpoint", "198.51.100.1:1")
	l.Info("relay", "device", "laptop", "address", "198.51.100.1", "bytes", 10)
	l.With("remote", "203.0.113.1").Warn("x")
	out := buf.String()
	if strings.Contains(out, "198.51.100") || strings.Contains(out, "laptop") || strings.Contains(out, "203.0.113") || strings.Contains(out, "endpoint seen") {
		t.Fatalf("metadata leaked: %s", out)
	}
	if !strings.Contains(out, `"bytes":10`) {
		t.Fatalf("other attributes lost: %s", out)
	}

	r := newMemRig(t)
	if err := r.restart(&Hardening{NoMetadata: true, RetentionMinutes: 1}); err != nil {
		t.Fatal(err)
	}
	// Usage is not loaded even with operations on.
	s, err := New(Config{Store: r.s.cfg.Store, Secrets: r.s.cfg.Secrets, Operations: true, Hardening: &Hardening{NoMetadata: true}})
	if err != nil {
		t.Fatal(err)
	}
	if s.ops.usage != nil {
		t.Fatal("usage file read in no-metadata mode")
	}
	r.setEndpoint(r.a, "198.51.100.1:40001")
	r.do(r.a, control.Message{T: control.TypeHello})
	r.s.relay.stats["x"] = &RelayStats{LastSeen: r.now}
	r.now = r.now.Add(2 * time.Minute)
	r.s.metadataSweep()
	if len(r.s.mem.clones) != 0 || len(r.s.relay.stats) != 0 {
		t.Fatalf("metadata kept: %d clones %d stats", len(r.s.mem.clones), len(r.s.relay.stats))
	}
	resp := r.do(r.boss, control.Message{T: TypeNoLog})
	var a NoLogAttestation
	if err := json.Unmarshal(resp.Data, &a); err != nil || !a.NoMetadata || a.RetentionMinutes != 1 || a.UsageFile {
		t.Fatalf("attestation %+v %v", a, err)
	}
	if resp := r.do(r.a, control.Message{T: TypeNoLog}); resp.T != control.TypeError {
		t.Fatal("non-admin got the attestation")
	}
}

func TestRAMOnlyRefusesDisk(t *testing.T) {
	r := newMemRig(t)
	if _, ram, _ := stateFileSystem(r.s.cfg.Store.Dir()); ram {
		t.Skip("test directory is on a RAM file system")
	}
	if err := r.restart(&Hardening{RAMOnly: true}); err == nil || !strings.Contains(err.Error(), "RAM") {
		t.Fatalf("RAM mode started on disk: %v", err)
	}
}

func TestSeedStateDir(t *testing.T) {
	seed, state := t.TempDir(), filepath.Join(t.TempDir(), "s")
	for name, body := range map[string]string{"anchor.json": "a", "network.json": "old", "coordinator.key": "k", "unrelated": "x"} {
		if err := os.WriteFile(filepath.Join(seed, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "network.json"), []byte("newer"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := SeedStateDir(seed, state)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "anchor.json,coordinator.key" {
		t.Fatalf("copied %v", got)
	}
	if b, _ := os.ReadFile(filepath.Join(state, "network.json")); string(b) != "newer" {
		t.Fatal("seed overwrote a newer document")
	}
	if _, err := os.Stat(filepath.Join(state, "unrelated")); err == nil {
		t.Fatal("unlisted file copied")
	}
}

func TestHeadAndCrossCheck(t *testing.T) {
	r := newMemRig(t)
	resp := r.do(r.a, control.Message{T: TypeHead})
	h, err := ParseHead(resp.Data)
	if err != nil || h.Version != r.s.cfg.Store.Document().Version {
		t.Fatalf("head %+v %v", h, err)
	}
	now := time.Now()
	h2 := h
	h2.Digest = strings.Repeat("ab", 32)
	rep := CrossCheck([]HeadObservation{{Coordinator: "c1", Head: &h}, {Coordinator: "c2", Head: &h2}, {Coordinator: "c3", Err: "timeout"}}, nil, now)
	kinds := map[string]bool{}
	for _, f := range rep.Findings {
		kinds[f.Kind] = true
	}
	if rep.OK || !kinds[FindingEquivocation] || !kinds[FindingUnreachable] {
		t.Fatalf("report %+v", rep)
	}
	h3 := h
	h3.Version++
	lag := map[string]time.Time{"c1": now.Add(-HeadStaleAfter - time.Minute)}
	rep = CrossCheck([]HeadObservation{{Coordinator: "c1", Head: &h}, {Coordinator: "c2", Head: &h3}}, lag, now)
	if rep.OK || len(rep.Findings) != 1 || rep.Findings[0].Kind != FindingStale || rep.Newest != h3.Version {
		t.Fatalf("stale report %+v", rep)
	}
	if rep := CrossCheck([]HeadObservation{{Coordinator: "c1", Head: &h}, {Coordinator: "c2", Head: &h3}}, nil, now); !rep.OK {
		t.Fatalf("fresh lag reported: %+v", rep)
	}
	if adv := IndependenceAdvice(r.s.cfg.Store.Document(), now); len(adv) != 1 || adv[0].Kind != FindingSingle {
		t.Fatalf("advice %+v", adv)
	}
	if _, err := ParseHead([]byte(`{"schema":1,"digest":"zz"}`)); err == nil {
		t.Fatal("bad head parsed")
	}
}

func TestCloneSweepAndQuarantine(t *testing.T) {
	r := newMemRig(t)
	if err := r.restart(&Hardening{CloneQuarantine: true}); err != nil {
		t.Fatal(err)
	}
	eps := []string{"198.51.100.1:40001", "203.0.113.9:50000"}
	// The device never asks anything; the sweep alone sees the flips.
	for i := 0; i < 8; i++ {
		r.now = r.now.Add(3 * time.Second)
		r.s.status = wgconf.Status{Peers: map[trust.Key]wgconf.PeerStatus{r.a.WireGuardKey: {Endpoint: netip.MustParseAddrPort(eps[i%2])}}}
		r.s.statAt = time.Now()
		r.s.cloneSweep()
	}
	if al := r.s.CloneAlerts(); len(al) != 1 || al[0].DeviceID != r.a.ID {
		t.Fatalf("alerts %+v", al)
	}
	r.s.statAt = time.Now().Add(time.Hour)
	if resp := r.do(r.a, control.Message{T: control.TypeHello}); resp.T != control.TypeError || !strings.Contains(resp.Error, "iki yerde") {
		t.Fatalf("quarantined device served: %+v", resp)
	}
	if resp := r.do(r.a, control.Message{T: control.TypeCaps}); resp.T == control.TypeError {
		t.Fatal("caps refused during quarantine")
	}
	if resp := r.do(r.b, control.Message{T: control.TypeHello}); resp.T == control.TypeError {
		t.Fatal("other device refused")
	}
	r.now = r.now.Add(cloneQuarantineFor + time.Minute)
	if resp := r.do(r.a, control.Message{T: control.TypeHello}); resp.T == control.TypeError {
		t.Fatal("quarantine did not end")
	}
}

func TestEmergencyPriority(t *testing.T) {
	r := newMemRig(t)
	r.do(r.a, control.Message{T: control.TypeCaps}) // subscribe a to pushes
	r.s.emergencyTick()
	if r.s.EmergencyActive() {
		t.Fatal("emergency without a lock")
	}
	r.commit(admin.SetLockdown(true, "panik testi", time.Now()))
	r.publish(r.boss)
	r.s.emergencyTick()
	if !r.s.EmergencyActive() {
		t.Fatal("lock did not start the emergency priority")
	}
	if p := r.pushed(); len(p[r.a.IPv4]) != 1 || p[r.a.IPv4][0].T != control.TypeNotify {
		t.Fatalf("first push missing: %v", p)
	}
	r.now = r.now.Add(3 * time.Second)
	r.s.emergencyTick()
	if p := r.pushed(); len(p[r.a.IPv4]) != 1 {
		t.Fatalf("repeat push missing: %v", p)
	}
	// Control limits exhausted: document fetches still pass, others not.
	for i := 0; i < 10000 && r.s.p15.allowControl(r.a.IPv4, r.s.cfg.Now()); i++ {
	}
	hello, _ := control.Encode(control.Message{T: control.TypeHello})
	peers, _ := control.Encode(control.Message{T: control.TypePeers})
	if !r.s.allowControlG2(r.a.IPv4, hello) || r.s.allowControlG2(r.a.IPv4, peers) {
		t.Fatal("emergency bypass wrong")
	}
	r.now = r.now.Add(EmergencyWindow + time.Second)
	r.s.emergencyTick()
	if r.s.EmergencyActive() {
		t.Fatal("emergency never ended")
	}
	if r.s.allowControlG2(r.a.IPv4, hello) && !r.s.p15.allowControl(r.a.IPv4, r.s.cfg.Now()) {
		t.Fatal("bypass outlived the window")
	}
}

func TestBlindCoordinatorIgnoresPolicy(t *testing.T) {
	r := newExtRig(t)
	if resp := r.do(r.c, control.Message{T: control.TypePeers}); resp.Total != 0 {
		t.Fatalf("c sees %d peers", resp.Total)
	}
	s, err := New(Config{Store: r.s.cfg.Store, Secrets: r.s.cfg.Secrets, Now: func() time.Time { return r.now },
		Hardening: &Hardening{Blind: true}, SealedPolicy: func(*trust.Document) bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	s.status, s.statAt = r.s.status, r.s.statAt
	s.tun = r.s.tun
	r.s = s
	if resp := r.do(r.c, control.Message{T: control.TypePeers}); resp.Total != 2 {
		t.Fatalf("blind c sees %d peers", resp.Total)
	}
	if v := CoordinatorView(r.s.cfg.Store.Document()); len(v) != 3 || v[0].ID == "" {
		t.Fatalf("view %+v", v)
	}
}

func TestG2FeaturesAnnounced(t *testing.T) {
	r := newExtRig(t)
	resp := r.do(r.a, control.Message{T: control.TypeCaps})
	for _, f := range g2Features {
		found := false
		for _, g := range resp.Features {
			found = found || g == f
		}
		if !found {
			t.Fatalf("feature %s missing in %v", f, resp.Features)
		}
	}
}

func FuzzParseHardening(f *testing.F) {
	f.Add([]byte(`{"schema":1,"spa":true}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		h, err := ParseHardening(data)
		if err == nil && h.Validate() != nil {
			t.Fatal("parsed invalid options")
		}
	})
}

func FuzzDecodeSignedObject(f *testing.F) {
	f.Add([]byte(`{"payload":"eA==","signature":""}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DecodeSignedObject(data)
		_, _, _ = OpenCanary(data, make(ed25519.PublicKey, ed25519.PublicKeySize), "n", time.Now())
	})
}

func TestSPAOnTCPTransport(t *testing.T) {
	tb, _, _, addr := startTCPBind(t, 8, 8)
	key := [32]byte{9}
	gate := newSPAGate(key, time.Now)
	tb.knock = gate.tcpKnock
	readMagic := func(c net.Conn) bool {
		buf := make([]byte, len(control.TCPMagic))
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, err := io.ReadFull(c, buf)
		return err == nil && string(buf) == control.TCPMagic
	}
	// Without a knock the preamble is never answered.
	c := dialTransport(t, addr)
	if readMagic(c) {
		t.Fatal("transport answered without a knock")
	}
	k, _ := SPAKnock(key, time.Now(), rand.Reader)
	c2, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	_, _ = c2.Write(append(k, control.TCPMagic...))
	if !readMagic(c2) {
		t.Fatal("transport refused a knocked connection")
	}
}
