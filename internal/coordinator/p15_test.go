package coordinator

import (
	"crypto/rand"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/control"
	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/internal/wgconf"
)

// p15Rig is a network with a primary and an additional coordinator and
// two devices a and b that see each other; c sees nobody.
type p15Rig struct {
	t          *testing.T
	n          *admin.Network
	store      *member.Store
	prim, home *trust.DeviceSecrets
	secrets    map[string]*trust.DeviceSecrets
	a, b, c    trust.Device
	now        time.Time
}

func newP15Rig(t *testing.T) *p15Rig {
	t.Helper()
	base := t.TempDir()
	n, err := admin.Init(filepath.Join(base, "ag"), admin.InitOptions{DNSDomain: trust.DefaultDNSDomain, IPv4Prefix: trust.DefaultIPv4Prefix, Validity: trust.DefaultValidity}, extPass, extOpts, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	r := &p15Rig{t: t, n: n, now: time.Now(), secrets: map[string]*trust.DeviceSecrets{}}
	gen := func() *trust.DeviceSecrets {
		s, err := trust.GenerateDeviceSecrets(rand.Reader, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	r.prim, r.home = gen(), gen()
	_, primWG, _ := r.prim.PublicKeys()
	_, homeWG, _ := r.home.PublicKeys()
	r.commit(func(doc *trust.Document) error { return doc.SetCoordinator("127.0.0.1:51820", primWG) })
	r.commit(func(doc *trust.Document) error { return doc.AddCoordinator("127.0.0.1:51821", homeWG, "ev", "ist") })
	for _, name := range []string{"a", "b", "c"} {
		s := gen()
		env, _, err := s.NewEnrollmentRequest(name, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		req, err := trust.OpenEnrollmentRequest(env, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		r.commit(func(doc *trust.Document) error {
			_, err := doc.AddDevice(req, name, nil, time.Now(), trust.DefaultDeviceLife)
			return err
		})
		r.secrets[name] = s
	}
	r.commit(func(doc *trust.Document) error {
		return doc.AddRule(trust.Rule{From: []string{"a"}, To: []string{"b"}, Protocol: trust.ProtocolAny})
	})
	bundle, err := n.JoinBundle()
	if err != nil {
		t.Fatal(err)
	}
	r.store, err = member.Join(filepath.Join(base, "koordinator"), bundle, n.RootFingerprint(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	doc := r.store.Document()
	r.a, _ = doc.DeviceByName("a")
	r.b, _ = doc.DeviceByName("b")
	r.c, _ = doc.DeviceByName("c")
	return r
}

func (r *p15Rig) commit(change admin.Change) {
	r.t.Helper()
	plan, err := r.n.Prepare(time.Now(), trust.DefaultValidity, change)
	if err != nil {
		r.t.Fatal(err)
	}
	if err := r.n.Commit(plan, extPass); err != nil {
		r.t.Fatal(err)
	}
}

func (r *p15Rig) server(secrets *trust.DeviceSecrets, mutate func(*Config)) *Server {
	r.t.Helper()
	cfg := Config{Store: r.store, Secrets: secrets, Now: func() time.Time { return r.now }}
	if mutate != nil {
		mutate(&cfg)
	}
	s, err := New(cfg)
	if err != nil {
		r.t.Fatalf("New: %v", err)
	}
	// Handlers are called directly; WireGuard's status is cached far ahead
	// so they never ask the (absent) device.
	s.status = wgconf.Status{Peers: map[trust.Key]wgconf.PeerStatus{}}
	s.statAt = time.Now().Add(time.Hour)
	return s
}

func call(t *testing.T, s *Server, from trust.Device, m control.Message) control.Message {
	t.Helper()
	m.ID = 7
	data, err := control.Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	out := s.handle(from.IPv4, data)
	if out == nil {
		t.Fatalf("%s: no reply", m.T)
	}
	resp, err := control.Decode(out)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestAdditionalCoordinatorServes(t *testing.T) {
	r := newP15Rig(t)
	doc := r.store.Document()
	home := r.server(r.home, nil)
	if got := home.controlAddr(doc); got != doc.Coordinators[0].IPv4 || got == doc.Coordinator.IPv4 {
		t.Fatalf("additional coordinator answers on %v", got)
	}
	prim := r.server(r.prim, nil)
	if got := prim.controlAddr(doc); got != doc.Coordinator.IPv4 {
		t.Fatalf("primary answers on %v", got)
	}
	resp := call(t, home, r.a, control.Message{T: control.TypeHello})
	if resp.T != control.TypeHello || resp.Version != doc.Version {
		t.Fatalf("hello from the additional coordinator: %+v", resp)
	}
	caps := call(t, home, r.a, control.Message{T: control.TypeCaps})
	if !strings.Contains(strings.Join(caps.Features, ","), control.FeatureRelaySession) {
		t.Fatal("caps must announce relay sessions")
	}
	// An unknown key is refused; a key whose transition ended too.
	stranger, _ := trust.GenerateDeviceSecrets(rand.Reader, time.Now())
	if _, err := New(Config{Store: r.store, Secrets: stranger}); err == nil {
		t.Fatal("an unlisted key must be refused")
	}
	_, homeWG, _ := r.home.PublicKeys()
	if err := checkListed(doc, homeWG, false, time.Now()); err != nil {
		t.Fatal(err)
	}
	ended := *doc
	ended.Coordinators = []trust.Coordinator{doc.Coordinators[0]}
	ended.Coordinators[0].Until = time.Now().Add(-time.Minute)
	if err := checkListed(&ended, homeWG, false, time.Now()); err == nil {
		t.Fatal("a coordinator after its transition must be refused")
	}
	if err := checkListed(&ended, homeWG, true, time.Now()); err != nil {
		t.Fatal("handoff mode must still start")
	}
}

func TestControlRateLimit(t *testing.T) {
	r := newP15Rig(t)
	s := r.server(r.prim, func(c *Config) { c.ControlRate, c.ControlBurst = 10, 10 })
	data, _ := control.Encode(control.Message{T: control.TypeHello, ID: 1})
	answered := 0
	for i := 0; i < 30; i++ {
		if s.limitedHandle(r.a.IPv4, data) != nil {
			answered++
		}
	}
	if answered != 10 {
		t.Fatalf("answered %d of 30 with a burst of 10", answered)
	}
	if s.ControlDropped() != 20 {
		t.Fatalf("dropped %d", s.ControlDropped())
	}
	// Another device has its own bucket.
	if s.limitedHandle(r.b.IPv4, data) == nil {
		t.Fatal("another device must not be limited")
	}
	// The bucket refills.
	r.now = r.now.Add(time.Second)
	if s.limitedHandle(r.a.IPv4, data) == nil {
		t.Fatal("bucket must refill")
	}
	for _, bad := range []Config{{ControlRate: 1}, {ControlBurst: MaxControlBurst + 1}, {RelayMaxPeers: -1}, {RelayTotalRate: 5}} {
		bad.Store, bad.Secrets = r.store, r.prim
		if _, err := New(bad); err == nil {
			t.Errorf("config %+v must be rejected", bad)
		}
	}
}

func (r *p15Rig) session(s *Server, dev trust.Device, coordKey trust.Key, end time.Time) control.Message {
	r.t.Helper()
	raw, _ := hex.DecodeString(dev.ID)
	var sess control.RelaySession
	copy(sess.Device[:], raw)
	sess.Coordinator, sess.Expires = [32]byte(coordKey), end
	payload, sig, err := control.SignRelaySession(r.secrets[dev.Name].SigningKey(), sess)
	if err != nil {
		r.t.Fatal(err)
	}
	return call(r.t, s, dev, control.Message{T: control.TypeRelaySession, Data: payload, Sig: sig})
}

func relayPacket(to trust.Device) []byte {
	raw, _ := hex.DecodeString(to.ID)
	return append(raw, make([]byte, 100)...)
}

func TestRelaySessions(t *testing.T) {
	r := newP15Rig(t)
	s := r.server(r.prim, nil)
	_, primWG, _ := r.prim.PublicKeys()
	_, homeWG, _ := r.home.PublicKeys()

	// Old behaviour: a device without a session is relayed.
	if _, _, ok := s.relay.forward(r.a.IPv4, relayPacket(r.b)); !ok {
		t.Fatal("a device that never opened a session must be relayed as before")
	}
	// Bad sessions.
	if resp := r.session(s, r.a, homeWG, r.now.Add(5*time.Minute)); resp.T != control.TypeError {
		t.Fatal("a session for another coordinator must be refused")
	}
	if resp := r.session(s, r.a, primWG, r.now.Add(-time.Second)); resp.T != control.TypeError {
		t.Fatal("an ended session must be refused")
	}
	if resp := r.session(s, r.a, primWG, r.now.Add(time.Hour)); resp.T != control.TypeError {
		t.Fatal("a session too far ahead must be refused")
	}
	// Signed by another device's key.
	raw, _ := hex.DecodeString(r.a.ID)
	var forged control.RelaySession
	copy(forged.Device[:], raw)
	forged.Coordinator, forged.Expires = [32]byte(primWG), r.now.Add(time.Minute)
	payload, sig, _ := control.SignRelaySession(r.secrets["b"].SigningKey(), forged)
	if resp := call(t, s, r.a, control.Message{T: control.TypeRelaySession, Data: payload, Sig: sig}); resp.T != control.TypeError {
		t.Fatal("a session signed by another key must be refused")
	}
	// A valid session; then the device is held to sessions.
	end := r.now.Add(control.RelaySessionMaxLife).Truncate(time.Second)
	if resp := r.session(s, r.a, primWG, end); resp.T != control.TypeRelaySession || !resp.Complete {
		t.Fatalf("valid session refused: %+v", resp)
	}
	if _, _, ok := s.relay.forward(r.a.IPv4, relayPacket(r.b)); !ok {
		t.Fatal("relaying under a session must work")
	}
	if _, _, ok := s.relay.forward(r.a.IPv4, relayPacket(r.c)); ok {
		t.Fatal("a session never widens what the document allows")
	}
	r.now = end.Add(time.Second)
	if _, _, ok := s.relay.forward(r.a.IPv4, relayPacket(r.b)); ok {
		t.Fatal("after the session ends a device that used sessions must not be relayed")
	}
	// RelayRequireSessions: nobody without a session.
	strict := r.server(r.prim, func(c *Config) { c.RelayRequireSessions = true })
	if _, _, ok := strict.relay.forward(r.b.IPv4, relayPacket(r.a)); ok {
		t.Fatal("RelayRequireSessions must refuse a device without a session")
	}
}

func TestRelayPeerAndTotalLimits(t *testing.T) {
	r := newP15Rig(t)
	g := newP15State(limitsConfig{relayMaxPeers: 2, relayTotal: float64(MinRelayRate)}, r.now)
	from := trust.Device{ID: "a"}
	for _, id := range []string{"b", "c"} {
		if !g.relayGuard(from, trust.Device{ID: id}, 100, r.now) {
			t.Fatalf("peer %s within the limit refused", id)
		}
	}
	if g.relayGuard(from, trust.Device{ID: "d"}, 100, r.now) {
		t.Fatal("a third peer within a minute must be refused")
	}
	if !g.relayGuard(from, trust.Device{ID: "b"}, 100, r.now) {
		t.Fatal("a known peer must still be relayed")
	}
	later := r.now.Add(relayPeerWindow + time.Second)
	if !g.relayGuard(from, trust.Device{ID: "d"}, 100, later) {
		t.Fatal("after the window a new peer must be allowed")
	}
	// Total rate: the bucket holds one second of traffic.
	total := 0
	for i := 0; i < 1000 && g.relayGuard(from, trust.Device{ID: "d"}, 1000, later); i++ {
		total += 1000
	}
	if total > MinRelayRate || total < MinRelayRate-1000 {
		t.Fatalf("total limit passed %d bytes", total)
	}
}
