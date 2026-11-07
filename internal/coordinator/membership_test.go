package coordinator

import (
	"crypto/rand"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/control"
	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/internal/wgconf"
)

// memRig is extRig with the device secrets kept and "boss" as admin.
type memRig struct {
	*extRig
	secrets map[string]*trust.DeviceSecrets
	boss    trust.Device
}

func newMemRig(t *testing.T) *memRig {
	t.Helper()
	base := t.TempDir()
	n, err := admin.Init(filepath.Join(base, "ag"), admin.InitOptions{DNSDomain: trust.DefaultDNSDomain, IPv4Prefix: trust.DefaultIPv4Prefix, Validity: trust.DefaultValidity}, extPass, extOpts, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	r := &memRig{extRig: &extRig{t: t, n: n, now: time.Now()}, secrets: map[string]*trust.DeviceSecrets{}}
	coordSecrets, _ := trust.GenerateDeviceSecrets(rand.Reader, time.Now())
	_, coordWG, _ := coordSecrets.PublicKeys()
	r.commit(func(doc *trust.Document) error { return doc.SetCoordinator("127.0.0.1:51820", coordWG) })
	for _, name := range []string{"a", "b", "boss"} {
		s, _ := trust.GenerateDeviceSecrets(rand.Reader, time.Now())
		env, _, _ := s.NewEnrollmentRequest(name, time.Now())
		req, err := trust.OpenEnrollmentRequest(env, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		r.secrets[name] = s
		roles := []trust.Role(nil)
		if name == "boss" {
			roles = []trust.Role{trust.RoleAdmin}
		}
		r.commit(func(doc *trust.Document) error {
			_, err := doc.AddDevice(req, name, roles, time.Now(), trust.DefaultDeviceLife)
			return err
		})
	}
	bundle, _ := n.JoinBundle()
	store, err := member.Join(filepath.Join(base, "koordinator"), bundle, n.RootFingerprint(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	r.s, err = New(Config{Store: store, Secrets: coordSecrets, Now: func() time.Time { return r.now }})
	if err != nil {
		t.Fatal(err)
	}
	doc := store.Document()
	r.a, _ = doc.DeviceByName("a")
	r.b, _ = doc.DeviceByName("b")
	r.boss, _ = doc.DeviceByName("boss")
	r.s.tun = newControlTUN(doc.Coordinator.IPv4, r.s.handle)
	r.setEndpoint(r.a, "198.51.100.1:40001")
	return r
}

func (r *memRig) commit(change admin.Change) {
	r.t.Helper()
	if _, err := r.n.Apply(extPass, time.Now(), change); err != nil {
		r.t.Fatal(err)
	}
}

func (r *memRig) networkJSON() []byte {
	r.t.Helper()
	data, err := securefile.ReadPrivate(filepath.Join(r.n.Dir(), "network.json"), trust.MaxEnvelopeSize)
	if err != nil {
		r.t.Fatal(err)
	}
	return data
}

// publish hands the owner's current document to the coordinator's store,
// which is what a completed put does (put itself also reconciles the
// WireGuard device, which this rig does not run).
func (r *memRig) publish(trust.Device) control.Message {
	r.t.Helper()
	if _, err := r.s.cfg.Store.Accept(r.networkJSON(), r.now); err != nil {
		return control.Message{T: control.TypeError, Error: err.Error()}
	}
	return control.Message{T: control.TypePut, Complete: true}
}

func (r *memRig) setEndpoint(d trust.Device, ep string) {
	r.s.status = wgconf.Status{Peers: map[trust.Key]wgconf.PeerStatus{d.WireGuardKey: {Endpoint: netip.MustParseAddrPort(ep)}}}
	r.s.statAt = time.Now().Add(time.Hour)
}

func TestMinimumClientVersion(t *testing.T) {
	r := newMemRig(t)
	r.commit(func(doc *trust.Document) error { return doc.SetMinClientVersion("1.0.0") })
	if resp := r.publish(r.boss); !resp.Complete {
		t.Fatalf("admin publish: %+v", resp)
	}
	hello := func(d trust.Device) control.Message { return r.do(d, control.Message{T: control.TypeHello}) }
	if resp := hello(r.a); resp.T != control.TypeError || !strings.Contains(resp.Error, control.ErrVersionNotReported) {
		t.Fatalf("unreported version: %+v", resp)
	}
	if resp := r.do(r.a, control.Message{T: control.TypeClientVersion, Data: []byte("0.9.9")}); !resp.Complete {
		t.Fatalf("ver: %+v", resp)
	}
	if resp := hello(r.a); resp.T != control.TypeError || !strings.Contains(resp.Error, "asgari") {
		t.Fatalf("old version: %+v", resp)
	}
	r.do(r.a, control.Message{T: control.TypeClientVersion, Data: []byte("1.2.0 (abc)")})
	if resp := hello(r.a); resp.T != control.TypeHello {
		t.Fatalf("new version refused: %+v", resp)
	}
	// Admin devices are never locked out.
	if resp := hello(r.boss); resp.T != control.TypeHello {
		t.Fatalf("admin refused: %+v", resp)
	}
	caps := r.do(r.b, control.Message{T: control.TypeCaps})
	if caps.T != control.TypeCaps || !slices.Contains(caps.Features, control.FeatureVersion) || !slices.Contains(caps.Features, control.FeatureRoot) {
		t.Fatalf("caps without membership features: %+v", caps)
	}
}

func TestLeaveRequestsForAdmins(t *testing.T) {
	r := newMemRig(t)
	sl, err := r.secrets["a"].NewLeaveRequest(rand.Reader, r.s.cfg.Store.Document().NetworkID, r.now)
	if err != nil {
		t.Fatal(err)
	}
	// A leave signed by another device is refused.
	if resp := r.do(r.b, control.Message{T: control.TypeLeave, Data: sl.Payload, Sig: sl.Signature}); resp.T != control.TypeError {
		t.Fatalf("forged leave accepted: %+v", resp)
	}
	if resp := r.do(r.a, control.Message{T: control.TypeLeave, Data: sl.Payload, Sig: sl.Signature}); !resp.Complete {
		t.Fatalf("leave: %+v", resp)
	}
	if resp := r.do(r.b, control.Message{T: control.TypeLeaves}); resp.T != control.TypeError {
		t.Fatal("non-admin listed leave requests")
	}
	resp := r.do(r.boss, control.Message{T: control.TypeLeaves})
	if resp.Total != 1 || resp.Target != r.a.ID {
		t.Fatalf("leaves: %+v", resp)
	}
	got := trust.SignedLeave{DeviceID: resp.Target, Payload: resp.Data, Signature: resp.Sig}
	if _, err := r.n.ApplyLeave(extPass, got, time.Now()); err != nil {
		t.Fatalf("owner apply: %v", err)
	}
	if resp := r.publish(r.boss); !resp.Complete {
		t.Fatalf("publish: %+v", resp)
	}
	if resp := r.do(r.boss, control.Message{T: control.TypeLeaves}); resp.Total != 0 {
		t.Fatal("leave of a removed device still listed")
	}
}

func TestCloneAlert(t *testing.T) {
	r := newMemRig(t)
	eps := []string{"198.51.100.1:40001", "203.0.113.9:50000"}
	for i := 0; i < 8; i++ {
		r.now = r.now.Add(3 * time.Second)
		r.setEndpoint(r.a, eps[i%2])
		r.do(r.a, control.Message{T: control.TypeHello})
	}
	resp := r.do(r.boss, control.Message{T: control.TypeAlerts})
	if resp.Total != 1 {
		t.Fatalf("alerts: %+v", resp)
	}
	a, err := control.DecodeCloneAlert(resp.Data)
	if err != nil || a.DeviceID != r.a.ID || len(a.Endpoints) != 2 {
		t.Fatalf("alert %+v %v", a, err)
	}
	// A device that roams once raises nothing.
	t2 := &cloneTrack{}
	now := time.Now()
	for i, ep := range []string{"x:1", "y:2", "y:2", "z:3"} {
		if observeEndpoint(t2, ep, now.Add(time.Duration(i)*time.Second)) {
			t.Fatal("roaming device flagged")
		}
	}
}

func TestRootTransitionThroughCoordinator(t *testing.T) {
	r := newMemRig(t)
	if _, err := r.n.RotateRoot(extPass, nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	// The new root's document is refused until the transition is known.
	if resp := r.publish(r.boss); resp.T != control.TypeError {
		t.Fatalf("new root accepted without transition: %+v", resp)
	}
	ts, _ := r.n.RootTransitions()
	if resp := r.do(r.b, control.Message{T: control.TypeRootPut, Data: []byte("{}"), Sig: make([]byte, 64)}); resp.T != control.TypeError {
		t.Fatal("garbage transition kept")
	}
	if resp := r.do(r.boss, control.Message{T: control.TypeRootPut, Data: ts[0].Payload, Sig: ts[0].Signature}); !resp.Complete {
		t.Fatalf("rput: %+v", resp)
	}
	if resp := r.publish(r.boss); !resp.Complete {
		t.Fatalf("publish after transition: %+v", resp)
	}
	resp := r.do(r.a, control.Message{T: control.TypeRoot})
	if resp.Version != 1 || resp.Total != 1 || len(resp.Data) == 0 {
		t.Fatalf("root: %+v", resp)
	}
}

func TestRejectPendingEnrollment(t *testing.T) {
	r := newMemRig(t)
	created, err := r.n.CreateInviteWith(extPass, time.Now(), admin.InviteRequest{Life: time.Hour, MaxUses: 3})
	if err != nil {
		t.Fatal(err)
	}
	if resp := r.publish(r.boss); !resp.Complete {
		t.Fatalf("publish: %+v", resp)
	}
	code, _ := trust.DecodeInviteCode(created.Code)
	send := func() (string, control.Message) {
		s, _ := trust.GenerateDeviceSecrets(rand.Reader, r.now)
		se, req, err := s.NewInviteEnrollment(code, "new", r.now)
		if err != nil {
			t.Fatal(err)
		}
		m := control.Message{T: control.TypeEnroll, Data: se.Payload, Sig: se.DeviceSignature, InviteSig: se.InviteSignature, ID: 7}
		data, _ := control.Encode(m)
		out, err := control.Decode(r.s.handle(code.IPv4, data))
		if err != nil {
			t.Fatal(err)
		}
		return req.DeviceID, out
	}
	id1, resp := send()
	if !resp.Complete {
		t.Fatalf("enroll: %+v", resp)
	}
	if _, resp := send(); !resp.Complete {
		t.Fatalf("second enroll: %+v", resp)
	}
	if got := r.do(r.boss, control.Message{T: control.TypePending}); got.Total != 2 {
		t.Fatalf("pending %d, want 2 for a multi-use invite", got.Total)
	}
	if got := r.do(r.a, control.Message{T: control.TypeReject, Target: created.Invite.ID, Data: []byte(id1)}); got.T != control.TypeError {
		t.Fatal("non-admin rejected an enrollment")
	}
	if got := r.do(r.boss, control.Message{T: control.TypeReject, Target: created.Invite.ID, Data: []byte(id1)}); !got.Complete {
		t.Fatalf("reject: %+v", got)
	}
	if got := r.do(r.boss, control.Message{T: control.TypePending}); got.Total != 1 {
		t.Fatalf("pending after reject %d", got.Total)
	}
}
