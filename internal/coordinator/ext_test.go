package coordinator

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/control"
	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/packet"
	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/internal/wgconf"
)

var (
	extPass = []byte("koordinatör uzantı testi 1")
	extOpts = admin.Options{Argon2: trust.Argon2Params{Time: 1, MemoryKiB: 64 * 1024, Threads: 1}, Random: rand.Reader}
)

// extRig is a coordinator with three devices: a and b see each other, c
// sees nobody. The server is not run; handlers are called directly and
// pushes are read from the control interface queue.
type extRig struct {
	t       *testing.T
	n       *admin.Network
	s       *Server
	a, b, c trust.Device
	now     time.Time
}

func newExtRig(t *testing.T) *extRig {
	t.Helper()
	base := t.TempDir()
	n, err := admin.Init(filepath.Join(base, "ag"), admin.InitOptions{DNSDomain: trust.DefaultDNSDomain, IPv4Prefix: trust.DefaultIPv4Prefix, Validity: trust.DefaultValidity}, extPass, extOpts, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	commitExt := func(change admin.Change) {
		plan, err := n.Prepare(time.Now(), trust.DefaultValidity, change)
		if err != nil {
			t.Fatal(err)
		}
		if err := n.Commit(plan, extPass); err != nil {
			t.Fatal(err)
		}
	}
	coordSecrets, err := trust.GenerateDeviceSecrets(rand.Reader, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_, coordWG, _ := coordSecrets.PublicKeys()
	commitExt(func(doc *trust.Document) error { return doc.SetCoordinator("127.0.0.1:51820", coordWG) })
	for _, name := range []string{"a", "b", "c"} {
		s, err := trust.GenerateDeviceSecrets(rand.Reader, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		env, _, err := s.NewEnrollmentRequest(name, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		req, err := trust.OpenEnrollmentRequest(env, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		commitExt(func(doc *trust.Document) error {
			_, err := doc.AddDevice(req, name, nil, time.Now(), trust.DefaultDeviceLife)
			return err
		})
	}
	commitExt(func(doc *trust.Document) error {
		return doc.AddRule(trust.Rule{From: []string{"a"}, To: []string{"b"}, Protocol: trust.ProtocolAny})
	})
	bundle, err := n.JoinBundle()
	if err != nil {
		t.Fatal(err)
	}
	store, err := member.Join(filepath.Join(base, "koordinator"), bundle, n.RootFingerprint(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	r := &extRig{t: t, n: n, now: time.Now()}
	r.s, err = New(Config{Store: store, Secrets: coordSecrets, Now: func() time.Time { return r.now }})
	if err != nil {
		t.Fatal(err)
	}
	doc := store.Document()
	r.a, _ = doc.DeviceByName("a")
	r.b, _ = doc.DeviceByName("b")
	r.c, _ = doc.DeviceByName("c")
	r.s.tun = newControlTUN(doc.Coordinator.IPv4, r.s.handle)
	// Observed endpoints as WireGuard would report them; cached far ahead
	// so handlers never ask the (absent) device.
	r.s.status = wgconf.Status{Peers: map[trust.Key]wgconf.PeerStatus{
		r.a.WireGuardKey: {Endpoint: netip.MustParseAddrPort("198.51.100.1:40001")},
		r.b.WireGuardKey: {Endpoint: netip.MustParseAddrPort("198.51.100.2:40002")},
	}}
	r.s.statAt = time.Now().Add(time.Hour)
	return r
}

func (r *extRig) do(from trust.Device, m control.Message) control.Message {
	r.t.Helper()
	m.ID = 42
	data, err := control.Encode(m)
	if err != nil {
		r.t.Fatal(err)
	}
	out := r.s.handle(from.IPv4, data)
	if out == nil {
		r.t.Fatalf("%s: no reply", m.T)
	}
	resp, err := control.Decode(out)
	if err != nil {
		r.t.Fatalf("%s: %v", m.T, err)
	}
	if resp.ID != 42 {
		r.t.Fatalf("%s: reply id %d", m.T, resp.ID)
	}
	return resp
}

// pushed returns the messages pushed so far, with their destination.
func (r *extRig) pushed() map[netip.Addr][]control.Message {
	out := map[netip.Addr][]control.Message{}
	for {
		select {
		case pkt := <-r.s.tun.out:
			info, err := packet.Parse(pkt)
			if err != nil || info.SrcPort != control.Port || info.DstPort != control.PushPort {
				r.t.Fatalf("bad push packet %+v %v", info, err)
			}
			m, err := control.Decode(info.Payload)
			if err != nil {
				r.t.Fatal(err)
			}
			out[info.Dst] = append(out[info.Dst], m)
		default:
			return out
		}
	}
}

func TestCapsAndCandidates(t *testing.T) {
	r := newExtRig(t)
	caps := r.do(r.a, control.Message{T: control.TypeCaps})
	if caps.T != control.TypeCaps || len(caps.Features) != len(coordFeatures) {
		t.Fatalf("caps = %+v", caps)
	}
	resp := r.do(r.a, control.Message{T: control.TypeCandidates, Cands: []string{"192.168.1.10:41641", "[2001:db8::10]:41641", "192.168.1.10:41641"}})
	if !resp.Complete || resp.Endpoint != "198.51.100.1:40001" {
		t.Fatalf("cand = %+v", resp)
	}
	for _, bad := range []string{"127.0.0.1:1", "0.0.0.0:5", "224.0.0.1:5", "[fe80::1%eth0]:5", "192.168.1.1:0", "255.255.255.255:9", "nope", r.b.IPv4.String() + ":5"} {
		if resp := r.do(r.a, control.Message{T: control.TypeCandidates, Cands: []string{bad}}); resp.T != control.TypeError {
			t.Errorf("candidate %q accepted", bad)
		}
	}
	// The refused update did not erase the earlier list.
	pc := r.do(r.b, control.Message{T: control.TypePeerCandidates})
	if pc.Total != 1 || len(pc.PeerCands) != 1 || pc.PeerCands[0].ID != r.a.ID {
		t.Fatalf("b's peers = %+v", pc)
	}
	got := pc.PeerCands[0]
	if got.Endpoint != "198.51.100.1:40001" || len(got.Cands) != 2 || got.Cands[0] != "192.168.1.10:41641" {
		t.Fatalf("a as seen by b = %+v", got)
	}
	// c sees nobody, and a's candidates never reach it.
	if pc := r.do(r.c, control.Message{T: control.TypePeerCandidates}); pc.Total != 0 || len(pc.PeerCands) != 0 {
		t.Fatalf("c got %+v", pc)
	}
	// Candidates expire.
	r.now = r.now.Add(candidateTTL + time.Second)
	if pc := r.do(r.b, control.Message{T: control.TypePeerCandidates}); len(pc.PeerCands[0].Cands) != 0 {
		t.Fatal("stale candidates handed out")
	}
}

func TestCallPushesToSubscribedPeerOnly(t *testing.T) {
	r := newExtRig(t)
	r.do(r.a, control.Message{T: control.TypeCandidates, Cands: []string{"10.0.0.5:41641"}})
	// b is not subscribed yet.
	if resp := r.do(r.a, control.Message{T: control.TypeCall, Target: r.b.ID}); resp.T != control.TypeError {
		t.Fatalf("call to an unsubscribed peer: %+v", resp)
	}
	r.do(r.b, control.Message{T: control.TypeCaps})
	r.now = r.now.Add(callInterval)
	if resp := r.do(r.a, control.Message{T: control.TypeCall, Target: r.b.ID}); !resp.Complete {
		t.Fatalf("call = %+v", resp)
	}
	p := r.pushed()[r.b.IPv4]
	if len(p) != 1 || p[0].T != control.TypeCall || p[0].Target != r.a.ID || p[0].Endpoint != "198.51.100.1:40001" ||
		len(p[0].Cands) != 1 || p[0].Cands[0] != "10.0.0.5:41641" {
		t.Fatalf("push = %+v", p)
	}
	// Rate limit per pair.
	if resp := r.do(r.a, control.Message{T: control.TypeCall, Target: r.b.ID}); resp.T != control.TypeError {
		t.Fatal("second call within the interval accepted")
	}
	// No call to a device the document does not pair it with.
	r.do(r.c, control.Message{T: control.TypeCaps})
	if resp := r.do(r.a, control.Message{T: control.TypeCall, Target: r.c.ID}); resp.T != control.TypeError {
		t.Fatal("call to an unrelated device accepted")
	}
	if len(r.pushed()) != 0 {
		t.Fatal("refused calls pushed something")
	}
}

func TestNotifyAndCompressedDocument(t *testing.T) {
	r := newExtRig(t)
	r.do(r.a, control.Message{T: control.TypeCaps})
	if n := r.s.notifyAll(); n != 1 {
		t.Fatalf("notified %d devices, want 1 (only a subscribed)", n)
	}
	p := r.pushed()[r.a.IPv4]
	doc, env, digest := r.s.cfg.Store.Snapshot()
	if len(p) != 1 || p[0].T != control.TypeNotify || p[0].Version != doc.Version || p[0].Size != len(env) || p[0].Digest != hexDigest(digest) {
		t.Fatalf("notice = %+v", p)
	}
	// Subscriptions run out.
	r.now = r.now.Add(control.SubscriptionTTL + time.Second)
	if n := r.s.notifyAll(); n != 0 {
		t.Fatal("expired subscription notified")
	}

	var z []byte
	for {
		resp := r.do(r.b, control.Message{T: control.TypeDocGzip, Version: doc.Version, Offset: len(z)})
		if resp.T != control.TypeDocGzip || resp.Offset != len(z) {
			t.Fatalf("docz = %+v", resp)
		}
		z = append(z, resp.Data...)
		if len(z) >= resp.Total {
			break
		}
	}
	zr, err := gzip.NewReader(bytes.NewReader(z))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(plain) != digest || len(z) >= len(env) {
		t.Fatalf("compressed document: %d -> %d bytes, digest ok %v", len(env), len(z), sha256.Sum256(plain) == digest)
	}
	if resp := r.do(r.b, control.Message{T: control.TypeDocGzip, Version: doc.Version + 1}); resp.T != control.TypeError {
		t.Fatal("wrong version served")
	}
}

// Every pcand page fits a datagram, and paging covers every peer once.
func TestPeerCandidatePagesFitDatagram(t *testing.T) {
	r := newExtRig(t)
	cands := make([]string, control.MaxCandidates)
	for i := range cands {
		cands[i] = "[2001:db8:1234:5678:9abc:def0:1234:" + strings.Repeat("a", 1) + string(rune('0'+i)) + "]:65535"
	}
	r.do(r.a, control.Message{T: control.TypeCandidates, Cands: cands})
	pc := r.do(r.b, control.Message{T: control.TypePeerCandidates})
	if len(pc.PeerCands) != 1 || len(pc.PeerCands[0].Cands) != control.MaxCandidates {
		t.Fatalf("pcand = %+v", pc)
	}
	if resp := r.do(r.b, control.Message{T: control.TypePeerCandidates, Offset: 5}); resp.T != control.TypeError {
		t.Fatal("offset past the end accepted")
	}
}

func TestExtPrune(t *testing.T) {
	r := newExtRig(t)
	r.do(r.a, control.Message{T: control.TypeCaps})
	r.do(r.a, control.Message{T: control.TypeCandidates, Cands: []string{"10.0.0.5:1"}})
	r.s.ext.prune(r.s.cfg.Store.Document(), r.now)
	if len(r.s.ext.subs) != 1 || len(r.s.ext.cands) != 1 {
		t.Fatal("fresh state pruned")
	}
	r.s.ext.prune(r.s.cfg.Store.Document(), r.now.Add(candidateTTL+control.SubscriptionTTL))
	if len(r.s.ext.subs) != 0 || len(r.s.ext.cands) != 0 {
		t.Fatal("stale state kept")
	}
}
