package coordinator

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/internal/usage"
	"github.com/openscale/openscale/internal/wgconf"
)

func opsServer(t *testing.T, r *p15Rig, secrets *trust.DeviceSecrets) *Server {
	t.Helper()
	return r.server(secrets, func(c *Config) { c.Operations = true })
}

func setPeers(s *Server, peers map[trust.Key]wgconf.PeerStatus) {
	s.mu.Lock()
	s.status = wgconf.Status{Peers: peers}
	s.statAt = time.Now().Add(time.Hour)
	s.mu.Unlock()
}

func TestRelayUsageAccountedAndSaved(t *testing.T) {
	r := newP15Rig(t)
	s := opsServer(t, r, r.prim)
	if _, _, ok := s.relay.forward(r.a.IPv4, relayPacket(r.b)); !ok {
		t.Fatal("relay refused")
	}
	month := usage.MonthOf(r.now)
	if got := s.ops.usage.Get(month, r.a.ID); got != uint64(len(relayPacket(r.b))) {
		t.Fatalf("usage = %d", got)
	}
	s.saveUsage()
	back, err := ReadRelayUsage(r.store.Dir())
	if err != nil {
		t.Fatal(err)
	}
	if back.Get(month, r.a.ID) == 0 {
		t.Fatal("usage not saved")
	}
	// The file contains the month, ids and numbers only.
	data, _ := os.ReadFile(filepath.Join(r.store.Dir(), RelayUsageFile))
	if strings.Contains(string(data), r.b.ID) || strings.Contains(string(data), r.a.IPv4.String()) {
		t.Fatalf("usage file holds more than the sender's total: %s", data)
	}
	// A restarted coordinator continues the month.
	s2 := opsServer(t, r, r.prim)
	if s2.ops.usage.Get(month, r.a.ID) == 0 {
		t.Fatal("usage not loaded")
	}
	// A corrupt file stops the coordinator instead of resetting the month.
	if err := os.WriteFile(filepath.Join(r.store.Dir(), RelayUsageFile), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{Store: r.store, Secrets: r.prim, Operations: true}); err == nil {
		t.Fatal("corrupt usage file accepted")
	}
	// Without Operations nothing is counted or written.
	_ = os.Remove(filepath.Join(r.store.Dir(), RelayUsageFile))
	off := r.server(r.prim, nil)
	off.relay.forward(r.a.IPv4, relayPacket(r.b))
	off.saveUsage()
	if _, err := os.Stat(filepath.Join(r.store.Dir(), RelayUsageFile)); err == nil {
		t.Fatal("usage written without Operations")
	}
}

func TestReachReportAndPreflight(t *testing.T) {
	r := newP15Rig(t)
	home := opsServer(t, r, r.home)
	prim := opsServer(t, r, r.prim)
	recent := r.now.Add(-30 * time.Second).Unix()
	old := r.now.Add(-time.Hour).Unix()
	// a reaches both, b only the primary, c nobody.
	setPeers(prim, map[trust.Key]wgconf.PeerStatus{r.a.WireGuardKey: {LastHandshakeUnix: recent}, r.b.WireGuardKey: {LastHandshakeUnix: recent}})
	setPeers(home, map[trust.Key]wgconf.PeerStatus{r.a.WireGuardKey: {LastHandshakeUnix: recent}, r.b.WireGuardKey: {LastHandshakeUnix: old}})
	target, err := home.reachReport()
	if err != nil {
		t.Fatal(err)
	}
	online, err := prim.reachReport()
	if err != nil {
		t.Fatal(err)
	}
	if target.Primary || !online.Primary || len(target.Devices) != 3 {
		t.Fatalf("reports: %+v %+v", target, online)
	}
	if _, err := Preflight(online, nil); err == nil {
		t.Fatal("preflight on the primary must be refused")
	}
	res, err := Preflight(target, &online)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(res.Reachable, ",") != "a" || strings.Join(res.Unreachable, ",") != "b" || strings.Join(res.Offline, ",") != "c" {
		t.Fatalf("preflight: %+v", res)
	}
	_, homeWG, _ := r.home.PublicKeys()
	if err := CheckPreflight(res, homeWG.String(), r.now); err == nil || !strings.Contains(err.Error(), "b") {
		t.Fatalf("unreachable device must block: %v", err)
	}
	// Without the online list, c counts as unreachable too (fail closed).
	closed, _ := Preflight(target, nil)
	if len(closed.Unreachable) != 2 || closed.Compared {
		t.Fatalf("fail closed: %+v", closed)
	}
	// Everyone reaches the target: allowed, but only for that key and
	// only while fresh.
	setPeers(home, map[trust.Key]wgconf.PeerStatus{r.a.WireGuardKey: {LastHandshakeUnix: recent}, r.b.WireGuardKey: {LastHandshakeUnix: recent}})
	target, _ = home.reachReport()
	res, _ = Preflight(target, &online)
	if err := CheckPreflight(res, homeWG.String(), r.now); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(res)
	back, err := ParsePreflight(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckPreflight(back, homeWG.String(), r.now.Add(2*time.Hour)); err == nil {
		t.Fatal("stale preflight accepted")
	}
	_, primWG, _ := r.prim.PublicKeys()
	if err := CheckPreflight(back, primWG.String(), r.now); err == nil {
		t.Fatal("preflight of another coordinator accepted")
	}
	// Reports taken far apart are refused.
	online.At = online.At.Add(-time.Hour)
	if _, err := Preflight(target, &online); err == nil {
		t.Fatal("skewed reports accepted")
	}
}

// dropBind counts packets passed through its receive function.
type dropBind struct {
	conn.Bind
	sent int
}

func (b *dropBind) Open(uint16) ([]conn.ReceiveFunc, uint16, error) {
	fn := func(packets [][]byte, sizes []int, _ []conn.Endpoint) (int, error) {
		sizes[0] = copy(packets[0], "x")
		return 1, nil
	}
	return []conn.ReceiveFunc{fn}, 1, nil
}

func (b *dropBind) Send([][]byte, conn.Endpoint) error { b.sent++; return nil }

func TestDrillLifecycle(t *testing.T) {
	r := newP15Rig(t)
	s := opsServer(t, r, r.prim)
	recent := r.now.Add(-10 * time.Second).Unix()
	setPeers(s, map[trust.Key]wgconf.PeerStatus{
		r.a.WireGuardKey: {LastHandshakeUnix: recent, RxBytes: 100},
		r.b.WireGuardKey: {LastHandshakeUnix: recent, RxBytes: 200},
	})
	inner := &dropBind{}
	b := s.wrapQuiet(inner)
	fns, _, _ := b.Open(0)
	pk := [][]byte{make([]byte, 8)}
	sizes := []int{0}
	if n, _ := fns[0](pk, sizes, make([]conn.Endpoint, 1)); n != 1 {
		t.Fatal("packet dropped outside a drill")
	}
	rep, err := s.startDrill(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(rep.Before, ",") != "a,b" || rep.State != DrillQuiet {
		t.Fatalf("drill: %+v", rep)
	}
	if _, err := s.startDrill(time.Minute); err == nil {
		t.Fatal("second drill accepted")
	}
	if n, _ := fns[0](pk, sizes, make([]conn.Endpoint, 1)); n != 0 {
		t.Fatal("packet passed during the silence")
	}
	_ = b.Send(nil, nil)
	if inner.sent != 0 {
		t.Fatal("packet sent during the silence")
	}
	// Silence ends; a sends again, b does not.
	r.now = r.now.Add(61 * time.Second)
	setPeers(s, map[trust.Key]wgconf.PeerStatus{
		r.a.WireGuardKey: {LastHandshakeUnix: recent, RxBytes: 160},
		r.b.WireGuardKey: {LastHandshakeUnix: recent, RxBytes: 200},
	})
	s.advanceDrill()
	if s.ops.drill.State != DrillObserving || len(s.ops.drill.Returned) != 1 {
		t.Fatalf("observing: %+v", s.ops.drill)
	}
	if n, _ := fns[0](pk, sizes, make([]conn.Endpoint, 1)); n != 1 {
		t.Fatal("packet dropped after the silence")
	}
	r.now = r.now.Add(DrillObserve)
	s.advanceDrill()
	got, err := ReadDrillReport(r.store.Dir())
	if err != nil {
		t.Fatal(err)
	}
	if got.State != DrillDone || strings.Join(got.Missing, ",") != "b" || got.Returned[0].Name != "a" {
		t.Fatalf("report: %+v", got)
	}
	if _, err := s.cancelDrill(); err == nil {
		t.Fatal("cancel without a drill accepted")
	}
}

func TestDrillNeedsSecondCoordinator(t *testing.T) {
	r := newP15Rig(t)
	_, homeWG, _ := r.home.PublicKeys()
	r.commit(func(doc *trust.Document) error { return doc.RemoveCoordinator(homeWG) })
	data, err := securefile.ReadPrivate(filepath.Join(r.n.Dir(), "network.json"), trust.MaxEnvelopeSize)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.store.Accept(data, time.Now()); err != nil {
		t.Fatal(err)
	}
	s := opsServer(t, r, r.prim)
	if _, err := s.startDrill(time.Minute); err == nil {
		t.Fatal("drill with a single coordinator accepted")
	}
}

func TestRequestOpRoundTrip(t *testing.T) {
	r := newP15Rig(t)
	s := opsServer(t, r, r.home)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		tk := time.NewTicker(50 * time.Millisecond)
		defer tk.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tk.C:
				s.opsTick()
			}
		}
	}()
	reply, err := RequestOp(ctx, r.store.Dir(), OpReach, 0, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if reply.Reach == nil || reply.Reach.Primary || len(reply.Reach.Devices) != 3 {
		t.Fatalf("reply: %+v", reply)
	}
	if _, err := RequestOp(ctx, r.store.Dir(), OpDrillCancel, 0, 5*time.Second); err == nil {
		t.Fatal("cancel without drill must fail")
	}
	cancel()
	if _, err := RequestOp(context.Background(), t.TempDir(), OpReach, 0, 300*time.Millisecond); err != ErrNoRunningCoordinator {
		t.Fatalf("no coordinator: %v", err)
	}
}

func TestParseOpsRequestStrict(t *testing.T) {
	for _, in := range []string{
		`{"schema":1,"id":"ab","op":"reach","duration_s":5}`,
		`{"schema":1,"id":"AB","op":"reach"}`,
		`{"schema":1,"id":"ab","op":"drill","duration_s":1}`,
		`{"schema":1,"id":"ab","op":"drill","duration_s":99999}`,
		`{"schema":1,"id":"ab","op":"rm"}`,
		`{"schema":2,"id":"ab","op":"reach"}`,
		`{"schema":1,"id":"ab","op":"reach","x":1}`,
		`{"schema":1,"id":"","op":"reach"}`,
	} {
		if _, err := ParseOpsRequest([]byte(in)); err == nil {
			t.Errorf("accepted %s", in)
		}
	}
	if _, err := ParseOpsRequest([]byte(`{"schema":1,"id":"ab","op":"drill","duration_s":60}`)); err != nil {
		t.Fatal(err)
	}
}

func FuzzParseOpsRequest(f *testing.F) {
	f.Add([]byte(`{"schema":1,"id":"ab","op":"drill","duration_s":60}`))
	f.Add([]byte(`{"schema":1,"id":"ab","op":"reach"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		req, err := ParseOpsRequest(data)
		if err != nil {
			return
		}
		out, _ := json.Marshal(req)
		if _, err := ParseOpsRequest(out); err != nil {
			t.Fatalf("own output rejected: %v", err)
		}
	})
}

func FuzzParsePreflight(f *testing.F) {
	f.Add([]byte(`{"schema":1,"coordinator":"k","fingerprint":"f","at":"2026-01-01T00:00:00Z","doc_version":1,"compared":true,"reachable":[],"unreachable":[],"offline":[]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParsePreflight(data)
	})
}
