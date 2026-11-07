package troubleshoot

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"
)

type fakeProbe struct {
	in       Interface
	gws      []netip.Addr
	gwErr    error
	endpoint string
	resolved []netip.Addr
	resolveN int
	magicErr string
	coord    Coordinator
	peers    []Peer
	relayErr error
	relayed  []string
}

func (f *fakeProbe) Interface(context.Context) Interface { return f.in }
func (f *fakeProbe) Gateways(context.Context) ([]netip.Addr, error) {
	return f.gws, f.gwErr
}
func (f *fakeProbe) CoordinatorEndpoint() string { return f.endpoint }
func (f *fakeProbe) Resolve(_ context.Context, host string) ([]netip.Addr, error) {
	f.resolveN++
	if len(f.resolved) == 0 {
		return nil, errors.New("no such host")
	}
	return f.resolved, nil
}
func (f *fakeProbe) MagicDNSError() string                   { return f.magicErr }
func (f *fakeProbe) Coordinator(context.Context) Coordinator { return f.coord }
func (f *fakeProbe) Peers(context.Context) ([]Peer, error)   { return f.peers, nil }
func (f *fakeProbe) RelayTest(_ context.Context, peer string) (time.Duration, error) {
	f.relayed = append(f.relayed, peer)
	return 20 * time.Millisecond, f.relayErr
}

func healthy() *fakeProbe {
	return &fakeProbe{
		in:       Interface{Running: true, Name: "openscale0", Up: true},
		gws:      []netip.Addr{netip.MustParseAddr("127.0.0.1")},
		endpoint: "coord.example.test:41641",
		resolved: []netip.Addr{netip.MustParseAddr("127.0.0.1")},
		coord:    Coordinator{Reachable: true, RTT: 30 * time.Millisecond},
		peers: []Peer{
			{Name: "nas", Online: true, Path: "direct"},
			{Name: "laptop", Online: true, Path: "relay", RelayReason: "simetrik NAT"},
			{Name: "eski", Online: false, Path: "none"},
		},
	}
}

func statuses(rep Report) map[string]Status {
	out := map[string]Status{}
	for _, s := range rep.Steps {
		k := s.Layer
		if s.Peer != "" && s.Layer == LayerPeer {
			k += ":" + s.Peer
		}
		out[k] = s.Status
	}
	return out
}

func TestHealthyOrderAndPeers(t *testing.T) {
	p := healthy()
	rep := Run(context.Background(), p, nil)
	want := []string{LayerInterface, LayerGateway, LayerDNS, LayerCoordinator, LayerRelay, LayerPeer, LayerPeer, LayerPeer}
	if len(rep.Steps) != len(want) {
		t.Fatalf("steps = %+v", rep.Steps)
	}
	for i, l := range want {
		if rep.Steps[i].Layer != l || rep.Steps[i].Key == "" || rep.Steps[i].Title == "" {
			t.Fatalf("step %d = %+v, want layer %s", i, rep.Steps[i], l)
		}
	}
	st := statuses(rep)
	if st[LayerCoordinator] != Pass || st["peer:nas"] != Pass || st["peer:laptop"] != Warn || st["peer:eski"] != Fail {
		t.Fatalf("statuses = %v", st)
	}
	if rep.OK || rep.FirstFailure != 7 {
		t.Fatalf("an offline peer must fail the report: ok=%v first=%d", rep.OK, rep.FirstFailure)
	}
	if len(p.relayed) != 1 || p.relayed[0] != "laptop" && p.relayed[0] != "nas" {
		t.Fatalf("relay tested with %v", p.relayed)
	}
	if rep.Steps[5].Code != "OS-3002" || rep.Steps[5].Vars["reason"] != "simetrik NAT" {
		t.Fatalf("relayed peer step = %+v", rep.Steps[5])
	}
}

func TestLowerFailureSkipsHigherLayers(t *testing.T) {
	p := healthy()
	p.gws = nil
	p.gwErr = errors.New("no route")
	rep := Run(context.Background(), p, nil)
	st := statuses(rep)
	if st[LayerInterface] != Pass || st[LayerGateway] != Fail {
		t.Fatalf("statuses = %v", st)
	}
	for _, l := range []string{LayerDNS, LayerCoordinator, LayerRelay, LayerPeer} {
		if st[l] != Skip {
			t.Fatalf("%s = %s, want skip after the gateway failed", l, st[l])
		}
	}
	if rep.Steps[1].Code != "OS-3005" || rep.FirstFailure != 1 || p.resolveN != 0 {
		t.Fatalf("gateway step = %+v first=%d resolves=%d", rep.Steps[1], rep.FirstFailure, p.resolveN)
	}
	if rep.Steps[2].Key != "skipped.lower_failed" || rep.Steps[2].Vars["layer"] != LayerGateway {
		t.Fatalf("skip step = %+v", rep.Steps[2])
	}
}

func TestDNSAndCoordinatorCases(t *testing.T) {
	p := healthy()
	p.resolved = nil
	if rep := Run(context.Background(), p, nil); statuses(rep)[LayerDNS] != Fail || rep.Steps[2].Key != "dns.resolve_failed" {
		t.Fatalf("unresolvable coordinator: %+v", rep.Steps[2])
	}
	p = healthy()
	p.endpoint = "127.0.0.1:41641"
	p.magicErr = "port 53 busy"
	rep := Run(context.Background(), p, nil)
	if rep.Steps[2].Status != Warn || rep.Steps[2].Code != "OS-4004" || p.resolveN != 0 {
		t.Fatalf("IP coordinator with broken MagicDNS: %+v (resolves %d)", rep.Steps[2], p.resolveN)
	}
	p = healthy()
	p.coord = Coordinator{}
	rep = Run(context.Background(), p, nil)
	if rep.Steps[3].Status != Fail || rep.Steps[3].Code != "OS-3001" || statuses(rep)[LayerRelay] != Skip {
		t.Fatalf("unreachable coordinator: %+v", rep.Steps)
	}
	p = healthy()
	p.coord = Coordinator{Captive: true}
	if rep := Run(context.Background(), p, nil); rep.Steps[3].Key != "coordinator.captive" {
		t.Fatalf("captive: %+v", rep.Steps[3])
	}
	p = healthy()
	p.in = Interface{Disconnected: true}
	rep = Run(context.Background(), p, nil)
	if rep.Steps[0].Key != "interface.disconnected" || statuses(rep)[LayerGateway] != Skip {
		t.Fatalf("disconnected: %+v", rep.Steps)
	}
	p = healthy()
	p.endpoint = ""
	p.peers = nil
	rep = Run(context.Background(), p, nil)
	if !rep.OK || statuses(rep)[LayerCoordinator] != Skip || statuses(rep)[LayerPeer] != Skip {
		t.Fatalf("no network yet: %+v", rep.Steps)
	}
}

func TestRelayFailureIsAWarning(t *testing.T) {
	p := healthy()
	p.peers = p.peers[:1]
	p.relayErr = errors.New("relay refused")
	rep := Run(context.Background(), p, nil)
	if !rep.OK || rep.Steps[4].Status != Warn || rep.Steps[4].Key != "relay.failed" {
		t.Fatalf("relay failure: %+v", rep.Steps[4])
	}
}

func TestPeerLimit(t *testing.T) {
	p := healthy()
	p.peers = nil
	for i := range MaxPeers + 3 {
		p.peers = append(p.peers, Peer{Name: string(rune('a'+i%26)) + "x" + string(rune('a'+i/26)), Online: true, Path: "direct"})
	}
	rep := Run(context.Background(), p, nil)
	last := rep.Steps[len(rep.Steps)-1]
	if last.Key != "peer.more" || last.Vars["count"] != "3" {
		t.Fatalf("last = %+v", last)
	}
}
