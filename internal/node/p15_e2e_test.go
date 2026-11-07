package node

import (
	"context"
	"crypto/rand"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/coordinator"
	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/trust"
)

// p15Net is an owner network with devices laptop (the owner's, which
// publishes from the network directory) and masaustu, ICMP allowed both
// ways, and one or two coordinators on 127.0.0.1.
type p15Net struct {
	t       *testing.T
	base    string
	netDir  string
	n       *admin.Network
	coords  []*trust.DeviceSecrets
	ports   []int
	laptop  *trust.DeviceSecrets
	masa    *trust.DeviceSecrets
	running []context.CancelFunc
}

func newP15Net(t *testing.T, coordinators int) *p15Net {
	t.Helper()
	if testing.Short() {
		t.Skip("end-to-end test uses real UDP sockets")
	}
	base := t.TempDir()
	p := &p15Net{t: t, base: base, netDir: filepath.Join(base, "ag")}
	var err error
	p.n, err = admin.Init(p.netDir, admin.InitOptions{DNSDomain: trust.DefaultDNSDomain, IPv4Prefix: trust.DefaultIPv4Prefix, Validity: trust.DefaultValidity}, e2ePass, e2eOpts, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < coordinators; i++ {
		s, err := trust.GenerateDeviceSecrets(rand.Reader, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		_, wg, _ := s.PublicKeys()
		port := freeUDPPort(t)
		ep := "127.0.0.1:" + strconv.Itoa(port)
		if i == 0 {
			commit(t, p.n, func(doc *trust.Document) error { return doc.SetCoordinator(ep, wg) })
		} else {
			name := "ek" + strconv.Itoa(i)
			commit(t, p.n, func(doc *trust.Document) error { return doc.AddCoordinator(ep, wg, name, "") })
		}
		p.coords, p.ports = append(p.coords, s), append(p.ports, port)
	}
	p.laptop = enroll(t, p.n, "laptop")
	p.masa = enroll(t, p.n, "masaustu")
	commit(t, p.n, func(doc *trust.Document) error {
		return doc.AddRule(trust.Rule{From: []string{"laptop"}, To: []string{"masaustu"}, Protocol: trust.ProtocolICMP})
	})
	commit(t, p.n, func(doc *trust.Document) error {
		return doc.AddRule(trust.Rule{From: []string{"masaustu"}, To: []string{"laptop"}, Protocol: trust.ProtocolICMP})
	})
	t.Cleanup(func() {
		for _, stop := range p.running {
			stop()
		}
	})
	return p
}

// startCoordinator runs coordinator i and returns its stop function.
func (p *p15Net) startCoordinator(i int) context.CancelFunc {
	p.t.Helper()
	store := join(p.t, p.n, filepath.Join(p.base, "koordinator"+strconv.Itoa(i)))
	ctx, cancel := context.WithCancel(context.Background())
	p.running = append(p.running, cancel)
	srv, err := coordinator.New(coordinator.Config{Store: store, Secrets: p.coords[i], ListenPort: p.ports[i], Logger: testLogger(p.t, "[k"+strconv.Itoa(i)+"]")})
	if err != nil {
		p.t.Fatalf("coordinator.New: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	select {
	case <-srv.Ready():
	case err := <-done:
		p.t.Fatalf("coordinator stopped: %v", err)
	case <-time.After(5 * time.Second):
		p.t.Fatal("coordinator did not start")
	}
	return func() {
		cancel()
		<-done
	}
}

func (p *p15Net) startDevice(name string, secrets *trust.DeviceSecrets, ch *tuntest.ChannelTUN, networkDir string, mutate ...func(*Config)) (*Engine, *member.Store) {
	p.t.Helper()
	store := join(p.t, p.n, filepath.Join(p.base, name))
	cfg := Config{Store: store, Secrets: secrets, TUN: ch.TUN(), NetworkDir: networkDir,
		PollInterval: 300 * time.Millisecond, Logger: testLogger(p.t, "["+name+"]")}
	for _, m := range mutate {
		m(&cfg)
	}
	e, err := New(cfg)
	if err != nil {
		p.t.Fatalf("node.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	p.running = append(p.running, cancel)
	go func() {
		if err := e.Run(ctx); err != nil && ctx.Err() == nil {
			p.t.Errorf("engine %s stopped: %v", name, err)
		}
	}()
	return e, store
}

// TestTwoCoordinatorsFailover: with two coordinators, devices keep both in
// step; when the primary stops, a new document still reaches every device
// through the other one (#153).
func TestTwoCoordinatorsFailover(t *testing.T) {
	old := fanOutInterval
	fanOutInterval = 300 * time.Millisecond
	t.Cleanup(func() { fanOutInterval = old })
	p := newP15Net(t, 2)
	stopPrimary := p.startCoordinator(0)
	p.startCoordinator(1)
	laptopTUN, masaTUN := tuntest.NewChannelTUN(), tuntest.NewChannelTUN()
	laptop, _ := p.startDevice("laptop", p.laptop, laptopTUN, p.netDir)
	masa, masaStore := p.startDevice("masaustu", p.masa, masaTUN, "")
	ls, _ := laptop.Self()
	ms, _ := masa.Self()
	if !expectPacket(t, laptopTUN, masaTUN, ls.IPv4, ms.IPv4, 20*time.Second) {
		t.Fatal("laptop -> masaustu ICMP did not arrive")
	}
	waitFor(t, 15*time.Second, "both coordinators answer the device", func() bool {
		cs := masa.Coordinators()
		return len(cs) == 2 && !cs[0].LastReply.IsZero() && !cs[1].LastReply.IsZero()
	})
	if cs := masa.Coordinators(); !cs[0].Active || cs[1].Name != "ek1" || !cs[1].Session {
		t.Fatalf("coordinator status: %+v", cs)
	}

	stopPrimary()
	stopDrain := p15Drain(laptopTUN, masaTUN)
	before := masaStore.Document().Version
	commit(t, p.n, func(doc *trust.Document) error { return doc.SetDisplayName("Ev ağı") })
	waitFor(t, 45*time.Second, "the new document reaches masaustu through the other coordinator", func() bool {
		return masaStore.Document().Version > before
	})
	if cs := masa.Coordinators(); !cs[1].Active {
		t.Fatalf("masaustu did not switch coordinators: %+v", cs)
	}
	stopDrain()
	if !expectPacket(t, masaTUN, laptopTUN, ms.IPv4, ls.IPv4, 20*time.Second) {
		t.Fatal("masaustu -> laptop ICMP did not arrive after the failover")
	}
	if rep := masa.CoordinatorIntegrity(); len(rep.Coordinators) != 2 {
		t.Fatalf("integrity report: %+v", rep)
	}
}

// TestGossipSpreadsDocumentWithoutCoordinator: with the only coordinator
// down, a new document from the owner's laptop still reaches the other
// device over their tunnel (#25).
func TestGossipSpreadsDocumentWithoutCoordinator(t *testing.T) {
	old := gossipInterval
	gossipInterval = 500 * time.Millisecond
	t.Cleanup(func() { gossipInterval = old })
	p := newP15Net(t, 1)
	stop := p.startCoordinator(0)
	laptopTUN, masaTUN := tuntest.NewChannelTUN(), tuntest.NewChannelTUN()
	laptop, _ := p.startDevice("laptop", p.laptop, laptopTUN, p.netDir)
	masa, masaStore := p.startDevice("masaustu", p.masa, masaTUN, "")
	ls, _ := laptop.Self()
	ms, _ := masa.Self()
	if !expectPacket(t, laptopTUN, masaTUN, ls.IPv4, ms.IPv4, 20*time.Second) {
		t.Fatal("laptop -> masaustu ICMP did not arrive")
	}
	stop()
	defer p15Drain(laptopTUN, masaTUN)()
	before := masaStore.Document().Version
	commit(t, p.n, func(doc *trust.Document) error { return doc.SetDisplayName("Koordinatörsüz") })
	waitFor(t, 30*time.Second, "the new document reaches masaustu from laptop", func() bool {
		return masaStore.Document().Version > before
	})
	if got := masaStore.Document().DisplayName; got != "Koordinatörsüz" {
		t.Fatalf("display name %q", got)
	}
	// Both views were exchanged.
	waitFor(t, 10*time.Second, "laptop appears in masaustu's report", func() bool {
		for _, pv := range masa.CoordinatorIntegrity().Peers {
			if pv.Peer == "laptop" {
				return true
			}
		}
		return false
	})
}

// p15Drain discards what the devices deliver to their OS while a test is
// not reading, so a full test channel does not stall WireGuard's receive
// path. The returned function stops it.
func p15Drain(chs ...*tuntest.ChannelTUN) func() {
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			for _, ch := range chs {
				select {
				case <-ch.Inbound:
				case <-stop:
					return
				default:
				}
			}
			select {
			case <-stop:
				return
			case <-time.After(10 * time.Millisecond):
			}
		}
	}()
	return func() {
		close(stop)
		<-done
	}
}

// TestRelayThroughAdditionalCoordinator: the primary coordinator is down
// from the start; both devices force the relay, open signed relay sessions
// at the additional coordinator and reach each other through it (#153,
// #57, #151).
func TestRelayThroughAdditionalCoordinator(t *testing.T) {
	old := fanOutInterval
	fanOutInterval = 300 * time.Millisecond
	t.Cleanup(func() { fanOutInterval = old })
	p := newP15Net(t, 2)
	p.startCoordinator(1)
	force := func(c *Config) { c.ForceRelay, c.DisableTCPFallback = true, true }
	laptopTUN, masaTUN := tuntest.NewChannelTUN(), tuntest.NewChannelTUN()
	laptop, _ := p.startDevice("laptop", p.laptop, laptopTUN, "", force)
	masa, _ := p.startDevice("masaustu", p.masa, masaTUN, "", force)
	ls, _ := laptop.Self()
	ms, _ := masa.Self()
	waitFor(t, 40*time.Second, "both devices use the additional coordinator with a relay session", func() bool {
		for _, e := range []*Engine{laptop, masa} {
			cs := e.Coordinators()
			if len(cs) != 2 || !cs[1].Active || !cs[1].Relay || !cs[1].Session {
				return false
			}
		}
		return true
	})
	if !expectPacket(t, laptopTUN, masaTUN, ls.IPv4, ms.IPv4, 30*time.Second) {
		t.Fatal("laptop -> masaustu ICMP did not arrive through the additional coordinator")
	}
}
