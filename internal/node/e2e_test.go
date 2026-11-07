package node

import (
	"context"
	"crypto/rand"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/coordinator"
	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/packet"
	"github.com/openscale/openscale/internal/trust"
)

var (
	e2ePass = []byte("uçtan uca test parolası 1")
	e2eOpts = admin.Options{Argon2: trust.Argon2Params{Time: 1, MemoryKiB: 64 * 1024, Threads: 1}, Random: rand.Reader}
)

type testWriter struct {
	t      *testing.T
	prefix string
}

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(w.prefix + strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

// testLogger logs at debug level when OPENSCALE_TEST_DEBUG is set.
func testLogger(t *testing.T, prefix string) *slog.Logger {
	if os.Getenv("OPENSCALE_TEST_DEBUG") == "" {
		return nil
	}
	return slog.New(slog.NewTextHandler(testWriter{t, prefix + " "}, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

func commit(t *testing.T, n *admin.Network, change admin.Change) {
	t.Helper()
	plan, err := n.Prepare(time.Now(), trust.DefaultValidity, change)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := n.Commit(plan, e2ePass); err != nil {
		t.Fatalf("Commit: %v", err)
	}
}

func enroll(t *testing.T, n *admin.Network, name string) *trust.DeviceSecrets {
	t.Helper()
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
	commit(t, n, func(doc *trust.Document) error {
		_, err := doc.AddDevice(req, name, nil, time.Now(), trust.DefaultDeviceLife)
		return err
	})
	return s
}

func join(t *testing.T, n *admin.Network, dir string) *member.Store {
	t.Helper()
	bundle, err := n.JoinBundle()
	if err != nil {
		t.Fatal(err)
	}
	st, err := member.Join(dir, bundle, n.RootFingerprint(), time.Now())
	if err != nil {
		t.Fatalf("Join: %v", err)
	}
	return st
}

// expectPacket sends ping from src's TUN until a matching packet arrives on
// dst's TUN or the deadline passes.
func expectPacket(t *testing.T, from, to *tuntest.ChannelTUN, srcIP, dstIP netip.Addr, within time.Duration) bool {
	t.Helper()
	deadline := time.After(within)
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case from.Outbound <- tuntest.Ping(dstIP, srcIP):
		case pkt := <-to.Inbound:
			if info, err := packet.Parse(pkt); err == nil && info.Src == srcIP && info.Dst == dstIP && info.IsICMP() {
				return true
			}
		case <-deadline:
			return false
		case <-tick.C:
		}
	}
}

func TestEndToEndTunnelThroughCoordinator(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end test uses real UDP sockets")
	}
	base := t.TempDir()
	netDir := filepath.Join(base, "ag")
	n, err := admin.Init(netDir, admin.InitOptions{DNSDomain: trust.DefaultDNSDomain, IPv4Prefix: trust.DefaultIPv4Prefix, Validity: trust.DefaultValidity}, e2ePass, e2eOpts, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	// Coordinator key and registration.
	coordSecrets, err := trust.GenerateDeviceSecrets(rand.Reader, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_, coordWG, _ := coordSecrets.PublicKeys()
	coordPort := freeUDPPort(t)
	commit(t, n, func(doc *trust.Document) error {
		return doc.SetCoordinator("127.0.0.1:"+strconv.Itoa(coordPort), coordWG)
	})

	laptopKey := enroll(t, n, "laptop")
	masaustuKey := enroll(t, n, "masaustu")
	commit(t, n, func(doc *trust.Document) error {
		return doc.AddRule(trust.Rule{From: []string{"laptop"}, To: []string{"masaustu"}, Protocol: trust.ProtocolICMP})
	})

	coordStore := join(t, n, filepath.Join(base, "coordinator"))
	laptopStore := join(t, n, filepath.Join(base, "laptop"))
	masaustuStore := join(t, n, filepath.Join(base, "masaustu"))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	coord, err := coordinator.New(coordinator.Config{Store: coordStore, Secrets: coordSecrets, ListenPort: coordPort, Logger: testLogger(t, "[koordinatör]")})
	if err != nil {
		t.Fatalf("coordinator.New: %v", err)
	}
	coordDone := make(chan error, 1)
	go func() { coordDone <- coord.Run(ctx) }()
	select {
	case <-coord.Ready():
	case err := <-coordDone:
		t.Fatalf("coordinator stopped: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("coordinator did not start")
	}

	laptopTUN, masaustuTUN := tuntest.NewChannelTUN(), tuntest.NewChannelTUN()
	start := func(store *member.Store, secrets *trust.DeviceSecrets, ch *tuntest.ChannelTUN, networkDir string) *Engine {
		e, err := New(Config{Store: store, Secrets: secrets, TUN: ch.TUN(), NetworkDir: networkDir,
			PollInterval: 300 * time.Millisecond, Logger: testLogger(t, "["+filepath.Base(store.Dir())+"]")})
		if err != nil {
			t.Fatalf("node.New: %v", err)
		}
		go func() {
			if err := e.Run(ctx); err != nil && ctx.Err() == nil {
				t.Errorf("engine stopped: %v", err)
			}
		}()
		return e
	}
	laptop := start(laptopStore, laptopKey, laptopTUN, netDir) // the owner's laptop publishes new documents
	masaustu := start(masaustuStore, masaustuKey, masaustuTUN, "")

	laptopSelf, _ := laptop.Self()
	masaustuSelf, _ := masaustu.Self()

	if !expectPacket(t, laptopTUN, masaustuTUN, laptopSelf.IPv4, masaustuSelf.IPv4, 20*time.Second) {
		t.Fatal("laptop -> masaustu ICMP did not arrive through the tunnel")
	}

	// MagicDNS: a query the OS sends to the reserved resolver address is
	// answered on the interface itself and never enters the tunnel.
	resolver := laptopStore.Document().DNSResolverIPv4()
	q := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 77, RecursionDesired: true})
	_ = q.StartQuestions()
	_ = q.Question(dnsmessage.Question{Name: dnsmessage.MustNewName("masaustu." + laptopStore.Document().DNSDomain + "."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	qb, err := q.Finish()
	if err != nil {
		t.Fatal(err)
	}
	qpkt, err := packet.BuildUDP4(laptopSelf.IPv4, resolver, 53000, 53, qb)
	if err != nil {
		t.Fatal(err)
	}
	laptopTUN.Outbound <- qpkt
	select {
	case pkt := <-laptopTUN.Inbound:
		info, err := packet.Parse(pkt)
		if err != nil || info.Src != resolver || info.SrcPort != 53 || info.DstPort != 53000 {
			t.Fatalf("unexpected DNS reply packet %+v %v", info, err)
		}
		var m dnsmessage.Message
		if err := m.Unpack(info.Payload); err != nil || len(m.Answers) != 1 {
			t.Fatalf("DNS reply %v %+v", err, m)
		}
		if a := netip.AddrFrom4(m.Answers[0].Body.(*dnsmessage.AResource).A); a != masaustuSelf.IPv4 {
			t.Fatalf("MagicDNS answered %s, want %s", a, masaustuSelf.IPv4)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no MagicDNS reply")
	}
	if expectPacket(t, masaustuTUN, laptopTUN, masaustuSelf.IPv4, laptopSelf.IPv4, 2*time.Second) {
		t.Fatal("masaustu -> laptop must be blocked: no rule allows it")
	}

	// The owner adds the reverse rule. The laptop publishes it to the
	// coordinator, the desktop downloads it, and traffic starts flowing.
	commit(t, n, func(doc *trust.Document) error {
		return doc.AddRule(trust.Rule{From: []string{"masaustu"}, To: []string{"laptop"}, Protocol: trust.ProtocolICMP})
	})
	if !expectPacket(t, masaustuTUN, laptopTUN, masaustuSelf.IPv4, laptopSelf.IPv4, 20*time.Second) {
		t.Fatalf("masaustu -> laptop did not work after the new rule (masaustu status: %+v)", masaustu.Status())
	}
	if v := coordStore.Document().Version; v != laptopStore.Document().Version {
		t.Fatalf("coordinator version %d, laptop version %d", v, laptopStore.Document().Version)
	}
}
