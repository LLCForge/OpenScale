package node

import (
	"context"
	"crypto/rand"
	"net"
	"net/netip"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/coordinator"
	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/packet"
	"github.com/openscale/openscale/internal/trust"
)

type fakeRouter struct {
	mu      sync.Mutex
	enabled string
}

func (r *fakeRouter) Enable(exit trust.Device, _ *trust.Document, _ string, _ conn.Bind) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.enabled = exit.Name
	return nil
}

func (r *fakeRouter) Disable() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.enabled = ""
	return nil
}

func (r *fakeRouter) get() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.enabled
}

// waitPacket returns the first packet on ch that matches, or nil.
func waitPacket(ch chan []byte, within time.Duration, match func(packet.Info) bool) []byte {
	deadline := time.After(within)
	for {
		select {
		case pkt := <-ch:
			if info, err := packet.Parse(pkt); err == nil && match(info) {
				return pkt
			}
		case <-deadline:
			return nil
		}
	}
}

func TestExitNodeForwardsInternetTraffic(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end test uses real UDP sockets")
	}
	base := t.TempDir()
	netDir := filepath.Join(base, "ag")
	n, err := admin.Init(netDir, admin.InitOptions{DNSDomain: trust.DefaultDNSDomain, IPv4Prefix: trust.DefaultIPv4Prefix, Validity: trust.DefaultValidity}, e2ePass, e2eOpts, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	coordSecrets, _ := trust.GenerateDeviceSecrets(rand.Reader, time.Now())
	_, coordWG, _ := coordSecrets.PublicKeys()
	coordPort := freeUDPPort(t)
	commit(t, n, func(doc *trust.Document) error {
		return doc.SetCoordinator("127.0.0.1:"+strconv.Itoa(coordPort), coordWG)
	})
	clientKey := enroll(t, n, "laptop")
	exitKey := enroll(t, n, "vps")
	// No rule between them: using an exit node needs only the role.
	commit(t, n, func(doc *trust.Document) error { return doc.SetExitNode("vps", true) })

	coordStore := join(t, n, filepath.Join(base, "coordinator"))
	clientStore := join(t, n, filepath.Join(base, "laptop"))
	exitStore := join(t, n, filepath.Join(base, "vps"))

	// A fake upstream resolver for the exit node.
	upstream, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := upstream.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = upstream.WriteToUDP(answerFor(buf[:n], 1, 30), addr)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	coord, err := coordinator.New(coordinator.Config{Store: coordStore, Secrets: coordSecrets, ListenPort: coordPort})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = coord.Run(ctx) }()
	<-coord.Ready()

	router := &fakeRouter{}
	var roleMu sync.Mutex
	exitRole := false
	cTUN, eTUN := tuntest.NewChannelTUN(), tuntest.NewChannelTUN()
	start := func(store *member.Store, secrets *trust.DeviceSecrets, ch *tuntest.ChannelTUN, cfg Config) *Engine {
		cfg.Store, cfg.Secrets, cfg.TUN, cfg.PollInterval = store, secrets, ch.TUN(), 300*time.Millisecond
		cfg.Logger = testLogger(t, "["+filepath.Base(store.Dir())+"]")
		e, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		go func() { _ = e.Run(ctx) }()
		return e
	}
	client := start(clientStore, clientKey, cTUN, Config{ExitRouter: router})
	exit := start(exitStore, exitKey, eTUN, Config{
		ExitDNSUpstream: upstream.LocalAddr().String(),
		OnExitRole: func(on bool) {
			roleMu.Lock()
			exitRole = on
			roleMu.Unlock()
		},
	})
	cSelf, _ := client.Self()
	eSelf, _ := exit.Self()

	if err := client.SetExitNode("laptop"); err == nil {
		t.Fatal("a device without the exit role was accepted as exit node")
	}
	if err := client.SetExitNode("vps"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for client.ExitNode() != "vps" && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	if router.get() != "vps" {
		t.Fatal("exit routes not enabled")
	}
	roleMu.Lock()
	if !exitRole {
		t.Fatal("exit node did not turn forwarding on")
	}
	roleMu.Unlock()

	// A ping to the internet leaves through the exit node...
	internet := netip.MustParseAddr("9.9.9.9")
	var forwarded []byte
	for i := 0; i < 60 && forwarded == nil; i++ {
		cTUN.Outbound <- tuntest.Ping(internet, cSelf.IPv4)
		forwarded = waitPacket(eTUN.Inbound, 500*time.Millisecond, func(in packet.Info) bool {
			return in.Src == cSelf.IPv4 && in.Dst == internet && in.IsEchoRequest()
		})
	}
	if forwarded == nil {
		t.Fatal("internet ping did not reach the exit node")
	}
	// ...and its reply comes back to the client.
	reply := append([]byte(nil), forwarded...)
	copy(reply[12:16], forwarded[16:20])
	copy(reply[16:20], forwarded[12:16])
	reply[20] = 0 // ICMP echo reply
	// From here on nothing reads the exit node's OS side; drain it so the
	// channel TUN never blocks WireGuard.
	go func() {
		for {
			select {
			case <-eTUN.Inbound:
			case <-ctx.Done():
				return
			}
		}
	}()
	eTUN.Outbound <- reply
	if waitPacket(cTUN.Inbound, 5*time.Second, func(in packet.Info) bool { return in.Src == internet && in.IsEchoReply() }) == nil {
		t.Fatal("reply from the internet did not reach the client")
	}
	// The internet cannot start a connection to the client.
	eTUN.Outbound <- tuntest.Ping(cSelf.IPv4, internet)
	if waitPacket(cTUN.Inbound, 1500*time.Millisecond, func(in packet.Info) bool { return in.Src == internet && in.IsEchoRequest() }) != nil {
		t.Fatal("unsolicited internet packet reached the client")
	}

	// DNS sent to the exit node is answered by its resolver.
	q, _ := packet.BuildUDP4(cSelf.IPv4, eSelf.IPv4, 53111, 53, dnsQuery(t, 4242, "ornek.com.", dnsmessage.TypeA, 0))
	cTUN.Outbound <- q
	got := waitPacket(cTUN.Inbound, 5*time.Second, func(in packet.Info) bool {
		return in.Src == eSelf.IPv4 && in.SrcPort == 53 && in.DstPort == 53111
	})
	if got == nil {
		t.Fatal("no DNS answer through the exit node")
	}
	in, _ := packet.Parse(got)
	if m := unpack(t, in.Payload); m.ID != 4242 || len(m.Answers) != 1 || m.Questions[0].Name.String() != "ornek.com." {
		t.Fatalf("DNS answer %+v", m)
	}

	// A MagicDNS name sent to the exit node (Linux sends every query
	// there) is answered on the client from its own document.
	q, _ = packet.BuildUDP4(cSelf.IPv4, eSelf.IPv4, 53112, 53, dnsQuery(t, 99, "vps."+trust.DefaultDNSDomain+".", dnsmessage.TypeA, 0))
	cTUN.Outbound <- q
	got = waitPacket(cTUN.Inbound, 5*time.Second, func(in packet.Info) bool {
		return in.Src == eSelf.IPv4 && in.SrcPort == 53 && in.DstPort == 53112
	})
	if got == nil {
		t.Fatal("no MagicDNS answer while using the exit node")
	}
	in, _ = packet.Parse(got)
	m := unpack(t, in.Payload)
	if m.ID != 99 || !m.Authoritative || len(m.Answers) != 1 {
		t.Fatalf("MagicDNS answer %+v", m)
	}
	if a := m.Answers[0].Body.(*dnsmessage.AResource).A; netip.AddrFrom4(a) != eSelf.IPv4 {
		t.Fatalf("MagicDNS answer %v, want %v", a, eSelf.IPv4)
	}

	// Turning the exit off restores the routes.
	if err := client.SetExitNode(""); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(10 * time.Second)
	for router.get() != "" && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	if router.get() != "" {
		t.Fatal("exit routes not removed")
	}
}
