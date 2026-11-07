package node

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net"
	"net/netip"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/control"
	"github.com/openscale/openscale/internal/coordinator"
	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/obfs"
	"github.com/openscale/openscale/internal/trust"
)

// TestEndToEndSPAWithCamouflage runs a coordinator with port hiding (#614)
// and the disguise ("auto" UDP, TLS camouflage on TCP) together, and two
// devices with the disguise "on". The devices must not be locked out: the
// tunnel works over UDP and the TLS-camouflaged TCP transport accepts a
// device's stream, while a stream without a knock is never answered.
func TestEndToEndSPAWithCamouflage(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end test uses real sockets")
	}
	base := t.TempDir()
	netDir := filepath.Join(base, "ag")
	n, err := admin.Init(netDir, admin.InitOptions{DNSDomain: trust.DefaultDNSDomain, IPv4Prefix: trust.DefaultIPv4Prefix, Validity: trust.DefaultValidity}, e2ePass, e2eOpts, time.Now())
	if err != nil {
		t.Fatal(err)
	}
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
	var stopped []chan struct{}
	defer func() {
		cancel()
		for _, c := range stopped {
			select {
			case <-c:
			case <-time.After(10 * time.Second):
			}
		}
	}()

	coordBind, err := coordinator.ObfsBind(nil, coordStore.Document().NetworkID, obfs.DefaultPadding())
	if err != nil {
		t.Fatal(err)
	}
	coord, err := coordinator.New(coordinator.Config{Store: coordStore, Secrets: coordSecrets, ListenPort: coordPort,
		Bind: coordBind, TCPListen: "127.0.0.1:0", Hardening: &coordinator.Hardening{SPA: true},
		Logger: testLogger(t, "[koordinatör]")})
	if err != nil {
		t.Fatal(err)
	}
	cert, pin, err := obfs.GenerateCertificate([]string{"koordinator.test"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	tlsLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	coordDone := make(chan error, 1)
	coordStopped := make(chan struct{})
	stopped = append(stopped, coordStopped)
	go func() { defer close(coordStopped); coordDone <- coord.Run(ctx) }()
	tlsStopped := make(chan struct{})
	stopped = append(stopped, tlsStopped)
	go func() {
		defer close(tlsStopped)
		_ = coord.ServeObfsTLS(ctx, tlsLn, obfs.ServerConfig(cert))
	}()
	select {
	case <-coord.Ready():
	case err := <-coordDone:
		t.Fatalf("coordinator stopped: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("coordinator did not start")
	}
	if !coord.SPAStats().Enabled {
		t.Fatal("port hiding is not on")
	}

	g3 := G3Config{Obfs: ObfsConfig{Mode: obfs.ModeOn, TLS: &obfs.ClientTLS{ServerName: "koordinator.test", Pins: []string{pin.String()}}}}
	laptopTUN, masaustuTUN := tuntest.NewChannelTUN(), tuntest.NewChannelTUN()
	start := func(store *member.Store, secrets *trust.DeviceSecrets, ch *tuntest.ChannelTUN, networkDir string) *Engine {
		e, err := New(Config{Store: store, Secrets: secrets, TUN: ch.TUN(), PollInterval: 300 * time.Millisecond,
			NetworkDir: networkDir, G3: g3, Logger: testLogger(t, "["+filepath.Base(store.Dir())+"]")})
		if err != nil {
			t.Fatalf("node.New: %v", err)
		}
		done := make(chan struct{})
		stopped = append(stopped, done)
		go func() {
			defer close(done)
			if err := e.Run(ctx); err != nil && ctx.Err() == nil {
				t.Errorf("engine stopped: %v", err)
			}
		}()
		return e
	}
	laptop := start(laptopStore, laptopKey, laptopTUN, netDir) // publishes the owner's changes
	masaustu := start(masaustuStore, masaustuKey, masaustuTUN, "")
	laptopSelf, _ := laptop.Self()
	masaustuSelf, _ := masaustu.Self()
	if !expectPacket(t, laptopTUN, masaustuTUN, laptopSelf.IPv4, masaustuSelf.IPv4, 25*time.Second) {
		t.Fatalf("laptop -> masaustu ICMP did not arrive with SPA on (coordinator %+v)", coord.SPAStats())
	}
	if st := coord.SPAStats(); st.Knocks == 0 || st.Open == 0 {
		t.Fatalf("coordinator saw no knocks: %+v", st)
	}
	if laptop.spa.knocks() == 0 {
		t.Fatal("the laptop sent no knock")
	}

	// TLS camouflage + SPA: the device's own dial (knock inside TLS, then
	// the preamble) is answered.
	tlsAddr := netip.MustParseAddrPort(tlsLn.Addr().String())
	s, err := laptop.tcp.dialStream(ctx, tlsAddr)
	if err != nil {
		t.Fatalf("TLS-camouflaged stream with SPA refused: %v", err)
	}
	_ = s.Close()
	// The plain TCP transport (no camouflage) answers a knocked stream too.
	camo := laptop.tcp.camo
	laptop.tcp.camo = nil
	defer func() { laptop.tcp.camo = camo }()
	tcpAddr := netip.MustParseAddrPort(coord.TCPAddr().String())
	laptop.tcp.noKnock.Store(false)
	s, err = laptop.tcp.dialStream(ctx, tcpAddr)
	if err != nil {
		t.Fatalf("plain TCP transport with SPA refused: %v", err)
	}
	_ = s.Close()
	// Sanity: without the knock the gate stays shut.
	laptop.tcp.noKnock.Store(true)
	if s, err := laptop.tcp.dialStream(ctx, tcpAddr); err == nil {
		_ = s.Close()
		t.Fatal("transport answered a stream without a knock")
	}
	if laptop.tcp.noKnock.Load() {
		t.Fatal("a failed stream without a knock did not switch back to knocking")
	}
	laptop.tcp.camo = camo

	// Lost mode end to end (#609): the owner tags the desktop "kayip"; the
	// signed document reaches it through the coordinator (with SPA on), it
	// isolates itself and stays reachable only by the coordinator; removing
	// the tag lifts it.
	setLost := func(on bool) {
		commit(t, n, func(doc *trust.Document) error {
			var tags []string
			if on {
				tags = []string{LostTag}
			}
			return doc.SetDeviceTags("masaustu", tags)
		})
	}
	waitLost := func(want bool) {
		deadline := time.Now().Add(45 * time.Second)
		for masaustu.LostStatus().Lost != want {
			if time.Now().After(deadline) {
				t.Fatalf("lost mode on the desktop = %v, want %v", !want, want)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	setLost(true)
	waitLost(true)
	if !masaustu.filter.Isolated() {
		t.Fatal("lost desktop is not isolated")
	}
	// Pings of the earlier checks may still sit in the desktop's TUN queue.
	for drained := false; !drained; {
		select {
		case <-masaustuTUN.Inbound:
		case <-time.After(300 * time.Millisecond):
			drained = true
		}
	}
	if expectPacket(t, laptopTUN, masaustuTUN, laptopSelf.IPv4, masaustuSelf.IPv4, 2*time.Second) {
		t.Fatal("a lost device still received member traffic")
	}
	setLost(false)
	waitLost(false)
	if !expectPacket(t, laptopTUN, masaustuTUN, laptopSelf.IPv4, masaustuSelf.IPv4, 25*time.Second) {
		t.Fatal("traffic did not resume after the lost mark was removed")
	}
}

// TestSPAPreambleAlternates checks the TCP form switch against an older
// coordinator that closes a stream starting with a knock.
func TestSPAPreambleAlternates(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				if control.ReadMagic(c) == nil { // old: preamble only
					_, _ = io.WriteString(c, control.TCPMagic)
					_, _ = io.Copy(io.Discard, c)
				}
			}(c)
		}
	}()
	tf := newTCPFallback(nil, testLoggerOrDiscard(t), time.Now)
	knock := bytes.Repeat([]byte{0}, obfs.SPAKnockSize)
	copy(knock, obfs.SPAMagic)
	tf.knock = func() []byte { return knock }
	addr := netip.MustParseAddrPort(ln.Addr().String())
	if s, err := tf.dialStream(context.Background(), addr); err == nil {
		_ = s.Close()
		t.Fatal("old coordinator accepted a knocked stream")
	}
	s, err := tf.dialStream(context.Background(), addr)
	if err != nil {
		t.Fatalf("second dial without the knock failed: %v", err)
	}
	_ = s.Close()
}

// TestSPAKnockBindSchedule checks when datagrams to a coordinator are
// preceded by a knock and that other peers never get one.
func TestSPAKnockBindSchedule(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	rec := &recordBind{}
	b := newSPAKnockBind(func() time.Time { return now }, testLoggerOrDiscard(t))
	b.Bind = rec
	coordAP := netip.MustParseAddrPort("127.0.0.1:41641")
	b.setCoordinator(trust.Key{7}, "ag", coordAP.Addr())
	std := conn.NewStdNetBind()
	coordEP, _ := std.ParseEndpoint(coordAP.String())
	peerEP, _ := std.ParseEndpoint("127.0.0.2:41641")
	data := [][]byte{{4, 0, 0, 0}}
	initiation := [][]byte{append([]byte{wgInitiationType}, make([]byte, wgInitiationSize-1)...)}
	step := func(bufs [][]byte, ep conn.Endpoint) int {
		rec.knocks = 0
		_ = b.Send(bufs, ep)
		return rec.knocks
	}
	if step(data, peerEP) != 0 {
		t.Fatal("knock sent to a non-coordinator")
	}
	if step(data, coordEP) != 1 {
		t.Fatal("no knock before the first datagram")
	}
	if step(data, coordEP) != 0 {
		t.Fatal("knock repeated at once")
	}
	now = now.Add(spaRekockHandshake)
	if step(data, coordEP) != 0 || step(initiation, coordEP) != 1 {
		t.Fatal("handshake initiation did not knock again")
	}
	now = now.Add(spaKnockEvery)
	if step(data, coordEP) != 1 {
		t.Fatal("no periodic knock")
	}
	if !obfs.IsSPAKnock(rec.lastKnock) {
		t.Fatal("knock shape")
	}
}

type recordBind struct {
	conn.Bind
	knocks    int
	lastKnock []byte
}

func (r *recordBind) Send(bufs [][]byte, _ conn.Endpoint) error {
	for _, b := range bufs {
		if obfs.IsSPAKnock(b) {
			r.knocks++
			r.lastKnock = append([]byte(nil), b...)
		}
	}
	return nil
}
