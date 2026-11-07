package node

import (
	"context"
	"crypto/rand"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/coordinator"
	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/testnet"
	"github.com/openscale/openscale/internal/trust"
)

// blockingBind drops every packet sent to one UDP port, like a NAT that
// never lets two devices reach each other directly.
type blockingBind struct {
	conn.Bind
	port string
}

func (b *blockingBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	if strings.HasSuffix(ep.DstToString(), ":"+b.port) {
		return nil
	}
	return b.Bind.Send(bufs, ep)
}

func TestRelayWhenDirectPathBlocked(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end test uses real UDP sockets")
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
	aKey := enroll(t, n, "laptop")
	bKey := enroll(t, n, "masaustu")
	commit(t, n, func(doc *trust.Document) error {
		if err := doc.AddRule(trust.Rule{From: []string{"laptop"}, To: []string{"masaustu"}, Protocol: trust.ProtocolICMP}); err != nil {
			return err
		}
		return doc.AddRule(trust.Rule{From: []string{"masaustu"}, To: []string{"laptop"}, Protocol: trust.ProtocolICMP})
	})
	coordStore := join(t, n, filepath.Join(base, "coordinator"))
	aStore := join(t, n, filepath.Join(base, "laptop"))
	bStore := join(t, n, filepath.Join(base, "masaustu"))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	coord, err := coordinator.New(coordinator.Config{Store: coordStore, Secrets: coordSecrets, ListenPort: coordPort, Logger: testLogger(t, "[koordinatör]")})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = coord.Run(ctx) }()
	<-coord.Ready()

	aPort, bPort := freeUDPPort(t), freeUDPPort(t)
	aTUN, bTUN := tuntest.NewChannelTUN(), tuntest.NewChannelTUN()
	start := func(store *member.Store, secrets *trust.DeviceSecrets, ch *tuntest.ChannelTUN, port, blocked int) *Engine {
		e, err := New(Config{
			Store: store, Secrets: secrets, TUN: ch.TUN(), ListenPort: port,
			Bind:         &blockingBind{Bind: testnet.NewLoopbackBind(), port: strconv.Itoa(blocked)},
			PollInterval: 300 * time.Millisecond, RelayAfter: time.Second,
			Logger: testLogger(t, "["+filepath.Base(store.Dir())+"]"),
		})
		if err != nil {
			t.Fatal(err)
		}
		go func() { _ = e.Run(ctx) }()
		return e
	}
	a := start(aStore, aKey, aTUN, aPort, bPort)
	b := start(bStore, bKey, bTUN, bPort, aPort)
	aSelf, _ := a.Self()
	bSelf, _ := b.Self()

	if !expectPacket(t, aTUN, bTUN, aSelf.IPv4, bSelf.IPv4, 30*time.Second) {
		t.Fatal("laptop -> masaustu did not arrive through the relay")
	}
	if !expectPacket(t, bTUN, aTUN, bSelf.IPv4, aSelf.IPv4, 15*time.Second) {
		t.Fatal("masaustu -> laptop did not arrive through the relay")
	}
	stats, err := a.PeerStats()
	if err != nil {
		t.Fatal(err)
	}
	if !stats[bSelf.WireGuardKey].Relayed {
		t.Fatal("laptop does not report the relayed path")
	}
	rs := coord.RelayStats()
	if rs[aSelf.ID].Bytes == 0 || rs[bSelf.ID].Bytes == 0 {
		t.Fatalf("coordinator relayed nothing: %+v", rs)
	}
}
