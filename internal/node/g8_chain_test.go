package node

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"path/filepath"
	"strconv"
	"sync/atomic"
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

// fakeResolver answers every query with count A records and counts them.
func fakeResolver(t *testing.T, count int) (*net.UDPConn, *atomic.Int32) {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	var seen atomic.Int32
	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			seen.Add(1)
			_, _ = c.WriteToUDP(answerFor(buf[:n], count, 30), addr)
		}
	}()
	t.Cleanup(func() { _ = c.Close() })
	return c, &seen
}

// TestSignedExitChainEndToEnd runs a member, an entry exit node and a final
// exit node on 127.0.0.1 with real wireguard-go devices: the member's
// internet traffic leaves only from the final, translated to the entry's
// address; the panel state turns ready only after the path answered; when
// the final stops, nothing leaves from the entry.
func TestSignedExitChainEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end test uses real UDP sockets")
	}
	oldEvery, oldFresh := chainProbeEvery, chainFresh
	chainProbeEvery, chainFresh = 300*time.Millisecond, 2*time.Second
	defer func() { chainProbeEvery, chainFresh = oldEvery, oldFresh }()

	base := t.TempDir()
	n, err := admin.Init(filepath.Join(base, "ag"), admin.InitOptions{DNSDomain: trust.DefaultDNSDomain, IPv4Prefix: trust.DefaultIPv4Prefix, Validity: trust.DefaultValidity}, e2ePass, e2eOpts, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	coordSecrets, _ := trust.GenerateDeviceSecrets(rand.Reader, time.Now())
	_, coordWG, _ := coordSecrets.PublicKeys()
	coordPort := freeUDPPort(t)
	commit(t, n, func(doc *trust.Document) error {
		return doc.SetCoordinator("127.0.0.1:"+strconv.Itoa(coordPort), coordWG)
	})
	memberKey := enroll(t, n, "laptop")
	entryKey := enroll(t, n, "giris")
	finalKey := enroll(t, n, "son")
	commit(t, n, func(doc *trust.Document) error {
		if err := doc.SetExitNode("giris", true); err != nil {
			return err
		}
		if err := doc.SetExitNode("son", true); err != nil {
			return err
		}
		return doc.SetExitChain("giris", "son")
	})
	coordStore := join(t, n, filepath.Join(base, "coordinator"))
	memberStore := join(t, n, filepath.Join(base, "laptop"))
	entryStore := join(t, n, filepath.Join(base, "giris"))
	finalStore := join(t, n, filepath.Join(base, "son"))

	entryResolver, entryAsked := fakeResolver(t, 1)
	finalResolver, _ := fakeResolver(t, 3)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	coord, err := coordinator.New(coordinator.Config{Store: coordStore, Secrets: coordSecrets, ListenPort: coordPort})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = coord.Run(ctx) }()
	<-coord.Ready()

	mTUN, aTUN, bTUN := tuntest.NewChannelTUN(), tuntest.NewChannelTUN(), tuntest.NewChannelTUN()
	start := func(ctx context.Context, store *member.Store, secrets *trust.DeviceSecrets, ch *tuntest.ChannelTUN, cfg Config) (*Engine, chan struct{}) {
		cfg.Store, cfg.Secrets, cfg.TUN, cfg.PollInterval = store, secrets, ch.TUN(), 300*time.Millisecond
		cfg.Logger = testLogger(t, "["+filepath.Base(store.Dir())+"]")
		e, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		go func() { _ = e.Run(ctx); close(done) }()
		return e, done
	}
	laptop, _ := start(ctx, memberStore, memberKey, mTUN, Config{ExitRouter: &fakeRouter{}})
	entry, _ := start(ctx, entryStore, entryKey, aTUN, Config{ExitDNSUpstream: entryResolver.LocalAddr().String()})
	finalCtx, stopFinal := context.WithCancel(ctx)
	defer stopFinal()
	_, finalDone := start(finalCtx, finalStore, finalKey, bTUN, Config{ExitDNSUpstream: finalResolver.LocalAddr().String()})
	mSelf, _ := laptop.Self()
	aSelf, _ := entry.Self()
	internet := netip.MustParseAddr("9.9.9.9")

	// Anything the entry writes to its own OS for the internet is a leak.
	var leaked atomic.Int32
	go func() {
		for {
			select {
			case pkt := <-aTUN.Inbound:
				if in, err := packet.Parse(pkt); err == nil && in.Dst.Is4() && chainInternet(in.Dst, trust.DefaultIPv4Prefix) {
					leaked.Add(1)
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	if err := laptop.SetExitNode("giris"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 15*time.Second, "laptop uses the entry", func() bool { return laptop.ExitNode() == "giris" })

	// A ping to the internet leaves from the final, from the entry's
	// overlay address, never from the member's.
	var forwarded []byte
	for i := 0; i < 60 && forwarded == nil; i++ {
		mTUN.Outbound <- tuntest.Ping(internet, mSelf.IPv4)
		forwarded = waitPacket(bTUN.Inbound, 500*time.Millisecond, func(in packet.Info) bool {
			return in.Dst == internet && in.IsEchoRequest()
		})
	}
	if forwarded == nil {
		t.Fatal("internet ping did not leave from the final exit")
	}
	fin, _ := packet.Parse(forwarded)
	if fin.Src != aSelf.IPv4 {
		t.Fatalf("final exit saw source %v, want the entry %v (member %v must stay hidden)", fin.Src, aSelf.IPv4, mSelf.IPv4)
	}
	// The internet's reply comes back to the member through both hops.
	reply := append([]byte(nil), forwarded...)
	copy(reply[12:16], forwarded[16:20])
	copy(reply[16:20], forwarded[12:16])
	reply[20] = 0
	reply[22], reply[23] = 0, 0
	binary.BigEndian.PutUint16(reply[22:24], chainSum(reply[20:], 0))
	bTUN.Outbound <- reply
	if waitPacket(mTUN.Inbound, 5*time.Second, func(in packet.Info) bool {
		return in.Src == internet && in.Dst == mSelf.IPv4 && in.IsEchoReply()
	}) == nil {
		t.Fatal("reply from the internet did not reach the member")
	}

	// UDP: translated with valid checksums.
	udp, _ := packet.BuildUDP4(mSelf.IPv4, internet, 5555, 443, []byte("zincir"))
	var got []byte
	for i := 0; i < 10 && got == nil; i++ {
		mTUN.Outbound <- udp
		got = waitPacket(bTUN.Inbound, 500*time.Millisecond, func(in packet.Info) bool {
			return in.Proto == packet.ProtoUDP && in.Dst == internet && in.DstPort == 443
		})
	}
	if got == nil {
		t.Fatal("UDP did not leave from the final exit")
	}
	uin, _ := packet.Parse(got)
	if uin.Src != aSelf.IPv4 || uin.SrcPort < chainPortLo || uin.SrcPort > chainPortHi || string(uin.Payload) != "zincir" {
		t.Fatalf("UDP at the final exit: %+v", uin)
	}
	if !udpChecksumOK(got) {
		t.Fatal("UDP checksum wrong after translation")
	}

	// The member's DNS sent to the entry is answered by the final's
	// resolver (3 records), not the entry's (1 record).
	before := entryAsked.Load()
	q, _ := packet.BuildUDP4(mSelf.IPv4, aSelf.IPv4, 53111, 53, dnsQuery(t, 4242, "ornek.com.", dnsmessage.TypeA, 0))
	var ans []byte
	for i := 0; i < 10 && ans == nil; i++ {
		mTUN.Outbound <- q
		ans = waitPacket(mTUN.Inbound, 500*time.Millisecond, func(in packet.Info) bool {
			return in.Src == aSelf.IPv4 && in.SrcPort == 53 && in.DstPort == 53111
		})
	}
	if ans == nil {
		t.Fatal("no DNS answer through the chain")
	}
	ain, _ := packet.Parse(ans)
	if m := unpack(t, ain.Payload); m.ID != 4242 || len(m.Answers) != 3 {
		t.Fatalf("DNS answer did not come from the final exit's resolver: %d answers", len(m.Answers))
	}
	if entryAsked.Load() != before {
		t.Fatal("the entry asked its own resolver for a member's query")
	}

	// Both ends report the verified path.
	waitFor(t, 10*time.Second, "entry verified", func() bool { return entry.ExitChainStatus().Wired })
	waitFor(t, 10*time.Second, "member verified", func() bool {
		st := laptop.ExitChainStatus()
		return st.Wired && st.Entry == "giris" && st.Final == "son" && st.Signed
	})

	// From here on drain the final's OS side.
	go func() {
		for {
			select {
			case <-bTUN.Inbound:
			case <-finalDone:
				return
			}
		}
	}()

	// The final stops: nothing leaves from the entry, and neither end
	// claims a working chain.
	stopFinal()
	<-finalDone
	for i := 0; i < 20; i++ {
		mTUN.Outbound <- tuntest.Ping(internet, mSelf.IPv4)
		mTUN.Outbound <- udp
		time.Sleep(100 * time.Millisecond)
	}
	waitFor(t, 10*time.Second, "entry not verified", func() bool { return !entry.ExitChainStatus().Wired })
	waitFor(t, 10*time.Second, "member not verified", func() bool { return !laptop.ExitChainStatus().Wired })
	if l := leaked.Load(); l != 0 {
		t.Fatalf("%d member packets left from the entry itself", l)
	}
}

func udpChecksumOK(pkt []byte) bool {
	ihl := int(pkt[0]&0x0f) * 4
	seg := pkt[ihl:]
	var pseudo uint32
	for i := 12; i < 20; i += 2 {
		pseudo += uint32(binary.BigEndian.Uint16(pkt[i : i+2]))
	}
	pseudo += uint32(packet.ProtoUDP) + uint32(len(seg))
	return chainSum(seg, pseudo) == 0
}

func TestChainRewriteChecksums(t *testing.T) {
	m := netip.MustParseAddr("100.80.0.5")
	a := netip.MustParseAddr("100.80.0.6")
	dst := netip.MustParseAddr("9.9.9.9")
	pkt, _ := packet.BuildUDP4(m, dst, 1234, 53, []byte("abc"))
	out, err := chainRewrite(pkt, netip.AddrPortFrom(a, 20001), netip.AddrPortFrom(dst, 53))
	if err != nil {
		t.Fatal(err)
	}
	in, err := packet.Parse(out)
	if err != nil || in.Src != a || in.SrcPort != 20001 || in.Dst != dst {
		t.Fatalf("rewrite %+v %v", in, err)
	}
	if chainSum(out[:20], 0) != 0 || !udpChecksumOK(out) {
		t.Fatal("checksum")
	}
	if pkt[12] != 100 || pkt[15] != 5 {
		t.Fatal("original packet modified")
	}
	if _, err := chainRewrite([]byte{0x60, 0, 0}, netip.AddrPort{}, netip.AddrPort{}); !errors.Is(err, errChainPacket) {
		t.Fatal("IPv6 accepted")
	}
}

func TestExitChainDocumentValidation(t *testing.T) {
	cases := []struct {
		chains []trust.ExitChain
		ok     bool
	}{
		{nil, true},
		{[]trust.ExitChain{{Entry: "a", Final: "b"}}, true},
		{[]trust.ExitChain{}, false},
		{[]trust.ExitChain{{Entry: "a", Final: "a"}}, false},
		{[]trust.ExitChain{{Entry: "a", Final: "b"}, {Entry: "a", Final: "c"}}, false},
		{[]trust.ExitChain{{Entry: "a", Final: "b"}, {Entry: "b", Final: "c"}}, false},
		{[]trust.ExitChain{{Entry: "A B", Final: "b"}}, false},
	}
	base := t.TempDir()
	n, err := admin.Init(filepath.Join(base, "ag"), admin.InitOptions{DNSDomain: trust.DefaultDNSDomain, IPv4Prefix: trust.DefaultIPv4Prefix, Validity: trust.DefaultValidity}, e2ePass, e2eOpts, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	doc, err := n.Document()
	if err != nil {
		t.Fatal(err)
	}
	for i, c := range cases {
		d := *doc
		d.ExitChains = c.chains
		if err := d.Validate(); (err == nil) != c.ok {
			t.Errorf("case %d: err %v, want ok=%v", i, err, c.ok)
		}
	}
	// SetExitChain needs two exit nodes.
	enroll(t, n, "a")
	enroll(t, n, "b")
	d, err := n.Document()
	if err != nil {
		t.Fatal(err)
	}
	if err := d.SetExitChain("a", "b"); err == nil {
		t.Fatal("chain between devices without the exit role accepted")
	}
}
