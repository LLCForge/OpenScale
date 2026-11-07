package upstream

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/openscale/openscale/internal/osnet"
	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/internal/wgconf"
)

// keepalive keeps the provider's NAT mapping and gives the health check a
// handshake at least every two minutes, even without member traffic.
const keepalive = 25

// Router installs the exit node's policy routing (osnet.UpstreamRouter).
type Router interface {
	Apply(ctx context.Context, r osnet.UpstreamRoute) error
	SetDirect(ctx context.Context, direct bool) error
	Remove(ctx context.Context) error
}

// Deps are the parts of the system the upstream tunnel uses; tests replace
// them with a channel TUN, a loopback bind and a recording router.
type Deps struct {
	// NewTUN creates the upstream interface.
	NewTUN func(name string, mtu int) (tun.Device, error)
	// NewBind returns the UDP bind of the second WireGuard device.
	NewBind func() conn.Bind
	Router  Router
	// Tor installs the Tor exit's packet filter (osnet.TorRouter); nil
	// refuses the Tor exit.
	Tor    TorRouter
	Logger *slog.Logger
	Now    func() time.Time
	// Mark is set on the tunnel's UDP sockets (osnet.TunnelBypassMark on
	// a real host, so the kill switch and leak guard let them through);
	// 0 sets none.
	Mark uint32
}

// HostDeps returns the dependencies for this host: a real TUN, the
// default bind and the OS router.
func HostDeps(logger *slog.Logger) Deps {
	return Deps{
		NewTUN: func(name string, mtu int) (tun.Device, error) {
			return osnet.CreateTUN(name, mtu, osnet.TUNOptions{})
		},
		NewBind: conn.NewDefaultBind,
		Router:  osnet.NewUpstreamRouter(),
		Tor:     osnet.NewTorRouter(),
		Logger:  logger,
		Now:     time.Now,
		Mark:    osnet.TunnelBypassMark,
	}
}

// tunnel is one running upstream WireGuard device, in this process (no
// kernel WireGuard, no netlink).
type tunnel struct {
	dev      *device.Device
	tdev     tun.Device
	name     string
	peer     trust.Key
	endpoint netip.AddrPort
	addr4    netip.Addr
	addr6    netip.Addr
	server   netip.Addr
	source   netip.Addr
}

// tunnelStats are the provider peer's counters.
type tunnelStats struct {
	lastHandshake time.Time
	rx, tx        uint64
}

func startTunnel(d Deps, name string, mtu int, cfg *Config) (*tunnel, error) {
	tdev, err := d.NewTUN(name, mtu)
	if err != nil {
		return nil, fmt.Errorf("üst tünel arayüzü oluşturulamadı: %w", err)
	}
	logger := d.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	dev := device.NewDevice(tdev, d.NewBind(), &device.Logger{
		Verbosef: func(format string, args ...any) { logger.Debug("upstream: " + fmt.Sprintf(format, args...)) },
		Errorf:   func(format string, args ...any) { logger.Warn("upstream: " + fmt.Sprintf(format, args...)) },
	})
	t := &tunnel{dev: dev, tdev: tdev, name: name, peer: trust.Key(cfg.PeerKey), endpoint: cfg.Endpoint,
		addr4: cfg.Address4, addr6: cfg.Address6}
	t.server, t.source, _ = cfg.ResolverFor()
	if n, err := tdev.Name(); err == nil && n != "" {
		t.name = n
	}

	// The private key goes in through a buffer that is cleared afterwards.
	var b bytes.Buffer
	b.Grow(512)
	b.WriteString("private_key=")
	keyHex := make([]byte, hex.EncodedLen(keySize))
	hex.Encode(keyHex, cfg.PrivateKey[:])
	b.Write(keyHex)
	clear(keyHex)
	b.WriteString("\n")
	if d.Mark != 0 {
		fmt.Fprintf(&b, "fwmark=%d\n", d.Mark)
	}
	allowed := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
	if cfg.IPv6 {
		allowed = append(allowed, netip.MustParsePrefix("::/0"))
	}
	b.WriteString(wgconf.AddOrUpdate(wgconf.Peer{PublicKey: t.peer, AllowedIPs: allowed, Endpoint: cfg.Endpoint, Keepalive: keepalive}))
	err = dev.IpcSetOperation(&b)
	clear(b.Bytes())
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("üst tünel yapılandırılamadı: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("üst tünel başlatılamadı: %w", err)
	}
	return t, nil
}

func (t *tunnel) route(ov Overlay, mtu int, failOpen bool) osnet.UpstreamRoute {
	return osnet.UpstreamRoute{
		Interface: t.name, MTU: mtu, Address4: t.addr4, Address6: t.addr6,
		Overlay: ov.Interface, OverlayV4: ov.V4, OverlayV6: ov.V6, FailOpen: failOpen,
	}
}

func (t *tunnel) stats() (tunnelStats, error) {
	raw, err := t.dev.IpcGet()
	if err != nil {
		return tunnelStats{}, err
	}
	st, err := wgconf.ParseStatus(raw)
	if err != nil {
		return tunnelStats{}, err
	}
	p, ok := st.Peers[t.peer]
	if !ok {
		return tunnelStats{}, errors.New("sağlayıcı eşi cihazda yok")
	}
	out := tunnelStats{rx: p.RxBytes, tx: p.TxBytes}
	if p.LastHandshakeUnix > 0 {
		out.lastHandshake = time.Unix(p.LastHandshakeUnix, 0)
	}
	return out, nil
}

// reconnect reopens the UDP sockets (the host's network may have changed)
// and makes the device start a new handshake at once: turning the
// keepalive off and on again in one operation sends a keepalive.
func (t *tunnel) reconnect() error {
	if err := t.dev.BindUpdate(); err != nil {
		return err
	}
	key := hex.EncodeToString(t.peer[:])
	return t.dev.IpcSet(fmt.Sprintf("public_key=%s\nupdate_only=true\nendpoint=%s\npersistent_keepalive_interval=0\npersistent_keepalive_interval=%d\n",
		key, t.endpoint, keepalive))
}

func (t *tunnel) close() {
	// Closing the device closes the TUN; the kernel removes the interface
	// and every route through it.
	t.dev.Close()
}
