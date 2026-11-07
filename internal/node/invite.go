package node

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/openscale/openscale/internal/control"
	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/internal/wgconf"
)

const (
	defaultInvitePoll   = 3 * time.Second
	enrollResendEvery   = 30 * time.Second
	inviteTunnelMTU     = 1420
	inviteTunnelQueue   = 64
	inviteTunnelAddrErr = "invite code addresses are invalid"
)

// Invite join errors.
var (
	ErrInviteGone     = errors.New("the invite no longer exists or has expired; ask for a new invite code")
	ErrInviteTaken    = errors.New("the invite was approved for another device; ask for a new invite code")
	ErrInviteRejected = errors.New("the coordinator rejected the enrollment")
)

// InviteJoinConfig configures JoinWithInvite.
type InviteJoinConfig struct {
	Code     *trust.InviteCode
	Secrets  *trust.DeviceSecrets
	Hostname string
	StateDir string
	Bind     conn.Bind
	// ListenPort 0 lets WireGuard pick a free port.
	ListenPort   int
	PollInterval time.Duration
	Resolve      func(ctx context.Context, host string) ([]netip.Addr, error)
	Logger       *slog.Logger
	Now          func() time.Time
	// OnWaiting is called once the coordinator holds the enrollment, with
	// the request whose short code must match the one in the owner's panel.
	OnWaiting func(req *trust.EnrollmentRequest)
}

// JoinWithInvite reaches the coordinator with the invite key, submits a
// signed enrollment and waits until the owner approves it. It returns the
// joined store once a document listing this device's keys arrives. Only the
// coordinator is reachable through the invite tunnel and no OS interface is
// created, so this needs no privileges.
func JoinWithInvite(ctx context.Context, cfg InviteJoinConfig) (*member.Store, error) {
	if cfg.Code == nil || cfg.Secrets == nil || cfg.StateDir == "" {
		return nil, errors.New("invite join needs a code, device key and state directory")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = defaultInvitePoll
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	if cfg.Resolve == nil {
		cfg.Resolve = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		}
	}
	code := cfg.Code
	if !code.IPv4.Is4() || !code.Coordinator.IPv4.Is4() {
		return nil, errors.New(inviteTunnelAddrErr)
	}
	keys, err := trust.DeriveInviteKeys(code.Seed)
	if err != nil {
		return nil, err
	}
	signingKey, wgKey, err := cfg.Secrets.PublicKeys()
	if err != nil {
		return nil, err
	}
	endpoint, err := resolveEndpoint(ctx, cfg.Resolve, code.Coordinator.Endpoint)
	if err != nil {
		return nil, err
	}

	t := newInviteTUN()
	c := newClient(t.inject)
	c.setAddrs(code.IPv4, code.Coordinator.IPv4)
	t.setDeliver(c.intercept)
	bind := cfg.Bind
	if bind == nil {
		bind = DefaultBind()
	}
	dev := device.NewDevice(t, bind, wgLogger(cfg.Logger))
	defer dev.Close()
	uapi := wgconf.Interface(keys.WireGuardPrivate, cfg.ListenPort) + wgconf.AddOrUpdate(wgconf.Peer{
		PublicKey:  code.Coordinator.WireGuardKey,
		AllowedIPs: []netip.Prefix{netip.PrefixFrom(code.Coordinator.IPv4, 32)},
		Endpoint:   endpoint,
		Keepalive:  keepaliveSeconds,
	})
	if err := dev.IpcSet(uapi); err != nil {
		return nil, fmt.Errorf("configure invite tunnel: %w", err)
	}
	if err := dev.Up(); err != nil {
		return nil, fmt.Errorf("bring invite tunnel up: %w", err)
	}

	anchor := code.Anchor()
	var (
		version   uint64
		doc       *trust.Document
		envData   []byte
		lastSent  time.Time
		announced bool
	)
	ticker := time.NewTicker(cfg.PollInterval)
	defer ticker.Stop()
	for {
		hello, err := c.call(ctx, control.Message{T: control.TypeHello})
		switch {
		case ctx.Err() != nil:
			return nil, ctx.Err()
		case err != nil:
			cfg.Logger.Warn("invite tunnel", "error", err.Error())
		case hello.Version != version:
			buf, err := fetchDocument(ctx, c, hello)
			if err != nil {
				cfg.Logger.Warn("download document", "error", err.Error())
				break
			}
			env, err := trust.UnmarshalEnvelope(buf)
			if err != nil {
				return nil, err
			}
			got, err := trust.VerifyDocumentSignature(env, anchor.RootKey)
			if err != nil {
				return nil, fmt.Errorf("the coordinator sent a document not signed by this network: %w", err)
			}
			if got.NetworkID != anchor.NetworkID || (doc != nil && got.Version < doc.Version) {
				return nil, errors.New("the coordinator sent a document of another network or an older version")
			}
			version, doc, envData = hello.Version, got, buf
		}

		if doc != nil {
			now := cfg.Now()
			if isListed(doc, signingKey, wgKey) {
				return member.JoinAnchor(cfg.StateDir, anchor, envData, now)
			}
			inv, ok := doc.InviteByID(code.InviteID)
			switch {
			case !ok || !inv.ActiveAt(now):
				return nil, ErrInviteGone
			case inv.Exhausted() && !inv.UsedFor(cfg.Secrets.DeviceID):
				return nil, ErrInviteTaken
			case !inv.UsedFor(cfg.Secrets.DeviceID) && now.Sub(lastSent) >= enrollResendEvery:
				// Re-sent periodically: the coordinator keeps pending
				// enrollments in memory only.
				req, err := sendEnrollment(ctx, c, cfg, code, now)
				if err != nil {
					if errors.Is(err, ErrInviteRejected) {
						return nil, err
					}
					cfg.Logger.Warn("send enrollment", "error", err.Error())
					break
				}
				lastSent = now
				if !announced && cfg.OnWaiting != nil {
					cfg.OnWaiting(req)
				}
				announced = true
			}
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

func sendEnrollment(ctx context.Context, c *client, cfg InviteJoinConfig, code *trust.InviteCode, now time.Time) (*trust.EnrollmentRequest, error) {
	se, req, err := cfg.Secrets.NewInviteEnrollment(code, cfg.Hostname, now)
	if err != nil {
		return nil, err
	}
	resp, err := c.call(ctx, control.Message{T: control.TypeEnroll, Data: se.Payload, Sig: se.DeviceSignature, InviteSig: se.InviteSignature})
	if err != nil {
		if resp.T == control.TypeError {
			return nil, fmt.Errorf("%w: %s", ErrInviteRejected, resp.Error)
		}
		return nil, err
	}
	if resp.T != control.TypeEnroll || !resp.Complete {
		return nil, errors.New("coordinator sent an unexpected reply")
	}
	return req, nil
}

func isListed(doc *trust.Document, signingKey, wgKey trust.Key) bool {
	for _, d := range doc.Devices {
		if d.SigningKey == signingKey && d.WireGuardKey == wgKey {
			return true
		}
	}
	return false
}

// inviteTUN is a userspace interface for the invite tunnel. Packets from
// the coordinator go to deliver; the client injects requests.
type inviteTUN struct {
	mu      sync.Mutex
	deliver func([]byte) bool
	out     chan []byte
	events  chan tun.Event
	closed  chan struct{}
	once    sync.Once
}

func newInviteTUN() *inviteTUN {
	t := &inviteTUN{
		out:    make(chan []byte, inviteTunnelQueue),
		events: make(chan tun.Event, 1),
		closed: make(chan struct{}),
	}
	t.events <- tun.EventUp
	return t
}

func (t *inviteTUN) setDeliver(f func([]byte) bool) {
	t.mu.Lock()
	t.deliver = f
	t.mu.Unlock()
}

func (t *inviteTUN) inject(pkt []byte) bool {
	select {
	case t.out <- append([]byte(nil), pkt...):
		return true
	case <-t.closed:
		return false
	default:
		return false
	}
}

func (t *inviteTUN) File() *os.File { return nil }

func (t *inviteTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case pkt := <-t.out:
		sizes[0] = copy(bufs[0][offset:], pkt)
		return 1, nil
	case <-t.closed:
		return 0, os.ErrClosed
	}
}

func (t *inviteTUN) Write(bufs [][]byte, offset int) (int, error) {
	t.mu.Lock()
	deliver := t.deliver
	t.mu.Unlock()
	for _, buf := range bufs {
		if offset <= len(buf) && deliver != nil {
			deliver(buf[offset:])
		}
	}
	return len(bufs), nil
}

func (t *inviteTUN) MTU() (int, error)        { return inviteTunnelMTU, nil }
func (t *inviteTUN) Name() (string, error)    { return "openscale-invite", nil }
func (t *inviteTUN) Events() <-chan tun.Event { return t.events }
func (t *inviteTUN) BatchSize() int           { return 1 }

func (t *inviteTUN) Close() error {
	t.once.Do(func() {
		close(t.closed)
		close(t.events)
	})
	return nil
}
