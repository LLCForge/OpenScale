package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/node"
	"github.com/openscale/openscale/internal/osnet"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/internal/wintunembed"
)

const (
	settingsFile    = "settings.json"
	interfaceName   = "OpenScale"
	maxSettingsSize = 64 << 10
	defaultName     = "bilgisayar"
)

// coordinatorPorts are tried in order. Windows reserves dynamic UDP ranges
// for Hyper-V and WSL that often include 51820, so it comes last.
var coordinatorPorts = []int{41820, 41821, 43820, 45820, 47820, 49820, 51820}

// Errors shown in the setup screens.
var (
	ErrAlreadySetUp = errors.New("bu bilgisayar zaten bir ağa bağlı")
	ErrJoinRunning  = errors.New("bir katılım zaten sürüyor")
	ErrNoFreePort   = errors.New("koordinatör için boş bir UDP portu bulunamadı")
)

type settings struct {
	CoordinatorPort int `json:"coordinator_port"`
	// HandoffSince is when this computer's coordinator was replaced in the
	// document; it keeps serving old devices for handoffPeriod.
	HandoffSince *time.Time `json:"handoff_since,omitempty"`
	// Disconnected keeps the tunnel off until the owner turns it on again.
	Disconnected bool `json:"disconnected,omitempty"`
	// RDPOverlayOnly and SSHOverlayOnly keep remote desktop and SSH limited
	// to OpenScale addresses; reapplied whenever the tunnel starts. Missing
	// means on (1.0.0-beta.2): a computer whose owner never chose keeps
	// Windows RDP and OpenSSH off the LAN and the internet. An explicit
	// false is the owner's choice and is never overridden.
	RDPOverlayOnly *bool `json:"rdp_overlay_only,omitempty"`
	SSHOverlayOnly *bool `json:"ssh_overlay_only,omitempty"`
	// ExitNode is the exit node this computer sends internet traffic
	// through ("" for none, ADR-0018).
	ExitNode string `json:"exit_node,omitempty"`
	// KillSwitch keeps the persistent kill switch on while an exit node is
	// used (ADR-0023). Missing means on, so settings written before the
	// field existed keep the protection.
	KillSwitch *bool `json:"kill_switch,omitempty"`
	// ExitAllowLAN permits the local network while an exit node is used;
	// off by default (ADR-0006). Applied only with the kill switch on.
	ExitAllowLAN bool `json:"exit_allow_lan,omitempty"`
	// Shields refuses every connection other devices open to this
	// computer, whatever the rules allow (F-077).
	Shields bool `json:"shields,omitempty"`
	// DisconnectedUntil turns the tunnel back on at this time (F-121); nil
	// with Disconnected means off until the owner turns it on.
	DisconnectedUntil *time.Time `json:"disconnected_until,omitempty"`
	// LastExitNode is the last exit node chosen, offered in the tray for a
	// one-click return (F-038).
	LastExitNode string `json:"last_exit_node,omitempty"`
	// Pinned devices come first in the panel and the tray (F-159).
	Pinned []string `json:"pinned,omitempty"`
	// CoordinatorAddrs are the coordinator's addresses from the last
	// successful name lookup, used when the name cannot be resolved (for
	// example while the kill switch blocks the system resolver).
	CoordinatorAddrs *addrCache `json:"coordinator_addrs,omitempty"`
	// IgnoreNetworkDNS keeps the network's DNS settings (ADR-0024) off on
	// this computer (F-065). MagicDNS names keep working.
	IgnoreNetworkDNS bool `json:"ignore_network_dns,omitempty"`
	// MTU is the tunnel interface MTU (F-019); 0 uses node.DefaultMTU.
	MTU int `json:"mtu,omitempty"`
	// ForceRelay reaches every peer through the coordinator (F-022).
	ForceRelay bool `json:"force_relay,omitempty"`
	// CoordinatorRelayRate (bytes per second per device) and
	// CoordinatorRelayBurst (bytes) limit the relay of the coordinator
	// running here (F-026); 0 uses the coordinator's defaults.
	CoordinatorRelayRate  int64 `json:"coordinator_relay_rate,omitempty"`
	CoordinatorRelayBurst int64 `json:"coordinator_relay_burst,omitempty"`
	// CoordinatorTCPListen is the TCP transport address of the coordinator
	// running here ("" = off, ADR-0032); the limits are 0 for the
	// coordinator's defaults.
	CoordinatorTCPListen        string `json:"coordinator_tcp_listen,omitempty"`
	CoordinatorTCPMaxConns      int    `json:"coordinator_tcp_max_conns,omitempty"`
	CoordinatorTCPMaxConnsPerIP int    `json:"coordinator_tcp_max_conns_per_ip,omitempty"`
	// Tunnel holds the connection and diagnostics preferences set with
	// "openscale set" (diag_prefs.go).
	Tunnel *tunnelOptions `json:"tunnel,omitempty"`
}

// addrCache remembers what a host name resolved to.
type addrCache struct {
	Host  string    `json:"host"`
	Addrs []string  `json:"addrs"`
	At    time.Time `json:"at"`
}

// Limits of the lists kept in the settings file.
const (
	maxPinned      = 64
	maxCachedAddrs = 8
)

// killSwitchOn reports the kill switch setting; missing means on.
func (s settings) killSwitchOn() bool { return s.KillSwitch == nil || *s.KillSwitch }

func loadSettings(dir string) (settings, error) {
	var st settings
	data, err := securefile.ReadPrivate(filepath.Join(dir, settingsFile), maxSettingsSize)
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(data, &st); err != nil {
		return st, errors.New("settings file is corrupt")
	}
	if st.CoordinatorPort < 0 || st.CoordinatorPort > 65535 {
		return settings{}, errors.New("settings file is corrupt")
	}
	// Lists from an older or hand-edited file are cut to their limits
	// instead of rejecting every other setting with them.
	if len(st.Pinned) > maxPinned {
		st.Pinned = st.Pinned[:maxPinned]
	}
	if c := st.CoordinatorAddrs; c != nil && len(c.Addrs) > maxCachedAddrs {
		c.Addrs = c.Addrs[:maxCachedAddrs]
	}
	return st, nil
}

func saveSettings(dir string, st settings) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return securefile.Replace(filepath.Join(dir, settingsFile), data)
}

// setUp reports whether this computer already has a network or membership.
func (r *Runtime) setUpLocked() bool {
	if r.network != nil || r.join != nil {
		return true
	}
	for _, d := range []string{NetworkDir, DeviceDir, CoordinatorDir} {
		if _, err := os.Stat(r.path(d, "anchor.json")); err == nil {
			return true
		}
	}
	_, err := os.Stat(r.path(NetworkDir, "root.key"))
	return err == nil
}

func (r *Runtime) deviceName(requested string) string {
	if name := trust.SanitizeHostname(requested); name != "" {
		return name
	}
	if host, err := r.cfg.Hostname(); err == nil {
		if name := trust.SanitizeHostname(host); name != "" {
			return name
		}
	}
	return defaultName
}

// CreateNetwork implements panel.App. This computer becomes the root key
// holder, the coordinator and the first (admin) device. Unless
// in.EmptyPolicy is set every device may reach every other one; the welcome
// screen asks the owner and defaults to an empty rule set (F-087).
func (r *Runtime) CreateNetwork(ctx context.Context, in panel.CreateNetworkInput) (*admin.Network, error) {
	r.mu.Lock()
	if r.setUpLocked() {
		r.mu.Unlock()
		return nil, ErrAlreadySetUp
	}
	r.mu.Unlock()
	if err := trust.CheckPassphrase(in.Passphrase); err != nil {
		return nil, err
	}
	host := in.EndpointHost
	if host == "" {
		host = suggestEndpoint()
	}
	if host == "" {
		return nil, errors.New("bu bilgisayarın adresi bulunamadı; diğer cihazların ulaşacağı IP adresini veya alan adını yazın")
	}
	port, err := pickUDPPort(coordinatorPorts)
	if err != nil {
		return nil, err
	}
	name := r.deviceName(in.DeviceName)

	n, err := r.createNetwork(ctx, in.Passphrase, name, net.JoinHostPort(host, strconv.Itoa(port)), !in.EmptyPolicy)
	if err != nil {
		// Leave nothing half-made behind so the owner can simply retry.
		for _, d := range []string{NetworkDir, DeviceDir, CoordinatorDir} {
			_ = os.RemoveAll(r.path(d))
		}
		return nil, err
	}
	if err := saveSettings(r.cfg.DataDir, settings{CoordinatorPort: port}); err != nil {
		return nil, err
	}
	r.mu.Lock()
	r.network = n
	r.mu.Unlock()
	r.logger.Info("network created", "device", name, "coordinator_port", port)
	r.startCoordinator()
	r.startDevice()
	return n, nil
}

// allowAll adds the "every device to every device" rule; without it the
// network starts with no rules (F-087, #286).
func (r *Runtime) createNetwork(_ context.Context, passphrase []byte, name, endpoint string, allowAll bool) (*admin.Network, error) {
	now := r.cfg.Now()
	n, err := admin.Init(r.path(NetworkDir), admin.InitOptions{
		DNSDomain:  trust.DefaultDNSDomain,
		IPv4Prefix: trust.DefaultIPv4Prefix,
		Validity:   trust.DefaultValidity,
	}, passphrase, r.adminOptions(), now)
	if err != nil {
		return nil, err
	}
	coordSecrets, err := loadOrCreateSecrets(r.path(CoordinatorDir, coordKeyFile), r.cfg.Random, now)
	if err != nil {
		return nil, err
	}
	_, coordWG, err := coordSecrets.PublicKeys()
	if err != nil {
		return nil, err
	}
	devSecrets, err := loadOrCreateSecrets(r.path(DeviceDir, deviceKeyFile), r.cfg.Random, now)
	if err != nil {
		return nil, err
	}
	env, _, err := devSecrets.NewEnrollmentRequest(name, now)
	if err != nil {
		return nil, err
	}
	req, err := trust.OpenEnrollmentRequest(env, now)
	if err != nil {
		return nil, err
	}
	plan, err := n.Prepare(now, trust.DefaultValidity, func(doc *trust.Document) error {
		if err := doc.SetCoordinator(endpoint, coordWG); err != nil {
			return err
		}
		if _, err := doc.AddDevice(req, name, []trust.Role{trust.RoleAdmin}, now, trust.DefaultDeviceLife); err != nil {
			return err
		}
		if !allowAll {
			return nil
		}
		return doc.AddRule(trust.Rule{
			From:        []string{trust.RuleWildcard},
			To:          []string{trust.RuleWildcard},
			Protocol:    trust.ProtocolAny,
			Description: "Tüm cihazlar birbirine erişebilir",
		})
	})
	if err != nil {
		return nil, err
	}
	if err := n.Commit(plan, passphrase); err != nil {
		return nil, err
	}
	bundle, err := n.JoinBundle()
	if err != nil {
		return nil, err
	}
	for _, d := range []string{CoordinatorDir, DeviceDir} {
		if _, err := member.Join(r.path(d), bundle, n.RootFingerprint(), now); err != nil {
			return nil, err
		}
	}
	return n, nil
}

// JoinNetwork implements panel.App: it starts the invite join in the
// background; Status shows the short code once the coordinator has it.
func (r *Runtime) JoinNetwork(code, name string) error {
	c, err := trust.DecodeInviteCode(code)
	if err != nil {
		return errors.New("davet kodu geçersiz; kodu eksiksiz kopyaladığınızdan emin olun")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.setUpLocked() {
		return ErrAlreadySetUp
	}
	secrets, err := loadOrCreateSecrets(r.path(DeviceDir, deviceKeyFile), r.cfg.Random, r.cfg.Now())
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(r.ctx)
	js := &joinState{name: r.deviceName(name), cancel: cancel}
	r.join, r.lastJoinErr = js, ""
	go r.runJoin(ctx, js, c, secrets)
	return nil
}

func (r *Runtime) runJoin(ctx context.Context, js *joinState, code *trust.InviteCode, secrets *trust.DeviceSecrets) {
	_, err := node.JoinWithInvite(ctx, node.InviteJoinConfig{
		Code:     code,
		Secrets:  secrets,
		Hostname: js.name,
		StateDir: r.path(DeviceDir),
		Logger:   r.logger.With("role", "join"),
		Now:      r.cfg.Now,
		OnWaiting: func(req *trust.EnrollmentRequest) {
			r.mu.Lock()
			js.shortCode = req.ShortCode()
			r.mu.Unlock()
		},
	})
	r.mu.Lock()
	if r.join == js {
		r.join = nil
	}
	if err != nil && ctx.Err() == nil {
		r.lastJoinErr = describe(err)
	}
	r.mu.Unlock()
	if err == nil {
		r.logger.Info("joined the network")
		r.startDevice()
	}
}

// CancelJoin implements panel.App.
func (r *Runtime) CancelJoin() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.join != nil {
		r.join.cancel()
		r.join = nil
	}
	r.lastJoinErr = ""
}

// listenUDP is net.ListenUDP; tests replace it to stay on loopback.
var listenUDP = net.ListenUDP

// pickUDPPort returns the first port that can be bound on IPv4 and IPv6.
// Ports in Windows' excluded ranges fail to bind and are skipped.
func pickUDPPort(candidates []int) (int, error) {
	for _, p := range candidates {
		c4, err := listenUDP("udp4", &net.UDPAddr{Port: p})
		if err != nil {
			continue
		}
		c6, err := listenUDP("udp6", &net.UDPAddr{Port: p})
		_ = c4.Close()
		if err != nil {
			continue
		}
		_ = c6.Close()
		return p, nil
	}
	return 0, ErrNoFreePort
}

// suggestEndpoint returns this computer's primary LAN IPv4 address. A UDP
// "connection" only selects a route; nothing is sent.
func suggestEndpoint() string {
	c, err := net.Dial("udp4", "192.0.2.1:9")
	if err != nil {
		return ""
	}
	defer c.Close()
	addr, ok := c.LocalAddr().(*net.UDPAddr)
	if !ok {
		return ""
	}
	ip, ok := netip.AddrFromSlice(addr.IP)
	if !ok || !ip.Unmap().IsPrivate() && !ip.Unmap().IsGlobalUnicast() {
		return ""
	}
	return ip.Unmap().String()
}

// openTunnel creates the OS interface and assigns the overlay addresses.
// The interface, the OS settings and the engine share one MTU (F-019).
func openTunnel(ctx context.Context, self trust.Device, doc *trust.Document, mtu int) (tun.Device, error) {
	if err := node.ValidateMTU(mtu); err != nil {
		return nil, err
	}
	if err := wintunembed.Ensure(); err != nil {
		return nil, fmt.Errorf("Wintun sürücüsü hazırlanamadı: %w", err)
	}
	dev, err := osnet.CreateTUN(interfaceName, mtu, tunOptionsFrom(ctx))
	if err != nil {
		return nil, fmt.Errorf("ağ arayüzü oluşturulamadı: %w", err)
	}
	name, err := dev.Name()
	if err != nil {
		_ = dev.Close()
		return nil, err
	}
	err = osnet.Configure(ctx, osnet.Config{
		Interface: name,
		IPv4:      netip.PrefixFrom(self.IPv4, doc.IPv4Prefix.Bits()),
		IPv6:      netip.PrefixFrom(self.IPv6, doc.IPv6Prefix.Bits()),
		MTU:       mtu,
	})
	if err != nil {
		_ = dev.Close()
		return nil, fmt.Errorf("arayüz adresleri ayarlanamadı: %w", err)
	}
	return dev, nil
}
