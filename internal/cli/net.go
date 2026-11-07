package cli

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/control"
	"github.com/openscale/openscale/internal/coordinator"
	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/node"
	"github.com/openscale/openscale/internal/osnet"
	"github.com/openscale/openscale/internal/privsep"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/service"
	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/internal/wintunembed"
)

const (
	coordinatorKeyFile     = "coordinator.key"
	deviceKeyFile          = "device.key"
	defaultCoordinatorPort = 51820
	defaultInterfaceName   = "OpenScale"
	maxBundleFile          = 4 << 20
)

func cmdCoordinatorKeygen(env *Env, args []string) error {
	fs := newFlagSet(env, "coordinator keygen")
	stateDir := fs.String("state-dir", "", "koordinatörün durum klasörü (zorunlu)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *stateDir == "" {
		return usageError("--state-dir zorunlu")
	}
	path := filepath.Join(*stateDir, coordinatorKeyFile)
	secrets, created, err := loadOrCreateDeviceSecrets(env, path)
	if err != nil {
		return err
	}
	_, wg, err := secrets.PublicKeys()
	if err != nil {
		return err
	}
	w := env.Stdout
	if created {
		fmt.Fprintf(w, "Koordinatör anahtarı oluşturuldu: %s\n", path)
	} else {
		fmt.Fprintln(w, "Mevcut koordinatör anahtarı kullanıldı.")
	}
	fmt.Fprintf(w, "\nWireGuard açık anahtarı: %s\n", wg)
	fmt.Fprintf(w, "Parmak izi:              %s\n", trust.CoordinatorFingerprint(wg))
	fmt.Fprintln(w, "\nYönetici cihazda şunu çalıştır (adresi kendi sunucunla değiştir):")
	fmt.Fprintf(w, "  openscale network set-coordinator --dir <ağ klasörü> --endpoint <alan-adı-veya-ip>:%d --wireguard-key %s --fingerprint <yukarıdaki parmak izi>\n", defaultCoordinatorPort, wg)
	fmt.Fprintln(w, "Özel anahtar bu sunucudan hiç çıkmaz.")
	return nil
}

func cmdNetworkSetCoordinator(env *Env, args []string) error {
	fs := newFlagSet(env, "network set-coordinator")
	common := addEditFlags(fs)
	endpoint := fs.String("endpoint", "", "koordinatörün dış adresi, ör. vpn.ornek.com:51820 veya 203.0.113.5:51820 (zorunlu)")
	keyText := fs.String("wireguard-key", "", "'coordinator keygen' çıktısındaki WireGuard açık anahtarı (zorunlu)")
	fingerprint := fs.String("fingerprint", "", "'coordinator keygen' çıktısındaki parmak izi (zorunlu)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *endpoint == "" || *keyText == "" || *fingerprint == "" {
		return usageError("--endpoint, --wireguard-key ve --fingerprint zorunlu")
	}
	key, err := trust.ParseKey(strings.TrimSpace(*keyText))
	if err != nil {
		return usageError("--wireguard-key geçerli bir WireGuard anahtarı değil")
	}
	got := []byte(trust.NormalizeFingerprint(*fingerprint))
	want := []byte(trust.NormalizeFingerprint(trust.CoordinatorFingerprint(key)))
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return admin.ErrFingerprintMismatch
	}
	ep := strings.TrimSpace(*endpoint)
	return runEdit(env, common, func(doc *trust.Document) error { return doc.SetCoordinator(ep, key) })
}

func cmdBundle(env *Env, args []string) error {
	fs := newFlagSet(env, "bundle")
	dir := fs.String("dir", "", "ağ klasörü (zorunlu)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *dir == "" {
		return usageError("--dir zorunlu")
	}
	n, err := admin.Load(*dir, env.adminOptions())
	if err != nil {
		return err
	}
	line, err := n.JoinBundle()
	if err != nil {
		return err
	}
	w := env.Stdout
	fmt.Fprintln(w, "Katılım paketi (yeni cihazda veya koordinatörde 'openscale join --bundle ...' ile kullan):")
	fmt.Fprintln(w, line)
	fmt.Fprintf(w, "\nKök anahtar parmak izi: %s\n", n.RootFingerprint())
	fmt.Fprintln(w, "Bu parmak izini yeni cihazda --root-fingerprint ile ELLE yaz; paketle birlikte kopyalama.")
	fmt.Fprintln(w, "Parmak izi eşleşmezse paket reddedilir; böylece yolda başka bir kök anahtar araya sokulamaz.")
	return nil
}

func cmdJoin(env *Env, args []string) error {
	fs := newFlagSet(env, "join")
	stateDir := fs.String("state-dir", "", "durum klasörü (varsayılan: kullanıcı yapılandırma klasörü)")
	bundle := fs.String("bundle", "", "katılım paketi satırı veya @dosya (zorunlu)")
	rootFingerprint := fs.String("root-fingerprint", "", "yönetici ekranındaki kök anahtar parmak izi (zorunlu)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *bundle == "" || *rootFingerprint == "" {
		return usageError("--bundle ve --root-fingerprint zorunlu")
	}
	dir, err := resolveStateDir(env, *stateDir)
	if err != nil {
		return err
	}
	line := *bundle
	if strings.HasPrefix(line, "@") {
		data, err := securefile.ReadLimited(strings.TrimPrefix(line, "@"), maxBundleFile)
		if err != nil {
			return fmt.Errorf("paket dosyası okunamadı: %w", err)
		}
		line = string(data)
	}
	store, err := member.Join(dir, line, *rootFingerprint, env.Now())
	if err != nil {
		return err
	}
	doc := store.Document()
	w := env.Stdout
	fmt.Fprintf(w, "Ağa katılındı: %s (belge sürümü %d)\n", doc.NetworkID, doc.Version)
	fmt.Fprintf(w, "Durum klasörü: %s\n", dir)
	describeMembership(w, dir, doc)
	return nil
}

// describeMembership tells the user whether a local key in dir is a device
// or the coordinator in doc.
func describeMembership(w io.Writer, dir string, doc *trust.Document) {
	if s, err := readSecrets(filepath.Join(dir, coordinatorKeyFile)); err == nil {
		if _, wg, err := s.PublicKeys(); err == nil && doc.Coordinator != nil && doc.Coordinator.WireGuardKey == wg {
			fmt.Fprintln(w, "Bu sunucu ağın koordinatörü. Başlatmak için: openscale coordinator run --state-dir "+dir)
			return
		}
		fmt.Fprintln(w, "UYARI: coordinator.key belgedeki koordinatörle eşleşmiyor; yönetici 'network set-coordinator' çalıştırmalı.")
		return
	}
	s, err := readSecrets(filepath.Join(dir, deviceKeyFile))
	if err != nil {
		fmt.Fprintln(w, "UYARI: bu klasörde cihaz anahtarı yok; önce 'openscale keygen' çalıştır ve cihazı yöneticiye ekletin.")
		return
	}
	_, wg, err := s.PublicKeys()
	if err != nil {
		return
	}
	for _, d := range doc.Devices {
		if d.WireGuardKey == wg {
			fmt.Fprintf(w, "Bu cihaz ağda kayıtlı: %s.%s (%s)\n", d.Name, doc.DNSDomain, d.IPv4)
			if doc.Coordinator == nil {
				fmt.Fprintln(w, "UYARI: belgede koordinatör yok; yönetici 'network set-coordinator' çalıştırmalı.")
				return
			}
			fmt.Fprintln(w, "Tüneli açmak için (yönetici/root olarak): openscale up")
			return
		}
	}
	fmt.Fprintln(w, "UYARI: bu cihaz belgede yok. Yönetici cihazı ekledikten sonra yeni bir paketle tekrar 'join' çalıştır.")
}

func cmdCoordinatorRun(env *Env, args []string) error {
	fs := newFlagSet(env, "coordinator run")
	stateDir := fs.String("state-dir", "", "koordinatörün durum klasörü (zorunlu)")
	port := fs.Int("listen-port", defaultCoordinatorPort, "dinlenecek UDP portu")
	relayRate := fs.Int64("relay-rate", 0, "aktarıcıda cihaz başına hız sınırı, bayt/sn (0: varsayılan 20 MiB/sn; en az 65536)")
	relayBurst := fs.Int64("relay-burst", 0, "aktarıcıda ani yük sınırı, bayt (0: varsayılan 4 MiB)")
	relayAdmission := fs.Bool("relay-admission", false, "aktarıcıyı durum klasöründeki "+coordinator.RelayAdmissionFile+" ile ayrıca sınırla; dosya yok/bozuksa hiçbir şey aktarılmaz (F-096)")
	tcpFlags := addCoordinatorTCPFlags(fs)
	limitFlags := addCoordinatorLimitFlags(fs) // P15 limits (ADR-0111, p22.go)
	debug := fs.Bool("debug", false, "ayrıntılı log (uç nokta adreslerini içerir)")
	if err := parseFlagsWithEnv(fs, args, coordinatorEnvFlags); err != nil {
		return err
	}
	tcpListen, tcpMax, tcpPerIP, err := tcpFlags.resolve()
	if err != nil {
		return err
	}
	if *stateDir == "" {
		return usageError("--state-dir zorunlu")
	}
	if *port < 1 || *port > 65535 {
		return usageError("--listen-port 1 ile 65535 arasında olmalı")
	}
	if err := validRelayFlags(*relayRate, *relayBurst); err != nil {
		return err
	}
	if err := limitFlags.resolve(); err != nil {
		return err
	}
	store, err := member.Open(*stateDir)
	if err != nil {
		return err
	}
	secrets, err := readSecrets(filepath.Join(*stateDir, coordinatorKeyFile))
	if err != nil {
		return fmt.Errorf("koordinatör anahtarı okunamadı; önce 'openscale coordinator keygen' çalıştır: %w", err)
	}
	logger := newLogger(env, *debug)
	removeStaleTemps(env, *stateDir, logger)
	warnCoordinatorDisk(env) // ADR-0109 (#155)
	ccfg := coordinator.Config{
		Store: store, Secrets: secrets, ListenPort: *port, Logger: logger, Now: env.Now,
		RelayRate: *relayRate, RelayBurst: *relayBurst, RelayAdmission: relayAdmissionPath(*stateDir, *relayAdmission),
		TCPListen: tcpListen, TCPMaxConns: tcpMax, TCPMaxConnsPerIP: tcpPerIP,
		ControlRate: *limitFlags.controlRate, ControlBurst: *limitFlags.controlBurst, ControlTotalRate: *limitFlags.controlTotal,
		RelayMaxPeers: *limitFlags.relayMaxPeers, RelayTotalRate: *limitFlags.relayTotalRate, RelayRequireSessions: *limitFlags.requireSessions,
		Sandbox: true, // Landlock (#147, ADR-0111); OPENSCALE_NO_LANDLOCK=1 turns it off
		// Relay usage, reach report and failover drill (P09, ADR-0153).
		Operations: true,
		// The owner's signed release, served inside the tunnel (ADR-0225).
		ReleaseMirror: filepath.Join(*stateDir, coordinator.ReleaseMirrorDir),
		Rejections:    coordinatorRejectionSink(env, *stateDir, logger), // #187, p2_coord_audit.go
	}
	obfsRT, err := startCoordinatorObfs(env, &ccfg, *stateDir) // ADR-0186, wire_coord_obfs.go
	if err != nil {
		return err
	}
	srv, err := coordinator.New(ccfg)
	if err != nil {
		obfsRT.Close()
		return err
	}
	obfsRT.Serve(envContext(env), srv, obfsServeErr(logger))
	if tcpListen != "" {
		fmt.Fprintf(env.Stdout, "Koordinatör %d/udp ve %s/tcp üzerinde başlıyor. Durdurmak için Ctrl+C.\n", *port, tcpListen)
	} else {
		fmt.Fprintf(env.Stdout, "Koordinatör %d/udp portunda başlıyor. Durdurmak için Ctrl+C.\n", *port)
	}
	notifyCoordinatorReady(envContext(env), srv, *port, tcpListen)
	return srv.Run(envContext(env))
}

func cmdUp(env *Env, args []string) error {
	if len(args) == 0 {
		// The desktop service owns the tunnel when it runs (F-171).
		if done, err := upViaService(env); done {
			return err
		}
	}
	fs := newFlagSet(env, "up")
	netFlags := addUpNetFlags(fs)
	transportFlags := addUpTransportFlags(fs)
	wave2Flags := addUpWave2Flags(fs) // ADR-0110
	p10Flags := addUpP10Flags(fs)     // ADR-0133
	p04Flags := addUpP04Flags(fs)     // P04: exit port policy, DoH list, source, quota
	dnsEnforceFlags := addUpDNSEnforceFlags(fs)
	stateDir := fs.String("state-dir", "", "durum klasörü (varsayılan: kullanıcı yapılandırma klasörü)")
	networkDir := fs.String("network-dir", "", "yönetici cihazda ağ klasörü; yeni belgeler buradan koordinatöre yayınlanır")
	port := fs.Int("listen-port", 0, "WireGuard UDP portu; 0 boş bir port seçer")
	iface := fs.String("interface", defaultInterfaceName, "oluşturulacak ağ arayüzünün adı")
	exitNode := fs.String("exit-node", "", "internet trafiğini bu çıkış düğümünden geçir (Windows; Linux'ta systemd-resolved gerekir)")
	exitDNS := fs.String("exit-dns-upstream", "", "bu cihaz çıkış düğümüyse üyelerin DNS sorgularını ileteceği üst çözücü: IP[:port] (düz DNS), tls://sunucu[:853] (DNS over TLS) veya https://sunucu/dns-query (DNS over HTTPS), recursive (kendi özyinelemeli çözücüsü) ya da recursive-dnssec (DNSSEC doğrulamalı); boşsa /etc/resolv.conf")
	exitUpstream := fs.String("exit-upstream", "", "bu cihaz Linux çıkış düğümüyse üyelerin internet trafiğini bu üst çıkış profilinin (ör. Mullvad) tünelinden çıkar; profil 'exit-node upstream import' ile eklenir (ADR-0142)")
	netfilterMode := fs.String("netfilter-mode", osnet.NetfilterAuto, "çıkış düğümü NAT kuralları (Linux): auto (nft varsa nftables, yoksa iptables), nftables veya iptables")
	mtu := fs.Int("mtu", node.DefaultMTU, fmt.Sprintf("tünel arayüzü MTU değeri (%d-%d); aktarıcı kullanılırken %d üstü parçalanmaya yol açabilir", node.MinMTU, node.MaxMTU, node.DefaultMTU))
	forceRelay := fs.Bool("force-relay", false, "bütün eşlere koordinatörün aktarıcısı üzerinden ulaş; doğrudan bağlantı deneme (MTU en fazla 1280)")
	relayAfter := fs.Duration("relay-after", 0, "doğrudan el sıkışma bu kadar süre olmazsa aktarıcıya geç (1s-10m; 0: varsayılan 30s)")
	directRetry := fs.Duration("direct-retry", 0, "aktarıcıdaki eş için doğrudan yolu yeniden deneme aralığı (10s-24h; 0: varsayılan 5m)")
	networkDNS := fs.Bool("network-dns", true, "ağ belgesindeki DNS ayarlarını uygula (split DNS, ağ geneli çözücü); false: yalnızca MagicDNS")
	dnsCatchAll := fs.Bool("dns-catch-all", false, "Windows: ağ geneli çözücü varken bütün adları tek NRPT kuralıyla MagicDNS'e gönder; split alanları MagicDNS iletir (F-063)")
	debug := fs.Bool("debug", false, "ayrıntılı log (uç nokta adreslerini içerir)")
	leak := addUpLeakFlags(fs)
	if err := parseFlagsWithEnv(fs, args, upEnvFlags); err != nil {
		return err
	}
	if err := leak.validate(strings.TrimSpace(*exitNode)); err != nil {
		return err
	}
	netOpts, err := netFlags.resolve()
	if err != nil {
		return err
	}
	transportOpts, err := transportFlags.resolve()
	if err != nil {
		return err
	}
	wave2Opts, err := wave2Flags.resolve()
	if err != nil {
		return err
	}
	p10Opts, err := p10Flags.resolve()
	if err != nil {
		return err
	}
	p04Opts, err := p04Flags.resolve()
	if err != nil {
		return err
	}
	if wave2Opts.cfg.TorSOCKS != "" && transportOpts.noTCP {
		return usageError("--tor-socks TCP taşımasını kullanır; --disable-tcp-fallback ile birlikte kullanılamaz")
	}
	if *port < 0 || *port > 65535 {
		return usageError("--listen-port 0 ile 65535 arasında olmalı")
	}
	if err := node.ValidateMTU(*mtu); err != nil {
		return usageError("--mtu: %v", err)
	}
	if *forceRelay && *mtu > node.DefaultMTU {
		return usageError("--force-relay ile --mtu en fazla %d olabilir", node.DefaultMTU)
	}
	if err := validTimingFlags(*relayAfter, *directRetry); err != nil {
		return err
	}
	upstream := strings.TrimSpace(*exitDNS)
	if err := node.ValidateExitDNSUpstream(upstream); err != nil {
		return usageError("--exit-dns-upstream: %v", err)
	}
	if err := osnet.SetNetfilterMode(strings.TrimSpace(*netfilterMode)); err != nil {
		return usageError("--netfilter-mode: %v", err)
	}
	dir, err := resolveStateDir(env, *stateDir)
	if err != nil {
		return err
	}
	store, err := member.Open(dir)
	if err != nil {
		return err
	}
	secrets, err := readSecrets(filepath.Join(dir, deviceKeyFile))
	if err != nil {
		return fmt.Errorf("cihaz anahtarı okunamadı; önce 'openscale keygen' çalıştır: %w", err)
	}
	logger, logLevel := newLeveledLogger(env, *debug)
	removeStaleTemps(env, dir, logger)
	parserGate := transportOpts.startParserGate(logger) // ADR-0233
	defer func() {
		privsep.SetDefault(nil)
		_ = parserGate.Close()
	}()

	// Validate membership before touching the OS, so a revoked device does
	// not create an interface. Keys from an approved rotation (ADR-0020)
	// take over once the document lists them.
	doc := store.Document()
	if next, ok, err := service.PromoteRotatedKey(dir, doc); err != nil {
		fmt.Fprintf(env.Stderr, "uyarı: anahtar yenilemesi tamamlanamadı: %v\n", err)
	} else if ok {
		secrets = next
		fmt.Fprintln(env.Stdout, "Anahtar yenilemesi onaylanmış: yeni anahtarlara geçildi.")
	}
	self, err := selfDevice(doc, secrets)
	if err != nil {
		return err
	}
	if doc.Coordinator == nil {
		return errors.New("ağ belgesinde koordinatör yok; yönetici 'openscale network set-coordinator' çalıştırmalı")
	}

	// Undo DNS and route changes a crashed run left behind (ADR-0051).
	journal := service.OpenJournal(dir, env.Now)
	recoverUpChanges(env, journal, logger)

	// On Windows this installs, verifies and pins the embedded, signed
	// wintun.dll before wireguard-go loads it by name; elsewhere a no-op.
	if err := wintunembed.Ensure(); err != nil {
		return fmt.Errorf("Wintun sürücüsü hazırlanamadı: %w", err)
	}
	dev, err := osnet.CreateTUN(*iface, *mtu, osnet.TUNOptions{DisableOffload: netOpts.disableOffload})
	if err != nil {
		return fmt.Errorf("ağ arayüzü oluşturulamadı (yönetici/root olarak çalıştırdığından emin ol): %w", err)
	}
	name, err := dev.Name()
	if err != nil {
		_ = dev.Close()
		return err
	}
	adoptUpTUN(dev, logger) // #203: an interface an update kept
	ctx := envContext(env)
	osCfg := osnet.Config{
		Interface: name,
		IPv4:      netip.PrefixFrom(self.IPv4, doc.IPv4Prefix.Bits()),
		IPv6:      netip.PrefixFrom(self.IPv6, doc.IPv6Prefix.Bits()),
		MTU:       *mtu,
	}
	if err := osnet.Configure(ctx, osCfg); err != nil {
		_ = dev.Close()
		return fmt.Errorf("arayüz adresleri ayarlanamadı: %w", err)
	}
	// Leak protection (ADR-0023): the kill switch goes in before the
	// tunnel carries anything; host firewalls are checked (#283).
	if err := leak.prepare(env, name); err != nil {
		_ = dev.Close()
		return err
	}
	defer leak.done(env)
	leak.checkHostFirewall(ctx, env, name)
	dns := osnet.DNSConfig{Interface: name, Server: doc.DNSResolverIPv4(), Domain: doc.DNSDomain}
	magicOK := false
	journalBegin(env, journal, service.DNSEntry(dns))
	if err := osnet.ConfigureDNS(ctx, dns); err != nil {
		fmt.Fprintf(env.Stderr, "uyarı: MagicDNS ayarlanamadı, cihaz adları çözülmeyecek: %v\n", err)
	} else {
		magicOK = true
		// A domain NRPT rule from Group Policy overrides the local one (#272).
		if w := osnet.NRPTGroupPolicyWarning(dns); w != "" {
			fmt.Fprintf(env.Stderr, "uyarı: %s\n", w)
		}
		// Reverse names of the network (PTR) are answered by MagicDNS too.
		if err := osnet.ConfigureReverseDNS(ctx, dns, doc.IPv4Prefix, doc.IPv6Prefix); err != nil {
			fmt.Fprintf(env.Stderr, "uyarı: ters DNS (PTR) ayarlanamadı: %v\n", err)
		}
		defer func() {
			cctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			if osnet.RemoveDNS(cctx, dns) == nil {
				_ = journal.Done(service.JournalDNS)
			}
		}()
	}
	// Host name announcements over mDNS are hidden for this run when the
	// opsec setting asks for it (#40); restored on exit and after a crash.
	if opsec, err := node.LoadOpsecSettings(dir); err == nil {
		restoreMDNS, err := service.HideMDNS(ctx, journal, service.MDNSHideWanted(opsec), service.MDNSRunners{}, logger)
		if err != nil {
			fmt.Fprintf(env.Stderr, "uyarı: mDNS ad duyurusu kapatılamadı: %v\n", err)
		}
		defer func() {
			cctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			if err := restoreMDNS(cctx); err != nil {
				fmt.Fprintf(env.Stderr, "uyarı: mDNS ad duyurusu geri açılamadı: %v\n", err)
			}
		}()
	}
	// Upstream exit (ADR-0142): a provider tunnel members' traffic leaves
	// through when this device is an exit node.
	upExit, err := startUpUpstream(env, dir, strings.TrimSpace(*exitUpstream), name, store, secrets, logger)
	if err != nil {
		_ = dev.Close()
		return err
	}
	exitNAT := osnet.ExitNAT{Interface: name, IPv4: doc.IPv4Prefix, IPv6: doc.IPv6Prefix}
	exitNAT.RateLimit = p10Opts.exitRate
	// P04: port policy, DoH list, source address and quota sets.
	p04Opts.applyExitNAT(env, &exitNAT, doc)
	warnExitNodeMAC(env, *exitNode) // ADR-0109 (#41)
	// #203: the last endpoints of a restart, before the engine starts.
	service.TakeHandover(dir, doc, env.Now(), logger.With("part", "handover"))
	engine, err := node.New(wave2Opts.apply(env, transportOpts.apply(netOpts.apply(node.Config{
		Store:       store,
		Secrets:     secrets,
		TUN:         dev,
		ListenPort:  *port,
		NetworkDir:  *networkDir,
		Logger:      logger,
		Now:         env.Now,
		ExitNode:    strings.TrimSpace(*exitNode),
		ExitRouter:  leak.exitRouter(ctx, service.JournaledExitRouter(journal, osnet.NewExitRouter())),
		Routes:      p10Opts.routeApplier(), // ADR-0133
		MTU:         *mtu,
		ForceRelay:  *forceRelay,
		RelayAfter:  *relayAfter,
		DirectRetry: *directRetry,
		// Members' DNS goes to this resolver while this device is an
		// exit node (ADR-0024: DoH/DoT is the owner's local choice).
		ExitDNSUpstream: upstream,
		ExitDNSVia:      upExit.dnsVia(), // ADR-0142
		OnExitRole: func(on bool) {
			// Called from the engine; forwarding and NAT follow the exit
			// node role in the signed document (ADR-0018).
			cctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if on {
				journalBegin(env, journal, service.JournalEntry{Kind: service.JournalExitNAT, Interface: name})
				// The upstream's drop routing goes in before forwarding
				// (ADR-0142): no member packet leaves from this host.
				if err := upExit.roleOn(); err != nil {
					fmt.Fprintf(env.Stderr, "uyarı: üst çıkış hazır değil, çıkış düğümü açılmadı: %v\n", err)
					return
				}
				if err := osnet.EnableExitNAT(cctx, exitNAT); err != nil {
					fmt.Fprintf(env.Stderr, "uyarı: çıkış düğümü açılamadı: %v\n", err)
					return
				}
				fmt.Fprintln(env.Stdout, "Bu cihaz çıkış düğümü: üyelerin internet trafiği buradan çıkıyor.")
				return
			}
			if osnet.DisableExitNAT(cctx) == nil {
				_ = journal.Done(service.JournalExitNAT)
			}
			upExit.roleOff()
		},
	}))))
	if err != nil {
		_ = dev.Close()
		return err
	}
	stopUpstream := upExit.run(env) // ADR-0142: health checks, settings changes
	defer stopUpstream()
	defer startUpHandover(ctx, env, dir, name, dev, engine, logger)() // #203: written at the stop
	// SSH, files, wake and speed test follow the rules (ADR-0030, ADR-0031).
	stopP10 := p10Opts.start(ctx, env, engine) // ADR-0133: exceptions, automatic exit node
	defer stopP10()
	stopP04 := p04Opts.start(ctx, env, engine, dir, logger) // P04: monthly exit quota (ADR-0155)
	defer stopP04()
	stopApps := startUpAppsWith(ctx, dir, engine, name, logger, wave2Opts.remoteDesktopHost(env))
	defer stopApps()
	// MagicDNS forwards to the network's resolvers only with the same
	// choice (F-065, ADR-0034).
	engine.SetNetworkDNSRejected(!*networkDNS)
	if magicOK {
		// Network DNS (ADR-0024, ADR-0034) follows the document and the exit
		// node in use, and settings another program changes are applied
		// again (F-061); it stops before the MagicDNS cleanup above removes
		// every OpenScale DNS setting.
		dnsCtx, stopDNS := context.WithCancel(ctx)
		dnsDone := make(chan struct{})
		defer func() {
			stopDNS()
			<-dnsDone
		}()
		go func() {
			defer close(dnsDone)
			service.DNSWatch{
				Magic:      dns,
				Document:   store.Document,
				ExitActive: func() bool { return engine.ExitNode() != "" },
				Accept:     func() bool { return *networkDNS },
				CatchAll:   func() bool { return *dnsCatchAll },
				Apply:      osnet.ConfigureNetworkDNS,
				Verify:     osnet.VerifyNetworkDNS,
				OnRepair: func(err error) {
					fmt.Fprintf(env.Stderr, "uyarı: %v; OpenScale DNS ayarları yeniden uygulandı\n", err)
				},
				Report: func(active bool, err error) {
					switch {
					case err != nil:
						fmt.Fprintf(env.Stderr, "uyarı: ağ DNS ayarları uygulanamadı: %v\n", err)
					case active:
						fmt.Fprintln(env.Stdout, "Ağ DNS ayarları uygulandı.")
					}
				},
				Now: env.Now,
			}.Run(dnsCtx)
		}()
	}
	defer dnsEnforceFlags.start(ctx, env, engine, name, magicOK)() // #717: rules leave before the DNS cleanup above
	defer startUpAutoUpdate(ctx, dir, engine, logger)()            // ADR-0225: only as the installed Linux device unit
	if netOpts.localAPI {
		stopAPI, err := startUpLocalAPI(env, dir, engine, name, logLevel, logger)
		if err != nil {
			fmt.Fprintf(env.Stderr, "uyarı: yerel tanı API'si açılamadı; status/ping/netcheck çalışmaz: %v\n", err)
		} else {
			defer stopAPI()
		}
	}
	fmt.Fprintf(env.Stdout, "Tünel açılıyor: %s.%s  %s  %s (arayüz %s)\n", self.Name, doc.DNSDomain, self.IPv4, self.IPv6, name)
	fmt.Fprintln(env.Stdout, "Durdurmak için Ctrl+C. Arayüz ve adresleri kapanışta kaldırılır.")
	// systemd Type=notify (F-149): the addresses are in place.
	notifyReadyWhenSynced(ctx, engine, name)
	return engine.Run(ctx)
}

// Bounds of the relay timings, the same as node.Config documents; checked
// here so a typo is refused before the interface is created.
const (
	minRelayAfter  = time.Second
	maxRelayAfter  = 10 * time.Minute
	minDirectRetry = 10 * time.Second
	maxDirectRetry = 24 * time.Hour
)

func validTimingFlags(relayAfter, directRetry time.Duration) error {
	if relayAfter != 0 && (relayAfter < minRelayAfter || relayAfter > maxRelayAfter) {
		return usageError("--relay-after %s ile %s arasında olmalı", minRelayAfter, maxRelayAfter)
	}
	if directRetry != 0 && (directRetry < minDirectRetry || directRetry > maxDirectRetry) {
		return usageError("--direct-retry %s ile %s arasında olmalı", minDirectRetry, maxDirectRetry)
	}
	return nil
}

func validRelayFlags(rate, burst int64) error {
	if rate != 0 && (rate < coordinator.MinRelayRate || rate > coordinator.MaxRelayRate) {
		return usageError("--relay-rate %d ile %d bayt/sn arasında olmalı", coordinator.MinRelayRate, int64(coordinator.MaxRelayRate))
	}
	if burst != 0 && (burst < control.RelayMaxPayload || burst > coordinator.MaxRelayBurst) {
		return usageError("--relay-burst %d ile %d bayt arasında olmalı", control.RelayMaxPayload, coordinator.MaxRelayBurst)
	}
	return nil
}

func resolveStateDir(env *Env, dir string) (string, error) {
	if dir != "" {
		return dir, nil
	}
	d, err := env.DefaultStateDir()
	if err != nil {
		return "", fmt.Errorf("varsayılan klasör bulunamadı, --state-dir kullan: %w", err)
	}
	return d, nil
}

func readSecrets(path string) (*trust.DeviceSecrets, error) {
	data, err := securefile.ReadPrivate(path, trust.MaxDeviceKeySize)
	if err != nil {
		return nil, err
	}
	defer wipe(data)
	return unmarshalDeviceKey(data) // TPM-sealed or plain, wire_tpm.go (ADR-0208)
}

func newLogger(env *Env, debug bool) *slog.Logger {
	level := slog.LevelInfo
	if debug {
		level = slog.LevelDebug
	}
	return maskedJSONLogger(env.Stderr, level)
}

func envContext(env *Env) context.Context {
	if env.Ctx != nil {
		return env.Ctx
	}
	return context.Background()
}

func selfDevice(doc *trust.Document, secrets *trust.DeviceSecrets) (trust.Device, error) {
	_, wg, err := secrets.PublicKeys()
	if err != nil {
		return trust.Device{}, err
	}
	for _, d := range doc.Devices {
		if d.WireGuardKey == wg {
			return d, nil
		}
	}
	return trust.Device{}, node.ErrNotMember
}

// describeNetError adds Turkish messages for errors from the tunnel packages.
func describeNetError(err error) (string, bool) {
	switch {
	case errors.Is(err, member.ErrNotJoined):
		return "Bu klasör henüz bir ağa katılmamış; önce 'openscale join' çalıştır.", true
	case errors.Is(err, node.ErrNotMember):
		return "Bu cihaz ağ belgesinde yok: iptal edilmiş veya henüz eklenmemiş. Yöneticiden cihazı eklemesini isteyip yeni paketle 'openscale join' çalıştır.", true
	case errors.Is(err, net.ErrClosed):
		return "Ağ bağlantısı kapandı.", true
	}
	return "", false
}
