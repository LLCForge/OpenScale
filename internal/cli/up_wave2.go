package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/openscale/openscale/internal/filesend"
	"github.com/openscale/openscale/internal/filter"
	"github.com/openscale/openscale/internal/node"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/rdesk"
	"github.com/openscale/openscale/internal/service"
)

// Connection wave 2 options of "openscale up" (ADR-0110): router port
// mapping (ADR-0042), padding, cover traffic and priority (ADR-0043), Tor
// (ADR-0044), the exit node's block list and DNSSEC anchors and threat
// detection (ADR-0102), and the in-process remote desktop server.

func init() {
	upEnvFlags = append(upEnvFlags, "port-map", "port-map-disable", "padding", "cover-traffic", "interactive-priority",
		"tor-socks", "blocklist", "dnssec-anchors", "threat-scan", "threat-block", "rdesk")
}

type upWave2Flags struct {
	portMap        *bool
	portMapDisable *string
	padding        *string
	cover          *int
	priority       *bool
	torSOCKS       *string
	blocklist      *string
	anchors        *string
	threatScan     *bool
	threatBlock    *bool
	rdesk          *bool
}

func addUpWave2Flags(fs *flag.FlagSet) upWave2Flags {
	return upWave2Flags{
		portMap:        fs.Bool("port-map", false, "yönlendiricide WireGuard portunu aç: PCP, NAT-PMP, UPnP (ADR-0042)"),
		portMapDisable: fs.String("port-map-disable", "", "port eşlemede kullanılmayacak protokoller, virgülle: pcp,natpmp,upnp"),
		padding:        fs.String("padding", "off", "paket dolgusu: off, buckets veya mtu (ek bant genişliği; başlarken maliyeti yazılır)"),
		cover:          fs.Int("cover-traffic", 0, fmt.Sprintf("koordinatöre sahte trafik, B/sn (0: kapalı; %d-%d; veri ve pil harcar)", node.MinCoverTraffic, node.MaxCoverTraffic)),
		priority:       fs.Bool("interactive-priority", false, "ICMP, SSH, uzak masaüstü ve DNS paketlerini toplu aktarımdan önce gönder"),
		torSOCKS:       fs.String("tor-socks", "", "koordinatöre bu makinedeki Tor istemcisi üzerinden bağlan, ör. 127.0.0.1:9050 (bütün eşler aktarıcıdan)"),
		blocklist:      fs.String("blocklist", "", "çıkış düğümüyken NXDOMAIN ile yanıtlanacak adların yerel listesi (dosya; indirilmez)"),
		anchors:        fs.String("dnssec-anchors", "", "--exit-dns-upstream recursive-dnssec için kök DS kayıtları dosyası (boş: gömülü)"),
		threatScan:     fs.Bool("threat-scan", true, "eşlerden port taramasını algıla (ADR-0102)"),
		threatBlock:    fs.Bool("threat-block", true, "tarama yapan eşin yeni bağlantılarını bir süre reddet"),
		rdesk:          fs.Bool("rdesk", false, "rdesk kuralı varsa uzak masaüstü sunucusunu bu süreçte çalıştır (Linux: X11 masaüstü oturumunda; onay penceresi olmadığından yalnızca allow_unattended kuralları oturum açar)"),
	}
}

type upWave2Options struct {
	cfg   service.UpWave2Config
	rdesk bool
}

func (f upWave2Flags) resolve() (upWave2Options, error) {
	var o upWave2Options
	padding, err := service.ParsePadding(*f.padding)
	if err != nil {
		return o, usageError("--padding: %v", err)
	}
	if err := service.ValidCoverTraffic(*f.cover); err != nil {
		return o, usageError("--cover-traffic: %v", err)
	}
	disable := splitList(strings.ToLower(*f.portMapDisable))
	if err := service.ValidPortMapDisable(disable); err != nil {
		return o, usageError("--port-map-disable: %v", err)
	}
	if *f.portMap && len(disable) == 3 {
		return o, usageError("--port-map açık ama bütün protokoller kapalı")
	}
	tor := strings.TrimSpace(*f.torSOCKS)
	if err := service.ValidTorSOCKS(tor); err != nil {
		return o, usageError("--tor-socks: %v", err)
	}
	if err := service.ValidLocalFile("--blocklist", strings.TrimSpace(*f.blocklist)); err != nil {
		return o, usageError("%v", err)
	}
	if err := service.ValidLocalFile("--dnssec-anchors", strings.TrimSpace(*f.anchors)); err != nil {
		return o, usageError("%v", err)
	}
	if *f.rdesk && runtime.GOOS == "linux" && os.Getenv("DISPLAY") == "" && !rdesk.WaylandSession() {
		return o, usageError("--rdesk için masaüstü oturumu gerekir: X11 (DISPLAY) veya Wayland (XDG_SESSION_TYPE=wayland, WAYLAND_DISPLAY ve oturum D-Bus'ı)")
	}
	if *f.rdesk && runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		return o, usageError("--rdesk bu işletim sisteminde desteklenmiyor")
	}
	o.cfg = service.UpWave2Config{
		PortMap: node.PortMapConfig{Enabled: *f.portMap, DisablePCP: hasItem(disable, "pcp"), DisableNATPMP: hasItem(disable, "natpmp"), DisableUPnP: hasItem(disable, "upnp")},
		Padding: padding, CoverTraffic: *f.cover, InteractivePriority: *f.priority, TorSOCKS: tor,
		Blocklist: strings.TrimSpace(*f.blocklist), Anchors: strings.TrimSpace(*f.anchors),
		Threats: filter.ThreatConfig{DisableScan: !*f.threatScan, DisableBlock: !*f.threatBlock},
	}
	o.rdesk = *f.rdesk
	return o, nil
}

func hasItem(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// apply adds the options to the engine configuration and prints what
// padding and cover traffic cost before the tunnel starts.
func (o upWave2Options) apply(env *Env, cfg node.Config) node.Config {
	for _, line := range service.ShapingCostText(o.cfg.Padding, o.cfg.CoverTraffic, cfg.MTU) {
		fmt.Fprintln(env.Stderr, "maliyet: "+line)
	}
	if o.cfg.TorSOCKS != "" {
		fmt.Fprintln(env.Stderr, "Tor: koordinatöre yalnızca Tor üzerinden bağlanılacak; bütün eşler aktarıcıdan geçer, doğrudan bağlantı kurulmaz.")
	}
	cfg = o.cfg.Apply(cfg)
	cfg.OnThreat = func(ev filter.ThreatEvent) {
		fmt.Fprintf(env.Stderr, "uyarı: %s\n", service.ThreatText(ev))
	}
	return cfg
}

// remoteDesktopHost returns the in-process server for --rdesk.
func (o upWave2Options) remoteDesktopHost(env *Env) service.RemoteDesktopHost {
	if !o.rdesk {
		return nil
	}
	h := &service.InProcessRemoteDesktop{
		Indicator: func(ev rdesk.SessionEvent) {
			switch ev.Kind {
			case rdesk.EventStart:
				fmt.Fprintf(env.Stderr, "UZAK MASAÜSTÜ: %s\n", strings.ReplaceAll(indicatorText(ev), "\n", " "))
			case rdesk.EventEnd:
				fmt.Fprintf(env.Stderr, "UZAK MASAÜSTÜ: %s oturumu bitti (%s)\n", ev.Peer, ev.Reason)
			}
			desktopIndicator(ev)
		},
	}
	if desktopPromptsAvailable() {
		h.Consent = desktopConsent
	}
	return h
}

// startUpAppsWith is startUpApps with the remote desktop host.
func startUpAppsWith(ctx context.Context, dir string, engine service.AppEngine, iface string, logger *slog.Logger, host service.RemoteDesktopHost) func() {
	actx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	apps := service.NewApps(service.AppsConfig{
		Dir:             dir,
		Engine:          func() service.AppEngine { return engine },
		TunnelInterface: func() string { return iface },
		Logger:          logger.With("role", "apps"),
		RemoteDesktop:   host,
	})
	go func() {
		defer close(done)
		apps.Run(actx)
	}()
	return func() {
		cancel()
		<-done
	}
}

// --- threats (ADR-0102) ---

func cmdThreats(env *Env, args []string) error {
	if len(args) > 0 && args[0] == "unblock" {
		return cmdThreatsUnblock(env, args[1:])
	}
	fs := newFlagSet(env, "threats")
	df := addDiagFlags(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	c, err := df.client(env)
	if err != nil {
		return err
	}
	var rep panel.ThreatsReply
	if err := c.get(env, "/threats", &rep); err != nil {
		return err
	}
	if *df.json {
		return printJSON(env.Stdout, rep)
	}
	w := env.Stdout
	fmt.Fprintf(w, "DNSSEC: %d güvenli, %d imzasız, %d reddedilen (sahte/bozuk)\n", rep.DNSSEC.Secure, rep.DNSSEC.Insecure, rep.DNSSEC.Bogus)
	if len(rep.Blocked) > 0 {
		fmt.Fprintln(w, "\nEngellenen cihazlar:")
		for _, b := range rep.Blocked {
			fmt.Fprintf(w, "  %s  %s saatine kadar  (kaldırmak için: openscale threats unblock %s)\n", b.Peer, b.Until.Local().Format("15:04"), b.Peer)
		}
	}
	if len(rep.Threats) == 0 {
		fmt.Fprintln(w, "\nAlgılama yok.")
		return nil
	}
	fmt.Fprintf(w, "\nAlgılamalar (%d):\n", len(rep.Threats))
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  ZAMAN\tTÜR\tCİHAZ\tAYRINTI")
	for _, t := range rep.Threats {
		detail := ""
		switch {
		case t.Count > 0:
			detail = fmt.Sprintf("%d farklı hedef", t.Count)
		case t.Port > 0:
			detail = fmt.Sprintf("tuzak port %d", t.Port)
		case t.Canary != "":
			detail = "tuzak adres " + t.Canary
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n", t.At.Local().Format("02.01 15:04"), threatKindLabel(t.Kind), orDash(t.Peer), detail)
	}
	return tw.Flush()
}

func threatKindLabel(k string) string {
	switch filter.ThreatKind(k) {
	case filter.ThreatInboundScan:
		return "gelen tarama"
	case filter.ThreatOutboundScan:
		return "giden tarama"
	case filter.ThreatCanaryAddress:
		return "tuzak adres"
	case filter.ThreatCanaryPort:
		return "tuzak port"
	case node.ThreatDNSRateLimit: // P05
		return "DNS hız sınırı"
	case node.ThreatDNSTunnel:
		return "DNS tünelleme"
	}
	return k
}

func cmdThreatsUnblock(env *Env, args []string) error {
	fs := newFlagSet(env, "threats unblock")
	df := addDiagFlags(fs)
	if err := parseFlagsWithArgs(fs, args, 1); err != nil {
		return err
	}
	c, err := df.client(env)
	if err != nil {
		return err
	}
	peer := strings.ToLower(strings.TrimSpace(fs.Arg(0)))
	if err := c.post(env, "/threats/unblock", map[string]string{"peer": peer}, nil); err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "%s cihazının engeli kaldırıldı.\n", peer)
	return nil
}

// --- send: metadata and offline queue (ADR-0104) ---

// sendStripMode maps --strip-metadata.
func sendStripMode(s string) (filesend.MetadataMode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "yok", "none":
		return filesend.MetadataKeep, nil
	case "konum", "location":
		return filesend.MetadataLocation, nil
	case "hepsi", "all":
		return filesend.MetadataAll, nil
	}
	return 0, usageError("--strip-metadata konum veya hepsi olmalı")
}

// sendQueued keeps a file for an offline recipient in a private,
// temporary queue and sends it once the recipient answers (#140); it ends
// when the file is sent, refused, changed or after seven days, or with
// Ctrl+C. Nothing is stored on another device.
func sendQueued(env *Env, ctx context.Context, stateDir string, devName string, addr netip.AddrPort, path, name string, mode filesend.MetadataMode) error {
	// The queue lives in the user's own state directory (owner-only), never
	// in the system temporary directory.
	base, err := resolveStateDir(env, stateDir)
	if err != nil {
		return err
	}
	parent := filepath.Join(base, "send-queue")
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return err
	}
	dir, err := os.MkdirTemp(parent, "send-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	type outcome struct {
		res filesend.SendResult
		err error
	}
	done := make(chan outcome, 1)
	o, err := filesend.OpenOutbox(filesend.OutboxConfig{
		File:    filepath.Join(dir, "outbox.json"),
		Resolve: func(string) (netip.AddrPort, bool) { return addr, true },
		OnDone:  func(_ filesend.OutboxItem, res filesend.SendResult, err error) { done <- outcome{res, err} },
	})
	if err != nil {
		return err
	}
	if _, err := o.Enqueue(devName, path, name, mode); err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "%s çevrimiçi olunca gönderilecek; bekleniyor (Ctrl+C ile vazgeçilir)...\n", devName)
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	last := ""
	for {
		o.RunOnce(ctx)
		select {
		case r := <-done:
			if r.err != nil {
				if errors.Is(r.err, filesend.ErrRejected) {
					return errors.New("alıcı dosyayı kabul etmedi (kural yok, reddedildi veya süre doldu)")
				}
				return r.err
			}
			fmt.Fprintf(env.Stdout, "Gönderildi: alıcıda %q olarak kaydedildi.\n", r.res.SavedName)
			return nil
		default:
		}
		if items := o.Items(); len(items) == 1 && items[0].LastError != "" && items[0].LastError != last {
			last = items[0].LastError
			fmt.Fprintf(env.Stderr, "henüz gönderilemedi (%s); sonraki deneme %s\n", last, items[0].NextTry.Local().Format("15:04"))
		}
		select {
		case <-ctx.Done():
			return errors.New("gönderim iptal edildi; dosya gönderilmedi")
		case <-t.C:
		case r := <-done:
			done <- r
		}
	}
}

// sendTempDir is the owner-only folder for stripped copies ("" falls back
// to the source file's folder).
func sendTempDir(env *Env, stateDir string) string {
	base, err := resolveStateDir(env, stateDir)
	if err != nil {
		return ""
	}
	dir := filepath.Join(base, "send-queue")
	if os.MkdirAll(dir, 0o700) != nil {
		return ""
	}
	return dir
}
