package cli

// #717 DNS enforcement on "openscale up" (ADR-0224): the foreground tunnel
// and the Linux and macOS service units, which run "up --config". The
// desktop service follows its own settings (internal/service/dnsenforce.go);
// here the owner's switch is the --dns-enforce flag, also settable with
// OPENSCALE_DNS_ENFORCE or the "dns-enforce" key of the configuration file.
//
// The conditions are those of the ADR: the switch, the tunnel interface up,
// an exit node in use. The rules leave before the run ends, and a table a
// crashed run left in the kernel is removed at the start of every run,
// with or without the switch.

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/dnsguard"
	"github.com/openscale/openscale/internal/node"
	"github.com/openscale/openscale/internal/osnet"
	"github.com/openscale/openscale/internal/service"
	"github.com/openscale/openscale/internal/trust"
)

func init() {
	upEnvFlags = append(upEnvFlags, "dns-enforce", "dns-enforce-doh-list")
}

// upDNSEnforceEvery is how often the run compares the wanted state with the
// installed one.
const upDNSEnforceEvery = 5 * time.Second

// newUpDNSApplier returns the system's rule applier; tests replace it.
var newUpDNSApplier = osnet.NewDNSEnforcer

// dohListFlag checks the owner's DoH file while the flags are read, so a bad
// file is refused before "up" changes anything on the system.
type dohListFlag struct{ path string }

func (l *dohListFlag) String() string {
	if l == nil {
		return ""
	}
	return l.path
}

func (l *dohListFlag) Set(v string) error {
	p := strings.TrimSpace(v)
	if p != "" {
		if _, err := loadUpDoHList(p); err != nil {
			return err
		}
	}
	l.path = p
	return nil
}

type upDNSEnforceFlags struct {
	on   *bool
	list *dohListFlag
}

func addUpDNSEnforceFlags(fs *flag.FlagSet) upDNSEnforceFlags {
	list := &dohListFlag{}
	fs.Var(list, "dns-enforce-doh-list", "engellenecek DoH uç noktaları dosyası: satır başına adres, aralık veya ad (boş: yalnızca 53 ve 853); --dns-enforce ile")
	return upDNSEnforceFlags{
		on:   fs.Bool("dns-enforce", false, "çıkış düğümü kullanılırken DNS yalnızca tünelden: tünel dışı DNS (53) ve DoT/DoQ (853) işletim sisteminde engellenir (Linux: nft, macOS: pf ve açık kill switch; ADR-0224)"),
		list: list,
	}
}

// loadUpDoHList reads and checks the owner's DoH file.
func loadUpDoHList(p string) (dnsguard.DoHList, error) {
	if err := service.ValidLocalFile("DoH listesi", p); err != nil {
		return dnsguard.DoHList{}, err
	}
	f, err := os.Open(p) //nolint:gosec // the owner's own file, checked above
	if err != nil {
		return dnsguard.DoHList{}, fmt.Errorf("DoH listesi açılamadı: %w", err)
	}
	defer func() { _ = f.Close() }()
	l, err := dnsguard.ParseDoHList(io.LimitReader(f, dnsguard.MaxDoHFileSize+1))
	if err != nil {
		return dnsguard.DoHList{}, fmt.Errorf("DoH listesi: %w", err)
	}
	return l, nil
}

// upInterfaceUp reports whether the named interface exists and is up.
func upInterfaceUp(name string) bool {
	ifi, err := net.InterfaceByName(name)
	return err == nil && ifi.Flags&net.FlagUp != 0
}

// start follows the tunnel run of engine. dnsOK says the system's DNS points
// at the tunnel: without it, blocking DNS outside the tunnel would only cut
// the computer off name resolution. The returned function stops the loop
// and waits until the rules are removed.
func (f upDNSEnforceFlags) start(ctx context.Context, env *Env, engine *node.Engine, iface string, dnsOK bool) func() {
	exitOf := func() (string, *trust.Document) { return engine.ExitNode(), engine.Document() }
	return f.startWith(ctx, env, newUpDNSApplier(), iface, dnsOK, upInterfaceUp, exitOf)
}

func (f upDNSEnforceFlags) startWith(ctx context.Context, env *Env, applier dnsguard.Applier, iface string, dnsOK bool, up func(string) bool, exitOf func() (string, *trust.Document)) func() {
	u := &upDNSEnforcer{
		applier:  applier,
		enf:      &dnsguard.Enforcer{Applier: applier},
		iface:    iface,
		dohPath:  f.list.path,
		tunnelUp: up,
		exitOf:   exitOf,
		stdout:   env.Stdout,
		stderr:   env.Stderr,
	}
	// A crashed earlier run may have left its rules (nftables tables live
	// in the kernel), also when the switch is off now.
	if err := applier.Remove(); err != nil {
		fmt.Fprintf(env.Stderr, "uyarı: eski DNS zorlama kuralları kaldırılamadı: %v\n", err)
	}
	if !*f.on {
		if f.list.path != "" {
			fmt.Fprintln(env.Stderr, "uyarı: --dns-enforce-doh-list yalnızca --dns-enforce ile etkilidir")
		}
		return func() {}
	}
	if !dnsOK {
		fmt.Fprintln(env.Stderr, "uyarı: DNS zorlama uygulanmıyor: MagicDNS ayarlanamadı, adlar tünele gitmiyor")
		return func() {}
	}
	lctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		u.run(lctx, upDNSEnforceEvery)
	}()
	return func() {
		cancel()
		<-done
	}
}

// upDNSEnforcer is one run's enforcement; only its goroutine uses it.
type upDNSEnforcer struct {
	applier  dnsguard.Applier
	enf      *dnsguard.Enforcer
	iface    string
	dohPath  string
	tunnelUp func(string) bool
	exitOf   func() (string, *trust.Document)
	stdout   io.Writer
	stderr   io.Writer

	active     bool
	lastReason string
	lastErr    string
	dohKey     string
	doh        dnsguard.DoHList
}

func (u *upDNSEnforcer) run(ctx context.Context, every time.Duration) {
	// Remove also after a failed Apply: pfctl may have loaded rules that pf
	// does not evaluate yet (ErrDNSEnforceInactive), and Enforcer does not
	// count them as installed.
	defer func() {
		if err := u.applier.Remove(); err != nil {
			fmt.Fprintf(u.stderr, "uyarı: DNS zorlama kuralları kaldırılamadı: %v\n", err)
		}
	}()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		u.tick()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// want decides whether the rules should hold now and with which
// configuration; reason explains an inactive state to the owner.
func (u *upDNSEnforcer) want() (bool, dnsguard.EnforceConfig, string, error) {
	// A local resolver on loopback stays reachable: on Linux the system's
	// resolver is usually the systemd-resolved stub on 127.0.0.53, which
	// itself asks the resolvers in the tunnel. Whatever such a resolver
	// sends outside the tunnel is still dropped by the next rules.
	cfg := dnsguard.EnforceConfig{Tunnel: u.iface, AllowLoopback: true}
	if !u.tunnelUp(u.iface) {
		return false, cfg, "Tünel arayüzü ayakta değil.", nil
	}
	exit, doc := u.exitOf()
	if exit == "" || doc == nil {
		return false, cfg, "Çıkış düğümü kullanılmıyor; DNS zorlama yalnızca çıkış düğümüyle çalışır.", nil
	}
	dev, ok := doc.DeviceByName(exit)
	if !ok || !dev.IPv4.IsValid() {
		return false, cfg, "Çıkış düğümünün tünel içi çözücüsü bilinmiyor.", nil
	}
	for _, a := range []netip.Addr{dev.IPv4, dev.IPv6, doc.DNSResolverIPv4(), doc.DNSResolverIPv6()} {
		if a.IsValid() {
			cfg.Resolvers = append(cfg.Resolvers, a)
		}
	}
	if u.dohPath != "" {
		l, err := u.cachedDoHList()
		if err != nil {
			// Fail closed on the file only: 53 and 853 still hold.
			return true, cfg, "", err
		}
		cfg.DoH = l
	}
	return true, cfg, "", nil
}

// cachedDoHList rereads the file only when it changed.
func (u *upDNSEnforcer) cachedDoHList() (dnsguard.DoHList, error) {
	fi, err := os.Stat(u.dohPath)
	if err != nil {
		return dnsguard.DoHList{}, fmt.Errorf("DoH listesi okunamadı: %w", err)
	}
	key := fmt.Sprintf("%d|%d", fi.Size(), fi.ModTime().UnixNano())
	if u.dohKey == key {
		return u.doh, nil
	}
	l, err := loadUpDoHList(u.dohPath)
	if err != nil {
		return dnsguard.DoHList{}, err
	}
	u.dohKey, u.doh = key, l
	return l, nil
}

func (u *upDNSEnforcer) tick() {
	want, cfg, reason, werr := u.want()
	err := u.enf.Sync(want, want, cfg)
	u.report(u.enf.Installed(), reason, errors.Join(err, werr))
}

// report writes state changes only: the loop runs every few seconds.
func (u *upDNSEnforcer) report(active bool, reason string, err error) {
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	if msg != u.lastErr && msg != "" {
		fmt.Fprintf(u.stderr, "uyarı: DNS zorlama: %s\n", msg)
	}
	switch {
	case active && !u.active:
		fmt.Fprintln(u.stdout, "DNS zorlama açık: tünel dışı DNS işletim sisteminde engelleniyor.")
	case !active && u.active:
		fmt.Fprintf(u.stdout, "DNS zorlama kaldırıldı: %s\n", reason)
	case !active && reason != "" && reason != u.lastReason:
		fmt.Fprintf(u.stdout, "DNS zorlama bekliyor: %s\n", reason)
	}
	u.active, u.lastReason, u.lastErr = active, reason, msg
}
