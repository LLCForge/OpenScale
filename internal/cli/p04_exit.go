package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/openscale/openscale/internal/leaktest"
	"github.com/openscale/openscale/internal/node"
	"github.com/openscale/openscale/internal/osnet"
	"github.com/openscale/openscale/internal/trust"
)

// "openscale up" flags of P04 for an exit node: outbound port policy
// (#402), the owner's DoH server list (#403), the public source address
// (#408) and the monthly data quota (#401, ADR-0155). All of it is local
// to the exit node; nothing is signed or sent to members.

// exitQuotaFile is the quota state under the device state directory.
const exitQuotaFile = "exit-quota.json"

// leakLocale feeds the leak test's location line (#404); tests replace it.
var leakLocale = leaktest.LocalLocale

type upP04Flags struct {
	blockPorts  *string
	blockDoH    *string
	source      *string
	quotaMember *string
	quotaTotal  *string
	quotaWarn   *int
}

func addUpP04Flags(fs *flag.FlagSet) upP04Flags {
	return upP04Flags{
		blockPorts: fs.String("exit-block-ports", "25", "çıkış düğümü: üyelerin internete iletilmeyecek hedef portları (ör. 25,465,udp/1900; bütün izinler için none)"),
		blockDoH:   fs.String("exit-block-doh", "", "çıkış düğümü: 443'ü engellenecek DoH sunucularının listesi (satır başına adres veya CIDR)"),
		source: fs.String("exit-source", "", "çıkış düğümü: üyelerin çıkacağı yerel genel adres; üye başına cihaz=adres, virgülle "+
			"(ör. 203.0.113.5,laptop=203.0.113.6)"),
		quotaMember: fs.String("exit-quota-member", "", "çıkış düğümü: üye başına aylık veri kotası (ör. 100GB; Linux)"),
		quotaTotal:  fs.String("exit-quota-total", "", "çıkış düğümü: bütün üyeler için toplam aylık veri kotası (ör. 2TB; Linux)"),
		quotaWarn:   fs.Int("exit-quota-warn", node.DefaultExitQuotaWarn, "kota uyarı eşiği, yüzde"),
	}
}

// exitSourceSpec is one --exit-source entry before device names resolve.
type exitSourceSpec struct {
	member string // "" default, a device name or an overlay address
	source netip.Addr
}

type upP04Options struct {
	ports       []osnet.ExitPort
	doh         []netip.Prefix
	sources     []exitSourceSpec
	quotaMember uint64
	quotaTotal  uint64
	quotaWarn   int
}

func (f upP04Flags) resolve() (upP04Options, error) {
	var o upP04Options
	var err error
	if o.ports, err = osnet.ParseExitPorts(*f.blockPorts); err != nil {
		return o, usageError("--exit-block-ports: %v", err)
	}
	if path := strings.TrimSpace(*f.blockDoH); path != "" {
		file, err := os.Open(path)
		if err != nil {
			return o, usageError("--exit-block-doh: %v", err)
		}
		o.doh, err = osnet.ParseDoHList(file)
		_ = file.Close()
		if err != nil {
			return o, usageError("--exit-block-doh: %v", err)
		}
	}
	if o.sources, err = parseExitSources(*f.source, localAddrs); err != nil {
		return o, usageError("--exit-source: %v", err)
	}
	if o.quotaMember, err = parseQuotaSize(*f.quotaMember); err != nil {
		return o, usageError("--exit-quota-member: %v", err)
	}
	if o.quotaTotal, err = parseQuotaSize(*f.quotaTotal); err != nil {
		return o, usageError("--exit-quota-total: %v", err)
	}
	if *f.quotaWarn < 1 || *f.quotaWarn > 99 {
		return o, usageError("--exit-quota-warn 1-99 arası olmalı")
	}
	o.quotaWarn = *f.quotaWarn
	return o, nil
}

// localAddrs lists this host's addresses; tests replace it.
var localAddrs = func() ([]netip.Addr, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	var out []netip.Addr
	for _, a := range addrs {
		if p, err := netip.ParsePrefix(a.String()); err == nil {
			out = append(out, p.Addr().Unmap())
		}
	}
	return out, nil
}

// parseExitSources parses "203.0.113.5,laptop=203.0.113.6". Every source
// must be an address of this host: a NAT rule to a foreign address would
// send members' traffic nowhere.
func parseExitSources(s string, local func() ([]netip.Addr, error)) ([]exitSourceSpec, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	have, err := local()
	if err != nil {
		return nil, fmt.Errorf("yerel adresler okunamadı: %w", err)
	}
	var out []exitSourceSpec
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		member, addr, named := strings.Cut(f, "=")
		if !named {
			member, addr = "", f
		}
		member = strings.TrimSpace(member)
		if named && member == "" {
			return nil, fmt.Errorf("%q: cihaz adı boş", f)
		}
		a, err := netip.ParseAddr(strings.TrimSpace(addr))
		if err != nil || a.Zone() != "" {
			return nil, fmt.Errorf("%q geçerli bir adres değil", addr)
		}
		a = a.Unmap()
		if !slices.Contains(have, a) {
			return nil, fmt.Errorf("%s bu sunucunun adresi değil", a)
		}
		out = append(out, exitSourceSpec{member: member, source: a})
		if len(out) > osnet.MaxExitSources {
			return nil, fmt.Errorf("en fazla %d kayıt", osnet.MaxExitSources)
		}
	}
	return out, nil
}

// parseQuotaSize parses "100GB", "500MB", "2TB" or plain bytes (binary units).
func parseQuotaSize(s string) (uint64, error) {
	s = strings.ToUpper(strings.TrimSpace(s))
	if s == "" || s == "0" {
		return 0, nil
	}
	mul := uint64(1)
	for _, u := range []struct {
		suffix string
		mul    uint64
	}{{"TB", 1 << 40}, {"GB", 1 << 30}, {"MB", 1 << 20}, {"KB", 1 << 10}, {"T", 1 << 40}, {"G", 1 << 30}, {"M", 1 << 20}, {"K", 1 << 10}, {"B", 1}} {
		if strings.HasSuffix(s, u.suffix) {
			s, mul = strings.TrimSpace(strings.TrimSuffix(s, u.suffix)), u.mul
			break
		}
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || v <= 0 || v*float64(mul) > float64(1<<50) {
		return 0, errors.New("boyut 100GB, 2TB veya bayt olarak yazılmalı (en çok 1024TB)")
	}
	n := uint64(v * float64(mul))
	if n < 1<<20 {
		return 0, errors.New("kota en az 1MB olmalı")
	}
	return n, nil
}

func (o upP04Options) quota() bool { return o.quotaMember > 0 || o.quotaTotal > 0 }

// applyExitNAT adds the policy to the exit node rules. Device names in
// --exit-source are resolved against the current document; an unknown
// name is reported and skipped.
func (o upP04Options) applyExitNAT(env *Env, c *osnet.ExitNAT, doc *trust.Document) {
	c.BlockPorts, c.BlockDoH, c.Quota = o.ports, o.doh, o.quota()
	for _, s := range o.sources {
		if s.member == "" {
			c.Sources = append(c.Sources, osnet.ExitSource{Source: s.source})
			continue
		}
		member, ok := exitSourceMember(doc, s.member, s.source.Is4())
		if !ok {
			fmt.Fprintf(env.Stderr, "uyarı: --exit-source: %q ağda yok veya bu adres ailesinde adresi yok; atlandı\n", s.member)
			continue
		}
		c.Sources = append(c.Sources, osnet.ExitSource{Member: member, Source: s.source})
	}
}

func exitSourceMember(doc *trust.Document, name string, v4 bool) (netip.Addr, bool) {
	if a, err := netip.ParseAddr(name); err == nil {
		return a.Unmap(), a.Unmap().Is4() == v4
	}
	if doc == nil {
		return netip.Addr{}, false
	}
	d, ok := doc.DeviceByName(name)
	if !ok {
		return netip.Addr{}, false
	}
	a := d.IPv6
	if v4 {
		a = d.IPv4
	}
	return a, a.IsValid()
}

// start runs the quota counter while "openscale up" runs.
func (o upP04Options) start(ctx context.Context, env *Env, engine *node.Engine, dir string, logger *slog.Logger) func() {
	if !o.quota() {
		return func() {}
	}
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		err := engine.RunExitQuota(ctx, node.ExitQuotaConfig{
			MemberLimit: o.quotaMember, TotalLimit: o.quotaTotal, WarnPercent: o.quotaWarn,
			StatePath: filepath.Join(dir, exitQuotaFile), Block: osnet.SetExitQuotaBlocked,
			Logger: logger.With("part", "exit-quota"), Now: env.Now,
		})
		if err != nil {
			fmt.Fprintf(env.Stderr, "uyarı: çıkış kotası başlatılamadı: %v\n", err)
		}
	}()
	return func() {
		cancel()
		<-done
	}
}

func p04Commands() []command {
	return []command{
		{"exit-node quota", "Çıkış düğümünün bu ayki veri kullanımı: üye başına ve toplam, uyarı ve durdurma durumu", cmdExitQuota},
	}
}

func cmdExitQuota(env *Env, args []string) error {
	flags := newFlagSet(env, "exit-node quota")
	stateDir := flags.String("state-dir", "", "cihazın durum klasörü")
	asJSON := flags.Bool("json", false, "JSON çıktı")
	if err := parseFlags(flags, args); err != nil {
		return err
	}
	dir, err := resolveStateDir(env, *stateDir)
	if err != nil {
		return err
	}
	st, err := node.ReadExitQuotaState(filepath.Join(dir, exitQuotaFile))
	if errors.Is(err, fs.ErrNotExist) {
		return errors.New("çıkış kotası kullanılmıyor (openscale up --exit-quota-member veya --exit-quota-total)")
	}
	if err != nil {
		return err
	}
	if *asJSON {
		return printJSON(env.Stdout, st)
	}
	w := env.Stdout
	fmt.Fprintf(w, "Ay: %s (UTC)\n", st.Month)
	fmt.Fprintf(w, "Toplam: %s%s\n", humanBytes(st.Total), limitText(st.TotalLimit, st.TotalBlocked))
	names := make([]string, 0, len(st.Members))
	for n := range st.Members {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		u := st.Members[n]
		state := ""
		switch {
		case u.Blocked || st.TotalBlocked:
			state = "  [internet durduruldu]"
		case u.Warned:
			state = "  [uyarı eşiği aşıldı]"
		}
		fmt.Fprintf(w, "  %-24s %s%s%s\n", n, humanBytes(u.Bytes), limitText(st.MemberLimit, false), state)
	}
	fmt.Fprintln(w, "Sayaç tünel baytlarıdır (WireGuard yükü); ay başında sıfırlanır ve durdurmalar kalkar.")
	return nil
}

func limitText(limit uint64, blocked bool) string {
	if limit == 0 {
		return ""
	}
	s := " / " + humanBytes(limit)
	if blocked {
		s += "  [sınıra ulaşıldı: bütün üyelerin interneti durduruldu]"
	}
	return s
}
