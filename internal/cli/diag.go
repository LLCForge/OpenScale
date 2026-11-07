package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/openscale/openscale/internal/node"
	"github.com/openscale/openscale/internal/panel"
)

// Diagnostics commands (F-014, F-015, F-016, F-057, F-110, F-171, F-188,
// F-190, F-191, F-192, F-208). They talk to the running tunnel through its
// loopback API; --json prints the API's versioned document (schema 1).

// diagFlags are shared by the diagnostics commands.
type diagFlags struct {
	json     *bool
	stateDir *string
}

func addDiagFlags(fs *flag.FlagSet) diagFlags {
	return diagFlags{
		json:     fs.Bool("json", false, "makine okunur JSON çıktı (sürümlü şema, \"schema\": 1)"),
		stateDir: fs.String("state-dir", "", "ön planda 'openscale up' ile açılan tünelin durum klasörü"),
	}
}

func (f diagFlags) client(env *Env) (*localClient, error) {
	return openLocalClient(env, *f.stateDir)
}

// parseInterspersed parses flags that may come before or after the
// positional arguments ("ping laptop -c 3").
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil, err
			}
			return nil, usageError("%v", err)
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return pos, nil
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
}

func printJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// humanBytes formats a byte count with binary units.
func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for m := n / unit; m >= unit && exp < 4; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTP"[exp])
}

// ago describes how long ago t was.
func ago(t *time.Time, now time.Time) string {
	if t == nil || t.IsZero() {
		return "hiç"
	}
	d := now.Sub(*t)
	switch {
	case d < 0:
		return "şimdi"
	case d < time.Minute:
		return fmt.Sprintf("%d sn önce", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d dk önce", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d sa önce", int(d.Hours()))
	}
	return fmt.Sprintf("%d gün önce", int(d.Hours()/24))
}

func pathLabel(p string) string {
	switch p {
	case panel.PathDirect:
		return "doğrudan"
	case panel.PathRelay:
		return "aktarıcı"
	}
	return "yok"
}

func msLabel(ms *float64) string {
	if ms == nil {
		return "-"
	}
	return fmt.Sprintf("%.1f ms", *ms)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func cmdStatus(env *Env, args []string) error {
	fs := newFlagSet(env, "status")
	df := addDiagFlags(fs)
	onlyPeers := fs.Bool("peers", false, "yalnızca eşleri göster")
	onlySelf := fs.Bool("self", false, "yalnızca bu cihazı göster")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *onlyPeers && *onlySelf {
		return usageError("--peers ve --self birlikte kullanılamaz")
	}
	c, err := df.client(env)
	if err != nil {
		return err
	}
	var st panel.DiagStatus
	if err := c.get(env, "/status", &st); err != nil {
		return err
	}
	if *onlyPeers {
		st.Self = nil
	}
	if *onlySelf {
		st.Peers = []panel.DiagPeer{}
	}
	if *df.json {
		return printJSON(env.Stdout, st)
	}
	w := env.Stdout
	if !*onlyPeers {
		state := "tünel çalışmıyor"
		switch {
		case st.Running && st.LastSyncError != "":
			state = "bağlı, koordinatöre ulaşılamıyor"
		case st.Running:
			state = "bağlı"
		case st.Mode != "" && !st.Connected && st.Mode != panel.ModeSetup && st.Mode != panel.ModeJoining:
			state = "bağlantı kapalı"
		}
		if s := st.Self; s != nil {
			fmt.Fprintf(w, "Bu cihaz: %s  %s  %s  (%s, belge v%d)\n", s.FQDN, s.IPv4, s.IPv6, state, st.DocumentVersion)
		} else {
			fmt.Fprintf(w, "Bu cihaz: %s\n", state)
		}
		if st.Interface != "" {
			fmt.Fprintf(w, "Arayüz: %s\n", st.Interface)
		}
		fmt.Fprintf(w, "Çıkış düğümü: %s\n", orDash(st.ExitNode))
		if st.LastSync != nil {
			fmt.Fprintf(w, "Son eşitleme: %s\n", ago(st.LastSync, env.Now()))
		}
	}
	if !*onlySelf {
		fmt.Fprintf(w, "\nEşler (%d):\n", len(st.Peers))
		if len(st.Peers) > 0 {
			tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "  AD\tIPv4\tDURUM\tYOL\tUÇ NOKTA\tSON EL SIKIŞMA\tALINAN\tGÖNDERİLEN\tGECİKME")
			for _, p := range st.Peers {
				state := "çevrimdışı"
				if p.Online {
					state = "çevrimiçi"
				}
				name := p.Name
				if p.ActiveExit {
					name += " (çıkış)"
				}
				fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", name, p.IPv4, state, pathLabel(p.Path), orDash(p.Endpoint),
					ago(p.LastHandshake, env.Now()), humanBytes(p.RxBytes), humanBytes(p.TxBytes), msLabel(p.LatencyMS))
			}
			_ = tw.Flush()
		}
	}
	if !*onlyPeers && !*onlySelf && len(st.Health) > 0 {
		fmt.Fprintln(w, "\nUyarılar:")
		for _, a := range st.Health {
			fmt.Fprintf(w, "  [%s] %s\n", a.Level, a.Message)
		}
	}
	return nil
}

// Bounds of "openscale ping".
const (
	defaultPingCount     = 4
	defaultUntilDirect   = 10
	maxPingCount         = 1000
	minPingInterval      = 200 * time.Millisecond
	maxPingInterval      = time.Minute
	defaultPingInterval  = time.Second
	pingSummaryPrecision = 1
)

func cmdPing(env *Env, args []string) error {
	fs := newFlagSet(env, "ping")
	df := addDiagFlags(fs)
	count := fs.Int("c", 0, fmt.Sprintf("gönderilecek ping sayısı (varsayılan %d; --until-direct ile %d)", defaultPingCount, defaultUntilDirect))
	interval := fs.Duration("i", defaultPingInterval, "pingler arası süre")
	untilDirect := fs.Bool("until-direct", false, "doğrudan yol görülünce dur; kurulmazsa hata ver")
	fs.Usage = func() {
		fmt.Fprintln(env.Stderr, "Kullanım: openscale ping <cihaz> [-c N] [-i süre] [--until-direct] [--json]")
		fs.PrintDefaults()
	}
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usageError("bir cihaz adı veya adresi yazın: openscale ping <cihaz>")
	}
	n := *count
	if n == 0 {
		n = defaultPingCount
		if *untilDirect {
			n = defaultUntilDirect
		}
	}
	if n < 1 || n > maxPingCount {
		return usageError("-c 1 ile %d arasında olmalı", maxPingCount)
	}
	if *interval < minPingInterval || *interval > maxPingInterval {
		return usageError("-i %s ile %s arasında olmalı", minPingInterval, maxPingInterval)
	}
	c, err := df.client(env)
	if err != nil {
		return err
	}
	ctx := envContext(env)
	var rtts []float64
	sent, direct := 0, false
	for i := 0; i < n; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(*interval):
			}
		}
		var res panel.PingResult
		if err := c.post(env, "/ping", map[string]string{"peer": pos[0]}, &res); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		sent++
		if *df.json {
			// One JSON document per line (json-line) for streaming readers.
			data, _ := json.Marshal(res)
			fmt.Fprintln(env.Stdout, string(data))
		} else {
			where := pathLabel(res.Path)
			if res.Endpoint != "" {
				where += " " + res.Endpoint
			}
			if res.RTTMS != nil {
				fmt.Fprintf(env.Stdout, "%s (%s) yanıt: %.1f ms  yol: %s  [%s]\n", res.Peer, res.IPv4, *res.RTTMS, where, methodLabel(res.Method))
			} else {
				fmt.Fprintf(env.Stdout, "%s (%s) %s  yol: %s\n", res.Peer, res.IPv4, orDash(res.Error), where)
			}
		}
		if res.RTTMS != nil {
			rtts = append(rtts, *res.RTTMS)
		}
		if *untilDirect && res.Path == panel.PathDirect {
			direct = true
			break
		}
	}
	if !*df.json {
		printPingSummary(env.Stdout, sent, rtts)
	}
	if *untilDirect && !direct {
		return errors.New("doğrudan yol kurulamadı; trafik koordinatörün aktarıcısından geçiyor. 'openscale netcheck' NAT durumunu açıklar")
	}
	if *untilDirect && !*df.json {
		fmt.Fprintln(env.Stdout, "Doğrudan yol kuruldu.")
	}
	if len(rtts) == 0 {
		return errors.New("hiç yanıt alınamadı")
	}
	return nil
}

func methodLabel(m string) string {
	switch m {
	case panel.PingICMP:
		return "icmp"
	case panel.PingRelay:
		return "aktarıcı yoklaması"
	case panel.PingProbe:
		return "son yol yoklaması"
	}
	return m
}

func printPingSummary(w io.Writer, sent int, rtts []float64) {
	loss := 0.0
	if sent > 0 {
		loss = 100 * float64(sent-len(rtts)) / float64(sent)
	}
	fmt.Fprintf(w, "\n%d gönderildi, %d yanıt, %%%.0f kayıp", sent, len(rtts), loss)
	if len(rtts) > 0 {
		lo, hi, sum := math.Inf(1), math.Inf(-1), 0.0
		for _, r := range rtts {
			lo, hi, sum = math.Min(lo, r), math.Max(hi, r), sum+r
		}
		fmt.Fprintf(w, "; en az/ort/en çok = %.*f/%.*f/%.*f ms", pingSummaryPrecision, lo, pingSummaryPrecision, sum/float64(len(rtts)), pingSummaryPrecision, hi)
	}
	fmt.Fprintln(w)
}

type netCheckReply struct {
	Schema int `json:"schema"`
	node.NetReport
}

func cmdNetcheck(env *Env, args []string) error {
	fs := newFlagSet(env, "netcheck")
	df := addDiagFlags(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	c, err := df.client(env)
	if err != nil {
		return err
	}
	var rep netCheckReply
	if err := c.get(env, "/netcheck", &rep); err != nil {
		return err
	}
	if *df.json {
		return printJSON(env.Stdout, rep)
	}
	w := env.Stdout
	yes := func(b bool) string {
		if b {
			return "evet"
		}
		return "hayır"
	}
	fmt.Fprintln(w, "Ağ denetimi (yalnızca kendi koordinatörünüz ve eşleriniz kullanıldı):")
	if rep.CoordinatorReachable {
		fmt.Fprintf(w, "  Koordinatör UDP:     ulaşılıyor (%.1f ms, IPv6: %s)\n", panel.Millis(rep.CoordinatorRTT), yes(rep.CoordinatorOverIPv6))
	} else {
		fmt.Fprintf(w, "  Koordinatör UDP:     ulaşılamıyor (%s)\n", orDash(rep.CoordinatorError))
	}
	fmt.Fprintf(w, "  Dış adres:           %s\n", orDash(rep.MappedEndpoint))
	fmt.Fprintf(w, "  Yerel port:          %d (korunuyor: %s)\n", rep.LocalPort, yes(rep.PortPreserved))
	fmt.Fprintf(w, "  NAT türü:            %s\n", rep.NAT)
	fmt.Fprintf(w, "  Eşleme değişimi:     son bir saatte %d\n", rep.MappingChanges)
	fmt.Fprintf(w, "  IPv4 / IPv6:         %s / %s\n", yes(rep.HaveIPv4), yes(rep.HaveIPv6))
	fmt.Fprintf(w, "  Eşler:               %d doğrudan, %d aktarıcı, %d IPv6\n", rep.DirectPeers, rep.RelayedPeers, rep.IPv6Peers)
	if len(rep.CoordinatorFeatures) > 0 {
		fmt.Fprintf(w, "  Koordinatör özellikleri: %s\n", strings.Join(rep.CoordinatorFeatures, ", "))
	}
	if len(rep.LocalCandidates) > 0 {
		fmt.Fprintf(w, "  Bildirilen adresler: %s\n", strings.Join(rep.LocalCandidates, ", "))
	}
	for _, o := range rep.Observations {
		fmt.Fprintf(w, "  %s bu cihazı %s olarak görüyor\n", o.Peer, o.SeenAs)
	}
	if rep.CaptivePortal.Detected {
		fmt.Fprintf(w, "  Giriş sayfası:       algılandı (%s) %s\n", rep.CaptivePortal.Reason, rep.CaptivePortal.Location)
	}
	if len(rep.Notes) > 0 {
		fmt.Fprintln(w, "\nNotlar:")
		for _, n := range rep.Notes {
			fmt.Fprintf(w, "  - %s\n", n)
		}
	}
	return nil
}

func cmdDebugReconnect(env *Env, args []string) error {
	fs := newFlagSet(env, "debug reconnect")
	df := addDiagFlags(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	c, err := df.client(env)
	if err != nil {
		return err
	}
	var out map[string]any
	if err := c.post(env, "/reconnect", nil, &out); err != nil {
		return err
	}
	if *df.json {
		return printJSON(env.Stdout, out)
	}
	fmt.Fprintln(env.Stdout, "Yollar sıfırlandı: koordinatör yeniden çözülüyor, eşler yeniden yoklanıyor.")
	return nil
}

func cmdDebugRelayTest(env *Env, args []string) error {
	fs := newFlagSet(env, "debug relay-test")
	df := addDiagFlags(fs)
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usageError("bir cihaz adı yazın: openscale debug relay-test <cihaz>")
	}
	c, err := df.client(env)
	if err != nil {
		return err
	}
	var out struct {
		Schema int     `json:"schema"`
		Peer   string  `json:"peer"`
		RTTMS  float64 `json:"rtt_ms"`
	}
	if err := c.post(env, "/relay-test", map[string]string{"peer": pos[0]}, &out); err != nil {
		return err
	}
	if *df.json {
		return printJSON(env.Stdout, out)
	}
	fmt.Fprintf(env.Stdout, "Aktarıcı üzerinden %s: %.1f ms\n", out.Peer, out.RTTMS)
	return nil
}

func cmdDebugEndpoints(env *Env, args []string) error {
	fs := newFlagSet(env, "debug endpoints")
	df := addDiagFlags(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	c, err := df.client(env)
	if err != nil {
		return err
	}
	var out struct {
		Schema int             `json:"schema"`
		Peers  []node.PeerPath `json:"peers"`
	}
	if err := c.get(env, "/paths", &out); err != nil {
		return err
	}
	if *df.json {
		return printJSON(env.Stdout, out)
	}
	w := env.Stdout
	if len(out.Peers) == 0 {
		fmt.Fprintln(w, "Tünel kurulu eş yok.")
		return nil
	}
	now := env.Now()
	for _, p := range out.Peers {
		hs := p.LastHandshake
		fmt.Fprintf(w, "%s  uç nokta: %s  sınıf: %s  son el sıkışma: %s  PQ: %s\n", p.Name, orDash(p.Endpoint), p.Class, ago(&hs, now), orDash(p.PostQuantum))
		if p.Observed != "" {
			fmt.Fprintf(w, "  koordinatörün gördüğü: %s\n", p.Observed)
		}
		if len(p.Candidates) > 0 {
			fmt.Fprintf(w, "  adaylar: %s\n", strings.Join(p.Candidates, ", "))
		}
		if p.BestProbed != "" {
			fmt.Fprintf(w, "  en iyi yoklama: %s (%.1f ms)\n", p.BestProbed, panel.Millis(p.ProbeRTT))
		}
		for _, h := range p.History {
			fmt.Fprintf(w, "  %s  -> %s\n", h.At.Local().Format("02.01 15:04:05"), h.Endpoint)
		}
	}
	return nil
}

func cmdDNSStatus(env *Env, args []string) error {
	fs := newFlagSet(env, "dns status")
	df := addDiagFlags(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	c, err := df.client(env)
	if err != nil {
		return err
	}
	var st panel.DNSStatus
	if err := c.get(env, "/dns", &st); err != nil {
		return err
	}
	if *df.json {
		return printJSON(env.Stdout, st)
	}
	w := env.Stdout
	fmt.Fprintf(w, "MagicDNS: *.%s -> %s\n", st.Domain, st.Resolver)
	if st.MagicDNSError != "" {
		fmt.Fprintf(w, "  sorun: %s\n", st.MagicDNSError)
	}
	if st.MagicDNSAllDevices {
		fmt.Fprintln(w, "  bütün cihaz adları yanıtlanıyor")
	} else {
		fmt.Fprintln(w, "  yalnızca tünel kurulan cihazların adları yanıtlanıyor")
	}
	accepted := "uygulanıyor"
	if !st.NetworkDNSAccepted {
		accepted = "bu cihazda kapalı"
	}
	fmt.Fprintf(w, "Ağ DNS ayarları: %s (etkin: %t)\n", accepted, st.NetworkDNSActive)
	if st.NetworkDNSError != "" {
		fmt.Fprintf(w, "  sorun: %s\n", st.NetworkDNSError)
	}
	if len(st.Nameservers) > 0 {
		fmt.Fprintf(w, "  genel çözücüler: %s\n", strings.Join(st.Nameservers, ", "))
	}
	for _, s := range st.Split {
		fmt.Fprintf(w, "  %s -> %s\n", s.Domain, strings.Join(s.Nameservers, ", "))
	}
	return nil
}

func cmdDNSQuery(env *Env, args []string) error {
	fs := newFlagSet(env, "dns query")
	df := addDiagFlags(fs)
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usageError("sorgulanacak adı yazın: openscale dns query <ad>")
	}
	c, err := df.client(env)
	if err != nil {
		return err
	}
	var res panel.DNSQueryResult
	if err := c.post(env, "/dns/query", map[string]string{"name": pos[0]}, &res); err != nil {
		return err
	}
	if *df.json {
		return printJSON(env.Stdout, res)
	}
	if res.Error != "" {
		return fmt.Errorf("%s (%s, MagicDNS %s): %s", res.Name, fmt.Sprintf("%.1f ms", res.RTTMS), res.Resolver, res.Error)
	}
	fmt.Fprintf(env.Stdout, "%s -> %s  (MagicDNS %s, %.1f ms)\n", res.Name, strings.Join(res.Addrs, ", "), res.Resolver, res.RTTMS)
	return nil
}

func printWhois(w io.Writer, res panel.WhoisResult) {
	if res.Coordinator {
		fmt.Fprintf(w, "%s ağın koordinatörüdür.\n", res.Query)
		return
	}
	d := res.Device
	if d == nil {
		return
	}
	fmt.Fprintf(w, "Ad:         %s", d.FQDN)
	if d.Self {
		fmt.Fprint(w, "  (bu cihaz)")
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Adresler:   %s  %s\n", d.IPv4, d.IPv6)
	if len(d.Roles) > 0 {
		fmt.Fprintf(w, "Roller:     %s\n", strings.Join(d.Roles, ", "))
	}
	if len(d.Tags) > 0 {
		fmt.Fprintf(w, "Etiketler:  %s\n", strings.Join(d.Tags, ", "))
	}
	if len(d.Groups) > 0 {
		fmt.Fprintf(w, "Gruplar:    %s\n", strings.Join(d.Groups, ", "))
	}
	fmt.Fprintf(w, "Eklendi:    %s\n", d.AddedAt.Local().Format("02.01.2006"))
	if d.ExpiresAt != nil {
		fmt.Fprintf(w, "Üyelik sonu: %s\n", d.ExpiresAt.Local().Format("02.01.2006"))
	}
	fmt.Fprintf(w, "Anahtar izi: %s\n", d.Fingerprint)
	if !d.Self && d.Path != "" {
		state := "çevrimdışı"
		if d.Online {
			state = "çevrimiçi"
		}
		fmt.Fprintf(w, "Bağlantı:   %s, %s\n", state, pathLabel(d.Path))
	}
}

func cmdWhois(env *Env, args []string) error {
	fs := newFlagSet(env, "whois")
	df := addDiagFlags(fs)
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usageError("bir IP adresi veya cihaz adı yazın: openscale whois <ip|ad>")
	}
	return whois(env, df, pos[0])
}

func cmdWhoami(env *Env, args []string) error {
	fs := newFlagSet(env, "whoami")
	df := addDiagFlags(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	return whois(env, df, "")
}

func whois(env *Env, df diagFlags, q string) error {
	c, err := df.client(env)
	if err != nil {
		return err
	}
	var res panel.WhoisResult
	if err := c.get(env, "/whois?q="+queryEscape(q), &res); err != nil {
		return err
	}
	if *df.json {
		return printJSON(env.Stdout, res)
	}
	printWhois(env.Stdout, res)
	return nil
}

func cmdWGShow(env *Env, args []string) error {
	fs := newFlagSet(env, "wg show")
	df := addDiagFlags(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	c, err := df.client(env)
	if err != nil {
		return err
	}
	var st panel.WGShow
	if err := c.get(env, "/wg", &st); err != nil {
		return err
	}
	if *df.json {
		return printJSON(env.Stdout, st)
	}
	w := env.Stdout
	fmt.Fprintf(w, "interface: %s\n  public key: %s\n", orDash(st.Interface), st.PublicKey)
	now := env.Now()
	for _, p := range st.Peers {
		fmt.Fprintf(w, "\npeer: %s  (%s)\n", p.PublicKey, p.Name)
		ep := p.Endpoint
		if p.Relayed {
			ep = "koordinatör aktarıcısı"
		}
		fmt.Fprintf(w, "  endpoint: %s\n", orDash(ep))
		fmt.Fprintf(w, "  allowed ips: %s\n", strings.Join(p.AllowedIPs, ", "))
		fmt.Fprintf(w, "  latest handshake: %s\n", ago(p.LastHandshake, now))
		fmt.Fprintf(w, "  transfer: %s alındı, %s gönderildi\n", humanBytes(p.RxBytes), humanBytes(p.TxBytes))
		if p.PostQuantum != "" {
			fmt.Fprintf(w, "  pre-shared key: %s (değeri gösterilmez)\n", p.PostQuantum)
		}
	}
	return nil
}

func cmdHealth(env *Env, args []string) error {
	fs := newFlagSet(env, "health")
	df := addDiagFlags(fs)
	liveOnly := fs.Bool("live", false, "yalnızca servisin yanıt verdiğini denetle (hazır olmayı bekleme)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	c, err := df.client(env)
	if err != nil {
		if *df.json {
			_ = printJSON(env.Stdout, panel.HealthReport{Schema: panel.DiagSchema, Reasons: []string{err.Error()}, Alerts: []panel.HealthAlert{}})
		}
		return err
	}
	var h panel.HealthReport
	if err := c.get(env, "/health", &h); err != nil {
		return err
	}
	if *df.json {
		if err := printJSON(env.Stdout, h); err != nil {
			return err
		}
	} else {
		fmt.Fprintf(env.Stdout, "canlı: %t\nhazır: %t\n", h.Live, h.Ready)
		for _, r := range h.Reasons {
			fmt.Fprintf(env.Stdout, "  - %s\n", r)
		}
		for _, a := range h.Alerts {
			fmt.Fprintf(env.Stdout, "  [%s] %s\n", a.Level, a.Message)
		}
	}
	if !*liveOnly && !h.Ready {
		return errors.New("tünel hazır değil")
	}
	return nil
}

func cmdLogLevel(env *Env, args []string) error {
	fs := newFlagSet(env, "log level")
	df := addDiagFlags(fs)
	fs.Usage = func() {
		fmt.Fprintln(env.Stderr, "Kullanım: openscale log level [debug|info|warn|error] [--json]")
		fs.PrintDefaults()
	}
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 1 {
		return usageError("en fazla bir seviye yazın")
	}
	level := ""
	if len(pos) == 1 {
		level = strings.ToLower(pos[0])
		if !slices.Contains([]string{"debug", "info", "warn", "warning", "error"}, level) {
			return usageError("seviye debug, info, warn veya error olmalı")
		}
	}
	c, err := df.client(env)
	if err != nil {
		return err
	}
	var out struct {
		Schema int    `json:"schema"`
		Level  string `json:"level"`
	}
	if level != "" {
		err = c.post(env, "/log-level", map[string]string{"level": level}, &out)
	} else {
		err = c.get(env, "/log-level", &out)
	}
	if err != nil {
		return err
	}
	if *df.json {
		return printJSON(env.Stdout, out)
	}
	if len(pos) == 1 {
		fmt.Fprintf(env.Stdout, "Günlük seviyesi: %s (hemen uygulandı", out.Level)
		if c.service {
			fmt.Fprint(env.Stdout, "; yeniden başlatmada korunur")
		}
		fmt.Fprintln(env.Stdout, ")")
		if out.Level == "debug" {
			fmt.Fprintln(env.Stdout, "Not: debug günlüğü uç nokta adreslerini içerir; işiniz bitince 'openscale log level info'.")
		}
		return nil
	}
	fmt.Fprintf(env.Stdout, "Günlük seviyesi: %s\n", out.Level)
	return nil
}

type prefsReply struct {
	Schema int          `json:"schema"`
	Prefs  []panel.Pref `json:"prefs"`
}

func printPrefs(w io.Writer, prefs []panel.Pref, only string) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, p := range prefs {
		if only != "" && p.Key != only {
			continue
		}
		marker := " "
		if p.Value != p.Default {
			marker = "*"
		}
		fmt.Fprintf(tw, "%s %s\t%s\t%s\n", marker, p.Key, orDash(p.Value), p.Description)
	}
	_ = tw.Flush()
}

func cmdGet(env *Env, args []string) error {
	fs := newFlagSet(env, "get")
	df := addDiagFlags(fs)
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 1 {
		return usageError("en fazla bir ayar adı yazın")
	}
	c, err := df.client(env)
	if err != nil {
		return err
	}
	var out prefsReply
	if err := c.get(env, "/prefs", &out); err != nil {
		return err
	}
	only := ""
	if len(pos) == 1 {
		only = pos[0]
		found := false
		for _, p := range out.Prefs {
			found = found || p.Key == only
		}
		if !found {
			return usageError("bilinmeyen ayar %q", only)
		}
		var kept []panel.Pref
		for _, p := range out.Prefs {
			if p.Key == only {
				kept = append(kept, p)
			}
		}
		out.Prefs = kept
	}
	if *df.json {
		return printJSON(env.Stdout, out)
	}
	printPrefs(env.Stdout, out.Prefs, only)
	if only == "" {
		fmt.Fprintln(env.Stdout, "\n* varsayılandan farklı. Değiştirmek için: openscale set <ayar>=<değer> ...")
	}
	return nil
}

func cmdSet(env *Env, args []string) error {
	fs := newFlagSet(env, "set")
	df := addDiagFlags(fs)
	fs.Usage = func() {
		fmt.Fprintln(env.Stderr, "Kullanım: openscale set <ayar>=<değer> [<ayar>=<değer> ...]  (ayarlar: openscale get)")
		fs.PrintDefaults()
	}
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) == 0 {
		return usageError("en az bir <ayar>=<değer> yazın; ayarların listesi: openscale get")
	}
	change := map[string]string{}
	for _, kv := range pos {
		k, v, ok := strings.Cut(kv, "=")
		k = strings.TrimSpace(k)
		if !ok || k == "" {
			return usageError("%q <ayar>=<değer> biçiminde değil", kv)
		}
		if _, dup := change[k]; dup {
			return usageError("%s birden çok kez yazıldı", k)
		}
		change[k] = v
	}
	c, err := df.client(env)
	if err != nil {
		return err
	}
	var out prefsReply
	if err := c.post(env, "/prefs", map[string]any{"set": change}, &out); err != nil {
		return err
	}
	if *df.json {
		return printJSON(env.Stdout, out)
	}
	for _, p := range out.Prefs {
		if _, ok := change[p.Key]; ok {
			fmt.Fprintf(env.Stdout, "%s = %s\n", p.Key, orDash(p.Value))
		}
	}
	fmt.Fprintln(env.Stdout, "Kaydedildi; servis yeniden başlatıldığında da geçerli.")
	return nil
}

func cmdDown(env *Env, args []string) error {
	fs := newFlagSet(env, "down")
	df := addDiagFlags(fs)
	forFlag := fs.String("for", "", "bağlantıyı süreli kes: 5m, 1h veya morning (sabah 08:00); boş: açılana kadar")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	switch *forFlag {
	case "", panel.Disconnect5Min, panel.Disconnect1Hour, panel.DisconnectMorning:
	default:
		return usageError("--for 5m, 1h veya morning olmalı")
	}
	c, err := df.client(env)
	if err != nil {
		return err
	}
	if !c.service {
		return errors.New("bu tünel ön planda 'openscale up' ile çalışıyor; kapatmak için o pencerede Ctrl+C'ye basın")
	}
	var st panel.AppStatus
	if *forFlag == "" {
		err = c.call(envContext(env), "POST", "/api/app/tray/connect", map[string]bool{"connected": false}, &st)
	} else {
		err = c.call(envContext(env), "POST", "/api/app/tray/disconnect", map[string]string{"for": *forFlag}, &st)
	}
	if err != nil {
		return err
	}
	if *df.json {
		return printJSON(env.Stdout, map[string]any{"schema": panel.DiagSchema, "connected": false, "for": *forFlag})
	}
	if *forFlag == "" {
		fmt.Fprintln(env.Stdout, "Bağlantı kapatıldı. Yeniden açmak için: openscale up")
	} else {
		fmt.Fprintln(env.Stdout, "Bağlantı süreli olarak kapatıldı; süre dolunca kendiliğinden açılır. Hemen açmak için: openscale up")
	}
	return nil
}

// upViaService turns the service's tunnel on when "openscale up" is run
// without arguments while the desktop service runs: a second, foreground
// tunnel would fight it for the interface. done is false when no service
// answers.
func upViaService(env *Env) (bool, error) {
	if localAPI.dataDir() == "" {
		return false, nil
	}
	token, err := localAPI.readToken(localAPI.dataDir())
	if err != nil {
		return false, nil
	}
	c := &localClient{base: localAPI.serviceBase, token: token, service: true, http: newHTTPClient()}
	if !c.reachable(envContext(env)) {
		return false, nil
	}
	var st panel.AppStatus
	if err := c.call(envContext(env), "POST", "/api/app/tray/connect", map[string]bool{"connected": true}, &st); err != nil {
		return true, err
	}
	fmt.Fprintln(env.Stdout, "OpenScale servisi çalışıyor: tünel servis üzerinden açıldı. Durum için: openscale status")
	fmt.Fprintln(env.Stdout, "(Servisten bağımsız ön plan tüneli için seçeneklerle çalıştırın, ör. openscale up --state-dir <klasör>.)")
	return true, nil
}
