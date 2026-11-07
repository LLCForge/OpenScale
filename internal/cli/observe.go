package cli

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/audit"
	"github.com/openscale/openscale/internal/panel"
)

// Observability commands (ADR-0105): refused connections (F-199), local
// metrics (F-198), the event stream (F-182), the audit log (#187, #188),
// the diagnostics bundle (F-194), packet capture (F-197), profiling
// (F-201) and the desktop notification switch (F-158). Files are written
// only on this computer and only where the owner says.

func observeCommands() []command {
	return []command{
		{"denied", "Reddedilen bağlantıları ve neden açılmadıklarını gösterir (--peer, --clear)", cmdDenied},
		{"metrics", "Yerel Prometheus metrikleri: print | on | off | status (varsayılan kapalı, yalnızca loopback)", cmdMetrics},
		{"events", "Olay akışını gösterir; --follow ile yeni olayları bekler", cmdEvents},
		{"audit list", "Güvenlik olayları denetim kaydını gösterir (-n)", cmdAuditList},
		{"audit verify", "Denetim kaydının hash zincirini doğrular; çıkış kodu 0 sağlam, 1 bozuk", cmdAuditVerify},
		{"debug bundle", "Teşhis paketi (zip) hazırlar; içeriği gösterir, onay olmadan dosya yazmaz", cmdDebugBundle},
		{"debug capture", "Tünel içi paketleri yerel bir pcap dosyasına yakalar (süre ve boyut sınırlı)", cmdDebugCapture},
		{"debug pprof", "Profillemeyi açar veya kapatır: on | off | status (bir saat sonra kendiliğinden kapanır)", cmdDebugPprof},
		{"debug profile", "Profil alır: cpu | heap | allocs | goroutine | block | mutex | threadcreate", cmdDebugProfile},
		{"notify", "Masaüstü bildirimleri: on | off | status", cmdNotify},
	}
}

// Limits of the observability replies.
const (
	maxBundleReply = 16 << 20
	maxMetricsText = 4 << 20
)

// rawClient is the local client without the per-call timeout, for long
// running answers (capture, profile, event stream).
func (c *localClient) rawClient() *http.Client {
	return &http.Client{Transport: c.http.Transport, CheckRedirect: c.http.CheckRedirect}
}

// do sends one request and returns the response; non-200 answers become
// errors.
func (c *localClient) do(ctx context.Context, method, path string, body any) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+panel.LocalAPIPrefix+path, reader)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.rawClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("tünelin yerel API'sine ulaşılamadı: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		reply, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(reply, &e) == nil && e.Error != "" {
			return nil, &apiError{status: resp.StatusCode, msg: e.Error}
		}
		return nil, &apiError{status: resp.StatusCode, msg: "yerel API yanıtı: " + resp.Status}
	}
	return resp, nil
}

// getLarge is get with a larger reply limit.
func (c *localClient) getLarge(env *Env, path string, limit int64, out any) error {
	ctx, cancel := context.WithTimeout(envContext(env), 2*time.Minute)
	defer cancel()
	resp, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return err
	}
	if int64(len(data)) > limit {
		return errors.New("yanıt çok büyük")
	}
	return json.Unmarshal(data, out)
}

var denyReasonLabels = map[string]string{
	panel.DenyNoRule:       "kural yok",
	panel.DenyDenyRule:     "reddet kuralı",
	panel.DenyDisabledRule: "devre dışı kural",
	panel.DenyShields:      "kalkan",
	panel.DenyUnknownPeer:  "bilinmeyen kaynak",
	panel.DenyNotForDevice: "yanlış adres",
	panel.DenyExitUsers:    "çıkış izni yok",
	panel.DenyUntracked:    "izlenmeyen yanıt",
	panel.DenyFlowLimit:    "tablo dolu",
	panel.DenyNoDocument:   "belge yok",
}

// DenyReasonLabel is the short Turkish label of a refusal reason.
func DenyReasonLabel(r string) string {
	if l, ok := denyReasonLabels[r]; ok {
		return l
	}
	return r
}

func cmdDenied(env *Env, args []string) error {
	fs := newFlagSet(env, "denied")
	df := addDiagFlags(fs)
	peer := fs.String("peer", "", "yalnızca bu cihazla ilgili kayıtlar")
	clear := fs.Bool("clear", false, "listeyi temizle (toplamlar kalır)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	c, err := df.client(env)
	if err != nil {
		return err
	}
	if *clear {
		if err := c.post(env, "/denied/clear", nil, nil); err != nil {
			return err
		}
		fmt.Fprintln(env.Stdout, "Reddedilen bağlantı listesi temizlendi.")
		return nil
	}
	var rep panel.DeniedReply
	if err := c.get(env, "/denied", &rep); err != nil {
		return err
	}
	if *peer != "" {
		kept := rep.Entries[:0]
		for _, e := range rep.Entries {
			if strings.EqualFold(e.Peer, *peer) {
				kept = append(kept, e)
			}
		}
		rep.Entries = kept
	}
	if *df.json {
		return printJSON(env.Stdout, rep)
	}
	writeDenied(env.Stdout, rep, env.Now())
	return nil
}

func writeDenied(w io.Writer, rep panel.DeniedReply, now time.Time) {
	if len(rep.Entries) == 0 {
		fmt.Fprintln(w, "Reddedilen bağlantı yok. (Liste yalnızca bellekte tutulur; servis yeniden başlayınca boşalır.)")
	}
	for _, e := range rep.Entries {
		who := e.Peer
		if who == "" {
			who = orDash(e.Remote)
		}
		arrow := who + " → bu cihaz"
		if e.Direction == "out" {
			arrow = "bu cihaz → " + who
		}
		target := e.Proto
		if e.Port > 0 {
			target += "/" + strconv.Itoa(e.Port)
		}
		last := e.Last
		fmt.Fprintf(w, "%-34s %-10s %6d kez  son: %s  [%s]\n", arrow, target, e.Count, ago(&last, now), DenyReasonLabel(e.Reason))
		fmt.Fprintf(w, "    neden: %s\n", e.Why)
	}
	if len(rep.Totals) > 0 {
		keys := make([]string, 0, len(rep.Totals))
		for k := range rep.Totals {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%s=%d", k, rep.Totals[k]))
		}
		fmt.Fprintf(w, "\nToplam reddedilen paket: %s\n", strings.Join(parts, ", "))
	}
}

// switchArg reads "on", "off" or "status".
func switchArg(fs interface{ Args() []string }, extra ...string) (string, error) {
	pos := fs.Args()
	if len(pos) != 1 {
		return "", usageError("bir alt komut gerekli: %s", strings.Join(append([]string{"on", "off", "status"}, extra...), " | "))
	}
	switch pos[0] {
	case "on", "off", "status":
		return pos[0], nil
	}
	for _, x := range extra {
		if pos[0] == x {
			return x, nil
		}
	}
	return "", usageError("bilinmeyen alt komut %q", pos[0])
}

func setObserve(env *Env, c *localClient, change panel.ObservePrefsChange) (panel.ObservePrefs, error) {
	var p panel.ObservePrefs
	err := c.post(env, "/observe", change, &p)
	return p, err
}

func onOff(b bool) string {
	if b {
		return "açık"
	}
	return "kapalı"
}

func cmdMetrics(env *Env, args []string) error {
	fs := newFlagSet(env, "metrics")
	df := addDiagFlags(fs)
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	fs2 := argList(pos)
	sub, err := switchArg(fs2, "print")
	if err != nil {
		return err
	}
	c, err := df.client(env)
	if err != nil {
		return err
	}
	switch sub {
	case "print":
		ctx, cancel := context.WithTimeout(envContext(env), localCallTimeout)
		defer cancel()
		resp, err := c.do(ctx, http.MethodGet, "/metrics", nil)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		_, err = io.Copy(env.Stdout, io.LimitReader(resp.Body, maxMetricsText))
		return err
	case "on", "off":
		on := sub == "on"
		p, err := setObserve(env, c, panel.ObservePrefsChange{Metrics: &on})
		if err != nil {
			return err
		}
		fmt.Fprintf(env.Stdout, "Yerel metrik uç noktası %s.\n", onOff(p.Metrics))
		if p.Metrics {
			fmt.Fprintf(env.Stdout, "Adres: %s%s/metrics (yalnızca 127.0.0.1; uygulama anahtarı Authorization: Bearer ile ve yönetici olarak çalışan bir süreçten)\n", c.base, panel.LocalAPIPrefix)
		}
		return nil
	default:
		var p panel.ObservePrefs
		if err := c.get(env, "/observe", &p); err != nil {
			return err
		}
		if *df.json {
			return printJSON(env.Stdout, p)
		}
		fmt.Fprintf(env.Stdout, "Yerel metrik uç noktası %s.\n", onOff(p.Metrics))
		return nil
	}
}

// argList adapts positional arguments to switchArg.
type argList []string

func (a argList) Args() []string { return a }

func cmdNotify(env *Env, args []string) error {
	fs := newFlagSet(env, "notify")
	df := addDiagFlags(fs)
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	sub, err := switchArg(argList(pos))
	if err != nil {
		return err
	}
	c, err := df.client(env)
	if err != nil {
		return err
	}
	var p panel.ObservePrefs
	if sub == "status" {
		err = c.get(env, "/observe", &p)
	} else {
		on := sub == "on"
		p, err = setObserve(env, c, panel.ObservePrefsChange{Notifications: &on})
	}
	if err != nil {
		return err
	}
	if *df.json {
		return printJSON(env.Stdout, p)
	}
	fmt.Fprintf(env.Stdout, "Masaüstü bildirimleri %s (yeni veya çıkarılan cihaz, kill switch, belge reddi).\n", onOff(p.Notifications))
	return nil
}

func cmdDebugPprof(env *Env, args []string) error {
	fs := newFlagSet(env, "debug pprof")
	df := addDiagFlags(fs)
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	sub, err := switchArg(argList(pos))
	if err != nil {
		return err
	}
	c, err := df.client(env)
	if err != nil {
		return err
	}
	var p panel.ObservePrefs
	if sub == "status" {
		err = c.get(env, "/observe", &p)
	} else {
		on := sub == "on"
		p, err = setObserve(env, c, panel.ObservePrefsChange{Profiling: &on})
	}
	if err != nil {
		return err
	}
	if *df.json {
		return printJSON(env.Stdout, p)
	}
	if p.Profiling && p.ProfilingUntil != nil {
		fmt.Fprintf(env.Stdout, "Profilleme açık; %s saatinde kendiliğinden kapanır.\n", p.ProfilingUntil.Local().Format("15:04"))
		return nil
	}
	fmt.Fprintln(env.Stdout, "Profilleme kapalı.")
	return nil
}

// createOutput creates a new private file; an existing file is replaced
// only with force.
func createOutput(path string, force bool) (*os.File, error) {
	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if force {
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	f, err := os.OpenFile(path, flags, 0o600)
	if errors.Is(err, os.ErrExist) {
		return nil, fmt.Errorf("%s zaten var; başka bir ad verin veya --force kullanın", path)
	}
	return f, err
}

func cmdDebugProfile(env *Env, args []string) error {
	fs := newFlagSet(env, "debug profile")
	df := addDiagFlags(fs)
	seconds := fs.Int("seconds", 30, "CPU profilinin süresi (1-60 saniye)")
	debug := fs.Int("debug", 0, "0 ikili pprof, 1-2 metin (goroutine dökümü için 2)")
	out := fs.String("o", "", "çıktı dosyası (varsayılan openscale-<tür>-<zaman>.pprof)")
	force := fs.Bool("force", false, "var olan dosyanın üzerine yaz")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usageError("profil türü gerekli: cpu | heap | allocs | goroutine | block | mutex | threadcreate")
	}
	kind := pos[0]
	c, err := df.client(env)
	if err != nil {
		return err
	}
	name := *out
	if name == "" {
		ext := ".pprof"
		if *debug > 0 {
			ext = ".txt"
		}
		name = fmt.Sprintf("openscale-%s-%s%s", kind, env.Now().Format("20060102-150405"), ext)
	}
	req := panel.ProfileRequest{Kind: kind, Debug: *debug}
	if kind == "cpu" {
		req.Seconds = *seconds
		fmt.Fprintf(env.Stderr, "CPU profili %d saniye alınıyor...\n", *seconds)
	}
	resp, err := c.do(envContext(env), http.MethodPost, "/pprof", req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	f, err := createOutput(name, *force)
	if err != nil {
		return err
	}
	n, err := io.Copy(f, resp.Body)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "%s yazıldı (%s). İncelemek için: go tool pprof %s\n", name, humanBytes(uint64(n)), name)
	return nil
}

// parseSize reads 16M, 512K, 1G or bytes.
func parseSize(s string) (int64, error) {
	s = strings.TrimSpace(strings.ToUpper(s))
	mult := int64(1)
	switch {
	case strings.HasSuffix(s, "G"):
		mult, s = 1<<30, strings.TrimSuffix(s, "G")
	case strings.HasSuffix(s, "M"):
		mult, s = 1<<20, strings.TrimSuffix(s, "M")
	case strings.HasSuffix(s, "K"):
		mult, s = 1<<10, strings.TrimSuffix(s, "K")
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 || n > (1<<40)/mult {
		return 0, fmt.Errorf("boyut %q geçersiz (ör. 16M)", s)
	}
	return n * mult, nil
}

func cmdDebugCapture(env *Env, args []string) error {
	fs := newFlagSet(env, "debug capture")
	df := addDiagFlags(fs)
	peer := fs.String("peer", "", "yalnızca bu cihazla olan trafik")
	proto := fs.String("proto", "", "tcp, udp, icmp veya protokol numarası")
	port := fs.Int("port", 0, "kaynak veya hedef portu")
	dir := fs.String("dir", "both", "yön: in, out veya both")
	denied := fs.Bool("denied", false, "reddedilen paketleri de yakala")
	seconds := fs.Int("seconds", 30, "en uzun süre (1-600 saniye)")
	maxSize := fs.String("max-size", "16M", "en büyük dosya boyutu (4K-256M)")
	full := fs.Bool("full", false, "paket içeriğini de yaz (varsayılan yalnızca ilk 128 bayt: başlıklar)")
	snap := fs.Int("snap", 0, "paket başına yazılacak bayt (0: başlıklar; --full ile 65535)")
	out := fs.String("o", "", "pcap dosyası (varsayılan openscale-<zaman>.pcap)")
	force := fs.Bool("force", false, "var olan dosyanın üzerine yaz")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	size, err := parseSize(*maxSize)
	if err != nil {
		return usageError("%v", err)
	}
	req := panel.CaptureRequest{Peer: *peer, Proto: strings.ToLower(*proto), Port: *port, Direction: *dir, Denied: *denied,
		Seconds: *seconds, MaxBytes: size, Snap: *snap}
	if *full {
		req.Snap = 65535
	}
	c, err := df.client(env)
	if err != nil {
		return err
	}
	name := *out
	if name == "" {
		name = "openscale-" + env.Now().Format("20060102-150405") + ".pcap"
	}
	f, err := createOutput(name, *force)
	if err != nil {
		return err
	}
	fmt.Fprintf(env.Stderr, "Tünel içi paketler %d saniye boyunca (veya %s dolana dek) yakalanıyor; durdurmak için Ctrl+C.\n", req.Seconds, humanBytes(uint64(size)))
	resp, err := c.do(envContext(env), http.MethodPost, "/capture", req)
	if err != nil {
		_ = f.Close()
		_ = os.Remove(name)
		return err
	}
	defer resp.Body.Close()
	n, copyErr := io.Copy(f, io.LimitReader(resp.Body, size+64))
	if err := f.Close(); copyErr == nil {
		copyErr = err
	}
	if copyErr != nil && envContext(env).Err() == nil {
		return copyErr
	}
	packets, dropped := resp.Trailer.Get("X-Capture-Packets"), resp.Trailer.Get("X-Capture-Dropped")
	fmt.Fprintf(env.Stdout, "%s yazıldı (%s", name, humanBytes(uint64(n)))
	if packets != "" {
		fmt.Fprintf(env.Stdout, ", %s paket", packets)
	}
	if dropped != "" && dropped != "0" {
		fmt.Fprintf(env.Stdout, ", %s paket kaçırıldı", dropped)
	}
	fmt.Fprintln(env.Stdout, "). Wireshark veya tcpdump -r ile açabilirsiniz; dosya yalnızca bu bilgisayarda.")
	return nil
}

func cmdEvents(env *Env, args []string) error {
	fs := newFlagSet(env, "events")
	df := addDiagFlags(fs)
	follow := fs.Bool("follow", false, "yeni olayları bekleyip göster (Ctrl+C ile çık)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	c, err := df.client(env)
	if err != nil {
		return err
	}
	ctx := envContext(env)
	since := uint64(0)
	for {
		path := "/events/poll?since=" + strconv.FormatUint(since, 10)
		if *follow {
			path += "&wait=25"
		}
		var rep panel.EventStreamReply
		pctx, cancel := context.WithTimeout(ctx, 40*time.Second)
		resp, err := c.do(pctx, http.MethodGet, path, nil)
		if err == nil {
			err = json.NewDecoder(io.LimitReader(resp.Body, maxLocalReply)).Decode(&rep)
			resp.Body.Close()
		}
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		for _, ev := range rep.Events {
			if *df.json {
				data, _ := json.Marshal(ev)
				fmt.Fprintln(env.Stdout, string(data))
				continue
			}
			fmt.Fprintf(env.Stdout, "%s  %-10s %-8s %s\n", ev.At.Local().Format("2006-01-02 15:04:05"), ev.Category, ev.Severity, ev.Message)
		}
		since = rep.Next
		if !*follow {
			return nil
		}
	}
}

func cmdAuditList(env *Env, args []string) error {
	fs := newFlagSet(env, "audit list")
	df := addDiagFlags(fs)
	n := fs.Int("n", 50, "gösterilecek kayıt sayısı (1-500)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	c, err := df.client(env)
	if err != nil {
		return err
	}
	var rep panel.AuditReply
	if err := c.get(env, "/audit?n="+strconv.Itoa(*n), &rep); err != nil {
		return err
	}
	if *df.json {
		return printJSON(env.Stdout, rep)
	}
	for _, r := range rep.Records {
		fmt.Fprintf(env.Stdout, "#%-6d %s  %-8s %-28s %s\n", r.Seq, r.At.Local().Format("2006-01-02 15:04:05"), r.Severity, r.Kind, r.Message)
	}
	if len(rep.Records) == 0 {
		fmt.Fprintln(env.Stdout, "Denetim kaydında kayıt yok.")
	}
	writeVerify(env.Stdout, rep.Verify)
	return nil
}

func writeVerify(w io.Writer, rep audit.Report) {
	if rep.OK {
		fmt.Fprintf(w, "\nZincir sağlam: %d kayıt (#%d-#%d), son özet %s\n", rep.Records, rep.FirstSeq, rep.LastSeq, shortHash(rep.LastHash))
	} else {
		fmt.Fprintf(w, "\nZİNCİR BOZUK: %d kayıt okundu.\n", rep.Records)
	}
	for _, p := range rep.Problems {
		fmt.Fprintf(w, "  sorun: %s\n", p)
	}
	for _, n := range rep.Notes {
		fmt.Fprintf(w, "  not: %s\n", n)
	}
}

func shortHash(h string) string {
	if len(h) > 16 {
		return h[:16] + "…"
	}
	return h
}

func cmdAuditVerify(env *Env, args []string) error {
	fs := newFlagSet(env, "audit verify")
	df := addDiagFlags(fs)
	dir := fs.String("dir", "", "servise sormadan bu klasördeki denetim kaydını doğrula (ör. veri klasörü)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	var rep audit.Report
	if *dir != "" {
		r, err := audit.Verify(*dir)
		if err != nil {
			return err
		}
		rep = r
	} else {
		c, err := df.client(env)
		if err != nil {
			return err
		}
		if err := c.get(env, "/audit/verify", &rep); err != nil {
			return err
		}
	}
	if *df.json {
		if err := printJSON(env.Stdout, rep); err != nil {
			return err
		}
	} else {
		writeVerify(env.Stdout, rep)
	}
	if !rep.OK {
		return errors.New("denetim kaydının zinciri bozuk")
	}
	return nil
}

// writeBundleZip writes the bundle files into a zip.
func writeBundleZip(w io.Writer, rep panel.BundleReply) error {
	zw := zip.NewWriter(w)
	for _, f := range rep.Files {
		name := filepath.ToSlash(filepath.Clean(f.Name))
		// The names come from the service; keep them inside the archive.
		if name == "." || strings.HasPrefix(name, "../") || strings.HasPrefix(name, "/") || strings.ContainsAny(name, `:\`) || name == ".." {
			continue
		}
		h := &zip.FileHeader{Name: "openscale-teshis/" + name, Method: zip.Deflate, Modified: rep.CreatedAt}
		fw, err := zw.CreateHeader(h)
		if err != nil {
			return err
		}
		if _, err := io.WriteString(fw, f.Content); err != nil {
			return err
		}
	}
	return zw.Close()
}

func cmdDebugBundle(env *Env, args []string) error {
	fs := newFlagSet(env, "debug bundle")
	df := addDiagFlags(fs)
	out := fs.String("o", "", "zip dosyası (varsayılan openscale-teshis-<zaman>.zip)")
	show := fs.Bool("show", false, "dosyaların tam içeriğini göster")
	yes := fs.Bool("yes", false, "içeriği gözden geçirdim; sormadan yaz")
	force := fs.Bool("force", false, "var olan dosyanın üzerine yaz")
	to := fs.String("to", "", "paketi yardım edecek kişinin alıcı anahtarına (osbk1:...) şifrele (#512)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	recipient, err := bundleRecipient(*to)
	if err != nil {
		return err
	}
	c, err := df.client(env)
	if err != nil {
		return err
	}
	var rep panel.BundleReply
	if err := c.getLarge(env, "/bundle", maxBundleReply, &rep); err != nil {
		return err
	}
	w := env.Stdout
	fmt.Fprintln(w, "Teşhis paketinin içeriği (IP adresleri kısaltıldı, anahtarlar ve gizli ayarlar çıkarıldı):")
	total := 0
	for _, f := range rep.Files {
		total += len(f.Content)
		fmt.Fprintf(w, "  %-28s %s\n", f.Name, humanBytes(uint64(len(f.Content))))
	}
	fmt.Fprintf(w, "Toplam %s. Paket yalnızca bu bilgisayara yazılır; hiçbir yere gönderilmez.\n", humanBytes(uint64(total)))
	printAll := func() {
		for _, f := range rep.Files {
			fmt.Fprintf(w, "\n===== %s =====\n%s", f.Name, f.Content)
			if !strings.HasSuffix(f.Content, "\n") {
				fmt.Fprintln(w)
			}
		}
	}
	if *show {
		printAll()
	}
	if !*yes {
		if env.IsTerminal == nil || !env.IsTerminal() || env.ReadLine == nil {
			return errors.New("dosya yazılmadı: içeriği --show ile gözden geçirip onaylamak için --yes verin")
		}
		for {
			ans, err := env.ReadLine("\nPaket yazılsın mı? [e]vet / [h]ayır / [g]öster: ")
			if err != nil {
				return err
			}
			switch strings.ToLower(strings.TrimSpace(ans)) {
			case "e", "evet", "y", "yes":
			case "g", "göster", "goster", "s", "show":
				printAll()
				continue
			default:
				fmt.Fprintln(w, "Vazgeçildi; dosya yazılmadı.")
				return nil
			}
			break
		}
	}
	name := *out
	if recipient != nil {
		return writeSealedBundle(env, rep, recipient, name, *force)
	}
	if name == "" {
		name = "openscale-teshis-" + env.Now().Format("20060102-150405") + ".zip"
	}
	f, err := createOutput(name, *force)
	if err != nil {
		return err
	}
	if err := writeBundleZip(f, rep); err != nil {
		_ = f.Close()
		_ = os.Remove(name)
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Fprintf(w, "%s yazıldı.\n", name)
	return nil
}
