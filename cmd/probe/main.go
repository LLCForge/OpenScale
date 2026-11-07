// Command probe checks the owner's own OpenScale servers from the outside
// (F-209, ADR-0108): DNS resolution, TCP connect latency, the TLS
// handshake and certificate lifetime, and HTTP status. It runs on the
// owner's computer against targets the owner names; there are no default
// targets, nothing is scanned (one port per target) and results go to
// standard output only, never to a metrics service.
//
// The coordinator's WireGuard UDP port and the relay inside the tunnel
// cannot be checked from outside without keys; use "openscale netcheck"
// and "openscale debug relay-test" for those.
//
//	go run ./cmd/probe -coordinator vpn.example.net:443 -tls vpn.example.net:443 \
//	    -dns vpn.example.net=198.51.100.7 -interval 60s -json
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	maxTargets      = 32
	minInterval     = 10 * time.Second
	defaultTimeout  = 5 * time.Second
	defaultWarnDays = 14
	maxBody         = 64 << 10
	maxCAFile       = 1 << 20
)

// Check kinds.
const (
	kindDNS  = "dns"
	kindTCP  = "tcp"
	kindTLS  = "tls"
	kindHTTP = "http"
)

// Statuses of a result.
const (
	statusOK   = "ok"
	statusWarn = "warn"
	statusFail = "fail"
)

// target is one check.
type target struct {
	Kind string
	// Addr is host:port (tcp, tls), a host name (dns) or a URL (http).
	Addr string
	// Expect lists the addresses a dns target must resolve to.
	Expect []netip.Addr
}

// Result is one check's outcome.
type Result struct {
	At        time.Time `json:"at"`
	Kind      string    `json:"kind"`
	Target    string    `json:"target"`
	Status    string    `json:"status"`
	LatencyMS float64   `json:"latency_ms"`
	Detail    string    `json:"detail,omitempty"`
	// DaysLeft is the TLS certificate's remaining validity.
	DaysLeft *int `json:"days_left,omitempty"`
	// Addrs are the resolved addresses (dns).
	Addrs []string `json:"addrs,omitempty"`
	// HTTPStatus is the response status (http).
	HTTPStatus int `json:"http_status,omitempty"`
}

// config is the parsed command line.
type config struct {
	targets  []target
	timeout  time.Duration
	warnDays int
	roots    *x509.CertPool
	resolver *net.Resolver
	now      func() time.Time
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("probe", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var dns, tcp, tlsT, httpT, coord, relay multiFlag
	fs.Var(&dns, "dns", "çözülecek ad; beklenen adreslerle: ad=ip1,ip2 (tekrarlanabilir)")
	fs.Var(&tcp, "tcp", "TCP bağlantısı: sunucu:port (tekrarlanabilir)")
	fs.Var(&tlsT, "tls", "TLS el sıkışması ve sertifika süresi: sunucu:port (tekrarlanabilir)")
	fs.Var(&httpT, "http", "HTTP(S) GET: adres (tekrarlanabilir; yönlendirme izlenmez)")
	fs.Var(&coord, "coordinator", "koordinatörün genel adresi sunucu:port: DNS ve TCP denetimi (tekrarlanabilir)")
	fs.Var(&relay, "relay", "aktarıcının genel adresi sunucu:port: DNS ve TCP denetimi (tekrarlanabilir)")
	timeout := fs.Duration("timeout", defaultTimeout, "her denetimin zaman aşımı")
	warnDays := fs.Int("warn-days", defaultWarnDays, "sertifikanın bitmesine bu kadar gün kala uyar")
	caFile := fs.String("ca", "", "kendi sertifika yetkilinizin PEM dosyası (öntanımlı: sistem kökleri)")
	interval := fs.Duration("interval", 0, "tekrar aralığı (0: bir kez; en az 10s)")
	count := fs.Int("count", 0, "tekrar sayısı (-interval ile; 0: Ctrl+C'ye kadar)")
	asJSON := fs.Bool("json", false, "her sonucu bir JSON satırı olarak yaz")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "hata: beklenmeyen argüman %q\n", fs.Arg(0))
		return 2
	}
	cfg := config{timeout: *timeout, warnDays: *warnDays, resolver: net.DefaultResolver, now: time.Now}
	var err error
	cfg.targets, err = buildTargets(dns, tcp, tlsT, httpT, append(coord, relay...))
	if err == nil && (*timeout <= 0 || *timeout > time.Minute) {
		err = errors.New("-timeout 0-1m olmalı")
	}
	if err == nil && *interval != 0 && *interval < minInterval {
		err = fmt.Errorf("-interval en az %s olmalı", minInterval)
	}
	if err == nil && (*warnDays < 0 || *warnDays > 365 || *count < 0) {
		err = errors.New("-warn-days 0-365, -count 0 veya üstü olmalı")
	}
	if err == nil && *caFile != "" {
		cfg.roots, err = loadCA(*caFile)
	}
	if err != nil {
		fmt.Fprintf(stderr, "hata: %v\n", err)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	failed := false
	for round := 1; ; round++ {
		for _, r := range runAll(ctx, cfg) {
			if r.Status == statusFail {
				failed = true
			}
			report(stdout, r, *asJSON)
		}
		if *interval == 0 || (*count > 0 && round >= *count) {
			break
		}
		t := time.NewTimer(*interval)
		select {
		case <-ctx.Done():
			t.Stop()
			if failed {
				return 1
			}
			return 0
		case <-t.C:
		}
	}
	if failed {
		return 1
	}
	return 0
}

// buildTargets validates the targets; there is no default.
func buildTargets(dns, tcp, tlsT, httpT, servers []string) ([]target, error) {
	var out []target
	for _, d := range dns {
		name, exp, _ := strings.Cut(d, "=")
		if !validHost(name) {
			return nil, fmt.Errorf("geçersiz ad: %q", name)
		}
		t := target{Kind: kindDNS, Addr: name}
		if exp != "" {
			for _, s := range strings.Split(exp, ",") {
				a, err := netip.ParseAddr(strings.TrimSpace(s))
				if err != nil {
					return nil, fmt.Errorf("geçersiz beklenen adres: %q", s)
				}
				t.Expect = append(t.Expect, a.Unmap())
			}
		}
		out = append(out, t)
	}
	hostPort := func(kind, v string) error {
		host, port, err := net.SplitHostPort(v)
		if err != nil || !validHost(host) {
			return fmt.Errorf("%s hedefi sunucu:port olmalı: %q", kind, v)
		}
		if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
			return fmt.Errorf("geçersiz port: %q", v)
		}
		out = append(out, target{Kind: kind, Addr: v})
		return nil
	}
	for _, v := range tcp {
		if err := hostPort(kindTCP, v); err != nil {
			return nil, err
		}
	}
	for _, v := range tlsT {
		if err := hostPort(kindTLS, v); err != nil {
			return nil, err
		}
	}
	for _, v := range servers {
		host, _, err := net.SplitHostPort(v)
		if err != nil {
			return nil, fmt.Errorf("sunucu adresi sunucu:port olmalı: %q", v)
		}
		if _, err := netip.ParseAddr(host); err != nil && validHost(host) {
			out = append(out, target{Kind: kindDNS, Addr: host})
		}
		if err := hostPort(kindTCP, v); err != nil {
			return nil, err
		}
	}
	for _, v := range httpT {
		u, err := url.Parse(v)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
			return nil, fmt.Errorf("http hedefi http(s)://sunucu/yol olmalı: %q", v)
		}
		out = append(out, target{Kind: kindHTTP, Addr: u.String()})
	}
	if len(out) == 0 {
		return nil, errors.New("en az bir hedef verin (-coordinator, -relay, -dns, -tcp, -tls veya -http); öntanımlı hedef yoktur")
	}
	if len(out) > maxTargets {
		return nil, fmt.Errorf("en çok %d hedef", maxTargets)
	}
	return out, nil
}

func validHost(h string) bool {
	if _, err := netip.ParseAddr(h); err == nil {
		return true
	}
	if h == "" || len(h) > 253 || strings.ContainsAny(h, "*/ ") {
		return false
	}
	for _, label := range strings.Split(strings.TrimSuffix(h, "."), ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func loadCA(path string) (*x509.CertPool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxCAFile+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxCAFile {
		return nil, errors.New("CA dosyası çok büyük")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, errors.New("CA dosyasında PEM sertifika yok")
	}
	return pool, nil
}

func runAll(ctx context.Context, cfg config) []Result {
	out := make([]Result, 0, len(cfg.targets))
	for _, t := range cfg.targets {
		if ctx.Err() != nil {
			break
		}
		out = append(out, check(ctx, cfg, t))
	}
	return out
}

func millis(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

func check(ctx context.Context, cfg config, t target) Result {
	ctx, cancel := context.WithTimeout(ctx, cfg.timeout)
	defer cancel()
	r := Result{At: cfg.now().UTC(), Kind: t.Kind, Target: t.Addr, Status: statusOK}
	start := time.Now()
	switch t.Kind {
	case kindDNS:
		addrs, err := cfg.resolver.LookupNetIP(ctx, "ip", t.Addr)
		r.LatencyMS = millis(time.Since(start))
		if err != nil {
			return fail(r, err)
		}
		got := make([]netip.Addr, 0, len(addrs))
		for _, a := range addrs {
			got = append(got, a.Unmap())
			r.Addrs = append(r.Addrs, a.Unmap().String())
		}
		slices.Sort(r.Addrs)
		for _, want := range t.Expect {
			if !slices.Contains(got, want) {
				r.Status, r.Detail = statusFail, "beklenen adres yok: "+want.String()
			}
		}
	case kindTCP:
		var d net.Dialer
		conn, err := d.DialContext(ctx, "tcp", t.Addr)
		r.LatencyMS = millis(time.Since(start))
		if err != nil {
			return fail(r, err)
		}
		_ = conn.Close()
	case kindTLS:
		host, _, _ := net.SplitHostPort(t.Addr)
		d := tls.Dialer{Config: &tls.Config{ServerName: host, RootCAs: cfg.roots, MinVersion: tls.VersionTLS12}}
		conn, err := d.DialContext(ctx, "tcp", t.Addr)
		r.LatencyMS = millis(time.Since(start))
		if err != nil {
			return fail(r, err)
		}
		defer conn.Close()
		tc, ok := conn.(*tls.Conn)
		if !ok || len(tc.ConnectionState().PeerCertificates) == 0 {
			return fail(r, errors.New("sertifika alınamadı"))
		}
		leaf := tc.ConnectionState().PeerCertificates[0]
		days := int(leaf.NotAfter.Sub(cfg.now()).Hours() / 24)
		r.DaysLeft = &days
		r.Detail = fmt.Sprintf("%s, %s tarihine kadar", tlsVersion(tc.ConnectionState().Version), leaf.NotAfter.UTC().Format("2006-01-02"))
		if days < cfg.warnDays {
			r.Status = statusWarn
			r.Detail += fmt.Sprintf("; %d günden az kaldı", cfg.warnDays)
		}
	case kindHTTP:
		client := &http.Client{
			Timeout:       cfg.timeout,
			Transport:     &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: cfg.roots, MinVersion: tls.VersionTLS12}},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.Addr, nil)
		if err != nil {
			return fail(r, err)
		}
		req.Header.Set("User-Agent", "OpenScale-Probe/1")
		resp, err := client.Do(req)
		r.LatencyMS = millis(time.Since(start))
		if err != nil {
			return fail(r, err)
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxBody))
		_ = resp.Body.Close()
		r.HTTPStatus = resp.StatusCode
		if resp.StatusCode >= 400 {
			r.Status = statusFail
		} else if resp.StatusCode >= 300 {
			r.Status, r.Detail = statusWarn, "yönlendirme (izlenmedi): "+resp.Header.Get("Location")
		}
	}
	return r
}

func fail(r Result, err error) Result {
	r.Status, r.Detail = statusFail, err.Error()
	return r
}

func tlsVersion(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	}
	return "TLS ?"
}

func report(w io.Writer, r Result, asJSON bool) {
	if asJSON {
		data, err := json.Marshal(r)
		if err == nil {
			fmt.Fprintln(w, string(data))
		}
		return
	}
	line := fmt.Sprintf("%s  %-4s  %-4s  %-40s  %8.1f ms", r.At.Format(time.RFC3339), strings.ToUpper(r.Status), r.Kind, r.Target, r.LatencyMS)
	if len(r.Addrs) > 0 {
		line += "  " + strings.Join(r.Addrs, ",")
	}
	if r.HTTPStatus != 0 {
		line += "  HTTP " + strconv.Itoa(r.HTTPStatus)
	}
	if r.Detail != "" {
		line += "  " + r.Detail
	}
	fmt.Fprintln(w, line)
}
