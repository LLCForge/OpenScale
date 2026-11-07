//go:build !openscale_noservices

package service

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/pki"
	"github.com/openscale/openscale/internal/proxy"
	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
)

func p18Bound(t *testing.T, a *Apps, key string) netip.AddrPort {
	t.Helper()
	var addr netip.AddrPort
	appsWait(t, key+" to listen", func() bool {
		st := a.p18()
		st.mu.Lock()
		defer st.mu.Unlock()
		if r := st.runners[key]; r != nil && r.cancel != nil {
			addr = r.bound
			return true
		}
		return false
	})
	return addr
}

func p18Stopped(t *testing.T, a *Apps, key string) {
	t.Helper()
	appsWait(t, key+" to stop", func() bool {
		st := a.p18()
		st.mu.Lock()
		defer st.mu.Unlock()
		r := st.runners[key]
		return r == nil || r.cancel == nil
	})
}

func TestTunnelServicesCAAndServe(t *testing.T) {
	be := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "cihaz="+r.Header.Get("OpenScale-Device"))
	}))
	defer be.Close()

	doc := appsDoc()
	for i := range doc.Devices {
		doc.Devices[i].ExpiresAt = time.Now().Add(24 * time.Hour)
	}
	caKey, err := pki.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	caDER, err := pki.NewCA(caKey, "", doc.DNSDomain, doc.IPv4Prefix, doc.IPv6Prefix, time.Now(), 0)
	if err != nil {
		t.Fatal(err)
	}
	doc.InternalCA = &trust.InternalCA{Certificate: caDER, Issuer: "nas", CertDays: 2}
	rules := []trust.Rule{
		{From: []string{"laptop"}, To: []string{"nas"}, Service: trust.ServiceServe},
		{From: []string{"*"}, To: []string{"nas"}, Service: trust.ServiceCert},
	}
	doc.Rules = rules
	eng := &appsFakeEngine{doc: doc, self: "nas"}
	dir := t.TempDir()
	keyPEM, _ := pki.KeyPEM(caKey)
	if err := securefile.WriteNew(CAKeyPath(dir), keyPEM); err != nil {
		t.Fatal(err)
	}
	if err := SaveServeConfig(dir, proxy.Config{Schema: proxy.ConfigSchema, Services: []proxy.Service{
		{Name: "web", Type: proxy.TypeHTTP, Target: be.URL, TLS: true},
	}}); err != nil {
		t.Fatal(err)
	}
	laptop, _ := doc.DeviceByName("laptop")
	a := NewApps(AppsConfig{Dir: dir, Engine: func() AppEngine { return eng }, Interval: 20 * time.Millisecond})
	a.listenHost, a.anyPort = appsLoopback, true
	a.mapPeer = func(netip.Addr) netip.Addr { return laptop.IPv4 }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	issuer := p18Bound(t, a, runnerIssuer)
	serveAddr := p18Bound(t, a, runnerShared)
	appsWait(t, "own TLS certificate", func() bool { return a.TunnelServices().CertUntil != nil })

	// Another device asks the issuer: it gets its own names only.
	key, _ := pki.GenerateKey(nil)
	leafDER, err := pki.Request(ctx, issuer, netip.Addr{}, key, caDER, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(leafDER)
	if leaf.DNSNames[0] != "laptop.openscale.internal" || leaf.NotAfter.Sub(leaf.NotBefore) > 2*24*time.Hour+time.Hour {
		t.Fatalf("laptop certificate: %v %v", leaf.DNSNames, leaf.NotAfter)
	}

	// The published service answers over HTTPS with the CA's certificate.
	ca, _ := x509.ParseCertificate(caDER)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	host := "web.nas.openscale.internal"
	hc := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: host},
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", serveAddr.String())
		},
	}}
	resp, err := hc.Get("https://" + host + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "cihaz=laptop" {
		t.Fatalf("https: %d %q", resp.StatusCode, body)
	}

	// The serve rule goes away: the shared port closes, the issuer stays.
	eng.setRules(2, rules[1:])
	p18Stopped(t, a, runnerShared)
	p18Bound(t, a, runnerIssuer)
	// The cert rule goes away too: the issuer closes.
	eng.setRules(3, nil)
	p18Stopped(t, a, runnerIssuer)
}

func TestServeConfigFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	c, err := LoadServeConfig(dir)
	if err != nil || len(c.Services) != 0 {
		t.Fatalf("missing file: %v %v", c, err)
	}
	c.Services = append(c.Services, proxy.Service{Name: "db", Type: proxy.TypeTCP, Target: "127.0.0.1:5432", Port: 5432})
	if err := SaveServeConfig(dir, c); err != nil {
		t.Fatal(err)
	}
	back, err := LoadServeConfig(dir)
	if err != nil || len(back.Services) != 1 || back.Services[0].Port != 5432 {
		t.Fatalf("round trip: %v %v", back, err)
	}
}
