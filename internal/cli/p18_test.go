//go:build !openscale_noservices

package cli

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/pki"
	"github.com/openscale/openscale/pkg/client"
)

func TestCAApproveAndRemove(t *testing.T) {
	h := newHarness(t)
	pass := "--passphrase-file=" + h.passFile
	h.run(exitOK, "network", "init", "--dir", h.netDir, pass)
	req, fp := h.keygen(filepath.Join(t.TempDir(), "nas"), "nas")
	h.run(exitOK, "device", "add", "--dir", h.netDir, "--request", req, "--fingerprint", fp, pass)

	n, err := admin.Load(h.netDir, h.env.adminOptions())
	if err != nil {
		t.Fatal(err)
	}
	doc, err := n.Document()
	if err != nil {
		t.Fatal(err)
	}
	key, _ := pki.GenerateKey(nil)
	der, err := pki.NewCA(key, "", doc.DNSDomain, doc.IPv4Prefix, doc.IPv6Prefix, h.env.Now(), 0)
	if err != nil {
		t.Fatal(err)
	}
	certFile := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(certFile, pki.CertPEM(der), 0o600); err != nil {
		t.Fatal(err)
	}
	// A wrong fingerprint signs nothing; without one and without a
	// terminal the command refuses.
	h.run(exitError, "ca", "approve", "--dir", h.netDir, "--cert", certFile, "--issuer", "nas", "--fingerprint", "AA:BB", pass)
	h.run(exitUsage, "ca", "approve", "--dir", h.netDir, "--cert", certFile, "--issuer", "nas", pass)
	h.run(exitError, "ca", "approve", "--dir", h.netDir, "--cert", certFile, "--issuer", "yok", "--fingerprint", pki.Fingerprint(der), pass)
	out := h.run(exitOK, "ca", "approve", "--dir", h.netDir, "--cert", certFile, "--issuer", "nas", "--cert-days", "3", "--fingerprint", strings.ToLower(pki.Fingerprint(der)), pass)
	if !strings.Contains(out, "İç CA eklendi: dağıtıcı nas") || !strings.Contains(out, "3 gün") {
		t.Fatalf("approve output:\n%s", out)
	}
	h.run(exitOK, "rule", "add", "--dir", h.netDir, "--from", "*", "--to", "nas", "--service", "cert", pass)
	h.run(exitOK, "rule", "add", "--dir", h.netDir, "--from", "*", "--to", "nas", "--service", "serve", pass)
	out = h.run(exitOK, "ca", "remove", "--dir", h.netDir, pass)
	if !strings.Contains(out, "İç CA kaldırıldı") {
		t.Fatalf("remove output:\n%s", out)
	}
	h.run(exitError, "ca", "remove", "--dir", h.netDir, pass)
}

func TestServeCommands(t *testing.T) {
	h := newHarness(t)
	state := t.TempDir()
	h.run(exitOK, "serve", "add", "nas", "--http", "http://127.0.0.1:5000", "--paths", "/api/", "--read-only", "--state-dir", state)
	h.run(exitError, "serve", "add", "nas", "--http", "http://127.0.0.1:5001", "--state-dir", state)
	h.run(exitUsage, "serve", "add", "iki", "--http", "http://127.0.0.1:1", "--tcp", "127.0.0.1:2", "--state-dir", state)
	h.run(exitError, "serve", "add", "db", "--tcp", "127.0.0.1:5432", "--state-dir", state) // tcp needs --port
	h.run(exitOK, "serve", "add", "db", "--tcp", "127.0.0.1:5432", "--port", "5432", "--state-dir", state)
	h.run(exitOK, "serve", "add", "idp", "--oidc", "--tls", "--state-dir", state)
	out := h.run(exitOK, "serve", "client", "add", "idp", "--id", "grafana", "--redirect", "https://grafana.nas.openscale.internal:4051/cb", "--state-dir", state)
	_, secret, ok := strings.Cut(out, "Sır (yalnızca şimdi gösterilir): ")
	secret, _, _ = strings.Cut(secret, "\n")
	if !ok || len(secret) < 40 {
		t.Fatalf("client add:\n%s", out)
	}
	out = h.run(exitOK, "serve", "list", "--state-dir", state)
	for _, want := range []string{"nas", "db", "idp", "salt okunur", "yollar: /api/"} {
		if !strings.Contains(out, want) {
			t.Errorf("list missing %q:\n%s", want, out)
		}
	}
	b, err := os.ReadFile(filepath.Join(state, "apps", "serve.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), secret) || !strings.Contains(string(b), "secret_sha256") {
		t.Fatalf("serve.json: %s", b)
	}
	h.run(exitOK, "serve", "rm", "db", "--state-dir", state)
	h.run(exitError, "serve", "rm", "db", "--state-dir", state)
}

type fakeResolver map[string]*client.Device

func (f fakeResolver) WhoIs(_ context.Context, addr string) (client.WhoIsResult, error) {
	if addr == "100.80.0.66" {
		return client.WhoIsResult{}, errors.New("tunnel down")
	}
	return client.WhoIsResult{Schema: 1, Query: addr, Device: f[addr]}, nil
}

func TestAuthHandler(t *testing.T) {
	r := fakeResolver{
		"100.80.0.2": {Name: "laptop", FQDN: "laptop.openscale.internal", Tags: []string{"aile"}},
		"100.80.0.3": {Name: "telefon", FQDN: "telefon.openscale.internal"},
	}
	h := authHandler(r, "Remote-Addr", []string{"tag:aile"})
	cases := []struct {
		path, addr string
		want       int
		device     string
	}{
		{"/auth", "100.80.0.2", http.StatusNoContent, "laptop"},
		{"/auth", "100.80.0.3", http.StatusForbidden, ""},
		{"/auth", "100.80.0.9", http.StatusForbidden, ""},
		{"/auth", "100.80.0.66", http.StatusBadGateway, ""},
		{"/auth", "bozuk", http.StatusBadRequest, ""},
		{"/auth", "", http.StatusBadRequest, ""},
		{"/baska", "100.80.0.2", http.StatusNotFound, ""},
	}
	for _, c := range cases {
		req := httptest.NewRequest("GET", c.path, nil)
		req.RemoteAddr = "127.0.0.1:5555"
		if c.addr != "" {
			req.Header.Set("Remote-Addr", c.addr)
		}
		req.Header.Set("OpenScale-Device", "sahte")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != c.want || w.Header().Get("OpenScale-Device") != c.device {
			t.Errorf("%s %s: %d %q, want %d %q", c.path, c.addr, w.Code, w.Header().Get("OpenScale-Device"), c.want, c.device)
		}
	}
	// Two address headers are refused.
	req := httptest.NewRequest("GET", "/auth", nil)
	req.Header.Add("Remote-Addr", "100.80.0.3")
	req.Header.Add("Remote-Addr", "100.80.0.2")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("two headers: %d", w.Code)
	}
}

func TestListenLocalRefusesNonLoopback(t *testing.T) {
	for _, s := range []string{"0.0.0.0:4180", "100.80.0.1:4180", "[::]:4180", "x"} {
		if ln, err := listenLocal(s); err == nil {
			ln.Close()
			t.Fatalf("%s accepted", s)
		}
	}
	ln, err := listenLocal("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln.Close()
}

func TestCertCoversAndShortcuts(t *testing.T) {
	dns := []string{"nas.openscale.internal", "*.nas.openscale.internal"}
	ips := []netip.Addr{netip.MustParseAddr("100.80.0.1")}
	for name, want := range map[string]bool{
		"nas.openscale.internal": true, "grafana.nas.openscale.internal": true, "a.b.nas.openscale.internal": false,
		"laptop.openscale.internal": false, "100.80.0.1": true, "100.80.0.2": false,
	} {
		if certCovers(name, dns, ips) != want {
			t.Errorf("%s: want %v", name, want)
		}
	}
	if got := rdpCommand("windows", "100.80.0.4"); strings.Join(got, " ") != "mstsc.exe /v:100.80.0.4" {
		t.Fatalf("rdp: %v", got)
	}
	if got := browserCommand("linux", "http://x/"); got[0] != "xdg-open" {
		t.Fatalf("browser: %v", got)
	}
	h := newHarness(t)
	out := h.run(exitOK, "connect", "100.80.0.4", "--rdp", "--print")
	if !strings.Contains(out, "100.80.0.4") {
		t.Fatalf("connect --rdp --print:\n%s", out)
	}
	out = h.run(exitOK, "connect", "100.80.0.4", "--https", "--port", "8443", "--print")
	if !strings.Contains(out, "https://100.80.0.4:8443/") {
		t.Fatalf("connect --https --print:\n%s", out)
	}
	h.run(exitUsage, "connect", "100.80.0.4", "--rdp", "--ssh")
	out = h.run(exitOK, "auth-server", "--nginx")
	if !strings.Contains(out, "proxy_set_header Remote-Addr $remote_addr;") {
		t.Fatalf("nginx snippet:\n%s", out)
	}
}
