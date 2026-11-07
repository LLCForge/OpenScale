package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNoDefaultTargetsAndLimits(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run(nil, &out, &errb); code != 2 || !strings.Contains(errb.String(), "öntanımlı hedef yoktur") {
		t.Fatalf("no targets = %d %s", code, errb.String())
	}
	args := []string{}
	for i := 0; i < maxTargets+1; i++ {
		args = append(args, "-tcp", "127.0.0.1:1")
	}
	if code := run(args, &out, &errb); code != 2 {
		t.Fatalf("too many targets = %d", code)
	}
	for _, bad := range [][]string{{"-tcp", "*.example:1"}, {"-tcp", "127.0.0.1"}, {"-http", "ftp://x/"}, {"-tcp", "127.0.0.1:1", "-interval", "1s"}, {"-dns", "a b"}} {
		if code := run(bad, &out, &errb); code != 2 {
			t.Fatalf("%v = %d", bad, code)
		}
	}
}

func TestProbesAgainstLocalServers(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "https://203.0.113.1/", http.StatusFound)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	cert := srv.Certificate()
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	addr := strings.TrimPrefix(srv.URL, "https://")
	closed, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedAddr := closed.Addr().String()
	_ = closed.Close()

	var out, errb bytes.Buffer
	code := run([]string{"-json", "-ca", caPath, "-tls", addr, "-tcp", addr, "-tcp", closedAddr, "-http", srv.URL + "/", "-http", srv.URL + "/redirect", "-warn-days", "365"}, &out, &errb)
	if code != 1 {
		t.Fatalf("exit = %d (one closed port must fail)\n%s%s", code, out.String(), errb.String())
	}
	var results []Result
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var r Result
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("line %q: %v", line, err)
		}
		results = append(results, r)
	}
	if len(results) != 5 {
		t.Fatalf("results = %+v", results)
	}
	byTarget := func(kind, target string) Result {
		for _, r := range results {
			if r.Kind == kind && r.Target == target {
				return r
			}
		}
		t.Fatalf("no %s %s", kind, target)
		return Result{}
	}
	tlsR := byTarget(kindTLS, addr)
	if tlsR.DaysLeft == nil || tlsR.Status != statusWarn {
		// httptest certificates are long-lived; with -warn-days 365 they
		// may or may not warn, but the lifetime must be reported.
		if tlsR.DaysLeft == nil || tlsR.Status == statusFail {
			t.Fatalf("tls = %+v", tlsR)
		}
	}
	if r := byTarget(kindTCP, addr); r.Status != statusOK {
		t.Fatalf("tcp = %+v", r)
	}
	if r := byTarget(kindTCP, closedAddr); r.Status != statusFail {
		t.Fatalf("closed tcp = %+v", r)
	}
	if r := byTarget(kindHTTP, srv.URL+"/"); r.Status != statusOK || r.HTTPStatus != 200 {
		t.Fatalf("http = %+v", r)
	}
	if r := byTarget(kindHTTP, srv.URL+"/redirect"); r.Status != statusWarn || r.HTTPStatus != http.StatusFound {
		t.Fatalf("redirect = %+v", r)
	}

	// Without the CA the handshake must fail: no silent trust.
	cfg := config{timeout: 2 * time.Second, warnDays: 14, resolver: net.DefaultResolver, now: time.Now}
	if r := check(context.Background(), cfg, target{Kind: kindTLS, Addr: addr}); r.Status != statusFail {
		t.Fatalf("untrusted tls = %+v", r)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	cfg.roots = pool
	cfg.warnDays = 0
	if r := check(context.Background(), cfg, target{Kind: kindTLS, Addr: addr}); r.Status != statusOK {
		t.Fatalf("trusted tls = %+v", r)
	}
	// DNS of a literal address with an expectation.
	if r := check(context.Background(), cfg, target{Kind: kindDNS, Addr: "localhost"}); r.Status == statusFail && !strings.Contains(r.Detail, "no such host") {
		t.Logf("localhost lookup: %+v", r)
	}
}
