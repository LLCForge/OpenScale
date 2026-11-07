//go:build linux

package desktop

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLinuxPrivilegedArgs(t *testing.T) {
	argv, err := privilegedArgs("/usr/bin/openscale", "app", "install-service")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(argv, " ") != "--disable-internal-agent /usr/bin/openscale app install-service" {
		t.Fatalf("%q", argv)
	}
	for _, bad := range [][]string{{"service", "uninstall"}, {"app", "install-service", "--x"}, {"sh", "-c"}} {
		if _, err := privilegedArgs("/usr/bin/openscale", bad...); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
	if _, err := privilegedArgs("openscale", "app", "install-service"); err == nil {
		t.Error("relative program accepted")
	}
	if _, err := privilegedArgs("/tmp/a\nb", "app", "install-service"); err == nil {
		t.Error("newline accepted")
	}
}

func TestInvokingUID(t *testing.T) {
	t.Setenv("PKEXEC_UID", "")
	t.Setenv("SUDO_UID", "")
	if _, ok := invokingUID(); ok {
		t.Fatal("no variables")
	}
	t.Setenv("SUDO_UID", "1000")
	if uid, ok := invokingUID(); !ok || uid != 1000 {
		t.Fatal(uid)
	}
	t.Setenv("PKEXEC_UID", "1001")
	if uid, _ := invokingUID(); uid != 1001 {
		t.Fatal("pkexec first")
	}
	t.Setenv("PKEXEC_UID", "0")
	t.Setenv("SUDO_UID", "x")
	if _, ok := invokingUID(); ok {
		t.Fatal("root or garbage accepted")
	}
}

func TestLinuxPeerProgramSelf(t *testing.T) {
	p, err := linuxPeerProgram(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	self, _ := os.Executable()
	if fi1, err1 := os.Stat(p); err1 != nil {
		t.Fatal(err1)
	} else if fi2, err2 := os.Stat(self); err2 != nil || !os.SameFile(fi1, fi2) {
		t.Fatalf("%s is not %s", p, self)
	}
	if _, err := linuxPeerProgram(1 << 30); err == nil {
		t.Fatal("missing process accepted")
	}
}

func TestTrayGatePolicyLinux(t *testing.T) {
	p := trayGatePolicy()
	if !p.partialGroups || p.inGroup == nil || p.image == nil {
		t.Fatalf("%+v", p)
	}
	if p.group == 0 || p.group == adminGroupID {
		t.Fatalf("group %d", p.group)
	}
}

// TestTraySocketLinux runs the tray gateway on a socket in a temporary
// folder: SO_PEERCRED identifies this process, the policy checks its
// group and program, and an allowed request reaches the panel with the
// token added.
func TestTraySocketLinux(t *testing.T) {
	var gotAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"mode":"device"}`))
	}))
	defer upstream.Close()
	sock := filepath.Join(t.TempDir(), "tray.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	self, err := ownExecutable()
	if err != nil {
		t.Fatal(err)
	}
	var hashes programHashes
	want, err := hashes.sum(self)
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	run := func(group int) (*http.Response, error) {
		policy := trayGatePolicy()
		policy.want, policy.hash, policy.group = want, hashes.sum, group
		gl := &gateListener{Listener: ln, policy: policy, logger: logger, slots: make(chan struct{}, 2)}
		srv := &http.Server{Handler: newTrayGate(upstream.URL, func() (string, error) { return strings.Repeat("t", 43), nil }, logger), ReadHeaderTimeout: time.Second}
		go func() { _ = srv.Serve(gl) }()
		defer srv.Close()
		hc := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		}}}
		return hc.Get(gateBase + "/api/app/tray")
	}
	resp, err := run(os.Getegid())
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || gotAuth != "Bearer "+strings.Repeat("t", 43) {
		t.Fatalf("allowed caller: %d %q", resp.StatusCode, gotAuth)
	}
	if os.Geteuid() == 0 {
		return // root is always allowed; the refusal needs another user
	}
	ln, err = net.Listen("unix", sock+"2")
	if err != nil {
		t.Fatal(err)
	}
	sock += "2"
	if resp, err := run(noGroup); err == nil {
		_ = resp.Body.Close()
		t.Fatalf("caller outside the group got %d", resp.StatusCode)
	}
}
