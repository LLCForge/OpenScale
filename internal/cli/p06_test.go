package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/node"
	"github.com/openscale/openscale/internal/service"
	"github.com/openscale/openscale/internal/svcmgr"
)

func TestUpTransportFlags(t *testing.T) {
	h := newHarness(t)
	fs := newFlagSet(h.env, "up")
	f := addUpTransportFlags(fs)
	if err := fs.Parse([]string{"--post-quantum=false", "--psk-rotation", "1h", "--tcp-fallback", "vpn.example.com:8443",
		"--keepalive", "15s", "--adaptive-keepalive", "--lazy-peers", "--lazy-idle", "20m"}); err != nil {
		t.Fatal(err)
	}
	o, err := f.resolve()
	if err != nil {
		t.Fatal(err)
	}
	cfg := o.apply(node.Config{})
	if cfg.PostQuantum != node.PostQuantumOff || cfg.PSKRotation != time.Hour || cfg.TCPFallback != "vpn.example.com:8443" ||
		cfg.Keepalive != 15*time.Second || !cfg.AdaptiveKeepalive || !cfg.LazyPeers || cfg.LazyIdle != 20*time.Minute {
		t.Fatalf("config: %+v", cfg)
	}
	for _, args := range [][]string{
		{"--keepalive", "3s"},
		{"--psk-rotation", "30s"},
		{"--tcp-fallback", "no-port"},
		{"--tcp-fallback", "a:443", "--disable-tcp-fallback"},
		{"--lazy-idle", "5m"},
	} {
		fs := newFlagSet(h.env, "up")
		f := addUpTransportFlags(fs)
		if err := fs.Parse(args); err != nil {
			t.Fatal(err)
		}
		if _, err := f.resolve(); !errors.Is(err, errUsage) {
			t.Errorf("%v: err = %v", args, err)
		}
	}
}

func TestCoordinatorTCPFlags(t *testing.T) {
	h := newHarness(t)
	fs := newFlagSet(h.env, "coordinator run")
	f := addCoordinatorTCPFlags(fs)
	if err := fs.Parse([]string{"--tcp-listen", ":443", "--tcp-max-conns", "512", "--tcp-max-conns-per-ip", "4"}); err != nil {
		t.Fatal(err)
	}
	listen, maxConns, perIP, err := f.resolve()
	if err != nil || listen != ":443" || maxConns != 512 || perIP != 4 {
		t.Fatalf("resolve = %q %d %d %v", listen, maxConns, perIP, err)
	}
	// Every new flag can come from OPENSCALE_* and --config.
	for _, name := range []string{"tcp-listen", "tcp-max-conns", "tcp-max-conns-per-ip"} {
		if !slices.Contains(coordinatorEnvFlags, name) {
			t.Errorf("%s missing from coordinatorEnvFlags", name)
		}
	}
	for _, name := range []string{"post-quantum", "psk-rotation", "tcp-fallback", "disable-tcp-fallback", "keepalive", "adaptive-keepalive", "lazy-peers", "lazy-idle"} {
		if !slices.Contains(upEnvFlags, name) {
			t.Errorf("%s missing from upEnvFlags", name)
		}
	}
	h.run(exitUsage, "coordinator", "run", "--state-dir", t.TempDir(), "--tcp-listen", "vpn.example.com:443")
}

func TestConfigValidateChecksTransportFlags(t *testing.T) {
	h := newHarness(t)
	cfg := filepath.Join(t.TempDir(), "up.json")
	if err := writeTestFile(cfg, `{"lazy-peers": true, "keepalive": "3s"}`); err != nil {
		t.Fatal(err)
	}
	out := h.run(exitError, "config", "validate", "--config", cfg)
	if !strings.Contains(out, "keepalive") {
		t.Fatalf("output:\n%s", out)
	}
	if err := writeTestFile(cfg, `{"tcp-listen": ":443"}`); err != nil {
		t.Fatal(err)
	}
	h.run(exitOK, "config", "validate", "--for", "coordinator", "--config", cfg)
}

func TestCompletionWords(t *testing.T) {
	words := completionWords(nil)
	for _, w := range []string{"service", "network", "up", "completion", "help"} {
		if !slices.Contains(words, w) {
			t.Errorf("top level misses %q: %v", w, words)
		}
	}
	if got := completionWords([]string{"service"}); !slices.Contains(got, "install") || !slices.Contains(got, "status") || !slices.Contains(got, "run") {
		t.Errorf("service: %v", got)
	}
	if got := completionWords([]string{"service", "status", "--role"}); !slices.Equal(got, []string{"coordinator", "device"}) {
		t.Errorf("--role: %v", got)
	}
	if got := completionWords([]string{"set"}); !slices.Contains(got, "lazy-peers=") || !slices.Contains(got, "post-quantum=") {
		t.Errorf("set: %v", got)
	}
	h := newHarness(t)
	for _, sh := range []string{"bash", "zsh", "fish", "powershell"} {
		if out := h.run(exitOK, "completion", sh); !strings.Contains(out, "completion --list") {
			t.Errorf("%s script:\n%s", sh, out)
		}
	}
	h.run(exitUsage, "completion", "tcsh")
	if out := h.run(exitOK, "completion", "--list", "--", "log"); strings.TrimSpace(out) != "level" {
		t.Errorf("list: %q", out)
	}
}

func TestConfirmCritical(t *testing.T) {
	h := newHarness(t)
	if err := confirmCritical(h.env, "", "laptop", "x"); !errors.Is(err, errUsage) {
		t.Fatalf("no terminal, no --confirm: %v", err)
	}
	if err := confirmCritical(h.env, "laptop", "laptop", "x"); err != nil {
		t.Fatal(err)
	}
	if err := confirmCritical(h.env, "nas", "laptop", "x"); !errors.Is(err, errNotConfirmed) {
		t.Fatalf("wrong --confirm: %v", err)
	}
	h.env.IsTerminal = func() bool { return true }
	h.env.ReadLine = func(string) (string, error) { return "evet", nil }
	if err := confirmCritical(h.env, "", "laptop", "x"); !errors.Is(err, errNotConfirmed) {
		t.Fatal("a generic yes must not confirm a revocation")
	}
	h.env.ReadLine = func(string) (string, error) { return " laptop ", nil }
	if err := confirmCritical(h.env, "", "laptop", "x"); err != nil {
		t.Fatal(err)
	}
}

func TestRevokeAndWideRuleNeedConfirmation(t *testing.T) {
	h := newHarness(t)
	pass := "--passphrase-file=" + h.passFile
	h.run(exitOK, "network", "init", "--dir", h.netDir, pass)
	req, fp := h.keygen(filepath.Join(t.TempDir(), "laptop"), "laptop")
	h.run(exitOK, "device", "add", "--dir", h.netDir, "--request", req, "--fingerprint", fp, pass)

	h.run(exitUsage, "device", "revoke", "--dir", h.netDir, "--name", "laptop", pass)
	h.run(exitError, "device", "revoke", "--dir", h.netDir, "--name", "laptop", "--confirm", "nas", pass)
	h.run(exitOK, "device", "revoke", "--dir", h.netDir, "--name", "laptop", "--dry-run")

	h.run(exitUsage, "rule", "add", "--dir", h.netDir, "--from", "*", "--to", "*", "--proto", "any", pass)
	h.run(exitOK, "rule", "add", "--dir", h.netDir, "--from", "*", "--to", "*", "--proto", "any", "--confirm", wideRuleWord, pass)
	// A narrow rule needs nothing extra.
	h.run(exitOK, "rule", "add", "--dir", h.netDir, "--from", "*", "--to", "laptop", "--proto", "tcp", "--ports", "22", pass)
}

func TestServiceCommands(t *testing.T) {
	h := newHarness(t)
	var calls []string
	oldI, oldS, oldG := svcInstall, svcStart, svcGet
	defer func() { svcInstall, svcStart, svcGet = oldI, oldS, oldG }()
	svcInstall = func(_ context.Context, o svcmgr.Options) (svcmgr.Result, error) {
		calls = append(calls, "install "+string(o.Role)+" "+o.TCPListen)
		return svcmgr.Result{Binary: "/usr/local/bin/openscale", Started: true, Notes: []string{"not"}}, nil
	}
	svcStart = func(_ context.Context, r svcmgr.Role) error { calls = append(calls, "start "+string(r)); return nil }
	svcGet = func(context.Context, svcmgr.Role) (svcmgr.Status, error) {
		return svcmgr.Status{Installed: true, Running: false, State: "inactive (dead)"}, nil
	}
	out := h.run(exitOK, "service", "install", "--role", "coordinator", "--tcp-listen", ":443")
	if !strings.Contains(out, "/usr/local/bin/openscale") || !strings.Contains(out, "not") {
		t.Fatalf("install output:\n%s", out)
	}
	h.run(exitOK, "service", "start", "--role", "coordinator")
	h.run(exitUsage, "service", "start", "--role", "exit")
	h.run(exitUsage, "service", "install", "--tcp-listen", "host.example:443")
	out = h.run(exitError, "service", "status", "--json")
	if !strings.Contains(out, `"running": false`) || !strings.Contains(out, `"schema": 1`) {
		t.Fatalf("status output:\n%s", out)
	}
	if strings.Join(calls, ";") != "install coordinator :443;start coordinator" {
		t.Fatalf("calls = %q", calls)
	}
}

func TestWaitWithoutTunnel(t *testing.T) {
	h := newHarness(t)
	h.run(exitUsage, "wait", "--timeout", "0s")
	start := time.Now()
	out := h.run(exitError, "wait", "--timeout", "1s", "--state-dir", t.TempDir())
	if !strings.Contains(out, "hazır olmadı") || time.Since(start) > 10*time.Second {
		t.Fatalf("wait output:\n%s", out)
	}
}

func TestCleanupWithEmptyJournal(t *testing.T) {
	h := newHarness(t)
	dir := t.TempDir()
	if out := h.run(exitOK, "cleanup", "--state-dir", dir); !strings.Contains(out, "Geri alınacak bir değişiklik yok") {
		t.Fatalf("cleanup output:\n%s", out)
	}
	// A journal with an unknown kind (a newer version) is left alone.
	if err := service.OpenJournal(dir, nil).Begin(service.JournalEntry{Kind: "future-kind"}); err != nil {
		t.Fatal(err)
	}
	h.run(exitOK, "cleanup", "--state-dir", dir)
}

func writeTestFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}
