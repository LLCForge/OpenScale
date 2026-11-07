package cli

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
)

// --- #798 name suggestions ---

func TestUnknownNamesGetSuggestions(t *testing.T) {
	h := newHarness(t)
	pass := policyNetwork(t, h)
	dir := []string{"--dir", h.netDir, pass}

	out := h.run(exitError, append([]string{"device", "extend", "--name", "lapotp"}, dir...)...)
	mustContain(t, out, "Cihaz bulunamadı", `"lapotp" adlı cihaz yok`, "Bunu mu demek istediniz: laptop?")
	out = h.run(exitError, append([]string{"device", "revoke", "--name", "Masaüstü", "--confirm", "Masaüstü"}, dir...)...)
	mustContain(t, out, "Bunu mu demek istediniz: masaustu?")
	out = h.run(exitError, append([]string{"rule", "add", "--from", "laptop", "--to", "masaustuu", "--proto", "any"}, dir...)...)
	mustContain(t, out, "masaustu?")

	h.run(exitOK, append([]string{"group", "set", "--name", "ofis", "--members", "laptop"}, dir...)...)
	out = h.run(exitError, append([]string{"group", "rm", "--name", "ofsi"}, dir...)...)
	mustContain(t, out, "group:ofis?")

	// Tags: an unused reference is a warning, with the closest real tag.
	h.run(exitOK, append([]string{"device", "tag", "--name", "laptop", "--tags", "sunucu"}, dir...)...)
	h.run(exitOK, append([]string{"rule", "add", "--from", "tag:sunucuu", "--to", "masaustu", "--proto", "any"}, dir...)...)
	mustContain(t, h.run(exitOK, "group", "list", "--dir", h.netDir), "UYARI: tag:sunucuu", "Bunu mu demek istediniz: tag:sunucu?")

	// Nothing close: the message stays as before, without a hint.
	out = h.run(exitError, append([]string{"device", "extend", "--name", "zzzzzzzz"}, dir...)...)
	if strings.Contains(out, "Bunu mu demek") {
		t.Fatalf("far name got a hint:\n%s", out)
	}
}

func TestSuggestionsSkipMembersOnlyPseudonyms(t *testing.T) {
	ids := []string{"0123456789abcdef0123456789abcdef", "fedcba9876543210fedcba9876543210"}
	doc := &trust.Document{Devices: []trust.Device{
		{ID: ids[0], Name: trust.PublicDeviceName(ids[0])},
		{ID: ids[1], Name: "laptop"},
	}}
	if got := knownDeviceNames(doc); len(got) != 2 {
		t.Fatalf("full document: %v", got)
	}
	doc.MembersOnly = &trust.MembersOnly{}
	if got := knownDeviceNames(doc); !slices.Equal(got, []string{"laptop"}) {
		t.Fatalf("public part: %v", got)
	}
	if got := knownDeviceNames(nil); got != nil {
		t.Fatalf("nil: %v", got)
	}
}

// --- #863 openscale prompt ---

func usePromptCache(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	old := promptCacheDir
	promptCacheDir = func() (string, error) { return dir, nil }
	t.Cleanup(func() { promptCacheDir = old })
	return dir
}

func TestPromptPrintsNothingWithoutTunnel(t *testing.T) {
	usePromptCache(t)
	h := newHarness(t)
	start := time.Now()
	if out := h.run(exitOK, "prompt"); out != "" {
		t.Fatalf("no tunnel must print nothing: %q", out)
	}
	if time.Since(start) > time.Second {
		t.Fatal("prompt waited")
	}
	h.run(exitUsage, "prompt", "--timeout", "10s")
	h.run(exitUsage, "prompt", "--format", "{{.yok")
	if out := h.run(exitOK, "prompt", "--format", "{{.state}}"); out != "" {
		t.Fatalf("format without tunnel: %q", out)
	}
	mustContain(t, h.run(exitOK, "prompt", "-h"), "PS1=", "PROMPT_SUBST", "fish_prompt", "$PROFILE")
}

func TestPromptThroughLocalAPIAndCache(t *testing.T) {
	cache := usePromptCache(t)
	h := newHarness(t)
	serveFake(t, h, &fakeDiag{level: "info"})
	if out := h.run(exitOK, "prompt", "--timeout", "2s"); out != "os:bağlı" {
		t.Fatalf("default format: %q", out)
	}
	if out := h.run(exitOK, "prompt", "--no-cache", "--timeout", "2s", "--format", "{{.device}}|{{.warnings}}|{{.connected}}"); out != "laptop|0|true\n" {
		t.Fatalf("template: %q", out)
	}
	mustContain(t, h.run(exitOK, "prompt", "--no-cache", "--timeout", "2s", "--json"), `"state":"bağlı"`, `"device":"laptop"`)
	data, err := os.ReadFile(filepath.Join(cache, promptCacheFile))
	if err != nil || !strings.Contains(string(data), `"state":"bağlı"`) || strings.Contains(string(data), strings.Repeat("a", 43)) {
		t.Fatalf("cache must hold the status only: %v %s", err, data)
	}

	// A fresh cache answers without the tunnel; a stale one does not.
	h2 := newHarness(t)
	writePromptCache(promptInfo{Connected: true, State: "bağlı", Exit: "vps", Warnings: 2, At: h2.env.Now()}, "")
	if out := h2.run(exitOK, "prompt"); out != "os:bağlı çıkış:vps !2" {
		t.Fatalf("cache: %q", out)
	}
	writePromptCache(promptInfo{Connected: true, State: "bağlı", At: h2.env.Now().Add(-time.Minute)}, "")
	if out := h2.run(exitOK, "prompt"); out != "" {
		t.Fatalf("stale cache: %q", out)
	}
}

func TestPromptDoesNotWaitForSlowService(t *testing.T) {
	usePromptCache(t)
	h := newHarness(t)
	release := make(chan struct{})
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv.Listener = ln
	srv.Start()
	t.Cleanup(func() { close(release); srv.Close() })
	dir, _ := h.env.DefaultStateDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	if err := securefile.Replace(filepath.Join(dir, localAPIFile), []byte(`{"port":`+port+`,"token":"`+strings.Repeat("b", 43)+`"}`)); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if out := h.run(exitOK, "prompt", "--timeout", "30ms"); out != "" {
		t.Fatalf("slow service: %q", out)
	}
	if d := time.Since(start); d > 700*time.Millisecond {
		t.Fatalf("prompt waited %v", d)
	}
}

// --- #815 openscale forward ---

func forwardDoc() *trust.Document {
	return &trust.Document{DNSDomain: "ag.test", Devices: []trust.Device{
		{Name: "laptop", IPv4: netip.MustParseAddr("100.64.0.2")},
		{Name: "nas", IPv4: netip.MustParseAddr("100.64.0.3")},
	}}
}

func TestForwardArgumentsAndTarget(t *testing.T) {
	local, name, port, err := parseForwardArgs([]string{"8080", "NAS:80"})
	if err != nil || local != 8080 || name != "nas" || port != 80 {
		t.Fatalf("parse: %d %s %d %v", local, name, port, err)
	}
	for _, bad := range [][]string{{"8080"}, {"x", "nas:80"}, {"70000", "nas:80"}, {"80", "nas"}, {"80", "nas:0"}, {"80", ":80"}, {"80", "nas:80:1"}} {
		if _, _, _, err := parseForwardArgs(bad); err == nil {
			t.Fatalf("accepted %v", bad)
		}
	}
	doc := forwardDoc()
	tg, err := resolveForwardTarget(doc, "laptop", "nas.ag.test", 80)
	if err != nil || tg.addr.String() != "100.64.0.3:80" || tg.device != "nas" {
		t.Fatalf("target: %+v %v", tg, err)
	}
	if _, err := resolveForwardTarget(doc, "laptop", "nsa", 80); err == nil || !strings.Contains(suggestionHint(err), "nas?") {
		t.Fatalf("unknown target: %v", err)
	}
	if _, err := resolveForwardTarget(doc, "laptop", "100.64.0.3", 80); err == nil {
		t.Fatal("an address outside the document's names must be refused")
	}
	if _, err := resolveForwardTarget(doc, "laptop", "laptop", 80); err == nil {
		t.Fatal("self target")
	}
	if _, err := resolveForwardTarget(nil, "", "nas", 80); err == nil {
		t.Fatal("no document")
	}
}

func TestForwardCopiesLoopbackConnections(t *testing.T) {
	echo, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	ln, err := listenForward(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if a := ln.Addr().(*net.TCPAddr); !a.IP.IsLoopback() {
		t.Fatalf("listener must be on 127.0.0.1: %v", a)
	}
	done := make(chan error, 1)
	go func() { done <- runForward(ctx, ln, echo.Addr().String(), "laptop") }()
	c, err := net.DialTimeout("tcp4", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte("merhaba")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 7)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "merhaba" {
		t.Fatalf("echo: %q %v", buf, err)
	}
	_ = c.Close()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("forward: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("forward did not stop")
	}
}

func TestForwardResolverAcceptsOnlyLoopback(t *testing.T) {
	r := loopbackResolver{self: "laptop"}
	if res, _ := r.WhoIs(context.Background(), "127.0.0.1"); res.Device == nil || !res.Device.Self {
		t.Fatalf("loopback: %+v", res)
	}
	for _, a := range []string{"192.168.1.5", "100.64.0.9", "x"} {
		if res, _ := r.WhoIs(context.Background(), a); res.Device != nil {
			t.Fatalf("%s accepted", a)
		}
	}
}

// --- #792 setup resume ---

func TestSetupResumesAtBackupAndRecordsNoSecrets(t *testing.T) {
	h := newHarness(t)
	policyNetwork(t, h) // root key without a backup, two devices
	out := h.run(exitOK, "setup", "--dir", h.netDir, "--plan")
	mustContain(t, out, "Eksik adımlar (2): Kök anahtar yedeği, Koordinatör")

	answers := []string{"", ""} // skip the backup, skip the coordinator
	h.env.IsTerminal = func() bool { return true }
	h.env.ReadLine = func(string) (string, error) {
		if len(answers) == 0 {
			return "", io.EOF
		}
		a := answers[0]
		answers = answers[1:]
		return a, nil
	}
	out = h.run(exitOK, "setup", "--dir", h.netDir)
	mustContain(t, out, "Kaldığınız yerden devam", "2/4  Kök anahtar yedeği", "Yedek atlandı")
	if strings.Index(out, "2/4") > strings.Index(out, "3/4") {
		t.Fatalf("backup must come first:\n%s", out)
	}
	data, err := os.ReadFile(filepath.Join(h.netDir, setupProgressFile))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"parola", "çok gizli", h.passFile, "root"} {
		if strings.Contains(string(data), secret) {
			t.Fatalf("progress record holds %q: %s", secret, data)
		}
	}
	p := readSetupProgress(h.netDir)
	if !slices.Equal(p.Skipped, []string{setupStepBackup, setupStepCoordinator}) {
		t.Fatalf("skipped: %+v", p)
	}
	answers = []string{"", ""}
	mustContain(t, h.run(exitOK, "setup", "--dir", h.netDir), "atlanan adımlar: Kök anahtar yedeği, Koordinatör")

	p.mark(setupStepBackup, false)
	if slices.Contains(p.Skipped, setupStepBackup) {
		t.Fatal("mark done")
	}
	if got := missingSteps(setupState{network: true, backups: 1, coordinator: true, devices: 1}); len(got) != 0 {
		t.Fatalf("complete: %v", got)
	}
}

// --- #825 device retire ---

func TestDeviceRetireCommand(t *testing.T) {
	h := newHarness(t)
	pass := policyNetwork(t, h)
	dir := []string{"--dir", h.netDir, pass}
	h.run(exitOK, append([]string{"rule", "add", "--from", "laptop", "--to", "masaustu", "--proto", "tcp", "--ports", "3389"}, dir...)...)
	h.run(exitOK, append([]string{"group", "set", "--name", "ofis", "--members", "masaustu"}, dir...)...)

	out := h.run(exitOK, append([]string{"device", "retire", "--name", "masaustu", "--dry-run"}, dir...)...)
	mustContain(t, out, "Emekliye ayrılacak cihaz: masaustu", "Erişim kuralları", "Kural silinir", "group:ofis", "Kuru çalıştırma")
	mustContain(t, h.run(exitOK, "device", "retire", "--dir", h.netDir, "--name", "masaustu", "--json"), `"device": "masaustu"`, `"sections"`)
	mustContain(t, h.run(exitError, append([]string{"device", "retire", "--name", "masastu"}, dir...)...), "masaustu?")
	h.run(exitUsage, append([]string{"device", "retire", "--name", "masaustu"}, dir...)...) // no terminal, no --confirm

	out = h.run(exitOK, append([]string{"device", "retire", "--name", "masaustu", "--confirm", "masaustu"}, dir...)...)
	mustContain(t, out, "imzalandı")
	mustContain(t, h.run(exitError, append([]string{"device", "retire", "--name", "masaustu", "--confirm", "masaustu"}, dir...)...), "Cihaz bulunamadı")
}
