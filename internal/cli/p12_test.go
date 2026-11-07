package cli

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/bundlecrypt"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/securefile"
)

func TestExplain(t *testing.T) {
	h := newHarness(t)
	out := h.run(exitOK, "explain", "OS-3001")
	for _, want := range []string{"OS-3001: Koordinatör yanıt vermiyor", "Ne yapmalı:", "1. ", "openscale netcheck", "docs/sorun-giderme.md#os-3001"} {
		if !strings.Contains(out, want) {
			t.Fatalf("explain missing %q:\n%s", want, out)
		}
	}
	h.run(exitOK, "explain", "3001", "--json")
	var e struct {
		Schema int
		Code   string
		Steps  []string
	}
	if err := json.Unmarshal(h.stdout.Bytes(), &e); err != nil || e.Schema != 1 || e.Code != "OS-3001" || len(e.Steps) == 0 {
		t.Fatalf("json: %v %s", err, h.stdout)
	}
	if out := h.run(exitOK, "explain", "--list"); !strings.Contains(out, "OS-1001") || !strings.Contains(out, "OS-7003") {
		t.Fatalf("list:\n%s", out)
	}
	if out := h.run(exitOK, "explain", "--search", "resolv.conf"); !strings.Contains(out, "OS-4003") {
		t.Fatalf("search:\n%s", out)
	}
	h.run(exitError, "explain", "OS-7999")
	h.run(exitUsage, "explain", "abc")
	h.run(exitUsage, "explain")
	h.run(exitUsage, "explain", "OS-1001", "--list")
}

func TestErrorsCarryCodes(t *testing.T) {
	h := newHarness(t)
	h.run(exitOK, "network", "init", "--dir", h.netDir, "--passphrase-file="+h.passFile)
	wrong := filepath.Join(filepath.Dir(h.passFile), "yanlis.txt")
	if err := securefile.WriteNew(wrong, []byte("bambaşka bir parola 99\n")); err != nil {
		t.Fatal(err)
	}
	out := h.run(exitError, "network", "renew", "--dir", h.netDir, "--passphrase-file="+wrong)
	if !strings.Contains(out, "kod: OS-1001") || !strings.Contains(out, "openscale explain OS-1001") {
		t.Fatalf("no code:\n%s", out)
	}
	// Usage errors have no code line.
	if out := h.run(exitUsage, "network", "renew"); strings.Contains(out, "kod: OS-") {
		t.Fatalf("usage error with code:\n%s", out)
	}
}

func TestFormatTemplate(t *testing.T) {
	h := newHarness(t)
	if out := h.run(exitOK, "--format", "v={{.version}}", "version"); out != "v="+Version+"\n" {
		t.Fatalf("version: %q", out)
	}
	h.run(exitOK, "network", "init", "--dir", h.netDir, "--passphrase-file="+h.passFile)
	out := h.run(exitOK, "network", "report", "--dir", h.netDir, "--format={{.domain}} {{len .devices}} {{upper .network}}")
	if !regexp.MustCompile(`^\S+ 0 \S+\n$`).MatchString(out) {
		t.Fatalf("report: %q", out)
	}
	if out := h.run(exitOK, "explain", "OS-1001", "--format", "json"); !strings.HasPrefix(out, `{"area":"belge"`) && !strings.Contains(out, `"code":"OS-1001"`) {
		t.Fatalf("json shorthand: %q", out)
	}
	if out := h.run(exitOK, "explain", "--list", "--format", `{{range .codes}}{{.code}} {{end}}`); !strings.HasPrefix(out, "OS-1001 OS-1002") {
		t.Fatalf("range: %q", out)
	}
	h.run(exitUsage, "--format", "{{.version", "version")
	h.run(exitUsage, "version", "--format")
	// A command without JSON output cannot be formatted.
	if out := h.run(exitUsage, "--format", "{{.}}", "network", "init", "--dir", filepath.Join(t.TempDir(), "x")); !strings.Contains(out, "json") {
		t.Fatalf("no json: %q", out)
	}
}

func TestWithJSONFlag(t *testing.T) {
	cases := map[string]string{
		"version":                        "version --json",
		"network report --dir x":         "network report --json --dir x",
		"--network ev status":            "--network ev status --json",
		"explain OS-1 --json":            "explain OS-1 --json",
		"bilinmeyen komut":               "bilinmeyen komut",
		"--network=ev traffic history a": "--network=ev traffic history --json a",
	}
	for in, want := range cases {
		if got := strings.Join(withJSONFlag(strings.Fields(in)), " "); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
	if _, _, found, err := extractFormat([]string{"status", "--", "--format", "x"}); found || err != nil {
		t.Fatal("format after --")
	}
}

func TestNetworkReportCommand(t *testing.T) {
	h := newHarness(t)
	h.run(exitOK, "network", "init", "--dir", h.netDir, "--passphrase-file="+h.passFile)
	out := h.run(exitOK, "network", "report", "--dir", h.netDir)
	if !strings.Contains(out, "## Cihazlar (0)") || !strings.Contains(out, "Kural yok") {
		t.Fatalf("md:\n%s", out)
	}
	file := filepath.Join(t.TempDir(), "rapor.html")
	h.run(exitOK, "network", "report", "--dir", h.netDir, "--html", "--out", file)
	data, err := os.ReadFile(file)
	if err != nil || !bytes.HasPrefix(data, []byte("<!doctype html>")) {
		t.Fatalf("html: %v", err)
	}
	h.run(exitError, "network", "report", "--dir", h.netDir, "--html", "--out", file) // never overwrites
	h.run(exitUsage, "network", "report")
	h.run(exitUsage, "network", "report", "--dir", h.netDir, "--html", "--json")
}

func TestSealedBundleRoundTrip(t *testing.T) {
	h := newHarness(t)
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "yardimci.key")
	out := h.run(exitOK, "debug", "bundle-key", "--out", keyFile)
	pub := regexp.MustCompile(`osbk1:[A-Za-z0-9_-]+`).FindString(out)
	if pub == "" || !strings.Contains(out, "Parmak izi:") {
		t.Fatalf("bundle-key:\n%s", out)
	}
	if again := h.run(exitOK, "debug", "bundle-key", "--out", keyFile, "--show"); !strings.Contains(again, pub) {
		t.Fatalf("show:\n%s", again)
	}
	h.run(exitError, "debug", "bundle-key", "--out", keyFile) // never overwrites a key

	to, err := bundleRecipient(pub)
	if err != nil {
		t.Fatal(err)
	}
	rep := panel.BundleReply{CreatedAt: time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC), Files: []panel.BundleFile{{Name: "README.txt", Content: "merhaba"}}}
	sealed := filepath.Join(dir, "paket.osb")
	if err := writeSealedBundle(h.env, rep, to, sealed, false); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(sealed)
	if !bundlecrypt.IsSealed(raw) || bytes.Contains(raw, []byte("merhaba")) {
		t.Fatal("bundle not sealed")
	}
	zipFile := filepath.Join(dir, "paket.zip")
	h.run(exitOK, "debug", "bundle-open", "--key", keyFile, "-o", zipFile, sealed)
	zr, err := zip.OpenReader(zipFile)
	if err != nil || len(zr.File) != 1 || zr.File[0].Name != "openscale-teshis/README.txt" {
		t.Fatalf("zip: %v", err)
	}
	zr.Close()

	other := filepath.Join(dir, "baska.key")
	h.run(exitOK, "debug", "bundle-key", "--out", other)
	if out := h.run(exitError, "debug", "bundle-open", "--key", other, "-o", filepath.Join(dir, "x.zip"), sealed); !strings.Contains(out, "başka bir alıcı") {
		t.Fatalf("wrong key:\n%s", out)
	}
	h.run(exitUsage, "debug", "bundle", "--to", "osbk1:bozuk")
	h.run(exitUsage, "debug", "bundle-open", "--key", keyFile, sealed)
}

// fakeTUISource is the terminal interface's data in tests.
type fakeTUISource struct {
	exit string
	sets []string
}

func (f *fakeTUISource) Status(context.Context) (panel.DiagStatus, error) {
	return panel.DiagStatus{Running: true, Connected: true, ExitNode: f.exit, Self: &panel.DiagSelf{Name: "laptop"},
		Peers: []panel.DiagPeer{
			{Name: "nas", Online: true, Path: panel.PathDirect, RxBytes: 2048},
			{Name: "vps", Online: true, Path: panel.PathRelay, ExitNode: true, ActiveExit: f.exit == "vps"},
		}}, nil
}
func (f *fakeTUISource) Events(_ context.Context, since uint64) (panel.EventStreamReply, error) {
	if since == 0 {
		return panel.EventStreamReply{Next: 5}, nil
	}
	return panel.EventStreamReply{Next: since + 1, Events: []panel.StreamEvent{{Seq: since, Severity: "info", Message: "olay\x1b[2Jtemiz"}}}, nil
}
func (f *fakeTUISource) SetExit(_ context.Context, name string) error {
	if name == "nas" {
		return errors.New("nas bir çıkış düğümü değil")
	}
	f.exit = name
	f.sets = append(f.sets, name)
	return nil
}

func TestTUIKeysAndRender(t *testing.T) {
	src := &fakeTUISource{}
	// down, x (vps), confirm, l (log), n, confirm, x on nas is refused locally, q.
	pr, pw := io.Pipe()
	var out bytes.Buffer
	done := make(chan error, 1)
	go func() {
		done <- runTUI(context.Background(), src, pr, &out, func() (int, int) { return 100, 20 }, time.Now, time.Hour)
	}()
	for _, k := range []string{"\x1b[B", "x", "e", "l", "r", "n", "e", "\x1b[A", "x", "q"} {
		if _, err := pw.Write([]byte(k)); err != nil {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("tui did not quit")
	}
	if strings.Join(src.sets, ",") != "vps," {
		t.Fatalf("exit changes: %q", src.sets)
	}
	screen := out.String()
	for _, want := range []string{"cihaz: laptop", "vps", "Çıkış düğümü: vps", "Çıkış düğümü kapatıldı.", "nas bir çıkış düğümü değil.", "olay"} {
		if !strings.Contains(screen, want) {
			t.Errorf("screen missing %q", want)
		}
	}
	if strings.Contains(screen, "\x1b[2J") {
		t.Fatal("control sequence from an event reached the terminal")
	}
}

func TestTUIRequiresTerminal(t *testing.T) {
	h := newHarness(t)
	if out := h.run(exitError, "tui"); !strings.Contains(out, "etkileşimli") {
		t.Fatalf("tui without terminal:\n%s", out)
	}
}

func TestMQTTConfigCommands(t *testing.T) {
	h := newHarness(t)
	cfg := filepath.Join(t.TempDir(), "mqtt.json")
	pw := filepath.Join(t.TempDir(), "parola")
	if err := securefile.WriteNew(pw, []byte("aracı-parolası\n")); err != nil {
		t.Fatal(err)
	}
	out := h.run(exitOK, "mqtt", "init", "--config", cfg, "--broker", "192.168.1.20", "--user", "ev", "--password-file", pw, "--events", "security")
	if !strings.Contains(out, "openscale/<cihaz>/availability") || !strings.Contains(out, "düz metin") {
		t.Fatalf("init:\n%s", out)
	}
	out = h.run(exitOK, "mqtt", "show", "--config", cfg)
	if strings.Contains(out, "aracı-parolası") || !strings.Contains(out, "192.168.1.20:1883") {
		t.Fatalf("show:\n%s", out)
	}
	h.run(exitError, "mqtt", "init", "--config", cfg, "--broker", "h:1883", "--prefix", "a/#")
	h.run(exitOK, "mqtt", "off", "--config", cfg)
	h.run(exitError, "mqtt", "show", "--config", cfg)
	h.run(exitUsage, "mqtt")
	h.run(exitUsage, "mqtt", "bilinmeyen", "--config", cfg)
}
