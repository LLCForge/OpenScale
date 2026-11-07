package node

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/openscale/openscale/internal/adblock"
	"github.com/openscale/openscale/internal/plugin"
	"github.com/openscale/openscale/internal/trust"
)

func g7Query(t *testing.T, name string, typ dnsmessage.Type) clientQuery {
	t.Helper()
	cq, err := parseClientQuery(dnsQuery(t, 9, name, typ, 1232))
	if err != nil {
		t.Fatal(err)
	}
	return cq
}

func g7RCode(t *testing.T, out []byte) dnsmessage.RCode {
	t.Helper()
	var p dnsmessage.Parser
	h, err := p.Start(out)
	if err != nil {
		t.Fatal(err)
	}
	return h.RCode
}

func g7Reset(t *testing.T) {
	t.Helper()
	t.Cleanup(func() { _ = ReloadExitExtensions(context.Background(), "", nil, false) })
}

func g7Dir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("testdata", ".g7tmp", t.Name()))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(filepath.Join("testdata", ".g7tmp")) })
	return dir
}

func g7Doc(t *testing.T) *trust.Document {
	t.Helper()
	doc, err := trust.NewDocument(strings.Repeat("ab", 16), "ev.test", netip.MustParsePrefix("100.64.0.0/24"), netip.MustParsePrefix("fd7a:115c:a1e0::/64"), time.Now(), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestG7DocumentFieldsValidate(t *testing.T) {
	doc := g7Doc(t)
	pol := adblock.Policy{Default: adblock.SetOf(adblock.CategoryOSTelemetry)}
	if err := doc.SetBlocking(&trust.BlockingSettings{Policy: &pol}); err == nil {
		t.Fatal("os-telemetry without keep list accepted")
	}
	if err := doc.SetBlocking(&trust.BlockingSettings{Policy: &pol, Keep: []string{"update.microsoft.com"}}); err != nil {
		t.Fatal(err)
	}
	if err := doc.SetBlocking(&trust.BlockingSettings{BlockDoH: []string{"Dns.Example.com"}}); err == nil {
		t.Fatal("upper case DoH name accepted")
	}
	good := strings.Repeat("a", 64)
	if err := doc.SetPluginPin(trust.PluginPin{Name: "x", ModuleSHA256: good, ManifestSHA256: "ABC"}); err == nil {
		t.Fatal("bad digest accepted")
	}
	if err := doc.SetPluginPin(trust.PluginPin{Name: "Bad Name", ModuleSHA256: good, ManifestSHA256: good}); err == nil {
		t.Fatal("bad name accepted")
	}
	if err := doc.SetPluginPin(trust.PluginPin{Name: "ornek", ModuleSHA256: good, ManifestSHA256: good}); err != nil {
		t.Fatal(err)
	}
	if err := doc.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := doc.RemovePluginPin("ornek"); err != nil || doc.Plugins != nil {
		t.Fatalf("remove: %v %v", err, doc.Plugins)
	}
	// Without the fields the document encodes as before (omitempty).
	plain := g7Doc(t)
	if err := plain.SetBlocking(&trust.BlockingSettings{}); err != nil || plain.Blocking != nil {
		t.Fatal("empty blocking kept")
	}
}

func TestG7PolicyAnswer(t *testing.T) {
	g7Reset(t)
	doc := g7Doc(t)
	pol := adblock.Policy{Default: adblock.SetOf(adblock.CategoryAds), Exceptions: []string{"ok.ads.test"}}
	if err := doc.SetBlocking(&trust.BlockingSettings{Policy: &pol, BlockDoH: []string{"doh.example.net"}}); err != nil {
		t.Fatal(err)
	}
	if err := ReloadExitExtensions(context.Background(), g7Dir(t), doc, true); err != nil {
		t.Fatal(err)
	}
	// Install a matcher with a listed name the way a downloaded list would.
	b := adblock.NewBuilder()
	if _, err := b.AddList(adblock.CategoryAds, strings.NewReader("ads.test\n")); err != nil {
		t.Fatal(err)
	}
	if err := ExitAdblockEngine().Install(b.Build(), pol); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	member := exitClient{name: "laptop"}
	cases := []struct {
		name     string
		decision string
	}{
		{"x.ads.test.", DecisionCategory},
		{"doh.example.net.", DecisionDoH},
		{"abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion.", DecisionOnion},
	}
	for _, c := range cases {
		out, d, ok, _ := g7PolicyAnswer(member, g7Query(t, c.name, dnsmessage.TypeA), now)
		if !ok || d != c.decision || g7RCode(t, out) != dnsmessage.RCodeNameError {
			t.Fatalf("%s: ok=%v decision=%q", c.name, ok, d)
		}
	}
	if _, _, ok, _ := g7PolicyAnswer(member, g7Query(t, "ok.ads.test.", dnsmessage.TypeA), now); ok {
		t.Fatal("exception blocked")
	}
	if _, _, ok, _ := g7PolicyAnswer(exitClient{name: "tv", noBlocklist: true}, g7Query(t, "x.ads.test.", dnsmessage.TypeA), now); ok {
		t.Fatal("profile without block list blocked")
	}
	st := ExitExtensions()
	if !st.Active || st.Onion != 1 || st.DoH != 1 || st.Adblock == nil || st.Adblock.Blocked["ads"] != 1 {
		t.Fatalf("status %+v", st)
	}
	// Turning the role off removes everything.
	if err := ReloadExitExtensions(context.Background(), "", doc, false); err != nil {
		t.Fatal(err)
	}
	if _, _, ok, _ := g7PolicyAnswer(member, g7Query(t, "x.ads.test.", dnsmessage.TypeA), now); ok {
		t.Fatal("answered while off")
	}
}

func TestG7PluginHook(t *testing.T) {
	g7Reset(t)
	dir := g7Dir(t)
	src := filepath.Join("..", "plugin", "testdata", "plugins")
	pdir := filepath.Join(dir, plugin.DirName)
	if err := os.MkdirAll(pdir, 0o700); err != nil {
		t.Fatal(err)
	}
	var pin trust.PluginPin
	pin.Name = "ornek-engel"
	for _, ext := range []string{".wasm", ".json"} {
		data, err := os.ReadFile(filepath.Join(src, pin.Name+ext))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(pdir, pin.Name+ext), data, 0o600); err != nil {
			t.Fatal(err)
		}
		if ext == ".wasm" {
			pin.ModuleSHA256 = plugin.Digest(data)
		} else {
			pin.ManifestSHA256 = plugin.Digest(data)
		}
	}
	doc := g7Doc(t)
	if err := doc.SetPluginPin(pin); err != nil {
		t.Fatal(err)
	}
	if err := ReloadExitExtensions(context.Background(), dir, doc, true); err != nil {
		t.Fatal(err)
	}
	st := ExitExtensions()
	if len(st.Plugins) != 1 || st.Plugins[0].Status != plugin.StatusLoaded {
		t.Fatalf("plugins %+v", st.Plugins)
	}
	out, d, ok, _ := g7PolicyAnswer(exitClient{name: "laptop"}, g7Query(t, "a.example.", dnsmessage.TypeA), time.Now())
	if !ok || d != DecisionPlugin || g7RCode(t, out) != dnsmessage.RCodeNameError {
		t.Fatalf("plugin did not block: %v %q", ok, d)
	}
	if _, _, ok, _ := g7PolicyAnswer(exitClient{name: "laptop"}, g7Query(t, "a.test.", dnsmessage.TypeA), time.Now()); ok {
		t.Fatal("plugin blocked an unrelated name")
	}
	// A changed module no longer matches its pin and is not loaded.
	if err := os.WriteFile(filepath.Join(pdir, pin.Name+".wasm"), []byte("\x00asm\x01\x00\x00\x00"), 0o600); err != nil {
		t.Fatal(err)
	}
	doc.Version++
	_ = ReloadExitExtensions(context.Background(), dir, doc, true)
	if st := ExitExtensions(); len(st.Plugins) != 1 || st.Plugins[0].Status == plugin.StatusLoaded {
		t.Fatalf("tampered plugin loaded: %+v", st.Plugins)
	}
}

func TestG7RewriteRefusesPrivate(t *testing.T) {
	cq := g7Query(t, "x.test.", dnsmessage.TypeA)
	for _, a := range []string{"10.0.0.1", "127.0.0.1", "192.168.1.1", "169.254.1.1", "0.0.0.0"} {
		if _, ok := g7RewriteAnswer(cq, netip.MustParseAddr(a)); ok {
			t.Fatalf("%s accepted", a)
		}
	}
	out, ok := g7RewriteAnswer(cq, netip.MustParseAddr("192.0.2.10"))
	if !ok {
		t.Fatal("documentation address refused")
	}
	var p dnsmessage.Parser
	if _, err := p.Start(out); err != nil {
		t.Fatal(err)
	}
	_ = p.SkipAllQuestions()
	ans, err := p.AllAnswers()
	if err != nil || len(ans) != 1 {
		t.Fatalf("answers %v %v", ans, err)
	}
}
