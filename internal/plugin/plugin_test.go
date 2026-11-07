package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"
)

var update = flag.Bool("update", false, "rewrite testdata/plugins/ornek-engel.wasm from the test encoder")

type recorder struct {
	mu     sync.Mutex
	events []Event
}

func (r *recorder) add(e Event) { r.mu.Lock(); r.events = append(r.events, e); r.mu.Unlock() }

func (r *recorder) kinds() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var k []string
	for _, e := range r.events {
		k = append(k, e.Kind)
	}
	return k
}

func manifestJSON(t *testing.T, m Manifest) []byte {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func dnsManifest(name string, data ...string) Manifest {
	return Manifest{ABI: 1, Name: name, Version: "1.0.0", Hooks: []string{HookDNS}, Data: append([]string{DataDNSName}, data...), OnError: OnErrorPass}
}

type testPlugin struct {
	m      Manifest
	module []byte
}

// newTestHost pins and loads the given plugins from an in-memory folder.
func newTestHost(t *testing.T, opt Options, ps ...testPlugin) (*Host, *recorder) {
	t.Helper()
	fsys := fstest.MapFS{}
	var pins PinList
	for _, p := range ps {
		mb := manifestJSON(t, p.m)
		fsys[p.m.Name+".json"] = &fstest.MapFile{Data: mb}
		fsys[p.m.Name+".wasm"] = &fstest.MapFile{Data: p.module}
		pins = append(pins, Pin{Name: p.m.Name, ModuleSHA256: Digest(p.module), ManifestSHA256: Digest(mb)})
	}
	st, err := LoadStore(fsys, pins)
	if err != nil {
		t.Fatal(err)
	}
	rec := &recorder{}
	opt.OnEvent = rec.add
	h, err := NewHost(context.Background(), st, opt)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.Close(context.Background()) })
	return h, rec
}

func dnsModule(body []byte, locals int, extra ...wfunc) []byte {
	return wmod{funcs: append([]wfunc{fnVersion, fnBuffer, hook("osp_dns_query", locals, body)}, extra...)}.bytes()
}

func TestExamplePluginBlocksExampleTLD(t *testing.T) {
	h, rec := newTestHost(t, Options{}, testPlugin{dnsManifest("ornek-engel"), exampleModule()})
	if h.Loaded() != 1 {
		t.Fatalf("loaded %d, entries %+v", h.Loaded(), h.Entries())
	}
	cases := map[string]Verdict{
		"reklam.ornek.example": VerdictBlock,
		"A.B.EXAMPLE.":         VerdictBlock,
		"x.example":            VerdictBlock,
		"example":              VerdictPass,
		"site.test":            VerdictPass,
		"example.test":         VerdictPass,
		"notexample":           VerdictPass,
	}
	for name, want := range cases {
		d := h.DNSQuery(context.Background(), DNSQuery{Name: name, QType: qtypeA})
		if d.Verdict != want {
			t.Errorf("%s: verdict %v, want %v", name, d.Verdict, want)
		}
		if want == VerdictBlock && (d.Plugin != "ornek-engel" || d.Fallback) {
			t.Errorf("%s: decision %+v", name, d)
		}
	}
	if len(rec.kinds()) != 0 {
		t.Fatalf("events %v", rec.kinds())
	}
	if d := h.DNSQuery(context.Background(), DNSQuery{Name: "bad name.example"}); d.Verdict != VerdictPass {
		t.Fatalf("invalid name reached a plugin: %+v", d)
	}
}

func TestInfiniteLoopIsCut(t *testing.T) {
	m := dnsManifest("dongu")
	m.OnError = OnErrorBlock
	h, rec := newTestHost(t, Options{CallTimeout: 30 * time.Millisecond}, testPlugin{m, dnsModule(infiniteBody, 0)})
	start := time.Now()
	d := h.DNSQuery(context.Background(), DNSQuery{Name: "a.test", QType: qtypeA})
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("call took %v", el)
	}
	if d.Verdict != VerdictBlock || !d.Fallback {
		t.Fatalf("decision %+v, want block from on_error", d)
	}
	if k := rec.kinds(); len(k) != 1 || k[0] != EventTimeout {
		t.Fatalf("events %v", k)
	}
}

func TestOnErrorPassAndAllow(t *testing.T) {
	trapPass := dnsManifest("tuzak")
	allow := dnsManifest("tuzak-izin")
	allow.OnError = OnErrorAllow
	h, rec := newTestHost(t, Options{},
		testPlugin{trapPass, dnsModule(trapBody, 0)},
		testPlugin{dnsManifest("ornek-engel"), exampleModule()})
	if d := h.DNSQuery(context.Background(), DNSQuery{Name: "a.example", QType: qtypeA}); d.Verdict != VerdictBlock || d.Plugin != "ornek-engel" {
		t.Fatalf("pass on error must let the next plugin decide: %+v", d)
	}
	if k := rec.kinds(); len(k) != 1 || k[0] != EventTrap {
		t.Fatalf("events %v", k)
	}
	h2, _ := newTestHost(t, Options{},
		testPlugin{allow, dnsModule(trapBody, 0)},
		testPlugin{dnsManifest("ornek-engel"), exampleModule()})
	if d := h2.DNSQuery(context.Background(), DNSQuery{Name: "a.example", QType: qtypeA}); d.Verdict != VerdictAllow || !d.Fallback {
		t.Fatalf("allow on error: %+v", d)
	}
}

func TestMemoryLimit(t *testing.T) {
	big := wmod{memMin: MaxMemoryPages + 1, funcs: []wfunc{fnVersion, fnBuffer, hook("osp_dns_query", 0, setVerdict(0))}}.bytes()
	m := dnsManifest("buyuk-bellek")
	h, rec := newTestHost(t, Options{}, testPlugin{m, big})
	if h.Loaded() != 0 || h.Entries()[0].Status != StatusInvalid {
		t.Fatalf("module over the memory limit loaded: %+v", h.Entries())
	}
	if k := rec.kinds(); len(k) != 1 || k[0] != EventRejected {
		t.Fatalf("events %v", k)
	}

	g := dnsManifest("buyume")
	g.OnError = OnErrorBlock
	h2, rec2 := newTestHost(t, Options{}, testPlugin{g, dnsModule(growBody, 0)})
	if h2.Loaded() != 1 {
		t.Fatal(h2.Entries())
	}
	if d := h2.DNSQuery(context.Background(), DNSQuery{Name: "a.test", QType: qtypeA}); d.Verdict != VerdictBlock || !d.Fallback {
		t.Fatalf("decision %+v", d)
	}
	if k := rec2.kinds(); len(k) != 1 || k[0] != EventTrap {
		t.Fatalf("memory.grow past the limit must fail (module traps on -1): %v", k)
	}
}

func TestUndeclaredDataIsNotGiven(t *testing.T) {
	// Same module; only the manifest differs.
	mod := dnsModule(tagsDNSBody, 1, hook("osp_http_location", 2, stripQueryBody))
	noTags := dnsManifest("etiketsiz")
	h, rec := newTestHost(t, Options{}, testPlugin{noTags, mod})
	q := DNSQuery{Name: "a.test", QType: qtypeA, ClientTags: []string{"tag:cocuk"}}
	if d := h.DNSQuery(context.Background(), q); d.Verdict != VerdictPass {
		t.Fatalf("client tags reached a plugin that did not declare them: %+v", d)
	}
	loc := "https://a.test/yol?utm_source=x"
	if got, changed := h.HTTPLocation(context.Background(), loc); changed || got != loc {
		t.Fatalf("undeclared http_location hook was called: %q", got)
	}
	if len(rec.kinds()) != 0 {
		t.Fatal(rec.kinds())
	}

	withTags := dnsManifest("etiketli", DataClientTags)
	h2, _ := newTestHost(t, Options{}, testPlugin{withTags, mod})
	if d := h2.DNSQuery(context.Background(), q); d.Verdict != VerdictBlock {
		t.Fatalf("declared client tags not given: %+v", d)
	}
	if d := h2.DNSQuery(context.Background(), DNSQuery{Name: "a.test", QType: qtypeA, ClientTags: []string{"kotu etiket"}}); d.Verdict != VerdictPass {
		t.Fatalf("invalid tag passed through: %+v", d)
	}
}

func TestHTTPLocation(t *testing.T) {
	m := Manifest{ABI: 1, Name: "utm-temizle", Version: "0.1", Hooks: []string{HookHTTPLocation}, Data: []string{DataHTTPLocation}, OnError: OnErrorPass}
	mod := wmod{funcs: []wfunc{fnVersion, fnBuffer, hook("osp_http_location", 2, stripQueryBody)}}.bytes()
	h, rec := newTestHost(t, Options{}, testPlugin{m, mod})
	got, changed := h.HTTPLocation(context.Background(), "https://a.test/yol?utm_source=x&id=1")
	if !changed || got != "https://a.test/yol" {
		t.Fatalf("got %q %v", got, changed)
	}
	if got, changed := h.HTTPLocation(context.Background(), "https://a.test/yol"); !changed && got != "https://a.test/yol" {
		t.Fatalf("got %q", got)
	}
	if got, changed := h.HTTPLocation(context.Background(), "javascript:alert(1)"); changed || got != "javascript:alert(1)" {
		t.Fatal("non-http URL handed to a plugin")
	}
	if len(rec.kinds()) != 0 {
		t.Fatal(rec.kinds())
	}

	other := "http://baska.invalid/"
	evil := wmod{
		funcs: []wfunc{fnVersion, fnBuffer, hook("osp_http_location", 0, fixedLocationBody(int32(len(other))))},
		data:  []wdata{{0, []byte(other)}},
	}.bytes()
	m.Name = "yonlendirici"
	h2, rec2 := newTestHost(t, Options{}, testPlugin{m, evil})
	if got, changed := h2.HTTPLocation(context.Background(), "http://a.test/x"); changed || got != "http://a.test/x" {
		t.Fatalf("plugin moved the redirect to another host: %q", got)
	}
	if k := rec2.kinds(); len(k) != 1 || k[0] != EventBadOutput {
		t.Fatalf("events %v", k)
	}
}

func TestRewriteAndBadOutput(t *testing.T) {
	h, _ := newTestHost(t, Options{}, testPlugin{dnsManifest("yeniden"), dnsModule(rewriteBody, 0)})
	d := h.DNSQuery(context.Background(), DNSQuery{Name: "nas.test", QType: qtypeA})
	if d.Verdict != VerdictRewrite || d.Addr != netip.MustParseAddr("10.0.0.1") {
		t.Fatalf("decision %+v", d)
	}
	// An IPv4 answer to an AAAA query is malformed.
	d = h.DNSQuery(context.Background(), DNSQuery{Name: "nas.test", QType: qtypeAAAA})
	if d.Verdict != VerdictPass {
		t.Fatalf("decision %+v", d)
	}

	cases := map[string][]byte{
		"negative":  i32c(-1),
		"too-long":  i32c(BufferSize + 1),
		"bad-value": cat(i32c(0), i32c(9), mem(opStore8, testBuf), i32c(1)),
	}
	want := map[string]string{"negative": EventPluginError, "too-long": EventBadOutput, "bad-value": EventBadOutput}
	for name, body := range cases {
		m := dnsManifest("bozuk-" + name)
		m.OnError = OnErrorBlock
		h, rec := newTestHost(t, Options{}, testPlugin{m, dnsModule(body, 0)})
		if d := h.DNSQuery(context.Background(), DNSQuery{Name: "a.test", QType: qtypeA}); d.Verdict != VerdictBlock || !d.Fallback {
			t.Errorf("%s: %+v", name, d)
		}
		if k := rec.kinds(); len(k) != 1 || k[0] != want[name] {
			t.Errorf("%s: events %v", name, k)
		}
	}
}

func TestBrokenModulesRejected(t *testing.T) {
	m := dnsManifest("x")
	wrongVersion := wfunc{results: []byte{i32}, body: i32c(2), export: "osp_abi_version"}
	badBuffer := wfunc{results: []byte{i32}, body: i32c(65536 - 100), export: "osp_buffer"}
	cases := map[string][]byte{
		"garbage":       []byte("bu bir wasm modulu degil"),
		"truncated":     exampleModule()[:20],
		"import":        wmod{importFunc: true, funcs: []wfunc{fnVersion, fnBuffer, hook("osp_dns_query", 1, exampleDNSBody)}}.bytes(),
		"no-memory":     wmod{noMemory: true, funcs: []wfunc{fnVersion, fnBuffer, hook("osp_dns_query", 0, i32c(0))}}.bytes(),
		"no-hook":       wmod{funcs: []wfunc{fnVersion, fnBuffer}}.bytes(),
		"wrong-sig":     wmod{funcs: []wfunc{fnVersion, fnBuffer, {results: []byte{i32}, body: i32c(0), export: "osp_dns_query"}}}.bytes(),
		"abi-version":   wmod{funcs: []wfunc{wrongVersion, fnBuffer, hook("osp_dns_query", 0, i32c(0))}}.bytes(),
		"buffer-bounds": wmod{funcs: []wfunc{fnVersion, badBuffer, hook("osp_dns_query", 0, i32c(0))}}.bytes(),
	}
	for name, mod := range cases {
		h, rec := newTestHost(t, Options{}, testPlugin{m, mod})
		e := h.Entries()[0]
		if h.Loaded() != 0 || e.Status != StatusInvalid || e.Reason == "" {
			t.Errorf("%s: loaded; entry %+v", name, e)
		}
		if k := rec.kinds(); len(k) != 1 || k[0] != EventRejected {
			t.Errorf("%s: events %v", name, k)
		}
		if d := h.DNSQuery(context.Background(), DNSQuery{Name: "a.example", QType: qtypeA}); d.Verdict != VerdictPass {
			t.Errorf("%s: rejected plugin decided", name)
		}
	}
}

func TestStoreDigests(t *testing.T) {
	mod := exampleModule()
	mb := manifestJSON(t, dnsManifest("ornek-engel"))
	fsys := fstest.MapFS{
		"ornek-engel.wasm": {Data: mod},
		"ornek-engel.json": {Data: mb},
		"yabanci.wasm":     {Data: []byte{1, 2, 3}},
		"benioku.txt":      {Data: []byte("yok sayilir")},
		"Kotu Ad.json":     {Data: []byte("{}")},
	}
	good := Pin{Name: "ornek-engel", ModuleSHA256: Digest(mod), ManifestSHA256: Digest(mb)}

	st, err := LoadStore(fsys, PinList{good})
	if err != nil {
		t.Fatal(err)
	}
	es := st.Entries()
	if len(es) != 3 || es[0].Status != StatusVerified || es[0].ModuleSize != len(mod) {
		t.Fatalf("entries %+v", es)
	}
	byName := map[string]Entry{}
	for _, e := range es {
		byName[e.Name] = e
	}
	if e := byName["yabanci"]; e.Status != StatusUnpinned || e.ModuleSHA256 != Digest([]byte{1, 2, 3}) {
		t.Fatalf("unpinned entry %+v", e)
	}
	if e := byName["Kotu Ad"]; e.Status != StatusInvalid {
		t.Fatalf("bad name entry %+v", e)
	}
	if strings.Join(es[0].DataLabels, ",") != dataLabels[DataDNSName] {
		t.Fatalf("labels %v", es[0].DataLabels)
	}

	badMod := good
	badMod.ModuleSHA256 = Digest([]byte("baska"))
	badMan := good
	badMan.ManifestSHA256 = Digest([]byte("baska"))
	for _, p := range []Pin{badMod, badMan} {
		st, err := LoadStore(fsys, PinList{p})
		if err != nil {
			t.Fatal(err)
		}
		h, err := NewHost(context.Background(), st, Options{})
		if err != nil {
			t.Fatal(err)
		}
		if h.Loaded() != 0 || h.Entries()[0].Status != StatusDigestMismatch {
			t.Fatalf("digest mismatch loaded: %+v", h.Entries()[0])
		}
		h.Close(context.Background())
	}

	missing := Pin{Name: "olmayan", ModuleSHA256: good.ModuleSHA256, ManifestSHA256: good.ManifestSHA256}
	st, _ = LoadStore(fsys, PinList{missing})
	if st.Entries()[0].Status != StatusMissing {
		t.Fatal(st.Entries()[0])
	}

	// Manifest naming another plugin than its file.
	renamed := manifestJSON(t, dnsManifest("baska-ad"))
	fs2 := fstest.MapFS{"ornek-engel.wasm": {Data: mod}, "ornek-engel.json": {Data: renamed}}
	st, _ = LoadStore(fs2, PinList{{Name: "ornek-engel", ModuleSHA256: Digest(mod), ManifestSHA256: Digest(renamed)}})
	if st.Entries()[0].Status != StatusInvalid {
		t.Fatal(st.Entries()[0])
	}

	for _, bad := range []PinList{
		{{Name: "a", ModuleSHA256: "xyz", ManifestSHA256: good.ManifestSHA256}},
		{good, good},
		{{Name: "../a", ModuleSHA256: good.ModuleSHA256, ManifestSHA256: good.ManifestSHA256}},
	} {
		if _, err := LoadStore(fsys, bad); err == nil {
			t.Errorf("malformed pins accepted: %+v", bad)
		}
	}

	big := fstest.MapFS{"b.wasm": {Data: make([]byte, MaxModuleSize+1)}, "b.json": {Data: mb}}
	st, _ = LoadStore(big, PinList{{Name: "b", ModuleSHA256: good.ModuleSHA256, ManifestSHA256: Digest(mb)}})
	if e := st.Entries()[0]; e.Status != StatusInvalid && e.Status != StatusDigestMismatch {
		t.Fatal(e)
	}

	// No folder: every pin is missing, nothing fails.
	st, err = LoadStore(nil, PinList{good})
	if err != nil || st.Entries()[0].Status != StatusMissing {
		t.Fatal(err, st.Entries())
	}
}

// TestExampleFiles keeps the committed example plugin in step with the
// encoder and loads it the way the exit node will: from a folder, by pin.
func TestExampleFiles(t *testing.T) {
	dir := filepath.Join("testdata", "plugins")
	wasmPath := filepath.Join(dir, "ornek-engel.wasm")
	if *update {
		if err := os.WriteFile(wasmPath, exampleModule(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mod, err := os.ReadFile(wasmPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mod, exampleModule()) {
		t.Fatal("testdata/plugins/ornek-engel.wasm differs from the encoder; run go test -run TestExampleFiles -update")
	}
	mb, err := os.ReadFile(filepath.Join(dir, "ornek-engel.json"))
	if err != nil {
		t.Fatal(err)
	}
	st, err := LoadStoreDir(dir, PinList{{Name: "ornek-engel", ModuleSHA256: Digest(mod), ManifestSHA256: Digest(mb)}})
	if err != nil {
		t.Fatal(err)
	}
	h, err := NewHost(context.Background(), st, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close(context.Background())
	e := h.Entries()[0]
	if e.Status != StatusLoaded || e.MemoryLimitMiB != 16 || e.CallTimeoutMS != 20 {
		t.Fatalf("entry %+v", e)
	}
	if d := h.DNSQuery(context.Background(), DNSQuery{Name: "iz.ornek.example", QType: qtypeAAAA}); d.Verdict != VerdictBlock {
		t.Fatalf("decision %+v", d)
	}
	st, err = LoadStoreDir(filepath.Join("testdata", "olmayan"), PinList{})
	if err != nil || len(st.Entries()) != 0 {
		t.Fatal(err)
	}
}

func TestConcurrentCalls(t *testing.T) {
	h, rec := newTestHost(t, Options{CallTimeout: MaxCallTimeout, MaxConcurrent: 2}, testPlugin{dnsManifest("ornek-engel"), exampleModule()})
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if d := h.DNSQuery(context.Background(), DNSQuery{Name: "a.example", QType: qtypeA}); d.Verdict != VerdictBlock {
				t.Errorf("decision %+v", d)
			}
		}()
	}
	wg.Wait()
	if len(rec.kinds()) != 0 {
		t.Fatal(rec.kinds())
	}
	h.Close(context.Background())
	if d := h.DNSQuery(context.Background(), DNSQuery{Name: "a.example", QType: qtypeA}); d.Verdict != VerdictPass {
		t.Fatal("closed host decided")
	}
}
