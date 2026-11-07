package node

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/openscale/openscale/internal/adblock"
	"github.com/openscale/openscale/internal/dnsguard"
	"github.com/openscale/openscale/internal/plugin"
	"github.com/openscale/openscale/internal/trust"
)

// Exit node resolver extensions (ADR-0220, G7): the category blocker
// (#692-#697), the DoH name rule (#717), .onion NXDOMAIN (#721) and the
// WebAssembly plugin DNS hook (#787-#790). They are configured only by the
// signed document (blocking, plugins) and run only while this device is an
// exit node. Lists live in <state>/adblock, plugins in <state>/plugins.

// Directory names below the state directory.
const (
	AdblockDirName  = "adblock"
	g7MaxEvents     = 50
	g7RewriteTTL    = 60
	g7PluginTimeout = 300 * time.Millisecond
)

// Decisions logged for extension answers.
const (
	DecisionCategory = "category"
	DecisionOnion    = "onion"
	DecisionDoH      = "doh"
	DecisionPlugin   = "plugin"
)

// g7Ext is the process state of the extensions.
type g7Ext struct {
	mu      sync.Mutex // serializes reloads
	version uint64
	dir     string
	active  bool
	lastErr string
	lists   []adblock.Artifact

	enabled atomic.Bool // the document has a blocking field
	engine  atomic.Pointer[adblock.Engine]
	plugins atomic.Pointer[plugin.Host]
	doh     atomic.Pointer[dnsguard.DoHList]
	tags    atomic.Pointer[map[string][]string]

	onion, dohHits, pluginBlocked, pluginAllowed, pluginRewritten atomic.Uint64

	evMu   sync.Mutex
	events []plugin.Event
}

var g7ext g7Ext

// ExitExtensionsStatus is the panel and CLI view of the extensions.
type ExitExtensionsStatus struct {
	Active          bool               `json:"active"`
	Version         uint64             `json:"version"`
	Error           string             `json:"error,omitempty"`
	Adblock         *adblock.Stats     `json:"adblock,omitempty"`
	Lists           []adblock.Artifact `json:"lists"`
	Plugins         []plugin.Entry     `json:"plugins"`
	PluginEvents    []plugin.Event     `json:"plugin_events"`
	Onion           uint64             `json:"onion"`
	DoH             uint64             `json:"doh"`
	PluginBlocked   uint64             `json:"plugin_blocked"`
	PluginAllowed   uint64             `json:"plugin_allowed"`
	PluginRewritten uint64             `json:"plugin_rewritten"`
}

// ExitExtensions reports the current state; counters only, never names.
func ExitExtensions() ExitExtensionsStatus {
	g7ext.mu.Lock()
	st := ExitExtensionsStatus{
		Active: g7ext.active, Version: g7ext.version, Error: g7ext.lastErr,
		Lists: append([]adblock.Artifact{}, g7ext.lists...),
	}
	g7ext.mu.Unlock()
	if e := g7ext.engine.Load(); e != nil {
		s := e.Stats()
		st.Adblock = &s
	}
	st.Plugins = []plugin.Entry{}
	if h := g7ext.plugins.Load(); h != nil {
		st.Plugins = h.Entries()
	}
	g7ext.evMu.Lock()
	st.PluginEvents = append([]plugin.Event{}, g7ext.events...)
	g7ext.evMu.Unlock()
	st.Onion, st.DoH = g7ext.onion.Load(), g7ext.dohHits.Load()
	st.PluginBlocked, st.PluginAllowed, st.PluginRewritten = g7ext.pluginBlocked.Load(), g7ext.pluginAllowed.Load(), g7ext.pluginRewritten.Load()
	return st
}

// ExitAdblockEngine returns the running category engine (allow once, top
// list) or nil when this device is not a blocking exit node.
func ExitAdblockEngine() *adblock.Engine { return g7ext.engine.Load() }

// PluginPins converts the document's pins for plugin.LoadStoreDir.
func PluginPins(doc *trust.Document) plugin.PinList {
	if doc == nil {
		return nil
	}
	out := make(plugin.PinList, 0, len(doc.Plugins))
	for _, p := range doc.Plugins {
		out = append(out, plugin.Pin{Name: p.Name, ModuleSHA256: p.ModuleSHA256, ManifestSHA256: p.ManifestSHA256})
	}
	return out
}

func g7RecordEvent(ev plugin.Event) {
	g7ext.evMu.Lock()
	defer g7ext.evMu.Unlock()
	if len(g7ext.events) >= g7MaxEvents {
		g7ext.events = append(g7ext.events[:0], g7ext.events[1:]...)
	}
	g7ext.events = append(g7ext.events, ev)
}

// g7SyncExtensions follows the document and the exit role (applyExit).
// Loading compiles plugins, so it runs off the caller's path.
func (e *Engine) g7SyncExtensions(doc *trust.Document, role bool) {
	if doc == nil {
		role = false
	}
	dir := ""
	if e.cfg.Store != nil {
		dir = e.cfg.Store.Dir()
	}
	g7ext.mu.Lock()
	same := g7ext.active == role && (!role || g7ext.version == doc.Version && g7ext.dir == dir)
	if !role && !g7ext.active && g7ext.version == 0 {
		same = true
	}
	g7ext.mu.Unlock()
	if same {
		return
	}
	go func() {
		if err := ReloadExitExtensions(context.Background(), dir, doc, role); err != nil && e.logger != nil {
			e.logger.Warn("exit extensions", "error", err.Error())
		}
	}()
}

// ReloadExitExtensions (re)builds the extensions from the document and the
// verified files in dir; role false or a document without the fields turns
// them off. A failure leaves the extensions off and is reported in the
// status, never half applied.
func ReloadExitExtensions(ctx context.Context, dir string, doc *trust.Document, role bool) error {
	g7ext.mu.Lock()
	defer g7ext.mu.Unlock()
	g7ext.version, g7ext.dir, g7ext.active, g7ext.lastErr, g7ext.lists = 0, dir, false, "", nil
	g7ext.enabled.Store(false)
	g7ext.engine.Store(nil)
	g7ext.doh.Store(nil)
	g7ext.tags.Store(nil)
	if old := g7ext.plugins.Swap(nil); old != nil {
		_ = old.Close(ctx)
	}
	if !role || doc == nil {
		return nil
	}
	g7ext.version = doc.Version
	tags := map[string][]string{}
	for _, d := range doc.Devices {
		if len(d.Tags) > 0 {
			tags[d.Name] = append([]string(nil), d.Tags...)
		}
	}
	g7ext.tags.Store(&tags)
	var errs []error
	if b := doc.Blocking; b != nil {
		if len(b.BlockDoH) > 0 {
			l, err := dnsguard.ParseDoHList(strings.NewReader(strings.Join(b.BlockDoH, "\n")))
			if err != nil {
				errs = append(errs, fmt.Errorf("DoH listesi: %w", err))
			} else {
				g7ext.doh.Store(&l)
			}
		}
		if b.Policy != nil && dir != "" {
			eng, lists, err := buildAdblock(filepath.Join(dir, AdblockDirName), b)
			if err != nil {
				errs = append(errs, err)
			} else {
				g7ext.engine.Store(eng)
				g7ext.lists = lists
			}
		}
		g7ext.enabled.Store(true)
	}
	if len(doc.Plugins) > 0 && dir != "" {
		st, err := plugin.LoadStoreDir(filepath.Join(dir, plugin.DirName), PluginPins(doc))
		if err == nil {
			var h *plugin.Host
			h, err = plugin.NewHost(ctx, st, plugin.Options{OnEvent: g7RecordEvent})
			if err == nil {
				g7ext.plugins.Store(h)
			}
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("eklentiler: %w", err))
		}
	}
	g7ext.active = true
	if err := errors.Join(errs...); err != nil {
		g7ext.lastErr = err.Error()
		return err
	}
	return nil
}

func buildAdblock(dir string, b *trust.BlockingSettings) (*adblock.Engine, []adblock.Artifact, error) {
	var keep *strings.Reader
	if len(b.Keep) > 0 {
		keep = strings.NewReader(strings.Join(b.Keep, "\n"))
	}
	var (
		m     *adblock.Matcher
		lists []adblock.Artifact
		err   error
	)
	if len(b.Subscriptions) > 0 {
		if keep != nil {
			m, lists, err = adblock.LoadDistributed(dir, b.Subscriptions, keep)
		} else {
			m, lists, err = adblock.LoadDistributed(dir, b.Subscriptions, nil)
		}
		if errors.Is(err, os.ErrNotExist) {
			err = errors.New("liste aboneliği henüz indirilmedi: openscale adblock update")
		}
	}
	if err != nil {
		return nil, nil, fmt.Errorf("engelleme listeleri: %w", err)
	}
	if m == nil {
		bl := adblock.NewBuilder()
		if keep != nil {
			if _, err := bl.AddKeep(keep); err != nil {
				return nil, nil, err
			}
		}
		m = bl.Build()
	}
	eng := adblock.NewEngine()
	if err := eng.Install(m, *b.Policy); err != nil {
		return nil, nil, fmt.Errorf("engelleme politikası: %w", err)
	}
	return eng, lists, nil
}

// UpdateExitBlocklists downloads every subscription of the document into
// <dir>/adblock (exit node only), verifies the signed digests, writes the
// manifest and reloads. A list whose digest changed is refused and kept
// out until the owner signs the new digest.
func UpdateExitBlocklists(ctx context.Context, dir string, doc *trust.Document, exitNode bool) ([]adblock.Artifact, error) {
	if doc == nil || doc.Blocking == nil || len(doc.Blocking.Subscriptions) == 0 {
		return nil, errors.New("imzalı belgede liste aboneliği yok")
	}
	if dir == "" {
		return nil, errors.New("durum klasörü yok")
	}
	out := filepath.Join(dir, AdblockDirName)
	if err := os.MkdirAll(out, 0o700); err != nil {
		return nil, err
	}
	f := adblock.Fetcher{ExitNode: exitNode}
	var lists []adblock.Artifact
	var errs []error
	for _, s := range doc.Blocking.Subscriptions {
		a, data, err := f.Fetch(ctx, s)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", s.Category, err))
			continue
		}
		a, err = adblock.WriteArtifact(out, a, data)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		lists = append(lists, a)
	}
	if err := adblock.WriteManifest(out, lists); err != nil {
		errs = append(errs, err)
	}
	return lists, errors.Join(errs...)
}

// g7PolicyAnswer applies the extensions to a member's query. answered is
// true with a local answer; skipList is true when a plugin allowed the name
// past the block lists.
func g7PolicyAnswer(client exitClient, cq clientQuery, now time.Time) (out []byte, decision string, answered, skipList bool) {
	if !g7ext.enabled.Load() && g7ext.plugins.Load() == nil {
		return nil, "", false, false
	}
	name := cq.key.name
	if g7ext.enabled.Load() && dnsguard.OnionDecision(name, false) == dnsguard.OnionNXDOMAIN {
		g7ext.onion.Add(1)
		out, err := nxdomainAnswer(cq, true)
		return out, DecisionOnion, err == nil, false
	}
	if l := g7ext.doh.Load(); l != nil && l.BlocksName(strings.TrimSuffix(name, ".")) {
		g7ext.dohHits.Add(1)
		out, err := nxdomainAnswer(cq, true)
		return out, DecisionDoH, err == nil, false
	}
	var tags []string
	if m := g7ext.tags.Load(); m != nil {
		tags = (*m)[client.name]
	}
	if h := g7ext.plugins.Load(); h != nil && client.name != "" {
		ctx, cancel := context.WithTimeout(context.Background(), g7PluginTimeout)
		d := h.DNSQuery(ctx, plugin.DNSQuery{Name: name, QType: uint16(cq.question.Type), ClientTags: tags})
		cancel()
		switch d.Verdict {
		case plugin.VerdictBlock:
			g7ext.pluginBlocked.Add(1)
			out, err := nxdomainAnswer(cq, true)
			return out, DecisionPlugin, err == nil, false
		case plugin.VerdictAllow:
			g7ext.pluginAllowed.Add(1)
			return nil, "", false, true
		case plugin.VerdictRewrite:
			if out, ok := g7RewriteAnswer(cq, d.Addr); ok {
				g7ext.pluginRewritten.Add(1)
				return out, DecisionPlugin, true, false
			}
		}
	}
	if client.noBlocklist {
		return nil, "", false, false
	}
	if eng := g7ext.engine.Load(); eng != nil && client.name != "" {
		if dec := eng.Decide(client.name, tags, name, now); dec.Blocked {
			out, err := nxdomainAnswer(cq, true)
			return out, DecisionCategory, err == nil, false
		}
	}
	return nil, "", false, false
}

// g7RewriteAnswer builds the plugin's A or AAAA answer. Private, loopback,
// link-local and unspecified addresses are refused (DNS rebinding, #739):
// a plugin cannot point a public name into the member's networks.
func g7RewriteAnswer(cq clientQuery, addr netip.Addr) ([]byte, bool) {
	addr = addr.Unmap()
	if !addr.IsValid() || addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() ||
		addr.IsUnspecified() || addr.IsMulticast() || addr.IsInterfaceLocalMulticast() {
		return nil, false
	}
	if dnsguard.RebindAddr(addr) {
		return nil, false
	}
	m := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID: cq.id, Response: true, RecursionDesired: true, RecursionAvailable: true,
		},
		Questions: []dnsmessage.Question{cq.question},
	}
	hdr := dnsmessage.ResourceHeader{Name: cq.question.Name, Class: dnsmessage.ClassINET, TTL: g7RewriteTTL}
	switch {
	case cq.question.Type == dnsmessage.TypeA && addr.Is4():
		hdr.Type = dnsmessage.TypeA
		m.Answers = []dnsmessage.Resource{{Header: hdr, Body: &dnsmessage.AResource{A: addr.As4()}}}
	case cq.question.Type == dnsmessage.TypeAAAA && addr.Is6():
		hdr.Type = dnsmessage.TypeAAAA
		m.Answers = []dnsmessage.Resource{{Header: hdr, Body: &dnsmessage.AAAAResource{AAAA: addr.As16()}}}
	default:
		// Other types or a family mismatch: an empty answer (NODATA).
	}
	out, err := m.Pack()
	if err != nil {
		return nil, false
	}
	return out, true
}
