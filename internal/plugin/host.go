// Package plugin runs the owner's signed WebAssembly plugins on the exit
// node (#787, #788, #790; ADR-0217, ADR-0218, ADR-0219).
//
// A plugin joins two decisions: the answer to a DNS query and the
// Location header of an HTTP redirect. It runs in a sandbox with no
// imports at all: no WASI, no clock, no randomness, no network, no files.
// Memory is capped at MaxMemoryPages, every call has a deadline, compiled
// code is cached only in memory, and every call gets a fresh instance so
// no state survives between queries. A plugin only receives the data
// classes its manifest declares. Only modules whose SHA-256 digest and
// manifest digest are pinned in the owner's signed document are loaded.
//
// A failing plugin (timeout, trap, malformed output) never fails the
// decision closed by itself: its manifest's on_error, chosen by the
// owner, decides, and an Event is reported.
package plugin

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// Sandbox limits.
const (
	MaxMemoryPages     = 256 // 16 MiB of 64 KiB pages per instance
	DefaultCallTimeout = 20 * time.Millisecond
	MaxCallTimeout     = 250 * time.Millisecond
	DefaultConcurrent  = 8
	MaxConcurrent      = 64
	loadTimeout        = 2 * time.Second
	maxEventDetail     = 200
)

// Event kinds.
const (
	EventRejected    = "rejected"     // not loaded (load time)
	EventTimeout     = "timeout"      // call deadline reached
	EventTrap        = "trap"         // wasm trap or instantiation failure
	EventBadOutput   = "bad_output"   // malformed answer or URL to another origin
	EventPluginError = "plugin_error" // hook returned a negative length
	EventBusy        = "busy"         // no free call slot before the deadline
	EventPanic       = "panic"        // runtime panic, recovered
)

// Event reports a plugin failure. It never carries the query name, client
// tags or URL.
type Event struct {
	Time   time.Time `json:"time"`
	Plugin string    `json:"plugin"`
	Hook   string    `json:"hook,omitempty"`
	Kind   string    `json:"kind"`
	Detail string    `json:"detail,omitempty"`
}

// Options of a Host.
type Options struct {
	// CallTimeout bounds one plugin call, instantiation included.
	// Zero means DefaultCallTimeout; it is capped at MaxCallTimeout.
	CallTimeout time.Duration
	// MaxConcurrent bounds simultaneous plugin instances (each up to
	// 16 MiB). Zero means DefaultConcurrent; capped at MaxConcurrent.
	MaxConcurrent int
	// OnEvent receives failure events synchronously; it must not block.
	OnEvent func(Event)
	// Now is the clock of events; nil means time.Now.
	Now func() time.Time
}

// Host runs the loaded plugins. It is safe for concurrent use.
type Host struct {
	rt      wazero.Runtime
	plugins []*loaded
	entries []Entry
	sem     chan struct{}
	timeout time.Duration
	onEvent func(Event)
	now     func() time.Time
	closed  atomic.Bool
}

type loaded struct {
	m  Manifest
	cm wazero.CompiledModule
}

// DNSQuery is what the resolver asks. ClientTags reach only plugins that
// declare client_tags.
type DNSQuery struct {
	Name       string
	QType      uint16
	ClientTags []string
}

// DNSDecision is the plugins' answer. Plugin is the deciding plugin and
// Fallback is true when the verdict came from its on_error after a
// failure. Verdict Pass means no plugin had an opinion.
type DNSDecision struct {
	Verdict  Verdict
	Addr     netip.Addr
	Plugin   string
	Fallback bool
}

// NewHost compiles the verified plugins of st. A plugin that fails the
// sandbox checks is marked invalid, reported and skipped; the others run.
func NewHost(ctx context.Context, st *Store, opt Options) (*Host, error) {
	if st == nil {
		st = &Store{}
	}
	h := &Host{
		timeout: opt.CallTimeout,
		onEvent: opt.OnEvent,
		now:     opt.Now,
		entries: cloneEntries(st.entries),
	}
	if h.timeout <= 0 {
		h.timeout = DefaultCallTimeout
	}
	h.timeout = min(h.timeout, MaxCallTimeout)
	n := opt.MaxConcurrent
	if n <= 0 {
		n = DefaultConcurrent
	}
	h.sem = make(chan struct{}, min(n, MaxConcurrent))
	if h.now == nil {
		h.now = time.Now
	}
	for i := range h.entries {
		h.entries[i].MemoryLimitMiB = MaxMemoryPages * 64 / 1024
		h.entries[i].CallTimeoutMS = int(h.timeout / time.Millisecond)
	}
	cfg := wazero.NewRuntimeConfig().
		WithCoreFeatures(api.CoreFeaturesV2).
		WithMemoryLimitPages(MaxMemoryPages).
		WithCloseOnContextDone(true).
		WithCustomSections(false).
		WithDebugInfoEnabled(false)
	h.rt = wazero.NewRuntimeWithConfig(ctx, cfg)
	for _, src := range st.sources {
		e := &h.entries[src.entry]
		p, err := h.load(ctx, src)
		if err != nil {
			e.set(StatusInvalid, err.Error())
			h.emit(src.manifest.Name, "", EventRejected, err)
			continue
		}
		e.set(StatusLoaded, "")
		h.plugins = append(h.plugins, p)
	}
	return h, nil
}

var (
	sigNone = signature{nil, []api.ValueType{api.ValueTypeI32}}
	sigHook = signature{[]api.ValueType{api.ValueTypeI32}, []api.ValueType{api.ValueTypeI32}}
)

type signature struct{ params, results []api.ValueType }

func (s signature) match(d api.FunctionDefinition) bool {
	return equalTypes(d.ParamTypes(), s.params) && equalTypes(d.ResultTypes(), s.results)
}

func equalTypes(a, b []api.ValueType) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (h *Host) load(ctx context.Context, src source) (_ *loaded, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("plugin: runtime panic while loading: %v", r)
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, loadTimeout)
	defer cancel()
	cm, err := h.rt.CompileModule(ctx, src.module)
	if err != nil {
		return nil, fmt.Errorf("modül derlenemedi: %s", short(err))
	}
	ok := false
	defer func() {
		if !ok {
			_ = cm.Close(context.Background())
		}
	}()
	if len(cm.ImportedFunctions()) > 0 || len(cm.ImportedMemories()) > 0 {
		return nil, errors.New("modül içe aktarma (import) kullanıyor; kum havuzu hiçbir içe aktarma sunmaz")
	}
	md, has := cm.ExportedMemories()[exportMemory]
	if !has {
		return nil, errors.New("modül memory dışa aktarmıyor")
	}
	if md.Min() > MaxMemoryPages {
		return nil, errors.New("modülün başlangıç belleği sınırı aşıyor")
	}
	fns := cm.ExportedFunctions()
	need := map[string]signature{exportVersion: sigNone, exportBuffer: sigNone}
	if src.manifest.HasHook(HookDNS) {
		need[exportDNS] = sigHook
	}
	if src.manifest.HasHook(HookHTTPLocation) {
		need[exportHTTP] = sigHook
	}
	for name, sig := range need {
		d, has := fns[name]
		if !has || !sig.match(d) {
			return nil, fmt.Errorf("modül %s işlevini doğru imzayla dışa aktarmıyor", name)
		}
	}
	mod, err := h.rt.InstantiateModule(ctx, cm, wazero.NewModuleConfig().WithName("").WithStartFunctions())
	if err != nil {
		return nil, fmt.Errorf("modül başlatılamadı: %s", short(err))
	}
	defer mod.Close(context.Background())
	res, err := mod.ExportedFunction(exportVersion).Call(ctx)
	if err != nil || len(res) != 1 || uint32(res[0]) != ABIVersion {
		return nil, fmt.Errorf("modülün ABI sürümü %d değil", ABIVersion)
	}
	if _, err := bufferOffset(ctx, mod); err != nil {
		return nil, err
	}
	ok = true
	return &loaded{m: src.manifest, cm: cm}, nil
}

func bufferOffset(ctx context.Context, mod api.Module) (uint32, error) {
	res, err := mod.ExportedFunction(exportBuffer).Call(ctx)
	if err != nil || len(res) != 1 {
		return 0, errors.New("osp_buffer çağrılamadı")
	}
	off := uint32(res[0])
	if uint64(off)+BufferSize > uint64(mod.Memory().Size()) {
		return 0, errors.New("osp_buffer alanı belleğin dışında")
	}
	return off, nil
}

// Entries returns the plugin rows for the panel with their final status.
func (h *Host) Entries() []Entry { return cloneEntries(h.entries) }

// Loaded reports how many plugins run.
func (h *Host) Loaded() int { return len(h.plugins) }

// Close releases the runtime. Calls after Close return Pass or the URL
// unchanged.
func (h *Host) Close(ctx context.Context) error {
	if h.closed.Swap(true) {
		return nil
	}
	return h.rt.Close(ctx)
}

// DNSQuery asks the dns plugins in pin order; the first verdict other
// than Pass decides. An invalid name is never shown to a plugin.
func (h *Host) DNSQuery(ctx context.Context, q DNSQuery) DNSDecision {
	name, ok := normalizeName(q.Name)
	if !ok || h.closed.Load() {
		return DNSDecision{}
	}
	var tags []string
	for _, t := range q.ClientTags {
		if len(tags) == MaxClientTags {
			break
		}
		if validTag(t) {
			tags = append(tags, t)
		}
	}
	for _, p := range h.plugins {
		if !p.m.HasHook(HookDNS) {
			continue
		}
		var pt []string
		if p.m.Sees(DataClientTags) {
			pt = tags
		}
		out, kind, err := h.call(ctx, p, exportDNS, encodeDNS(name, q.QType, pt))
		var v Verdict
		var addr netip.Addr
		if err == nil {
			v, addr, err = decodeDNS(out, q.QType)
			if err != nil {
				kind = EventBadOutput
			}
		}
		if err != nil {
			h.emit(p.m.Name, HookDNS, kind, err)
			switch p.m.OnError {
			case OnErrorBlock:
				return DNSDecision{Verdict: VerdictBlock, Plugin: p.m.Name, Fallback: true}
			case OnErrorAllow:
				return DNSDecision{Verdict: VerdictAllow, Plugin: p.m.Name, Fallback: true}
			}
			continue
		}
		if v != VerdictPass {
			return DNSDecision{Verdict: v, Addr: addr, Plugin: p.m.Name}
		}
	}
	return DNSDecision{}
}

// HTTPLocation lets the http_location plugins clean a redirect target in
// pin order; each sees the previous one's result. A plugin may change
// the path, query and fragment and upgrade http to https, never the host.
// On any failure the URL stays as it was (on_error has no other meaning
// here). It returns the URL and whether it changed.
func (h *Host) HTTPLocation(ctx context.Context, loc string) (string, bool) {
	cur, ok := checkLocation(loc)
	if !ok || h.closed.Load() {
		return loc, false
	}
	curStr := loc
	for _, p := range h.plugins {
		if !p.m.HasHook(HookHTTPLocation) {
			continue
		}
		out, kind, err := h.call(ctx, p, exportHTTP, encodeHTTP(curStr))
		if err == nil {
			var nu string
			var changed bool
			nu, changed, err = decodeHTTP(out)
			if err == nil && changed {
				u, ok := checkLocation(nu)
				if !ok || !sameTarget(cur, u) {
					err = errors.New("plugin: new Location is not a URL of the same origin")
				} else {
					cur, curStr = u, nu
				}
			}
			if err != nil {
				kind = EventBadOutput
			}
		}
		if err != nil {
			h.emit(p.m.Name, HookHTTPLocation, kind, err)
		}
	}
	return curStr, curStr != loc
}

// call runs one hook in a fresh instance under the call deadline.
func (h *Host) call(ctx context.Context, p *loaded, fn string, in []byte) (out []byte, kind string, err error) {
	ctx, cancel := context.WithTimeout(ctx, h.timeout)
	defer cancel()
	select {
	case h.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, EventBusy, errors.New("plugin: no free call slot")
	}
	defer func() { <-h.sem }()
	defer func() {
		if r := recover(); r != nil {
			out, kind, err = nil, EventPanic, fmt.Errorf("plugin: runtime panic: %v", r)
		}
	}()
	failed := func(err error) ([]byte, string, error) {
		if ctx.Err() != nil {
			return nil, EventTimeout, errors.New("plugin: call deadline reached")
		}
		return nil, EventTrap, err
	}
	mod, err := h.rt.InstantiateModule(ctx, p.cm, wazero.NewModuleConfig().WithName("").WithStartFunctions())
	if err != nil {
		return failed(err)
	}
	defer mod.Close(context.Background())
	off, err := bufferOffset(ctx, mod)
	if err != nil {
		if ctx.Err() != nil {
			return failed(err)
		}
		return nil, EventBadOutput, err
	}
	if len(in) > BufferSize || !mod.Memory().Write(off, in) {
		return nil, EventBadOutput, errors.New("plugin: request does not fit the buffer")
	}
	res, err := mod.ExportedFunction(fn).Call(ctx, uint64(len(in)))
	if err != nil {
		return failed(err)
	}
	if len(res) != 1 {
		return nil, EventBadOutput, errBadOutput
	}
	n := int32(uint32(res[0]))
	if n < 0 {
		return nil, EventPluginError, fmt.Errorf("plugin: hook reported failure %d", n)
	}
	if n > BufferSize {
		return nil, EventBadOutput, errBadOutput
	}
	b, ok := mod.Memory().Read(off, uint32(n))
	if !ok {
		return nil, EventBadOutput, errBadOutput
	}
	return append([]byte(nil), b...), "", nil
}

func (h *Host) emit(plugin, hook, kind string, err error) {
	if h.onEvent == nil {
		return
	}
	ev := Event{Time: h.now(), Plugin: plugin, Hook: hook, Kind: kind}
	if err != nil {
		ev.Detail = short(err)
	}
	h.onEvent(ev)
}

// short keeps the first line of an error, bounded; wazero traps append a
// stack trace that the panel does not need.
func short(err error) string {
	s := err.Error()
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			s = s[:i]
			break
		}
	}
	return truncate(s, maxEventDetail)
}
