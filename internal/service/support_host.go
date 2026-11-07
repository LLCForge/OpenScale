package service

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"

	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/rdesk"
	"github.com/openscale/openscale/internal/support"
	"github.com/openscale/openscale/internal/trust"
)

// Remote support toolbox in the desktop service (#852, ADR-0232).
//
// Target side: the support server runs when a signed support rule names
// this device. Every request is authorized from the accepted document
// (never from anything the coordinator says), asks the person at the device
// through a pending request shown in the local panel and a desktop
// notification, and shows the "remotely connected" notice: the #671 frame
// where this process can draw on the user's screen, the notification and
// the red bar in the local panel otherwise.
//
// Helper side: SupportSnapshot and SupportKill dial the target's support
// port inside the tunnel.

const (
	maxSupportPending = 8
	maxSupportLog     = 50
)

// newSupportFrame shows the #671 frame for a support session; tests
// replace it so no window is ever drawn by a test run.
var newSupportFrame = defaultSupportFrame

// supportCollector replaces the system collector in tests; nil means
// support.System.
var supportCollector support.Collector

func defaultSupportFrame(info support.SessionInfo) (rdesk.SessionFrame, error) {
	if !canDrawFrame() {
		return nil, rdesk.ErrUnsupported
	}
	mode := rdesk.ModeView
	if info.Kill {
		mode = rdesk.ModeControl
	}
	return rdesk.NewSystemFrame(rdesk.FrameInfo{Peer: info.Peer + " (destek)", Mode: mode})
}

type pendingSupport struct {
	req    support.Request
	decide chan bool
}

// supportHost is the Apps state of the toolbox.
type supportHost struct {
	mu      sync.Mutex
	srv     *support.Server
	pending map[string]*pendingSupport
	log     []support.LogEvent
	// notify sends a desktop notification and a security event (set by
	// the runtime, support_runtime.go).
	notify func(kind, peer, message string)
	// target maps a device to its support address; tests point it at
	// loopback.
	target func(trust.Device) netip.AddrPort
	dial   support.DialFunc
}

func (a *Apps) supportState() *supportHost {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.supportHostState == nil {
		a.supportHostState = &supportHost{pending: map[string]*pendingSupport{}}
	}
	return a.supportHostState
}

// SetSupportNotify sets how support requests and sessions reach the
// person at the device.
func (a *Apps) SetSupportNotify(fn func(kind, peer, message string)) {
	h := a.supportState()
	h.mu.Lock()
	h.notify = fn
	h.mu.Unlock()
}

func (h *supportHost) send(kind, peer, msg string) bool {
	h.mu.Lock()
	fn := h.notify
	h.mu.Unlock()
	if fn == nil {
		return false
	}
	fn(kind, peer, msg)
	return true
}

// startSupport builds the support server for the tunnel listener.
func (a *Apps) startSupport(ctx context.Context, ln net.Listener) (func() error, error) {
	h := a.supportState()
	srv, err := support.New(support.Config{
		Authorize: a.authorizeSupport,
		Consent:   a.supportConsent,
		Indicator: a.supportIndicator,
		OnEvent:   a.supportEvent,
		Collector: supportCollector,
		Now:       a.cfg.Now,
		Logger:    a.log.With("service", "support"),
	})
	if err != nil {
		return nil, err
	}
	h.mu.Lock()
	h.srv = srv
	h.mu.Unlock()
	return func() error {
		defer func() {
			h.mu.Lock()
			if h.srv == srv {
				h.srv = nil
			}
			h.mu.Unlock()
		}()
		return srv.Serve(ctx, ln)
	}, nil
}

// authorizeSupport decides from the accepted document only. The source
// address must be a device of that document other than this one.
func (a *Apps) authorizeSupport(remote netip.Addr, mode support.Mode) support.Decision {
	doc, self, dev, ok := a.peer(remote)
	if !ok {
		return support.Decision{Reason: "kaynak adres ağdaki bir cihaz değil"}
	}
	m := trust.SupportRead
	if mode == support.ModeKill {
		m = trust.SupportKill
	}
	if !doc.AllowsSupport(dev.Name, self.Name, m) {
		return support.Decision{Peer: dev.Name, Reason: "kural izin vermiyor"}
	}
	return support.Decision{Allowed: true, Peer: dev.Name}
}

// supportConsent waits for the person at the device.
func (a *Apps) supportConsent(ctx context.Context, req support.Request) (bool, error) {
	h := a.supportState()
	p := &pendingSupport{req: req, decide: make(chan bool, 1)}
	h.mu.Lock()
	if len(h.pending) >= maxSupportPending {
		h.mu.Unlock()
		return false, errors.New("çok fazla bekleyen destek isteği")
	}
	h.pending[req.ID] = p
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		delete(h.pending, req.ID)
		h.mu.Unlock()
	}()
	what := "işlemleri, hizmetleri, sistem olaylarını, diskleri ve açılış programlarını görmek"
	if req.Kill {
		what = "bir süreci sonlandırmak"
	}
	h.send("support_request", req.Peer, req.Peer+" bu cihazda "+what+" istiyor. OpenScale panelini açıp izin verin veya reddedin; yanıt vermezseniz istek bir dakikada düşer.")
	select {
	case ok := <-p.decide:
		return ok, nil
	case <-ctx.Done():
		return false, ctx.Err()
	}
}

// supportIndicator shows the session; at least one visible channel must
// work or the session does not start.
func (a *Apps) supportIndicator(info support.SessionInfo) (support.Indicator, error) {
	h := a.supportState()
	what := "salt okunur"
	if info.Kill {
		what = "süreç sonlandırma dahil"
	}
	notified := h.send("support_connected", info.Peer, "Uzaktan destek bağlı: "+info.Peer+" ("+what+"). Kesmek için OpenScale panelindeki \"Desteği kes\" düğmesini kullanın.")
	frame, err := newSupportFrame(info)
	if err != nil {
		frame = nil
		if !errors.Is(err, rdesk.ErrUnsupported) {
			a.log.Warn("support frame failed", "peer", info.Peer, "error", err.Error())
		}
	}
	if !notified && frame == nil {
		return nil, errors.New("görünür bir uzaktan bağlı göstergesi yok")
	}
	return &supportIndicator{h: h, peer: info.Peer, frame: frame}, nil
}

type supportIndicator struct {
	h     *supportHost
	peer  string
	frame rdesk.SessionFrame
	once  sync.Once
}

func (i *supportIndicator) Close() error {
	var err error
	i.once.Do(func() {
		if i.frame != nil {
			err = i.frame.Close()
		}
		i.h.send("support_ended", i.peer, "Uzaktan destek oturumu bitti: "+i.peer+".")
	})
	return err
}

func (a *Apps) supportEvent(ev support.LogEvent) {
	h := a.supportState()
	h.mu.Lock()
	h.log = append(h.log, ev)
	if len(h.log) > maxSupportLog {
		h.log = slices.Delete(h.log, 0, len(h.log)-maxSupportLog)
	}
	h.mu.Unlock()
	if ev.Kind == support.EventKill {
		h.send("support_kill", ev.Peer, ev.Peer+" bu cihazda bir süreci sonlandırdı: "+ev.Detail+".")
	}
}

// --- panel.SupportApp, target side ---

// SupportLocal implements panel.SupportApp.
func (a *Apps) SupportLocal() panel.SupportLocalView {
	h := a.supportState()
	v := panel.SupportLocalView{}
	if doc, self, ok := a.current(); ok {
		v.Hosted = doc.HostsService(self.Name, trust.ServiceSupport)
	}
	h.mu.Lock()
	srv := h.srv
	for _, p := range h.pending {
		v.Pending = append(v.Pending, p.req)
	}
	v.Log = slices.Clone(h.log)
	h.mu.Unlock()
	slices.SortFunc(v.Pending, func(x, y support.Request) int { return x.At.Compare(y.At) })
	slices.Reverse(v.Log)
	if srv != nil {
		v.Sessions = srv.Sessions()
	}
	return v
}

// SupportDecide implements panel.SupportApp.
func (a *Apps) SupportDecide(id string, accept bool) error {
	h := a.supportState()
	h.mu.Lock()
	p := h.pending[id]
	h.mu.Unlock()
	if p == nil {
		return errors.New("istek bulunamadı")
	}
	select {
	case p.decide <- accept:
	default:
	}
	return nil
}

// SupportEndAll implements panel.SupportApp.
func (a *Apps) SupportEndAll() int {
	h := a.supportState()
	h.mu.Lock()
	srv := h.srv
	for _, p := range h.pending {
		select {
		case p.decide <- false:
		default:
		}
	}
	h.mu.Unlock()
	if srv == nil {
		return 0
	}
	return srv.EndAll("cihazdaki kişi desteği kesti")
}

// --- panel.SupportApp, helper side ---

func (a *Apps) supportTarget(device string, mode trust.SupportMode) (netip.AddrPort, *support.Client, error) {
	doc, self, ok := a.current()
	if !ok {
		return netip.AddrPort{}, nil, errNoTunnel()
	}
	target, ok := doc.DeviceByName(normalizeDevice(device))
	if !ok || target.Name == self.Name {
		return netip.AddrPort{}, nil, errors.New("böyle bir cihaz yok")
	}
	if !doc.AllowsSupport(self.Name, target.Name, mode) {
		if mode == trust.SupportKill {
			return netip.AddrPort{}, nil, errors.New("bu cihazda süreç sonlandırmaya izin veren bir destek kuralı (support.kill) yok")
		}
		return netip.AddrPort{}, nil, errors.New("bu cihaza destek izni veren bir kural yok")
	}
	h := a.supportState()
	h.mu.Lock()
	mapTarget, dial := h.target, h.dial
	h.mu.Unlock()
	addr := netip.AddrPortFrom(target.IPv4, trust.SupportPort)
	if mapTarget != nil {
		addr = mapTarget(target)
	}
	return addr, support.NewClient(dial), nil
}

// SupportSnapshot implements panel.SupportApp.
func (a *Apps) SupportSnapshot(ctx context.Context, device, kind string) (support.Snapshot, error) {
	addr, c, err := a.supportTarget(device, trust.SupportRead)
	if err != nil {
		return support.Snapshot{}, err
	}
	return c.Snapshot(ctx, addr, strings.TrimSpace(kind))
}

// SupportKill implements panel.SupportApp.
func (a *Apps) SupportKill(ctx context.Context, device string, pid int, name string) error {
	addr, c, err := a.supportTarget(device, trust.SupportKill)
	if err != nil {
		return err
	}
	return c.Kill(ctx, addr, pid, name)
}
