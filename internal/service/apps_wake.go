package service

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/sysinfo"
	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/internal/wol"
)

// Wake-on-LAN relay (ADR-0031). A device that may wake a sleeping one asks
// a relay device on the sleeper's LAN, through the tunnel, to broadcast the
// magic packet there. The request is one JSON line to the relay's tunnel
// address on trust.WakePort; the relay checks AllowsWake(from, target,
// itself) and answers with one JSON line.

const (
	wakeProtocol    = 1
	maxWakeRequest  = 512
	wakeIOTimeout   = 5 * time.Second
	wakeMaxConns    = 4
	wakePerSource   = 3 * time.Second
	wakeGlobalLimit = 20 // per minute
)

type wakeRequest struct {
	V      int    `json:"v"`
	Target string `json:"target"`
	MAC    string `json:"mac"`
}

type wakeReply struct {
	OK    bool   `json:"ok"`
	Sent  int    `json:"sent,omitempty"`
	Error string `json:"error,omitempty"`
}

var (
	// ErrWakeDenied means the relay refused the request.
	ErrWakeDenied = errors.New("aracı cihaz uyandırma isteğini reddetti (kural yok)")
	// ErrWakeNoLAN means the relay found no LAN interface to send on.
	ErrWakeNoLAN = errors.New("aracı cihazda magic paket gönderilecek bir yerel ağ bulunamadı")
)

type wakeServer struct {
	a      *Apps
	mu     sync.Mutex
	last   map[netip.Addr]time.Time
	minute time.Time
	count  int
	slots  chan struct{}
}

func newWakeServer(a *Apps) *wakeServer {
	return &wakeServer{a: a, last: map[netip.Addr]time.Time{}, slots: make(chan struct{}, wakeMaxConns)}
}

func (w *wakeServer) serve(ctx context.Context, ln net.Listener) error {
	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		select {
		case w.slots <- struct{}{}:
		default:
			_ = c.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-w.slots }()
			defer c.Close()
			w.handle(ctx, c)
		}()
	}
}

// allowRate limits wake requests per source and overall.
func (w *wakeServer) allowRate(from netip.Addr, now time.Time) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if now.Sub(w.minute) >= time.Minute {
		w.minute, w.count = now, 0
		for k, t := range w.last {
			if now.Sub(t) > time.Minute {
				delete(w.last, k)
			}
		}
	}
	if t, ok := w.last[from]; ok && now.Sub(t) < wakePerSource {
		return false
	}
	if w.count >= wakeGlobalLimit {
		return false
	}
	w.last[from] = now
	w.count++
	return true
}

func (w *wakeServer) handle(ctx context.Context, c net.Conn) {
	_ = c.SetDeadline(time.Now().Add(wakeIOTimeout))
	ta, ok := c.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return
	}
	from := ta.AddrPort().Addr().Unmap()
	reply := func(r wakeReply) {
		data, _ := json.Marshal(r)
		_, _ = c.Write(append(data, '\n'))
	}
	line, err := bufio.NewReaderSize(io.LimitReader(c, maxWakeRequest), maxWakeRequest).ReadSlice('\n')
	if err != nil {
		return
	}
	var req wakeRequest
	dec := json.NewDecoder(strings.NewReader(string(line)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || req.V != wakeProtocol {
		reply(wakeReply{Error: "geçersiz istek"})
		return
	}
	doc, self, dev, ok := w.a.peer(from)
	if !ok || !doc.AllowsWake(dev.Name, req.Target, self.Name) {
		w.a.log.Info("wake request refused: no rule allows it")
		reply(wakeReply{Error: "izin yok"})
		return
	}
	mac, err := wol.ParseMAC(req.MAC)
	if err != nil {
		reply(wakeReply{Error: "geçersiz MAC adresi"})
		return
	}
	if !w.allowRate(from, time.Now()) {
		reply(wakeReply{Error: "çok sık istek; birkaç saniye sonra yeniden deneyin"})
		return
	}
	send := w.a.wakeLocal
	if w.a.wakeSend != nil {
		send = w.a.wakeSend
	}
	sent, err := send(ctx, doc, mac)
	if err != nil {
		w.a.log.Warn("wake packet not sent", "error", err.Error())
		reply(wakeReply{Error: err.Error()})
		return
	}
	w.a.log.Info("wake packet sent", "from", dev.Name, "target", req.Target, "interfaces", sent)
	reply(wakeReply{OK: true, Sent: sent})
}

// wakeLocal broadcasts the magic packet on every LAN interface of this
// computer except the tunnel.
func (a *Apps) wakeLocal(ctx context.Context, doc *trust.Document, mac net.HardwareAddr) (int, error) {
	targets, err := wol.Targets(a.skipInterface)
	if err != nil {
		return 0, err
	}
	sent := 0
	var lastErr error
	for _, t := range targets {
		if doc != nil && (doc.IPv4Prefix.Contains(t.Source)) {
			continue
		}
		sctx, cancel := context.WithTimeout(ctx, wakeIOTimeout)
		err := wol.Send(sctx, wol.Options{MAC: mac, Broadcast: t.Broadcast, Source: t.Source})
		cancel()
		if err != nil {
			lastErr = err
			continue
		}
		sent++
	}
	if sent == 0 {
		if lastErr != nil {
			return 0, lastErr
		}
		return 0, ErrWakeNoLAN
	}
	return sent, nil
}

func (a *Apps) skipInterface(name string) bool {
	if a.cfg.TunnelInterface != nil {
		if t := a.cfg.TunnelInterface(); t != "" && strings.EqualFold(t, name) {
			return true
		}
	}
	return strings.HasPrefix(strings.ToLower(name), "openscale")
}

// localWakeMAC returns the MAC of the first LAN card with an IPv4 address
// outside the tunnel; it is what other devices use to wake this one.
func (a *Apps) localWakeMAC() string {
	targets, err := wol.Targets(a.skipInterface)
	if err != nil {
		return ""
	}
	var overlay netip.Prefix
	if doc, _, ok := a.current(); ok {
		overlay = doc.IPv4Prefix
	}
	for _, t := range targets {
		if overlay.IsValid() && overlay.Contains(t.Source) {
			continue
		}
		ifc, err := net.InterfaceByName(t.Interface)
		if err != nil {
			continue
		}
		if m := sysinfo.NormalizeMAC(ifc.HardwareAddr.String()); m != "" {
			return m
		}
	}
	return ""
}

// SendWakeRequest asks the relay at addr to wake target with mac.
func SendWakeRequest(ctx context.Context, addr netip.AddrPort, target, mac string) (int, error) {
	d := net.Dialer{Timeout: wakeIOTimeout}
	c, err := d.DialContext(ctx, "tcp", addr.String())
	if err != nil {
		return 0, fmt.Errorf("aracı cihaza bağlanılamadı: %w", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * wakeIOTimeout))
	data, err := json.Marshal(wakeRequest{V: wakeProtocol, Target: target, MAC: mac})
	if err != nil {
		return 0, err
	}
	if _, err := c.Write(append(data, '\n')); err != nil {
		return 0, fmt.Errorf("istek gönderilemedi: %w", err)
	}
	line, err := bufio.NewReaderSize(io.LimitReader(c, maxWakeRequest), maxWakeRequest).ReadSlice('\n')
	if err != nil {
		return 0, fmt.Errorf("aracı cihaz yanıt vermedi: %w", err)
	}
	var r wakeReply
	if err := json.Unmarshal(line, &r); err != nil {
		return 0, errors.New("aracı cihazın yanıtı anlaşılamadı")
	}
	if !r.OK {
		if r.Error == "izin yok" {
			return 0, ErrWakeDenied
		}
		return 0, fmt.Errorf("aracı cihaz: %s", r.Error)
	}
	return r.Sent, nil
}

// Wake implements panel.RemoteApps.
func (a *Apps) Wake(ctx context.Context, device string) (panel.WakeResult, error) {
	doc, self, ok := a.current()
	if !ok {
		return panel.WakeResult{}, errNoTunnel()
	}
	target, ok := doc.DeviceByName(normalizeDevice(device))
	if !ok {
		return panel.WakeResult{}, errors.New("böyle bir cihaz yok")
	}
	relays := doc.WakeRelays(self.Name, target.Name)
	if len(relays) == 0 {
		return panel.WakeResult{}, errors.New("bu cihazı uyandırmaya izin veren bir wake kuralı (aracı cihazıyla) yok")
	}
	macs, _ := LoadWakeMACs(a.cfg.Dir)
	mac := WakeMACFor(macs, target.Name)
	if mac == "" {
		return panel.WakeResult{}, errors.New("cihazın MAC adresi bilinmiyor; cihaz açıkken envanter toplanınca öğrenilir veya elle girilebilir")
	}
	return WakeVia(ctx, doc, self.Name, target.Name, mac, relays, func(ctx context.Context, hw net.HardwareAddr) (int, error) {
		return a.wakeLocal(ctx, doc, hw)
	})
}

// WakeVia tries the relays in order: this device itself sends locally,
// others get a wake request through the tunnel.
func WakeVia(ctx context.Context, doc *trust.Document, self, target, mac string, relays []string,
	local func(context.Context, net.HardwareAddr) (int, error)) (panel.WakeResult, error) {
	hw, err := wol.ParseMAC(mac)
	if err != nil {
		return panel.WakeResult{}, err
	}
	var errs []error
	for _, relay := range relays {
		if relay == self {
			if local == nil {
				continue
			}
			if _, err := local(ctx, hw); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", relay, err))
				continue
			}
			return panel.WakeResult{Relay: relay, MAC: hw.String()}, nil
		}
		d, ok := doc.DeviceByName(relay)
		if !ok {
			continue
		}
		if _, err := SendWakeRequest(ctx, netip.AddrPortFrom(d.IPv4, trust.WakePort), target, hw.String()); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", relay, err))
			continue
		}
		return panel.WakeResult{Relay: relay, MAC: hw.String()}, nil
	}
	if len(errs) == 0 {
		return panel.WakeResult{}, errors.New("kullanılabilir aracı cihaz yok")
	}
	return panel.WakeResult{}, errors.Join(errs...)
}

// SetWakeMAC implements panel.RemoteApps.
func (a *Apps) SetWakeMAC(device, mac string) error {
	device = normalizeDevice(device)
	doc, _, ok := a.current()
	if !ok {
		return errNoTunnel()
	}
	if _, ok := doc.DeviceByName(device); !ok {
		return errors.New("böyle bir cihaz yok")
	}
	norm := ""
	if strings.TrimSpace(mac) != "" {
		hw, err := wol.ParseMAC(mac)
		if err != nil {
			return errors.New("geçersiz MAC adresi")
		}
		norm = hw.String()
	}
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	macs, _ := LoadWakeMACs(a.cfg.Dir)
	if norm == "" {
		delete(macs, manualKey(device))
	} else {
		macs[manualKey(device)] = norm
	}
	return saveJSON(a.appsPath(wakeMACsFn), macs)
}
