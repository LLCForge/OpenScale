package service

// #717 DNS enforcement on this computer (ADR-0213, ADR-0224): the owner's
// switch turns the dnsguard rule set into operating system rules through
// Hooks.DNSEnforce. The rules hold only while three things are true:
//
//   - the owner turned the switch on ("dns-enforce", panel switch);
//   - the tunnel interface exists and is up;
//   - an exit node is in use: only then does the system send every name
//     to a resolver inside the tunnel (the exit node, and MagicDNS for the
//     network's own names). Without one, general names go to the local
//     resolver and blocking it would cut the computer off.
//
// When any of them stops, the rules are removed; when the tunnel run ends
// they are removed before it returns. On Windows the WFP session is
// dynamic, so a crashed service leaves nothing behind; on Linux a stale
// nftables table of a crashed run is removed when the next run starts.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/dnsguard"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/trust"
)

// DNSApplier installs and removes the operating system rules
// (osnet.NewDNSEnforcer); nil in Hooks means this system has none.
type DNSApplier = dnsguard.Applier

// dnsEnforceEvery is how often the loop compares the wanted state with
// the installed one; a panel change wakes it at once.
const dnsEnforceEvery = 5 * time.Second

// dnsEnforceOptions live in settings.json under "tunnel"."dns_enforce";
// the zero value is off, so older settings files keep their behaviour.
type dnsEnforceOptions struct {
	On bool `json:"on,omitempty"`
	// DoHList is the owner's file of DoH endpoints (dnsguard.ParseDoHList).
	DoHList string `json:"doh_list,omitempty"`
}

var dnsEnforcePrefSpecs = []prefSpec{
	{"dns-enforce", "false", "Çıkış düğümü kullanılırken DNS yalnızca tünelden: tünel dışı DNS (53) ve DoT/DoQ (853) ile listedeki DoH uç noktaları işletim sisteminde engellenir", func(s settings) string { return boolText(s.tunnel().DNSEnforce.On) }},
	{"dns-enforce-doh-list", "", "Engellenecek DoH uç noktaları dosyası: satır başına adres, aralık veya ad (boş: yalnızca 53 ve 853)", func(s settings) string { return s.tunnel().DNSEnforce.DoHList }},
}

func init() { prefSpecs = append(prefSpecs, dnsEnforcePrefSpecs...) }

// applyWave2ExtraPref handles the keys after the wave 2 switch: DNS
// enforcement here, then the exit node resolver hardening (P05).
func applyWave2ExtraPref(w *wave2Options, key, v string) (bool, error) {
	if ok, err := applyDNSEnforcePref(&w.DNSEnforce, key, v); ok {
		return true, err
	}
	return applyExitDNSGuardPref(&w.ExitDNSGuard, key, v)
}

// applyDNSEnforcePref changes one key of "openscale set"; ok is false for
// other keys.
func applyDNSEnforcePref(o *dnsEnforceOptions, key, v string) (bool, error) {
	v = strings.TrimSpace(v)
	switch key {
	case "dns-enforce":
		on, err := parseBoolPref(key, v)
		if err == nil {
			o.On = on
		}
		return true, err
	case "dns-enforce-doh-list":
		if len(v) > maxPathPref {
			return true, errors.New("DoH listesi yolu çok uzun")
		}
		if v != "" {
			if _, err := loadDoHList(v); err != nil {
				return true, err
			}
		}
		o.DoHList = v
		return true, nil
	}
	return false, nil
}

// loadDoHList reads and checks the owner's DoH file.
func loadDoHList(p string) (dnsguard.DoHList, error) {
	if err := ValidLocalFile("DoH listesi", p); err != nil {
		return dnsguard.DoHList{}, err
	}
	f, err := os.Open(p) //nolint:gosec // the owner's own file, checked above
	if err != nil {
		return dnsguard.DoHList{}, fmt.Errorf("DoH listesi açılamadı: %w", err)
	}
	defer func() { _ = f.Close() }()
	l, err := dnsguard.ParseDoHList(io.LimitReader(f, dnsguard.MaxDoHFileSize+1))
	if err != nil {
		return dnsguard.DoHList{}, fmt.Errorf("DoH listesi: %w", err)
	}
	return l, nil
}

// dnsEnforceState is this process's view of the enforcement. Its mutex
// is a leaf.
type dnsEnforceState struct {
	mu      sync.Mutex
	enf     *dnsguard.Enforcer
	kick    chan struct{}
	running bool
	active  bool
	reason  string
	err     string
	doh     int
	dohKey  string
	dohList dnsguard.DoHList
	// ifaceUp and exitOf replace the system and the engine in tests.
	ifaceUp func(name string) bool
	exitOf  func() (string, *trust.Document)
}

func (r *Runtime) dnsEnforcer() *dnsguard.Enforcer {
	r.dnsEnf.mu.Lock()
	defer r.dnsEnf.mu.Unlock()
	if r.dnsEnf.enf == nil {
		r.dnsEnf.enf = &dnsguard.Enforcer{Applier: r.cfg.Hooks.DNSEnforce}
		r.dnsEnf.kick = make(chan struct{}, 1)
	}
	return r.dnsEnf.enf
}

// namedDevice is the part of the tunnel device the loop needs.
type namedDevice interface{ Name() (string, error) }

// startDNSEnforce follows the tunnel run that owns dev; the returned
// function stops the loop and waits until the rules are removed.
func (r *Runtime) startDNSEnforce(ctx context.Context, dev namedDevice, doc *trust.Document) func() {
	if r.cfg.Hooks.DNSEnforce == nil {
		return func() {}
	}
	name, err := dev.Name()
	if err != nil || name == "" {
		return func() {}
	}
	enf := r.dnsEnforcer()
	// A crashed earlier run may have left its rules (nftables tables live
	// in the kernel); they name a tunnel that no longer exists.
	if err := r.cfg.Hooks.DNSEnforce.Remove(); err != nil {
		r.logger.Warn("DNS enforcement cleanup", "error", err.Error())
	}
	lctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.dnsEnforceLoop(lctx, enf, name, doc)
	}()
	return func() {
		cancel()
		<-done
	}
}

func (r *Runtime) dnsEnforceLoop(ctx context.Context, enf *dnsguard.Enforcer, iface string, doc *trust.Document) {
	r.dnsEnf.mu.Lock()
	r.dnsEnf.running = true
	kick := r.dnsEnf.kick
	r.dnsEnf.mu.Unlock()
	defer func() {
		err := enf.Sync(false, false, dnsguard.EnforceConfig{})
		if err != nil {
			r.logger.Warn("DNS enforcement removal", "error", err.Error())
		}
		r.setDNSEnforceResult(false, "Tünel çalışmıyor.", err)
		r.dnsEnf.mu.Lock()
		r.dnsEnf.running = false
		r.dnsEnf.mu.Unlock()
	}()
	t := time.NewTicker(dnsEnforceEvery)
	defer t.Stop()
	for {
		r.dnsEnforceTick(enf, iface, doc)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-kick:
		}
	}
}

// dnsEnforceWant decides whether the rules should hold now and with which
// configuration; reason explains an inactive state to the owner.
func (r *Runtime) dnsEnforceWant(iface string, doc *trust.Document) (bool, dnsguard.EnforceConfig, string, error) {
	cfg := dnsguard.EnforceConfig{Tunnel: iface}
	st, err := r.currentSettings()
	if err != nil {
		return false, cfg, "Ayarlar okunamadı.", err
	}
	opts := st.tunnel().DNSEnforce
	if !opts.On {
		return false, cfg, "Kapalı.", nil
	}
	up, exitOf := interfaceUp, r.engineExit
	r.dnsEnf.mu.Lock()
	if r.dnsEnf.ifaceUp != nil {
		up = r.dnsEnf.ifaceUp
	}
	if r.dnsEnf.exitOf != nil {
		exitOf = r.dnsEnf.exitOf
	}
	r.dnsEnf.mu.Unlock()
	if !up(iface) {
		return false, cfg, "Tünel arayüzü ayakta değil.", nil
	}
	exit, cur := exitOf()
	if cur != nil {
		doc = cur
	}
	if exit == "" || doc == nil {
		return false, cfg, "Çıkış düğümü kullanılmıyor; DNS zorlama yalnızca çıkış düğümüyle çalışır.", nil
	}
	dev, ok := doc.DeviceByName(exit)
	if !ok || !dev.IPv4.IsValid() {
		return false, cfg, "Çıkış düğümünün tünel içi çözücüsü bilinmiyor.", nil
	}
	for _, a := range []netip.Addr{dev.IPv4, dev.IPv6, doc.DNSResolverIPv4(), doc.DNSResolverIPv6()} {
		if a.IsValid() {
			cfg.Resolvers = append(cfg.Resolvers, a)
		}
	}
	if opts.DoHList != "" {
		l, err := r.cachedDoHList(opts.DoHList)
		if err != nil {
			// Fail closed on the file only: 53 and 853 still hold.
			return true, cfg, "", err
		}
		cfg.DoH = l
	}
	return true, cfg, "", nil
}

// cachedDoHList rereads the file only when it changed.
func (r *Runtime) cachedDoHList(p string) (dnsguard.DoHList, error) {
	fi, err := os.Stat(p)
	if err != nil {
		return dnsguard.DoHList{}, fmt.Errorf("DoH listesi okunamadı: %w", err)
	}
	key := fmt.Sprintf("%s|%d|%d", p, fi.Size(), fi.ModTime().UnixNano())
	r.dnsEnf.mu.Lock()
	if r.dnsEnf.dohKey == key {
		l := r.dnsEnf.dohList
		r.dnsEnf.mu.Unlock()
		return l, nil
	}
	r.dnsEnf.mu.Unlock()
	l, err := loadDoHList(p)
	if err != nil {
		return dnsguard.DoHList{}, err
	}
	r.dnsEnf.mu.Lock()
	r.dnsEnf.dohKey, r.dnsEnf.dohList = key, l
	r.dnsEnf.mu.Unlock()
	return l, nil
}

func (r *Runtime) dnsEnforceTick(enf *dnsguard.Enforcer, iface string, doc *trust.Document) {
	want, cfg, reason, werr := r.dnsEnforceWant(iface, doc)
	err := enf.Sync(want, want, cfg)
	if err == nil {
		err = werr
	}
	r.dnsEnf.mu.Lock()
	r.dnsEnf.doh = len(cfg.DoH.Prefixes)
	r.dnsEnf.mu.Unlock()
	r.setDNSEnforceResult(enf.Installed(), reason, err)
}

func (r *Runtime) setDNSEnforceResult(active bool, reason string, err error) {
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	r.dnsEnf.mu.Lock()
	changed := r.dnsEnf.active != active || r.dnsEnf.err != msg
	r.dnsEnf.active, r.dnsEnf.reason, r.dnsEnf.err = active, reason, msg
	r.dnsEnf.mu.Unlock()
	if !changed {
		return
	}
	switch {
	case msg != "":
		r.logger.Warn("DNS enforcement", "active", active, "error", msg)
	case active:
		r.logger.Info("DNS enforcement installed")
	default:
		r.logger.Info("DNS enforcement removed")
	}
}

// interfaceUp reports whether the named interface exists and is up.
func interfaceUp(name string) bool {
	ifi, err := net.InterfaceByName(name)
	return err == nil && ifi.Flags&net.FlagUp != 0
}

// DNSEnforceStatus implements panel.DNSEnforceControl.
func (r *Runtime) DNSEnforceStatus() (panel.DNSEnforceStatus, error) {
	st, err := r.currentSettings()
	if err != nil {
		return panel.DNSEnforceStatus{}, err
	}
	opts := st.tunnel().DNSEnforce
	r.dnsEnf.mu.Lock()
	defer r.dnsEnf.mu.Unlock()
	out := panel.DNSEnforceStatus{
		Supported: r.cfg.Hooks.DNSEnforce != nil,
		On:        opts.On,
		Active:    r.dnsEnf.active,
		Reason:    r.dnsEnf.reason,
		Error:     r.dnsEnf.err,
		DoHList:   opts.DoHList,
		DoHRanges: r.dnsEnf.doh,
	}
	if !r.dnsEnf.running {
		out.Active = false
		if opts.On {
			out.Reason = "Tünel çalışmıyor."
		} else {
			out.Reason = "Kapalı."
		}
	}
	return out, nil
}

// SetDNSEnforce implements panel.DNSEnforceControl: it saves the switch
// without restarting the tunnel and wakes the loop.
func (r *Runtime) SetDNSEnforce(on bool) (panel.DNSEnforceStatus, error) {
	if on && r.cfg.Hooks.DNSEnforce == nil {
		return panel.DNSEnforceStatus{}, errors.New("DNS zorlama bu sistemde yok")
	}
	err := r.updateSettings(func(st *settings) (bool, error) {
		t := st.tunnel()
		if t.DNSEnforce.On == on {
			return false, nil
		}
		t.DNSEnforce.On = on
		st.Tunnel = &t
		return true, nil
	})
	if err != nil {
		return panel.DNSEnforceStatus{}, err
	}
	state := "kapatıldı"
	if on {
		state = "açıldı"
	}
	r.auditLocal("dns_enforce_changed", "DNS zorlama "+state+".")
	r.dnsEnforcer()
	r.dnsEnf.mu.Lock()
	kick := r.dnsEnf.kick
	r.dnsEnf.mu.Unlock()
	select {
	case kick <- struct{}{}:
	default:
	}
	return r.DNSEnforceStatus()
}

// engineExit returns the exit node in use and the current document.
func (r *Runtime) engineExit() (string, *trust.Document) {
	e := r.currentEngine()
	if e == nil {
		return "", nil
	}
	return e.ExitNode(), e.Document()
}
