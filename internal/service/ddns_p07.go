package service

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/audit"
	"github.com/openscale/openscale/internal/ddns"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/securefile"
)

// Dynamic DNS check and updater (P07, ADR-0160; #448, #449).
//
// The check compares the coordinator's name in the trust document with
// the address the tunnel really talks to. The updater sends an RFC 2136
// update signed with the owner's TSIG key to the owner's own
// authoritative server when the public address the coordinator reports
// for this device changes. It is off until the owner configures it; the
// secret is kept owner-only beside the settings and never shown again.

const (
	ddnsConfigFn   = "ddns.json"
	ddnsKeyFn      = "ddns.key"
	ddnsEvery      = 10 * time.Minute
	ddnsRetryAfter = 2 * time.Minute
	ddnsOpTimeout  = 20 * time.Second
	ddnsKeyHeader  = "openscale-ddns-tsig-v1"
)

type ddnsConfig struct {
	Enabled   bool   `json:"enabled,omitempty"`
	Server    string `json:"server,omitempty"`
	Zone      string `json:"zone,omitempty"`
	Name      string `json:"name,omitempty"`
	TTL       uint32 `json:"ttl,omitempty"`
	KeyName   string `json:"key_name,omitempty"`
	Algorithm string `json:"algorithm,omitempty"`
	// Published is the address the server last accepted.
	Published   string    `json:"published,omitempty"`
	PublishedAt time.Time `json:"published_at,omitzero"`
}

type ddnsState struct {
	mu        sync.Mutex
	check     *panel.DDNSCheckView
	lastTry   time.Time
	lastError string
	alerted   string // status of the last alert, to alert once per change
	// lookup and observed are replaced in tests.
	lookup   ddns.Lookup
	observed func() (string, netip.Addr, bool)
	public   func() netip.Addr
}

var ddnsStates sync.Map // *Runtime -> *ddnsState

func (r *Runtime) ddns() *ddnsState {
	if v, ok := ddnsStates.Load(r); ok {
		return v.(*ddnsState)
	}
	v, _ := ddnsStates.LoadOrStore(r, &ddnsState{lookup: ddns.SystemLookup, observed: r.coordinatorObserved, public: r.publicAddr})
	return v.(*ddnsState)
}

func (r *Runtime) ddnsPath(name string) string { return filepath.Join(r.cfg.DataDir, name) }

func (r *Runtime) loadDDNS() (ddnsConfig, error) {
	var c ddnsConfig
	err := loadJSON(r.ddnsPath(ddnsConfigFn), &c)
	if errors.Is(err, fs.ErrNotExist) {
		return ddnsConfig{}, nil
	}
	return c, err
}

func (r *Runtime) loadDDNSKey(c ddnsConfig) (ddns.Key, error) {
	data, err := securefile.ReadPrivate(r.ddnsPath(ddnsKeyFn), 4096)
	if err != nil {
		return ddns.Key{}, err
	}
	f := strings.Fields(string(data))
	if len(f) != 2 || f[0] != ddnsKeyHeader {
		return ddns.Key{}, errors.New("ddns.key bozuk")
	}
	return ddns.ParseKey(c.KeyName, c.Algorithm, f[1])
}

// coordinatorObserved returns the coordinator's host name from the
// document and the address the tunnel talks to it at.
func (r *Runtime) coordinatorObserved() (string, netip.Addr, bool) {
	e := r.currentEngine()
	if e == nil {
		return "", netip.Addr{}, false
	}
	doc := e.Document()
	if doc == nil || doc.Coordinator == nil {
		return "", netip.Addr{}, false
	}
	host, _, err := net.SplitHostPort(doc.Coordinator.Endpoint)
	if err != nil {
		return "", netip.Addr{}, false
	}
	stats, err := e.PeerStats()
	if err != nil {
		return host, netip.Addr{}, true
	}
	p, ok := stats[doc.Coordinator.WireGuardKey]
	if !ok || !p.Endpoint.IsValid() || p.LastHandshakeUnix == 0 {
		return host, netip.Addr{}, true
	}
	return host, p.Endpoint.Addr().Unmap(), true
}

// publicAddr is the public address the coordinator reports for this
// device.
func (r *Runtime) publicAddr() netip.Addr {
	e := r.currentEngine()
	if e == nil {
		return netip.Addr{}
	}
	a, err := netip.ParseAddr(e.SelfInfo().PublicIP)
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap()
}

// ddnsCheck runs the consistency check and alerts once per new problem.
func (r *Runtime) ddnsCheck(ctx context.Context) *panel.DDNSCheckView {
	st := r.ddns()
	host, observed, ok := st.observed()
	if !ok || host == "" {
		return nil
	}
	res := ddns.Check(ctx, st.lookup, host, observed)
	v := &panel.DDNSCheckView{At: r.cfg.Now().UTC(), Host: res.Host, Resolved: res.Resolved, Status: string(res.Status), Message: res.Message}
	if res.Observed.IsValid() {
		v.Observed = res.Observed.String()
	}
	st.mu.Lock()
	st.check = v
	alert := (res.Status == ddns.StatusStale || res.Status == ddns.StatusUnresolved) && st.alerted != string(res.Status)
	if res.Status == ddns.StatusOK {
		st.alerted = ""
	} else if alert {
		st.alerted = string(res.Status)
	}
	st.mu.Unlock()
	if alert {
		r.observer().Security("ddns_stale", audit.SeverityWarning, panel.CategoryConnection, "", res.Message, true)
	}
	return v
}

// ddnsUpdate publishes the current public address when it changed.
func (r *Runtime) ddnsUpdate(ctx context.Context, force bool) error {
	c, err := r.loadDDNS()
	if err != nil {
		return err
	}
	if !c.Enabled {
		if force {
			return errors.New("dinamik DNS güncelleyici kapalı")
		}
		return nil
	}
	st := r.ddns()
	now := r.cfg.Now().UTC()
	st.mu.Lock()
	if !force && st.lastError != "" && now.Sub(st.lastTry) < ddnsRetryAfter {
		st.mu.Unlock()
		return nil
	}
	st.mu.Unlock()
	addr := st.public()
	if !ddns.Public(addr) {
		if force {
			return errors.New("bu cihazın genel adresi bilinmiyor veya genel bir adres değil; yayımlanmadı")
		}
		return nil
	}
	if !force && c.Published == addr.String() {
		return nil
	}
	key, err := r.loadDDNSKey(c)
	if err != nil {
		return r.ddnsFailed(now, fmt.Errorf("TSIG anahtarı okunamadı: %w", err))
	}
	server, err := netip.ParseAddrPort(c.Server)
	if err != nil {
		return r.ddnsFailed(now, errors.New("DNS sunucusu adresi geçersiz"))
	}
	cl := &ddns.Client{Server: server, Key: key, Now: r.cfg.Now}
	opCtx, cancel := context.WithTimeout(ctx, ddnsOpTimeout)
	defer cancel()
	if err := cl.Send(opCtx, ddns.Update{Zone: c.Zone, Name: c.Name, TTL: c.TTL, Addrs: []netip.Addr{addr}}); err != nil {
		return r.ddnsFailed(now, err)
	}
	c.Published, c.PublishedAt = addr.String(), now
	if err := saveJSON(r.ddnsPath(ddnsConfigFn), c); err != nil {
		return err
	}
	st.mu.Lock()
	st.lastTry, st.lastError = now, ""
	st.mu.Unlock()
	r.logger.Info("dynamic DNS updated", "name", c.Name)
	r.auditLocal("ddns_updated", "Dinamik DNS kaydı güncellendi: "+c.Name+" -> "+addr.String())
	return nil
}

func (r *Runtime) ddnsFailed(now time.Time, err error) error {
	st := r.ddns()
	st.mu.Lock()
	first := st.lastError == ""
	st.lastTry, st.lastError = now, err.Error()
	st.mu.Unlock()
	r.logger.Warn("dynamic DNS update failed", "error", err.Error())
	if first {
		r.observer().Security("ddns_update_failed", audit.SeverityWarning, panel.CategoryConnection, "", "Dinamik DNS güncellenemedi: "+err.Error(), true)
	}
	return err
}

// p07Loop runs the check and the updater.
func (r *Runtime) p07Loop(ctx context.Context) {
	t := time.NewTicker(ddnsEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		opCtx, cancel := context.WithTimeout(ctx, ddnsOpTimeout)
		r.ddnsCheck(opCtx)
		cancel()
		_ = r.ddnsUpdate(ctx, false)
	}
}

// --- panel.DDNSControl ---

var _ panel.DDNSControl = (*Runtime)(nil)

// DDNSStatus implements panel.DDNSControl.
func (r *Runtime) DDNSStatus() (panel.DDNSStatus, error) {
	c, err := r.loadDDNS()
	if err != nil {
		return panel.DDNSStatus{}, err
	}
	st := r.ddns()
	out := panel.DDNSStatus{Updater: panel.DDNSUpdaterView{Enabled: c.Enabled, Server: c.Server, Zone: c.Zone, Name: c.Name, TTL: c.TTL,
		KeyName: c.KeyName, Algorithm: c.Algorithm, Published: c.Published}}
	if !c.PublishedAt.IsZero() {
		t := c.PublishedAt
		out.Updater.PublishedAt = &t
	}
	if _, err := os.Stat(r.ddnsPath(ddnsKeyFn)); err == nil {
		out.Updater.KeySet = true
	}
	if a := st.public(); a.IsValid() {
		out.Updater.Current = a.String()
	}
	st.mu.Lock()
	if st.check != nil {
		cp := *st.check
		out.Check = &cp
	}
	if !st.lastTry.IsZero() {
		t := st.lastTry
		out.Updater.LastTry = &t
	}
	out.Updater.LastError = st.lastError
	st.mu.Unlock()
	return out, nil
}

// SetDDNS implements panel.DDNSControl.
func (r *Runtime) SetDDNS(req panel.DDNSConfigRequest) (panel.DDNSStatus, error) {
	old, err := r.loadDDNS()
	if err != nil {
		return panel.DDNSStatus{}, err
	}
	c := ddnsConfig{Enabled: req.Enabled, Server: strings.TrimSpace(req.Server), Zone: strings.TrimSpace(req.Zone),
		Name: strings.TrimSpace(req.Name), TTL: req.TTL, KeyName: strings.TrimSpace(req.KeyName), Algorithm: strings.TrimSpace(req.Algorithm)}
	if c.Algorithm == "" {
		c.Algorithm = "hmac-sha256"
	}
	if c.Server != "" || c.Enabled {
		ap, err := netip.ParseAddrPort(c.Server)
		if err != nil || ap.Port() == 0 || ap.Addr().IsUnspecified() || ap.Addr().IsMulticast() {
			return panel.DDNSStatus{}, errors.New("DNS sunucusu IP:port biçiminde olmalı (ör. sunucunun IP adresi ve 53)")
		}
		c.Server = ap.String()
	}
	if c.Enabled || c.Zone != "" || c.Name != "" {
		u := ddns.Update{Zone: c.Zone, Name: c.Name, TTL: c.TTL, Addrs: []netip.Addr{netip.IPv4Unspecified()}}
		if err := u.Validate(); err != nil {
			return panel.DDNSStatus{}, err
		}
	}
	// The secret: nil keeps it, "" removes it, otherwise it is checked
	// and stored owner-only.
	keyPath := r.ddnsPath(ddnsKeyFn)
	switch {
	case req.Secret == nil:
	case *req.Secret == "":
		if err := os.Remove(keyPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return panel.DDNSStatus{}, err
		}
	default:
		secret := strings.TrimSpace(*req.Secret)
		if _, err := ddns.ParseKey(c.KeyName, c.Algorithm, secret); err != nil {
			return panel.DDNSStatus{}, err
		}
		if _, err := base64.StdEncoding.DecodeString(secret); err != nil {
			return panel.DDNSStatus{}, errors.New("gizli değer base64 olmalı")
		}
		if err := os.MkdirAll(r.cfg.DataDir, 0o700); err != nil {
			return panel.DDNSStatus{}, err
		}
		if err := securefile.Replace(keyPath, []byte(ddnsKeyHeader+" "+secret+"\n")); err != nil {
			return panel.DDNSStatus{}, err
		}
	}
	if c.Enabled {
		if _, err := os.Stat(keyPath); err != nil {
			return panel.DDNSStatus{}, errors.New("güncelleyiciyi açmak için TSIG gizli değeri gerekli")
		}
		if _, err := ddns.ParseKey(c.KeyName, c.Algorithm, base64.StdEncoding.EncodeToString(make([]byte, 32))); err != nil {
			return panel.DDNSStatus{}, err
		}
	}
	// A changed target is published again.
	if old.Server == c.Server && old.Zone == c.Zone && old.Name == c.Name && req.Secret == nil {
		c.Published, c.PublishedAt = old.Published, old.PublishedAt
	}
	if err := saveJSON(r.ddnsPath(ddnsConfigFn), c); err != nil {
		return panel.DDNSStatus{}, err
	}
	st := r.ddns()
	st.mu.Lock()
	st.lastError, st.lastTry = "", time.Time{}
	st.mu.Unlock()
	r.auditLocal("ddns_settings", fmt.Sprintf("Dinamik DNS güncelleyici ayarlandı (açık: %t, ad: %s)", c.Enabled, c.Name))
	return r.DDNSStatus()
}

// DDNSCheckNow implements panel.DDNSControl.
func (r *Runtime) DDNSCheckNow(ctx context.Context) (panel.DDNSStatus, error) {
	if r.ddnsCheck(ctx) == nil {
		return panel.DDNSStatus{}, errors.New("tünel kapalı veya koordinatör tanımlı değil")
	}
	return r.DDNSStatus()
}

// DDNSUpdateNow implements panel.DDNSControl.
func (r *Runtime) DDNSUpdateNow(ctx context.Context) (panel.DDNSStatus, error) {
	if err := r.ddnsUpdate(ctx, true); err != nil {
		return panel.DDNSStatus{}, err
	}
	return r.DDNSStatus()
}
