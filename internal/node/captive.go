package node

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/openscale/openscale/internal/osnet"
)

// Captive portal detection (F-018). When the exit node or the kill switch
// keeps all traffic in the tunnel and the coordinator stops answering, a
// hotel or café Wi-Fi may be waiting for its login page, which the tunnel
// hides. The check asks only the local default gateway for "/" over plain
// HTTP, without following redirects: no third-party test URL (such as the
// operating systems' connectivity checks) and no request to the
// coordinator. A portal is reported when the gateway answers 511 or
// redirects to another host.

const (
	captiveTimeout  = 3 * time.Second
	captiveInterval = 30 * time.Second
	// captiveAfterFails: failed syncs in a row before checking.
	captiveAfterFails = 2
	// captiveUserAgent is a generic browser string: the local network must
	// not learn from the check that OpenScale is running (ADR-0008).
	captiveUserAgent = "Mozilla/5.0"
)

// CaptiveStatus is the last captive portal check.
type CaptiveStatus struct {
	Checked    time.Time `json:"checked"`
	Detected   bool      `json:"detected"`
	Gateway    string    `json:"gateway,omitempty"`
	HTTPStatus int       `json:"http_status,omitempty"`
	// Location is the redirect target, for the owner to open by hand.
	Location string `json:"location,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

// captiveProber fetches http://gw/ without following redirects.
type captiveProber interface {
	get(ctx context.Context, gw netip.Addr) (status int, location string, err error)
}

// httpCaptiveProber asks gw on port 80 (port is set by tests only).
type httpCaptiveProber struct{ port uint16 }

func (h httpCaptiveProber) get(ctx context.Context, gw netip.Addr) (int, string, error) {
	tr := &http.Transport{
		Proxy:             nil, // never through a configured proxy
		DialContext:       (&net.Dialer{Timeout: captiveTimeout, Control: captiveControl}).DialContext,
		DisableKeepAlives: true,
		// A portal page can be large; only the head matters.
		MaxResponseHeaderBytes: 16 << 10,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{
		Transport:     tr,
		Timeout:       captiveTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	host := gw.String()
	if h.port != 0 {
		host = netip.AddrPortFrom(gw, h.port).String()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+host+"/", nil)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("User-Agent", captiveUserAgent)
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	_, _ = io.CopyN(io.Discard, resp.Body, 4<<10)
	return resp.StatusCode, resp.Header.Get("Location"), nil
}

// gatewayAllowed limits the check to local next hops: the request must
// never go to a public address.
func gatewayAllowed(gw netip.Addr) bool {
	gw = gw.Unmap()
	return gw.Is4() && (gw.IsPrivate() || gw.IsLinkLocalUnicast() || sharedAddressSpace.Contains(gw))
}

var sharedAddressSpace = netip.MustParsePrefix("100.64.0.0/10")

// detectCaptivePortal asks each gateway in turn and judges the answer.
func detectCaptivePortal(ctx context.Context, p captiveProber, gateways []netip.Addr, now time.Time) CaptiveStatus {
	st := CaptiveStatus{Checked: now, Reason: "yerel ağ geçidi bulunamadı"}
	for _, gw := range gateways {
		if !gatewayAllowed(gw) {
			continue
		}
		st.Gateway = gw.String()
		code, loc, err := p.get(ctx, gw)
		if err != nil {
			st.Reason = "ağ geçidi HTTP isteğine yanıt vermedi"
			continue
		}
		st.HTTPStatus, st.Location = code, loc
		switch {
		case code == http.StatusNetworkAuthenticationRequired:
			st.Detected, st.Reason = true, "ağ geçidi kimlik doğrulaması istiyor (HTTP 511)"
		case code >= 300 && code < 400 && redirectsElsewhere(loc, gw):
			st.Detected, st.Reason = true, "ağ geçidi başka bir adrese yönlendiriyor"
		default:
			st.Reason = "ağ geçidi giriş sayfasına yönlendirmiyor"
		}
		return st
	}
	return st
}

// redirectsElsewhere reports whether a Location points away from gw.
func redirectsElsewhere(loc string, gw netip.Addr) bool {
	u, err := url.Parse(strings.TrimSpace(loc))
	if err != nil || u.Host == "" {
		return false // relative: the gateway's own page (a router login)
	}
	host := u.Hostname()
	if a, err := netip.ParseAddr(host); err == nil {
		return a.Unmap() != gw.Unmap()
	}
	return true
}

// gatewaysFunc is replaced in tests.
var gatewaysFunc = osnet.DefaultGateways4

// noteSync records a sync result and, while all traffic is held in the
// tunnel (exit node or kill switch) and the coordinator does not answer,
// checks for a captive portal in the background.
func (e *Engine) noteSync(ctx context.Context, ok bool) {
	now := e.cfg.Now()
	e.mu.Lock()
	if ok {
		e.syncFails = 0
		if e.captive.Detected {
			e.captive = CaptiveStatus{Checked: now, Reason: "koordinatöre yeniden ulaşıldı"}
		}
		e.mu.Unlock()
		return
	}
	e.syncFails++
	due := e.syncFails >= captiveAfterFails && now.Sub(e.captiveAt) >= captiveInterval
	exit := e.exitActive != ""
	e.mu.Unlock()
	if !due || e.cfg.DisableCaptiveCheck {
		return
	}
	if !exit && (e.cfg.KillSwitchActive == nil || !e.cfg.KillSwitchActive()) {
		return
	}
	if !e.captiveBusy.CompareAndSwap(false, true) {
		return
	}
	e.mu.Lock()
	e.captiveAt = now
	e.mu.Unlock()
	go func() {
		defer e.captiveBusy.Store(false)
		cctx, cancel := context.WithTimeout(ctx, 2*captiveTimeout)
		defer cancel()
		st, err := e.CheckCaptivePortal(cctx)
		if err == nil && st.Detected {
			e.logger.Warn("captive portal detected", "gateway", st.Gateway)
		}
	}()
}

// CheckCaptivePortal asks the local default gateway whether it holds a
// login page and records the result (F-018). It contacts nothing else.
func (e *Engine) CheckCaptivePortal(ctx context.Context) (CaptiveStatus, error) {
	gws, err := gatewaysFunc()
	if err != nil {
		return CaptiveStatus{}, err
	}
	if len(gws) == 0 {
		return CaptiveStatus{}, errors.New("varsayılan ağ geçidi yok")
	}
	st := detectCaptivePortal(ctx, e.captiveHTTP, gws, e.cfg.Now())
	e.mu.Lock()
	e.captive = st
	e.mu.Unlock()
	return st, nil
}

// CaptivePortal returns the last captive portal check.
func (e *Engine) CaptivePortal() CaptiveStatus {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.captive
}
