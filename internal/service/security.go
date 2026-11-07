package service

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"net/netip"
	"sort"
	"time"

	"github.com/openscale/openscale/internal/member"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/winapp"
)

// securityCacheTTL: the check starts PowerShell and takes seconds.
const securityCacheTTL = 30 * time.Second

// Exposure classes of a listening socket.
const (
	exposureAll       = "all"
	exposureLAN       = "lan"
	exposureOpenScale = "openscale"
	exposureLocal     = "local"
)

// overlayPrefixes returns the network ranges from this computer's document.
func (r *Runtime) overlayPrefixes() ([]netip.Prefix, error) {
	store, err := member.Open(r.path(DeviceDir))
	if err != nil {
		return nil, errors.New("bu bilgisayar henüz bir ağa bağlı değil")
	}
	doc := store.Document()
	return []netip.Prefix{doc.IPv4Prefix, doc.IPv6Prefix}, nil
}

// LocalSecurity implements panel.App.
func (r *Runtime) LocalSecurity(_ context.Context, refresh bool) (panel.LocalSecurity, error) {
	r.secMu.Lock()
	defer r.secMu.Unlock()
	if !refresh && !r.secAt.IsZero() && r.cfg.Now().Sub(r.secAt) < securityCacheTTL {
		return r.secCache, nil
	}
	out := panel.LocalSecurity{Supported: true, Listeners: []panel.ListenerView{}, CheckedAt: r.cfg.Now()}
	st, err := winapp.GetRemoteAccess()
	if errors.Is(err, winapp.ErrUnsupported) {
		out.Supported = false
		return out, nil
	}
	if err != nil {
		out.Error = err.Error()
	}
	out.RDP = panel.ServiceAccess{Available: st.RDPEnabled, Port: st.RDPPort, OverlayOnly: st.RDPScoped}
	out.SSH = panel.ServiceAccess{Available: st.SSHInstalled, Port: st.SSHPort, OverlayOnly: st.SSHScoped}

	prefixes, _ := r.overlayPrefixes()
	ls, err := winapp.ListeningPorts()
	if err != nil && out.Error == "" {
		out.Error = err.Error()
	}
	for _, l := range ls {
		v := panel.ListenerView{Proto: l.Proto, Address: l.Address, Port: l.Port, Process: l.Process, Exposure: classify(l.Address, prefixes)}
		switch v.Exposure {
		case exposureAll:
			out.Summary.All++
		case exposureLAN:
			out.Summary.LAN++
		case exposureOpenScale:
			out.Summary.OpenScale++
		default:
			out.Summary.Local++
			continue // loopback-only sockets are not shown
		}
		out.Listeners = append(out.Listeners, v)
	}
	sort.Slice(out.Listeners, func(i, j int) bool {
		a, b := out.Listeners[i], out.Listeners[j]
		if a.Exposure != b.Exposure {
			return a.Exposure < b.Exposure
		}
		if a.Proto != b.Proto {
			return a.Proto < b.Proto
		}
		return a.Port < b.Port
	})
	r.secCache, r.secAt = out, r.cfg.Now()
	return out, nil
}

func classify(addr string, overlay []netip.Prefix) string {
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return exposureLAN
	}
	a = a.Unmap()
	switch {
	case a.IsUnspecified():
		return exposureAll
	case a.IsLoopback():
		return exposureLocal
	}
	for _, p := range overlay {
		if p.Contains(a) {
			return exposureOpenScale
		}
	}
	return exposureLAN
}

// SetRemoteAccess implements panel.App.
func (r *Runtime) SetRemoteAccess(service string, overlayOnly bool) error {
	if service != "rdp" && service != "ssh" {
		return errors.New("bilinmeyen servis")
	}
	prefixes, err := r.overlayPrefixes()
	if err != nil {
		return err
	}
	if err := remoteAccessScopeFn(service, overlayOnly, prefixes); err != nil {
		return err
	}
	r.settingsMu.Lock()
	st, err := loadSettings(r.cfg.DataDir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		r.settingsMu.Unlock()
		return err
	}
	// Stored as an explicit choice, so the default never overrides it.
	choice := overlayOnly
	if service == "rdp" {
		st.RDPOverlayOnly = &choice
	} else {
		st.SSHOverlayOnly = &choice
	}
	err = saveSettings(r.cfg.DataDir, st)
	r.settingsMu.Unlock()
	r.secMu.Lock()
	r.secAt = time.Time{}
	r.secMu.Unlock()
	r.logger.Info("remote access scope changed", "service", service, "openscale_only", overlayOnly)
	return err
}

// remoteAccessScopeFn and remoteAccessStatusFn change and read the Windows
// firewall rules of RDP and OpenSSH; tests replace them so no real rule is
// touched.
var (
	remoteAccessScopeFn  = winapp.SetRemoteAccessScope
	remoteAccessStatusFn = winapp.GetRemoteAccess
)

// remoteAccessServices fixes the order the services are handled in.
var remoteAccessServices = []string{"rdp", "ssh"}

// overlayOnlyChoice is the effective setting and whether the owner chose it.
// Missing means on: limiting RDP and SSH to the tunnel is the default, so a
// compromised coordinator (which can only reach this computer through
// devices of the root-signed document) gains nothing from the LAN or the
// internet side either.
func overlayOnlyChoice(p *bool) (on, explicit bool) {
	if p == nil {
		return true, false
	}
	return *p, true
}

// reapplyRemoteAccess restores the owner's choices, or the default, when the
// tunnel starts, for example after a Windows update re-enabled the default
// rules. An explicit "off" is never touched.
func (r *Runtime) reapplyRemoteAccess() {
	st, err := loadSettings(r.cfg.DataDir)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			r.logger.Warn("settings unreadable; remote access keeps the default (OpenScale only)", "error", err.Error())
		}
		// Unreadable or missing settings carry no explicit choice: the
		// default (limited to the tunnel) applies.
		st = settings{}
	}
	prefixes, err := r.overlayPrefixes()
	if err != nil {
		return
	}
	applyRemoteAccessScopes(st, prefixes, r.logger)
}

// applyRemoteAccessScopes limits every service whose setting is on (chosen
// or by default) to prefixes and returns the services it limited. A service
// that is on only by default is skipped when Windows reports it is not
// installed or not enabled, so no rule is created for a port nothing serves;
// when the status cannot be read the limit is applied anyway (fail closed).
func applyRemoteAccessScopes(st settings, prefixes []netip.Prefix, logger *slog.Logger) []string {
	if len(prefixes) == 0 {
		return nil
	}
	status, statusErr := remoteAccessStatusFn()
	if errors.Is(statusErr, winapp.ErrUnsupported) {
		return nil
	}
	var applied []string
	for _, svc := range remoteAccessServices {
		p, available := st.RDPOverlayOnly, status.RDPEnabled
		if svc == "ssh" {
			p, available = st.SSHOverlayOnly, status.SSHInstalled
		}
		on, explicit := overlayOnlyChoice(p)
		if !on {
			continue
		}
		if !explicit && statusErr == nil && !available {
			continue
		}
		if err := remoteAccessScopeFn(svc, true, prefixes); err != nil {
			if !errors.Is(err, winapp.ErrUnsupported) && logger != nil {
				logger.Warn("reapply remote access scope", "service", svc, "default", !explicit, "error", err.Error())
			}
			continue
		}
		applied = append(applied, svc)
	}
	return applied
}
