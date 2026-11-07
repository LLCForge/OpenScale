package panel

import (
	"net/http"
	"net/netip"
	"slices"
	"time"

	"github.com/openscale/openscale/internal/admin"
	"github.com/openscale/openscale/internal/geoip"
	"github.com/openscale/openscale/internal/posture"
	"github.com/openscale/openscale/internal/sysinfo"
	"github.com/openscale/openscale/internal/trust"
)

// onlineWindow: WireGuard renews the handshake every two minutes while
// keepalives flow, so a peer silent for longer is treated as offline.
const onlineWindow = 3*time.Minute + 30*time.Second

// Device status values.
const (
	statusThis    = "this"
	statusOnline  = "online"
	statusOffline = "offline"
	statusUnknown = "unknown"
)

// live is a snapshot of what this computer knows about the other devices.
type live struct {
	stats    LiveStats
	inv      Inventory
	selfName string
	synced   bool
}

func (s *Server) liveView() live {
	if s.app == nil {
		return live{}
	}
	l := live{stats: s.app.LiveStats(), inv: s.app.Inventory()}
	if st := s.app.Status(); st.Device != nil {
		l.selfName = st.Device.Name
		l.synced = st.Device.Running && st.Device.LastSyncError == "" && st.Device.LastSync != nil
	}
	return l
}

// reportFresh is how long a system report proves a device is online.
const reportFresh = 90 * time.Second

type systemView struct {
	OS         string    `json:"os"`
	OSName     string    `json:"osName"`
	Version    string    `json:"version"`
	Arch       string    `json:"arch"`
	CPU        string    `json:"cpu"`
	Cores      int       `json:"cores"`
	MemTotal   uint64    `json:"memTotal"`
	MemFree    uint64    `json:"memFree"`
	DiskTotal  uint64    `json:"diskTotal"`
	DiskFree   uint64    `json:"diskFree"`
	Uptime     int64     `json:"uptime"`
	PublicIP   string    `json:"publicIp"`
	Country    string    `json:"country"`
	ReportedAt time.Time `json:"reportedAt"`
	Stale      bool      `json:"stale"`
	// Outdated: older than this panel's version, Latest (F-153).
	Outdated bool   `json:"outdated"`
	Latest   string `json:"latest,omitempty"`
	// Environment (F-172, #322): container or VM kind, model, install.
	Virt    string `json:"virt,omitempty"`
	Model   string `json:"model,omitempty"`
	Install string `json:"install,omitempty"`
	// Posture is the device's own security posture statement (ADR-0109);
	// nil when the report carried none. Display data, never proof.
	Posture *postureView `json:"posture,omitempty"`
	// OSLabel is the operating system from the detailed inventory
	// (ADR-0143), "" without one; OSName stays the base report's name.
	OSLabel string `json:"osLabel,omitempty"`
	// Upstream is an exit node's upstream exit (ADR-0142).
	Upstream *UpstreamView `json:"upstream,omitempty"`
	// Detail is the detailed inventory, only in the device detail answer.
	// DetailPending is true when the device announces one that this
	// computer has not fetched yet.
	Detail        *sysinfo.Detail `json:"detail,omitempty"`
	DetailPending bool            `json:"detailPending,omitempty"`
}

// postureView is posture.Report with stable state codes for the panel:
// "on", "off" or "unknown".
type postureView struct {
	DiskEncryption string `json:"diskEncryption"`
	Firewall       string `json:"firewall"`
	WindowsBuild   int    `json:"windowsBuild,omitempty"`
}

func postureState(s posture.State) string {
	switch s {
	case posture.On:
		return "on"
	case posture.Off:
		return "off"
	}
	return "unknown"
}

// postureOf decodes a report's posture field; a missing or malformed one
// gives nil.
func postureOf(encoded string) *postureView {
	if encoded == "" {
		return nil
	}
	r, err := posture.Decode(encoded)
	if err != nil {
		return nil
	}
	return &postureView{DiskEncryption: postureState(r.DiskEncryption), Firewall: postureState(r.Firewall), WindowsBuild: r.WindowsBuild}
}

func system(rep *Report, now time.Time) *systemView {
	if rep == nil || rep.Info.OS == "" {
		return nil
	}
	in := rep.Info
	v := &systemView{
		OS: in.OS, OSName: in.OSName, Version: in.Version, Arch: in.Arch, CPU: in.CPU, Cores: in.Cores,
		MemTotal: in.MemTotal, MemFree: in.MemFree, DiskTotal: in.DiskTotal, DiskFree: in.DiskFree,
		Uptime: in.Uptime, PublicIP: in.PublicIP, ReportedAt: rep.At, Virt: in.Virt, Model: in.Model, Install: in.Pkg,
		Stale:    rep.Err != "" || now.Sub(rep.At) > reportFresh,
		Posture:  postureOf(in.Posture),
		OSLabel:  osLabel(in.OS, in.Detail),
		Upstream: UpstreamOf(in),
	}
	if a, err := netip.ParseAddr(in.PublicIP); err == nil {
		v.Country = geoip.Country(a)
	}
	markOutdated(v)
	return v
}

func (l live) report(name string) *Report {
	if name == l.selfName && l.inv.Self != nil {
		return l.inv.Self
	}
	if rep, ok := l.inv.Devices[name]; ok {
		return &rep
	}
	return nil
}

type coordinatorLive struct {
	Endpoint    string      `json:"endpoint"`
	IPv4        string      `json:"ipv4"`
	Fingerprint string      `json:"fingerprint"`
	PublicIP    string      `json:"publicIp"`
	Country     string      `json:"country"`
	Status      string      `json:"status"`
	System      *systemView `json:"system"`
}

func (l live) coordinator(doc *trust.Document, now time.Time) *coordinatorLive {
	c := doc.Coordinator
	if c == nil {
		return nil
	}
	v := &coordinatorLive{
		Endpoint: c.Endpoint, IPv4: c.IPv4.String(),
		Fingerprint: trust.CoordinatorFingerprint(c.WireGuardKey),
		PublicIP:    l.inv.CoordinatorAddr, Status: statusUnknown,
		System: system(l.inv.Coordinator, now),
	}
	if a, err := netip.ParseAddr(v.PublicIP); err == nil {
		v.Country = geoip.Country(a)
	}
	switch {
	case v.System != nil && !v.System.Stale, l.synced:
		v.Status = statusOnline
	case l.inv.Coordinator != nil:
		v.Status = statusOffline
	}
	return v
}

// seen returns the most recent handshake from either view.
func (l live) seen(key trust.Key) (time.Time, bool) {
	var last time.Time
	found := false
	for _, m := range []map[trust.Key]PeerTraffic{l.stats.Direct, l.stats.ViaCoordinator} {
		if p, ok := m[key]; ok {
			found = true
			if p.LastHandshake.After(last) {
				last = p.LastHandshake
			}
		}
	}
	return last, found
}

func (l live) device(doc *trust.Document, d trust.Device, now time.Time) deviceView {
	v := deviceView{
		ID: d.ID, Name: d.Name, FQDN: d.Name + "." + doc.DNSDomain,
		IPv4: d.IPv4.String(), IPv6: d.IPv6.String(),
		ExitNode: d.HasRole(trust.RoleExitNode), Admin: d.HasRole(trust.RoleAdmin),
		AddedAt: d.AddedAt, ExpiresAt: d.ExpiresAt, DaysLeft: daysUntil(now, d.ExpiresAt),
		Status: statusUnknown, Tags: append([]string{}, d.Tags...),
		Icon: string(d.Icon), // #233, ADR-0232
	}
	v.System = system(l.report(d.Name), now)
	if v.System != nil && !v.System.Stale && d.Name != l.selfName {
		t := v.System.ReportedAt
		v.LastSeen, v.Status = &t, statusOnline
		return v
	}
	switch last, found := l.seen(d.WireGuardKey); {
	case l.selfName != "" && d.Name == l.selfName:
		v.ThisComputer, v.Status = true, statusThis
	case !found:
	case last.IsZero():
		v.Status = statusOffline
	default:
		t := last
		v.LastSeen = &t
		v.Status = statusOffline
		if now.Sub(last) < onlineWindow {
			v.Status = statusOnline
		}
	}
	return v
}

type trafficView struct {
	Relayed       bool       `json:"relayed"`
	Endpoint      string     `json:"endpoint"`
	LastHandshake *time.Time `json:"lastHandshake"`
	RxBytes       uint64     `json:"rxBytes"`
	TxBytes       uint64     `json:"txBytes"`
}

type deviceDetail struct {
	deviceView
	SigningKey   string       `json:"signingKey"`
	WireGuardKey string       `json:"wireguardKey"`
	Fingerprint  string       `json:"fingerprint"`
	DNSDomain    string       `json:"dnsDomain"`
	Outgoing     []ruleView   `json:"outgoing"`
	Incoming     []ruleView   `json:"incoming"`
	Peers        []peerView   `json:"peers"`
	Direct       *trafficView `json:"direct"`
	Coordinator  *trafficView `json:"coordinator"`
	// LiveAvailable is false for the CLI panel, which has no tunnel.
	LiveAvailable bool `json:"liveAvailable"`
	// MayUseExitNode is false when exit_users leaves this device out.
	MayUseExitNode bool `json:"mayUseExitNode"`
}

type peerView struct {
	Name string `json:"name"`
	IPv4 string `json:"ipv4"`
}

func (s *Server) handleDeviceDetail(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" || len(name) > 63 {
		writeError(w, http.StatusBadRequest, "Cihaz adı geçersiz.")
		return
	}
	doc, ok := s.currentDocument(w)
	if !ok {
		return
	}
	d, found := doc.DeviceByName(name)
	if !found {
		writeError(w, http.StatusNotFound, admin.Describe(trust.ErrUnknownDevice))
		return
	}
	l := s.liveView()
	req := trust.EnrollmentRequest{DeviceID: d.ID, SigningKey: d.SigningKey, WireGuardKey: d.WireGuardKey}
	out := deviceDetail{
		deviceView:    l.device(doc, d, s.now()),
		SigningKey:    d.SigningKey.String(),
		WireGuardKey:  d.WireGuardKey.String(),
		Fingerprint:   req.Fingerprint(),
		DNSDomain:     doc.DNSDomain,
		Outgoing:      []ruleView{},
		Incoming:      []ruleView{},
		Peers:         []peerView{},
		LiveAvailable: s.app != nil,
	}
	for i, rule := range doc.Rules {
		v := newRuleView(i, rule)
		if matches(doc, rule.From, d) && reachesOther(rule.To, d.Name) {
			out.Outgoing = append(out.Outgoing, v)
		}
		if matches(doc, rule.To, d) && reachesOther(rule.From, d.Name) {
			out.Incoming = append(out.Incoming, v)
		}
	}
	out.MayUseExitNode = doc.MayUseExitNode(d.Name)
	for _, p := range doc.PeersOf(d.Name) {
		out.Peers = append(out.Peers, peerView{Name: p.Name, IPv4: p.IPv4.String()})
	}
	if sys := out.System; sys != nil {
		if rep := l.report(d.Name); rep != nil {
			sys.Detail = panelDetail(rep.Info.Detail)
			sys.DetailPending = sys.Detail == nil && rep.Info.DetailID != ""
		}
	}
	out.Direct = traffic(l.stats.Direct, d.WireGuardKey)
	out.Coordinator = traffic(l.stats.ViaCoordinator, d.WireGuardKey)
	writeJSON(w, http.StatusOK, out)
}

// matches reports whether any entry covers device d, including tag and
// group entries (ADR-0021).
func matches(doc *trust.Document, entries []string, d trust.Device) bool {
	return slices.ContainsFunc(entries, func(e string) bool { return entryMatchesDevice(doc, e, d) })
}

// reachesOther reports whether entries name any device besides name; a
// rule from a device only to itself means nothing for its connections.
func reachesOther(entries []string, name string) bool {
	return slices.ContainsFunc(entries, func(e string) bool { return e != name })
}

func traffic(m map[trust.Key]PeerTraffic, key trust.Key) *trafficView {
	p, ok := m[key]
	if !ok {
		return nil
	}
	v := &trafficView{Relayed: p.Relayed, Endpoint: p.Endpoint, RxBytes: p.RxBytes, TxBytes: p.TxBytes}
	if !p.LastHandshake.IsZero() {
		t := p.LastHandshake
		v.LastHandshake = &t
	}
	return v
}

type exitNodeRequest struct {
	signRequest
	Name     string `json:"name"`
	ExitNode bool   `json:"exitNode"`
}

func (s *Server) handleSetExitNode(w http.ResponseWriter, r *http.Request) {
	var req exitNodeRequest
	if !decodeBody(w, r, &req) {
		return
	}
	s.change(w, req.signRequest, func(doc *trust.Document) error { return doc.SetExitNode(req.Name, req.ExitNode) })
}
