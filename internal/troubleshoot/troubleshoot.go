// Package troubleshoot is the layered connection troubleshooter (#835).
// It walks the layers a packet needs, in order: the tunnel interface, the
// local gateway, DNS, the coordinator, the relay and then every peer. Each
// step passes, fails or is skipped (a lower layer already failed, or the
// step does not apply), with a short explanation and a suggested fix.
//
// Every result carries a stable Key (e.g. "gateway.missing") that the
// panel translates, its variable parts in Vars, and an error code from
// internal/errcode where one fits, so the Turkish texts here are only for
// the command line. The only traffic that leaves the computer goes to the
// owner's own coordinator (and its relay); no outside service is asked.
package troubleshoot

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// Schema is the version of the Report JSON.
const Schema = 1

// Status of one step.
type Status string

// Statuses.
const (
	Pass Status = "pass"
	Fail Status = "fail"
	Warn Status = "warn"
	Skip Status = "skip"
)

// Layers, in order.
const (
	LayerInterface   = "interface"
	LayerGateway     = "gateway"
	LayerDNS         = "dns"
	LayerCoordinator = "coordinator"
	LayerRelay       = "relay"
	LayerPeer        = "peer"
)

// Limits.
const (
	// MaxPeers bounds the peers checked one by one.
	MaxPeers = 32
	// stepTimeout bounds one network step.
	stepTimeout = 8 * time.Second
)

// Step is the result of one check.
type Step struct {
	Layer  string `json:"layer"`
	Status Status `json:"status"`
	// Key names the result for translation ("dns.resolve_failed").
	Key string `json:"key"`
	// Vars are the variable parts of the texts ({peer}, {ms}).
	Vars map[string]string `json:"vars,omitempty"`
	// Title, Detail and Fix are the Turkish texts.
	Title  string `json:"title"`
	Detail string `json:"detail,omitempty"`
	Fix    string `json:"fix,omitempty"`
	// Code is the internal/errcode code, when one explains the failure.
	Code string `json:"code,omitempty"`
	// Peer is set for the per-peer steps.
	Peer       string  `json:"peer,omitempty"`
	DurationMS float64 `json:"duration_ms"`
}

// Report is a whole run.
type Report struct {
	Schema int       `json:"schema"`
	At     time.Time `json:"at"`
	// OK is true when no step failed.
	OK bool `json:"ok"`
	// FirstFailure is the index of the first failed step, -1 when none.
	FirstFailure int    `json:"first_failure"`
	Steps        []Step `json:"steps"`
}

// Interface is the tunnel interface as the service sees it.
type Interface struct {
	// Running: the tunnel engine runs.
	Running bool
	// Disconnected: the owner turned the tunnel off on purpose.
	Disconnected bool
	Name         string
	// Up: the operating system reports the interface up.
	Up  bool
	Err string
}

// Coordinator is the result of one coordinator check.
type Coordinator struct {
	Reachable bool
	RTT       time.Duration
	OverTCP   bool
	Captive   bool
	Err       string
}

// Peer is one peer from the tunnel's status.
type Peer struct {
	Name   string
	Online bool
	// Path is "direct", "relay" or "none".
	Path          string
	LastHandshake time.Time
	RelayReason   string
}

// Probe is what the service gives the troubleshooter.
type Probe interface {
	Interface(ctx context.Context) Interface
	// Gateways lists the default IPv4 gateways.
	Gateways(ctx context.Context) ([]netip.Addr, error)
	// CoordinatorEndpoint is "host:port" of the owner's coordinator; ""
	// when this computer has no network yet.
	CoordinatorEndpoint() string
	// Resolve asks the system resolver for host.
	Resolve(ctx context.Context, host string) ([]netip.Addr, error)
	// MagicDNSError is the MagicDNS resolver's error, "" when it is fine.
	MagicDNSError() string
	Coordinator(ctx context.Context) Coordinator
	Peers(ctx context.Context) ([]Peer, error)
	// RelayTest measures one round trip through the coordinator's relay.
	RelayTest(ctx context.Context, peer string) (time.Duration, error)
}

// Run checks every layer and returns the report. It never returns an
// error: a probe failure is a failed step.
func Run(ctx context.Context, p Probe, now func() time.Time) Report {
	if now == nil {
		now = time.Now
	}
	r := &runner{ctx: ctx, p: p, now: now}
	r.run()
	rep := Report{Schema: Schema, At: now().UTC(), OK: true, FirstFailure: -1, Steps: r.steps}
	for i, s := range r.steps {
		if s.Status == Fail {
			rep.OK = false
			if rep.FirstFailure < 0 {
				rep.FirstFailure = i
			}
		}
	}
	return rep
}

type runner struct {
	ctx   context.Context
	p     Probe
	now   func() time.Time
	steps []Step
	// broken is the first failed layer; the layers above it are skipped.
	broken string
}

func (r *runner) add(s Step, start time.Time) {
	s.DurationMS = float64(r.now().Sub(start).Microseconds()) / 1000
	if s.DurationMS < 0 {
		s.DurationMS = 0
	}
	if s.Status == Fail && r.broken == "" {
		r.broken = s.Layer
	}
	r.steps = append(r.steps, s)
}

// skipBelow records a skipped step because a lower layer failed.
func (r *runner) skipBelow(layer, title string) bool {
	if r.broken == "" {
		return false
	}
	r.steps = append(r.steps, Step{Layer: layer, Status: Skip, Key: "skipped.lower_failed", Vars: map[string]string{"layer": r.broken},
		Title: title, Detail: "Önceki adım başarısız olduğu için denenmedi; önce o adımı düzeltin."})
	return true
}

func (r *runner) stepCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.ctx, stepTimeout)
}

func (r *runner) run() {
	r.checkInterface()
	r.checkGateway()
	r.checkDNS()
	r.checkCoordinator()
	peers := r.loadPeers()
	r.checkRelay(peers)
	r.checkPeers(peers)
}

func (r *runner) checkInterface() {
	start := r.now()
	ctx, cancel := r.stepCtx()
	defer cancel()
	in := r.p.Interface(ctx)
	const title = "Tünel arayüzü"
	s := Step{Layer: LayerInterface, Title: title}
	switch {
	case in.Disconnected:
		s.Status, s.Key, s.Code = Fail, "interface.disconnected", ""
		s.Detail = "Tünel kapalı (bağlantı elle kesildi)."
		s.Fix = "Tepsi simgesinden veya panelden bağlantıyı açın: openscale up."
	case !in.Running:
		s.Status, s.Key, s.Code = Fail, "interface.not_running", "OS-3003"
		s.Detail = "Tünel çalışmıyor."
		if in.Err != "" {
			s.Detail = "Tünel çalışmıyor: " + in.Err
			s.Vars = map[string]string{"error": in.Err}
		}
		s.Fix = "Servisi yeniden başlatın; sürüyorsa servis günlüğüne bakın."
	case in.Name != "" && !in.Up:
		s.Status, s.Key, s.Code = Fail, "interface.down", "OS-3003"
		s.Vars = map[string]string{"name": in.Name}
		s.Detail = fmt.Sprintf("%s arayüzü işletim sisteminde kapalı görünüyor.", in.Name)
		s.Fix = "Bağlantıyı yeniden kurun: openscale debug reconnect; olmazsa servisi yeniden başlatın."
	default:
		s.Status, s.Key = Pass, "interface.ok"
		s.Vars = map[string]string{"name": in.Name}
		s.Detail = "Tünel çalışıyor."
		if in.Name != "" {
			s.Detail = fmt.Sprintf("Tünel %s arayüzünde çalışıyor.", in.Name)
		}
	}
	r.add(s, start)
}

func (r *runner) checkGateway() {
	const title = "Yerel ağ geçidi"
	if r.skipBelow(LayerGateway, title) {
		return
	}
	start := r.now()
	ctx, cancel := r.stepCtx()
	defer cancel()
	gws, err := r.p.Gateways(ctx)
	s := Step{Layer: LayerGateway, Title: title}
	if err != nil || len(gws) == 0 {
		s.Status, s.Key, s.Code = Fail, "gateway.missing", "OS-3005"
		s.Detail = "Varsayılan ağ geçidi bulunamadı; bu bilgisayar yerel ağa veya internete bağlı değil."
		s.Fix = "Wi-Fi veya kablo bağlantısını denetleyin; modemi yeniden başlatın."
	} else {
		s.Status, s.Key = Pass, "gateway.ok"
		s.Vars = map[string]string{"count": fmt.Sprint(len(gws))}
		s.Detail = "Varsayılan ağ geçidi var."
	}
	r.add(s, start)
}

func (r *runner) checkDNS() {
	const title = "DNS"
	if r.skipBelow(LayerDNS, title) {
		return
	}
	start := r.now()
	s := Step{Layer: LayerDNS, Title: title}
	ep := r.p.CoordinatorEndpoint()
	host, _, err := net.SplitHostPort(ep)
	magic := r.p.MagicDNSError()
	switch {
	case ep == "" || err != nil:
		s.Status, s.Key = Skip, "dns.no_network"
		s.Detail = "Bu bilgisayar henüz bir ağa katılmamış; koordinatör adı yok."
	case isAddr(host):
		// Nothing to resolve; the MagicDNS resolver is the only DNS here.
		s.Status, s.Key = Pass, "dns.coordinator_is_ip"
		s.Detail = "Koordinatör IP adresiyle tanımlı; ad çözmeye gerek yok."
	default:
		ctx, cancel := r.stepCtx()
		addrs, rerr := r.p.Resolve(ctx, host)
		cancel()
		if rerr != nil || len(addrs) == 0 {
			s.Status, s.Key = Fail, "dns.resolve_failed"
			s.Detail = "Sistem DNS'i koordinatörün adını çözemedi."
			s.Fix = "Ağın DNS sunucusunu denetleyin; koordinatörün DNS kaydının doğru olduğundan emin olun."
		} else {
			s.Status, s.Key = Pass, "dns.ok"
			s.Detail = "Koordinatörün adı çözüldü."
		}
	}
	if s.Status != Fail && magic != "" {
		s.Status, s.Key, s.Code = Warn, "dns.magicdns", "OS-4004"
		s.Detail = "MagicDNS çözücüsü çalışmıyor; cihaz adları çözülmeyebilir."
		s.Fix = "openscale dns status ile ayrıntıya bakın; başka bir DNS programı 53. portu tutuyor olabilir."
	}
	r.add(s, start)
}

func isAddr(host string) bool {
	_, err := netip.ParseAddr(strings.Trim(host, "[]"))
	return err == nil
}

func (r *runner) checkCoordinator() {
	const title = "Koordinatör"
	if r.skipBelow(LayerCoordinator, title) {
		return
	}
	start := r.now()
	s := Step{Layer: LayerCoordinator, Title: title}
	if r.p.CoordinatorEndpoint() == "" {
		s.Status, s.Key = Skip, "coordinator.no_network"
		s.Detail = "Bu bilgisayar henüz bir ağa katılmamış."
		r.add(s, start)
		return
	}
	ctx, cancel := r.stepCtx()
	c := r.p.Coordinator(ctx)
	cancel()
	switch {
	case c.Captive:
		s.Status, s.Key, s.Code = Fail, "coordinator.captive", "OS-5003"
		s.Detail = "Ağ bir giriş sayfası (captive portal) istiyor; koordinatöre ulaşılamıyor."
		s.Fix = "Tarayıcıda ağın giriş sayfasını açıp oturum açın."
	case !c.Reachable:
		s.Status, s.Key, s.Code = Fail, "coordinator.unreachable", "OS-3001"
		s.Detail = "Koordinatör yanıt vermedi."
		s.Fix = "Koordinatörün çalıştığını ve güvenlik duvarında UDP portunun açık olduğunu denetleyin; UDP engelliyse TCP yedeğini açın."
	case c.OverTCP:
		s.Status, s.Key, s.Code = Warn, "coordinator.over_tcp", "OS-3004"
		s.Vars = map[string]string{"ms": ms(c.RTT)}
		s.Detail = fmt.Sprintf("Koordinatöre yalnızca TCP üzerinden ulaşılıyor (%s ms); UDP engelli.", ms(c.RTT))
		s.Fix = "Ağ UDP'yi engelliyor; doğrudan bağlantılar kurulamayabilir. Başka bir ağ deneyin."
	default:
		s.Status, s.Key = Pass, "coordinator.ok"
		s.Vars = map[string]string{"ms": ms(c.RTT)}
		s.Detail = fmt.Sprintf("Koordinatör yanıt verdi (%s ms).", ms(c.RTT))
	}
	r.add(s, start)
}

func ms(d time.Duration) string { return fmt.Sprintf("%.0f", float64(d.Microseconds())/1000) }

func (r *runner) loadPeers() []Peer {
	if r.broken != "" {
		return nil
	}
	ctx, cancel := r.stepCtx()
	defer cancel()
	peers, err := r.p.Peers(ctx)
	if err != nil {
		return nil
	}
	sort.SliceStable(peers, func(i, j int) bool {
		if peers[i].Online != peers[j].Online {
			return peers[i].Online
		}
		return peers[i].Name < peers[j].Name
	})
	return peers
}

func (r *runner) checkRelay(peers []Peer) {
	const title = "Aktarıcı"
	if r.skipBelow(LayerRelay, title) {
		return
	}
	start := r.now()
	s := Step{Layer: LayerRelay, Title: title}
	target := ""
	for _, p := range peers {
		if p.Online {
			target = p.Name
			break
		}
	}
	if target == "" {
		s.Status, s.Key = Skip, "relay.no_peer"
		s.Detail = "Aktarıcıyı denemek için çevrimiçi bir eş yok."
		r.add(s, start)
		return
	}
	ctx, cancel := r.stepCtx()
	rtt, err := r.p.RelayTest(ctx, target)
	cancel()
	s.Peer = target
	if err != nil {
		// A relay failure is not fatal: direct paths may still work.
		s.Status, s.Key, s.Code = Warn, "relay.failed", "OS-3002"
		s.Vars = map[string]string{"peer": target}
		s.Detail = fmt.Sprintf("Koordinatörün aktarıcısı üzerinden %s cihazına ulaşılamadı.", target)
		s.Fix = "Doğrudan bağlantı kurulamayan eşlere ulaşılamaz; koordinatörün aktarıcı sınırlarını ve sürümünü denetleyin."
	} else {
		s.Status, s.Key = Pass, "relay.ok"
		s.Vars = map[string]string{"peer": target, "ms": ms(rtt)}
		s.Detail = fmt.Sprintf("Aktarıcı üzerinden %s: %s ms.", target, ms(rtt))
	}
	r.add(s, start)
}

func (r *runner) checkPeers(peers []Peer) {
	const title = "Eşler"
	if r.skipBelow(LayerPeer, title) {
		return
	}
	if len(peers) == 0 {
		r.steps = append(r.steps, Step{Layer: LayerPeer, Status: Skip, Key: "peer.none", Title: title, Detail: "Bu cihazın tünel kurabileceği bir eş yok."})
		return
	}
	for i, p := range peers {
		if i >= MaxPeers {
			r.steps = append(r.steps, Step{Layer: LayerPeer, Status: Skip, Key: "peer.more", Vars: map[string]string{"count": fmt.Sprint(len(peers) - MaxPeers)},
				Title: title, Detail: fmt.Sprintf("%d eş daha denetlenmedi.", len(peers)-MaxPeers)})
			return
		}
		if err := r.ctx.Err(); err != nil {
			return
		}
		start := r.now()
		s := Step{Layer: LayerPeer, Peer: p.Name, Title: p.Name, Vars: map[string]string{"peer": p.Name}}
		switch {
		case !p.Online:
			s.Status, s.Key = Fail, "peer.offline"
			s.Detail = fmt.Sprintf("%s ile son birkaç dakikada el sıkışma olmadı.", p.Name)
			s.Fix = "Cihazın açık ve OpenScale'in çalıştığını denetleyin; uzun süredir çevrimdışıysa kendi bağlantısını denetleyin."
		case p.Path == "relay":
			s.Status, s.Key, s.Code = Warn, "peer.relayed", "OS-3002"
			s.Detail = fmt.Sprintf("%s aktarıcı üzerinden bağlı; doğrudan yol kurulamadı.", p.Name)
			if p.RelayReason != "" {
				s.Vars["reason"] = p.RelayReason
				s.Detail += " " + p.RelayReason
			}
			s.Fix = "Bağlantı çalışır ama daha yavaştır; iki taraftan birinde UDP port yönlendirmesi doğrudan yolu açar."
		default:
			s.Status, s.Key = Pass, "peer.direct"
			s.Detail = fmt.Sprintf("%s doğrudan bağlı.", p.Name)
		}
		// One offline peer is that peer's problem, not this computer's:
		// it does not skip the others.
		s.DurationMS = float64(r.now().Sub(start).Microseconds()) / 1000
		r.steps = append(r.steps, s)
	}
}

// ErrNoProbe is returned where no tunnel is available.
var ErrNoProbe = errors.New("arıza ayıklayıcı için çalışan bir OpenScale servisi gerekli")
