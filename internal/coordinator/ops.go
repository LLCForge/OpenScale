package coordinator

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/internal/usage"
)

// Coordinator operations (P09, ADR-0153): relay data accounting (#482),
// the reach report behind the migration preflight (#485) and the live
// failover drill (#481). They are asked for through files in the state
// directory, which only the coordinator's own user and root can write, so
// they add no network surface. Nothing here changes what the coordinator
// may do: documents stay root-signed and the coordinator still decides
// nothing about membership.

// Files of the operations in the state directory.
const (
	// OpsRequestFile is written by the command line; the running
	// coordinator reads and removes it within about a second.
	OpsRequestFile = "ops-request.json"
	// OpsReplyFile carries the answer with the request's id.
	OpsReplyFile = "ops-reply.json"
	// DrillReportFile is the latest drill's report.
	DrillReportFile = "drill-report.json"
	// RelayUsageFile holds the monthly relayed bytes per device (#482).
	RelayUsageFile = "relay-usage.json"
)

// Operation names.
const (
	OpReach       = "reach"
	OpDrill       = "drill"
	OpDrillCancel = "drill-cancel"
)

// Limits of the operations.
const (
	// ReachWindow: a device whose last handshake with this coordinator is
	// at most this old counts as reaching it. Devices keep a persistent
	// keepalive and re-handshake every two minutes (ADR-0111).
	ReachWindow = 3 * time.Minute
	// MinDrill and MaxDrill bound the silent period of a drill.
	MinDrill = 10 * time.Second
	MaxDrill = 30 * time.Minute
	// DrillObserve is how long after the silence the drill waits for the
	// devices to come back.
	DrillObserve = 10 * time.Minute
	maxOpsFile   = 256 << 10
	opsSchema    = 1
	maxOpsID     = 64
)

// OpsRequest asks the running coordinator for an operation.
type OpsRequest struct {
	Schema    int    `json:"schema"`
	ID        string `json:"id"`
	Op        string `json:"op"`
	DurationS int    `json:"duration_s,omitempty"`
}

// OpsReply answers an OpsRequest.
type OpsReply struct {
	Schema int          `json:"schema"`
	ID     string       `json:"id"`
	Op     string       `json:"op"`
	Error  string       `json:"error,omitempty"`
	Reach  *ReachReport `json:"reach,omitempty"`
	Drill  *DrillReport `json:"drill,omitempty"`
}

// ReachDevice is one device of the document as this coordinator sees it.
type ReachDevice struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	LastHandshake time.Time `json:"last_handshake,omitzero"`
	Reached       bool      `json:"reached"`
}

// ReachReport lists which devices currently reach this coordinator over
// WireGuard with its own key: a real handshake, not a guess.
type ReachReport struct {
	Schema      int           `json:"schema"`
	Coordinator string        `json:"coordinator"`
	Fingerprint string        `json:"fingerprint"`
	Primary     bool          `json:"primary"`
	DocVersion  uint64        `json:"doc_version"`
	At          time.Time     `json:"at"`
	WindowS     int           `json:"window_s"`
	Devices     []ReachDevice `json:"devices"`
}

// DrillReturn is a device that came back after the silence.
type DrillReturn struct {
	Name   string  `json:"name"`
	AfterS float64 `json:"after_s"`
}

// Drill states.
const (
	DrillQuiet     = "quiet"
	DrillObserving = "observing"
	DrillDone      = "done"
)

// DrillReport is the record of one failover drill on this coordinator.
type DrillReport struct {
	Schema       int           `json:"schema"`
	Coordinator  string        `json:"coordinator"`
	State        string        `json:"state"`
	Started      time.Time     `json:"started"`
	QuietUntil   time.Time     `json:"quiet_until"`
	Finished     time.Time     `json:"finished,omitzero"`
	Cancelled    bool          `json:"cancelled,omitempty"`
	Coordinators int           `json:"coordinators"`
	Before       []string      `json:"before"`
	Returned     []DrillReturn `json:"returned"`
	Missing      []string      `json:"missing"`
}

// opsState is the coordinator side of the operations.
type opsState struct {
	// quietUntil is the end of a drill's silence (Unix nanoseconds; zero:
	// not silent). The bind reads it on every packet.
	quietUntil atomic.Int64

	mu      sync.Mutex
	usage   *usage.Monthly
	drill   *DrillReport
	drillRx map[trust.Key]uint64 // received bytes at the drill's start
	drillBy map[trust.Key]string // name of each device of Before
}

// initOps loads the relay usage counter and hooks it into the relay. It
// runs only with Config.Operations.
func (s *Server) initOps() error {
	s.ops = &opsState{}
	// The no-metadata mode never reads or writes the usage file (#630).
	if !s.cfg.Operations || (s.g2 != nil && s.g2.hard.NoMetadata) {
		return nil
	}
	m, err := loadUsage(filepath.Join(s.cfg.Store.Dir(), RelayUsageFile))
	if err != nil {
		return err
	}
	s.ops.usage = m
	s.relay.account = func(id string, n int, now time.Time) { m.Add(id, uint64(n), now) } //nolint:gosec // n > 0
	return nil
}

// loadUsage reads the usage file; a missing file starts empty, a corrupt
// one is an error so a typo never silently resets the month.
func loadUsage(path string) (*usage.Monthly, error) {
	data, err := securefile.ReadLimited(path, usage.MaxFileSize)
	if errors.Is(err, fs.ErrNotExist) {
		return usage.NewMonthly(0), nil
	}
	if err != nil {
		return nil, fmt.Errorf("relay usage: %w", err)
	}
	m, err := usage.Decode(data, 0)
	if err != nil {
		return nil, fmt.Errorf("relay usage (%s): %w", RelayUsageFile, err)
	}
	return m, nil
}

// ReadRelayUsage reads the usage file of a coordinator state directory.
func ReadRelayUsage(dir string) (*usage.Monthly, error) {
	return loadUsage(filepath.Join(dir, RelayUsageFile))
}

// saveUsage writes the usage counter when it changed.
func (s *Server) saveUsage() {
	if s.ops == nil || s.ops.usage == nil || !s.ops.usage.Dirty() {
		return
	}
	data, err := s.ops.usage.Encode()
	if err == nil {
		err = securefile.Replace(filepath.Join(s.cfg.Store.Dir(), RelayUsageFile), data)
	}
	if err != nil {
		s.logger.Warn("save relay usage", "error", err.Error())
	}
}

// quiet reports whether a drill keeps the coordinator silent at now.
func (o *opsState) quiet(now time.Time) bool {
	until := o.quietUntil.Load()
	return until != 0 && now.UnixNano() < until
}

// quietBind drops every packet in both directions while a drill is silent,
// so devices see exactly what they would see if the server were down.
type quietBind struct {
	conn.Bind
	ops *opsState
	now func() time.Time
}

func (s *Server) wrapQuiet(b conn.Bind) conn.Bind {
	return &quietBind{Bind: b, ops: s.ops, now: s.cfg.Now}
}

func (b *quietBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actual, err := b.Bind.Open(port)
	if err != nil {
		return nil, 0, err
	}
	for i, fn := range fns {
		fns[i] = func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
			n, err := fn(packets, sizes, eps)
			if n > 0 && b.ops.quiet(b.now()) {
				return 0, err
			}
			return n, err
		}
	}
	return fns, actual, nil
}

func (b *quietBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	if b.ops.quiet(b.now()) {
		return nil
	}
	return b.Bind.Send(bufs, ep)
}

// opsTick runs about once a second: it answers a pending request and
// advances a running drill.
func (s *Server) opsTick() {
	if !s.cfg.Operations || s.ops == nil {
		return
	}
	dir := s.cfg.Store.Dir()
	if req, ok := s.readRequest(dir); ok {
		reply := s.answer(req)
		if data, err := json.Marshal(reply); err == nil {
			if err := securefile.Replace(filepath.Join(dir, OpsReplyFile), data); err != nil {
				s.logger.Warn("write operation reply", "error", err.Error())
			}
		}
	}
	s.advanceDrill()
}

// readRequest reads and removes the request file. An unreadable file is
// left for the next tick (its permissions may still be changing).
func (s *Server) readRequest(dir string) (OpsRequest, bool) {
	path := filepath.Join(dir, OpsRequestFile)
	data, err := securefile.ReadLimited(path, maxOpsFile)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, fs.ErrPermission) {
			_ = os.Remove(path)
		}
		return OpsRequest{}, false
	}
	_ = os.Remove(path)
	req, err := ParseOpsRequest(data)
	if err != nil {
		s.logger.Warn("invalid operation request", "error", err.Error())
		return OpsRequest{}, false
	}
	return req, true
}

// ParseOpsRequest decodes a request strictly.
func ParseOpsRequest(data []byte) (OpsRequest, error) {
	var req OpsRequest
	if err := decodeOps(data, &req); err != nil {
		return OpsRequest{}, err
	}
	if req.Schema != opsSchema {
		return OpsRequest{}, fmt.Errorf("unsupported schema %d", req.Schema)
	}
	if req.ID == "" || len(req.ID) > maxOpsID || !isHexID(req.ID) {
		return OpsRequest{}, errors.New("invalid id")
	}
	switch req.Op {
	case OpReach, OpDrillCancel:
		if req.DurationS != 0 {
			return OpsRequest{}, errors.New("duration is only for drills")
		}
	case OpDrill:
		d := time.Duration(req.DurationS) * time.Second
		if d < MinDrill || d > MaxDrill {
			return OpsRequest{}, fmt.Errorf("drill duration must be %s to %s", MinDrill, MaxDrill)
		}
	default:
		return OpsRequest{}, fmt.Errorf("unknown operation %q", req.Op)
	}
	return req, nil
}

func isHexID(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func decodeOps(data []byte, v any) error {
	if len(data) > maxOpsFile {
		return errors.New("file is too large")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data")
	}
	return nil
}

func (s *Server) answer(req OpsRequest) OpsReply {
	reply := OpsReply{Schema: opsSchema, ID: req.ID, Op: req.Op}
	var err error
	switch req.Op {
	case OpReach:
		var r ReachReport
		r, err = s.reachReport()
		reply.Reach = &r
	case OpDrill:
		var d DrillReport
		d, err = s.startDrill(time.Duration(req.DurationS) * time.Second)
		reply.Drill = &d
	case OpDrillCancel:
		var d DrillReport
		d, err = s.cancelDrill()
		reply.Drill = &d
	}
	if err != nil {
		reply.Error = err.Error()
		reply.Reach, reply.Drill = nil, nil
	}
	return reply
}

// reachReport lists the document's current devices with their last
// handshake with this coordinator.
func (s *Server) reachReport() (ReachReport, error) {
	st, err := s.wgStatus(false)
	if err != nil {
		return ReachReport{}, err
	}
	doc := s.cfg.Store.Document()
	now := s.cfg.Now()
	r := ReachReport{
		Schema: opsSchema, Coordinator: s.wgKey.String(), Fingerprint: trust.CoordinatorFingerprint(s.wgKey),
		Primary: doc.Coordinator != nil && doc.Coordinator.WireGuardKey == s.wgKey, DocVersion: doc.Version,
		At: now.UTC(), WindowS: int(ReachWindow / time.Second), Devices: []ReachDevice{},
	}
	for _, d := range doc.Devices {
		if !now.Before(d.ExpiresAt) {
			continue
		}
		rd := ReachDevice{ID: d.ID, Name: d.Name}
		if p, ok := st.Peers[d.WireGuardKey]; ok && p.LastHandshakeUnix > 0 {
			rd.LastHandshake = time.Unix(p.LastHandshakeUnix, 0).UTC()
			rd.Reached = now.Sub(rd.LastHandshake) <= ReachWindow
		}
		r.Devices = append(r.Devices, rd)
	}
	slices.SortFunc(r.Devices, func(a, b ReachDevice) int { return compareStrings(a.Name, b.Name) })
	return r, nil
}

func compareStrings(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// startDrill silences the coordinator for d (#481). It refuses when this
// is the only usable coordinator: devices would have nowhere to go.
func (s *Server) startDrill(d time.Duration) (DrillReport, error) {
	doc := s.cfg.Store.Document()
	now := s.cfg.Now()
	usable := len(doc.UsableCoordinators(now))
	if usable < 2 {
		return DrillReport{}, errors.New("the network has only one usable coordinator; a drill would cut every device off (add one with 'network coordinator add' first)")
	}
	s.ops.mu.Lock()
	defer s.ops.mu.Unlock()
	if s.ops.drill != nil && s.ops.drill.State != DrillDone {
		return DrillReport{}, errors.New("a drill is already running")
	}
	st, err := s.wgStatus(false)
	if err != nil {
		return DrillReport{}, err
	}
	rep := &DrillReport{
		Schema: opsSchema, Coordinator: trust.CoordinatorFingerprint(s.wgKey), State: DrillQuiet,
		Started: now.UTC(), QuietUntil: now.Add(d).UTC(), Coordinators: usable,
		Before: []string{}, Returned: []DrillReturn{}, Missing: []string{},
	}
	s.ops.drillRx = map[trust.Key]uint64{}
	s.ops.drillBy = map[trust.Key]string{}
	for _, dev := range doc.Devices {
		p, ok := st.Peers[dev.WireGuardKey]
		if !ok || p.LastHandshakeUnix <= 0 || now.Sub(time.Unix(p.LastHandshakeUnix, 0)) > ReachWindow || !now.Before(dev.ExpiresAt) {
			continue
		}
		rep.Before = append(rep.Before, dev.Name)
		s.ops.drillRx[dev.WireGuardKey] = p.RxBytes
		s.ops.drillBy[dev.WireGuardKey] = dev.Name
	}
	slices.Sort(rep.Before)
	s.ops.drill = rep
	s.ops.quietUntil.Store(now.Add(d).UnixNano())
	s.logger.Warn("failover drill: coordinator silent", "seconds", int(d/time.Second), "devices", len(rep.Before))
	s.writeDrillLocked()
	return *rep, nil
}

// cancelDrill ends the silence now; observation continues.
func (s *Server) cancelDrill() (DrillReport, error) {
	s.ops.mu.Lock()
	defer s.ops.mu.Unlock()
	if s.ops.drill == nil || s.ops.drill.State == DrillDone {
		return DrillReport{}, errors.New("no drill is running")
	}
	now := s.cfg.Now()
	s.ops.quietUntil.Store(0)
	if s.ops.drill.State == DrillQuiet {
		s.ops.drill.QuietUntil = now.UTC()
	}
	s.ops.drill.Cancelled = true
	s.writeDrillLocked()
	return *s.ops.drill, nil
}

// advanceDrill moves a drill from silence to observation and records the
// devices that send this coordinator traffic again.
func (s *Server) advanceDrill() {
	s.ops.mu.Lock()
	defer s.ops.mu.Unlock()
	rep := s.ops.drill
	if rep == nil || rep.State == DrillDone {
		return
	}
	now := s.cfg.Now()
	if rep.State == DrillQuiet {
		if now.Before(rep.QuietUntil) {
			return
		}
		s.ops.quietUntil.Store(0)
		rep.State = DrillObserving
		s.logger.Info("failover drill: coordinator answering again")
		s.writeDrillLocked()
	}
	st, err := s.wgStatus(false)
	if err != nil {
		return
	}
	for key, rx := range s.ops.drillRx {
		if p, ok := st.Peers[key]; ok && p.RxBytes > rx {
			rep.Returned = append(rep.Returned, DrillReturn{Name: s.ops.drillBy[key], AfterS: now.Sub(rep.QuietUntil).Seconds()})
			delete(s.ops.drillRx, key)
		}
	}
	if len(s.ops.drillRx) > 0 && now.Sub(rep.QuietUntil) < DrillObserve {
		return
	}
	rep.Missing = rep.Missing[:0]
	for _, name := range s.ops.drillBy {
		if !slices.ContainsFunc(rep.Returned, func(r DrillReturn) bool { return r.Name == name }) {
			rep.Missing = append(rep.Missing, name)
		}
	}
	slices.Sort(rep.Missing)
	slices.SortFunc(rep.Returned, func(a, b DrillReturn) int { return compareStrings(a.Name, b.Name) })
	rep.State, rep.Finished = DrillDone, now.UTC()
	s.ops.drillRx, s.ops.drillBy = nil, nil
	s.logger.Info("failover drill finished", "returned", len(rep.Returned), "missing", len(rep.Missing))
	s.writeDrillLocked()
}

func (s *Server) writeDrillLocked() {
	data, err := json.Marshal(s.ops.drill)
	if err == nil {
		err = securefile.Replace(filepath.Join(s.cfg.Store.Dir(), DrillReportFile), data)
	}
	if err != nil {
		s.logger.Warn("write drill report", "error", err.Error())
	}
}

// ReadDrillReport reads the latest drill report of a state directory.
func ReadDrillReport(dir string) (DrillReport, error) {
	data, err := securefile.ReadLimited(filepath.Join(dir, DrillReportFile), maxOpsFile)
	if err != nil {
		return DrillReport{}, err
	}
	var r DrillReport
	if err := decodeOps(data, &r); err != nil {
		return DrillReport{}, fmt.Errorf("drill report: %w", err)
	}
	return r, nil
}
