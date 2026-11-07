package node

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/netip"
	"slices"
	"time"

	"github.com/openscale/openscale/internal/securefile"
	"github.com/openscale/openscale/internal/trust"
	"github.com/openscale/openscale/internal/wgconf"
)

// Monthly data quota of an exit node (#401, ADR-0155). The exit node adds
// up, per member and in total, the WireGuard bytes it exchanges with each
// member in the current calendar month (UTC). At the warning threshold it
// logs once; at the limit it puts the member's overlay addresses into the
// exit filter's quota set, so that member's internet traffic is dropped at
// the exit node. Members keep their tunnel: with their kill switch on
// nothing leaks, and overlay services (DNS, files) keep working. When the
// total limit is reached every member is blocked. A new month starts from
// zero and removes every block.
//
// The count is what the VPS provider bills for: everything the member's
// tunnel carries, internet traffic and the little overlay traffic to the
// exit node itself. It is local to the exit node and never reported.

// Exit quota defaults and limits.
const (
	DefaultExitQuotaWarn = 80
	exitQuotaInterval    = time.Minute
	exitQuotaStateMax    = 1 << 20
	exitQuotaVersion     = 1
	// maxExitQuotaMembers bounds the state file.
	maxExitQuotaMembers = 4096
)

// ExitQuotaConfig configures the quota.
type ExitQuotaConfig struct {
	// MemberLimit and TotalLimit are bytes per calendar month; 0 is none.
	MemberLimit, TotalLimit uint64
	// WarnPercent is the warning threshold in percent (1-99); 0 is
	// DefaultExitQuotaWarn.
	WarnPercent int
	// StatePath is the state file (0600).
	StatePath string
	// Block replaces the blocked member addresses (osnet.SetExitQuotaBlocked).
	Block  func(ctx context.Context, members []netip.Addr) error
	Logger *slog.Logger
	Now    func() time.Time
}

func (c ExitQuotaConfig) validate() error {
	if c.MemberLimit == 0 && c.TotalLimit == 0 {
		return errors.New("kota yok")
	}
	if c.WarnPercent < 0 || c.WarnPercent > 99 {
		return errors.New("uyarı eşiği 1-99 arası olmalı")
	}
	if c.StatePath == "" || c.Block == nil {
		return errors.New("eksik kota yapılandırması")
	}
	return nil
}

// ExitQuotaUsage is one member's month.
type ExitQuotaUsage struct {
	Bytes   uint64 `json:"bytes"`
	Warned  bool   `json:"warned,omitempty"`
	Blocked bool   `json:"blocked,omitempty"`
}

// ExitQuotaState is the state file and what "exit-node quota" prints.
type ExitQuotaState struct {
	Version int    `json:"v"`
	Month   string `json:"month"`
	// Members is keyed by device name.
	Members map[string]*ExitQuotaUsage `json:"members"`
	Total   uint64                     `json:"total"`
	// TotalWarned and TotalBlocked: the total threshold and limit hit.
	TotalWarned  bool `json:"total_warned,omitempty"`
	TotalBlocked bool `json:"total_blocked,omitempty"`
	// Counters are the last WireGuard byte counters per peer key (hex),
	// for the difference at the next check.
	Counters map[string]uint64 `json:"counters"`
	// Limits as configured, for the status command.
	MemberLimit uint64 `json:"member_limit,omitempty"`
	TotalLimit  uint64 `json:"total_limit,omitempty"`
	Updated     int64  `json:"updated"`
}

// ReadExitQuotaState reads the state file.
func ReadExitQuotaState(path string) (ExitQuotaState, error) {
	data, err := securefile.ReadPrivate(path, exitQuotaStateMax)
	if err != nil {
		return ExitQuotaState{}, err
	}
	var st ExitQuotaState
	if err := json.Unmarshal(data, &st); err != nil {
		return ExitQuotaState{}, fmt.Errorf("kota durumu bozuk: %w", err)
	}
	if st.Version != exitQuotaVersion || len(st.Members) > maxExitQuotaMembers || len(st.Counters) > maxExitQuotaMembers {
		return ExitQuotaState{}, errors.New("kota durumu tanınmıyor")
	}
	for name, u := range st.Members {
		if u == nil {
			delete(st.Members, name)
		}
	}
	return st, nil
}

// exitQuota is the running quota.
type exitQuota struct {
	cfg     ExitQuotaConfig
	st      ExitQuotaState
	applied []netip.Addr
	// dirty: the state changed since it was written.
	dirty bool
}

func newExitQuota(cfg ExitQuotaConfig) *exitQuota {
	if cfg.WarnPercent == 0 {
		cfg.WarnPercent = DefaultExitQuotaWarn
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	q := &exitQuota{cfg: cfg}
	st, err := ReadExitQuotaState(cfg.StatePath)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		// The month's count is lost with the file; it starts over from
		// zero, which lifts any block, so this is logged as a warning.
		cfg.Logger.Warn("exit quota state unreadable, starting over", "error", err.Error())
	}
	if err != nil {
		st = ExitQuotaState{}
	}
	q.st = st
	q.normalize(cfg.Now())
	return q
}

func monthOf(t time.Time) string { return t.UTC().Format("2006-01") }

func (q *exitQuota) normalize(now time.Time) {
	m := monthOf(now)
	if q.st.Version != exitQuotaVersion || q.st.Month != m {
		counters := q.st.Counters
		if q.st.Month != "" && q.st.Month != m {
			q.cfg.Logger.Info("exit quota: new month, counters reset", "month", m)
		}
		q.st = ExitQuotaState{Version: exitQuotaVersion, Month: m, Counters: counters}
		q.dirty = true
	}
	if q.st.Members == nil {
		q.st.Members = map[string]*ExitQuotaUsage{}
	}
	if q.st.Counters == nil {
		q.st.Counters = map[string]uint64{}
	}
	q.st.MemberLimit, q.st.TotalLimit = q.cfg.MemberLimit, q.cfg.TotalLimit
}

// step adds the traffic since the last check and returns the member
// addresses to block. members are the network's devices other than this
// exit node.
func (q *exitQuota) step(now time.Time, stats map[trust.Key]wgconf.PeerStatus, members []trust.Device) []netip.Addr {
	q.normalize(now)
	seen := map[string]bool{}
	for _, d := range members {
		ps, ok := stats[d.WireGuardKey]
		if !ok {
			continue
		}
		key := d.WireGuardKey.String()
		seen[key] = true
		cur := ps.RxBytes + ps.TxBytes
		last, known := q.st.Counters[key]
		delta := cur
		if known && cur >= last {
			delta = cur - last
		}
		// A counter below the last one means the tunnel restarted.
		q.st.Counters[key] = cur
		if delta == 0 {
			continue
		}
		u := q.st.Members[d.Name]
		if u == nil {
			if len(q.st.Members) >= maxExitQuotaMembers {
				continue
			}
			u = &ExitQuotaUsage{}
			q.st.Members[d.Name] = u
		}
		u.Bytes = satAdd(u.Bytes, delta)
		q.st.Total = satAdd(q.st.Total, delta)
		q.dirty = true
	}
	for key := range q.st.Counters {
		if !seen[key] {
			delete(q.st.Counters, key)
		}
	}
	q.judge()
	var block []netip.Addr
	for _, d := range members {
		u := q.st.Members[d.Name]
		if q.st.TotalBlocked || (u != nil && u.Blocked) {
			for _, a := range []netip.Addr{d.IPv4, d.IPv6} {
				if a.IsValid() {
					block = append(block, a)
				}
			}
		}
	}
	slices.SortFunc(block, func(a, b netip.Addr) int { return a.Compare(b) })
	return slices.Compact(block)
}

// judge sets the warning and block marks, logging each once per month.
func (q *exitQuota) judge() {
	warnAt := func(limit uint64) uint64 { return limit / 100 * uint64(q.cfg.WarnPercent) }
	if lim := q.cfg.MemberLimit; lim > 0 {
		for name, u := range q.st.Members {
			if !u.Warned && u.Bytes >= warnAt(lim) {
				u.Warned, q.dirty = true, true
				q.cfg.Logger.Warn("exit quota: member near its monthly limit", "member", name, "bytes", u.Bytes, "limit", lim)
			}
			if !u.Blocked && u.Bytes >= lim {
				u.Blocked, q.dirty = true, true
				q.cfg.Logger.Warn("exit quota: member's internet traffic stopped for this month", "member", name, "bytes", u.Bytes, "limit", lim)
			}
		}
	}
	if lim := q.cfg.TotalLimit; lim > 0 {
		if !q.st.TotalWarned && q.st.Total >= warnAt(lim) {
			q.st.TotalWarned, q.dirty = true, true
			q.cfg.Logger.Warn("exit quota: total near the monthly limit", "bytes", q.st.Total, "limit", lim)
		}
		if !q.st.TotalBlocked && q.st.Total >= lim {
			q.st.TotalBlocked, q.dirty = true, true
			q.cfg.Logger.Warn("exit quota: monthly total reached, every member's internet traffic stopped", "bytes", q.st.Total, "limit", lim)
		}
	}
}

func satAdd(a, b uint64) uint64 {
	if a+b < a {
		return ^uint64(0)
	}
	return a + b
}

func (q *exitQuota) save(now time.Time) error {
	if !q.dirty {
		return nil
	}
	q.st.Updated = now.Unix()
	data, err := json.Marshal(q.st)
	if err != nil {
		return err
	}
	if err := securefile.Replace(q.cfg.StatePath, data); err != nil {
		return err
	}
	q.dirty = false
	return nil
}

// RunExitQuota counts members' traffic while this device is an exit node
// and applies the quota until ctx ends. Blocks are applied again at every
// check, so they survive the exit filter being rebuilt.
func (e *Engine) RunExitQuota(ctx context.Context, cfg ExitQuotaConfig) error {
	if err := cfg.validate(); err != nil {
		return err
	}
	q := newExitQuota(cfg)
	t := time.NewTicker(exitQuotaInterval)
	defer t.Stop()
	for {
		e.exitQuotaStep(ctx, q)
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

func (e *Engine) exitQuotaStep(ctx context.Context, q *exitQuota) {
	self, err := e.Self()
	if err != nil || !self.HasRole(trust.RoleExitNode) {
		return
	}
	stats, err := e.PeerStats()
	if err != nil {
		return
	}
	var members []trust.Device
	for _, d := range e.Document().Devices {
		if d.Name != self.Name {
			members = append(members, d)
		}
	}
	now := q.cfg.Now()
	block := q.step(now, stats, members)
	if err := q.save(now); err != nil {
		q.cfg.Logger.Warn("exit quota state not saved", "error", err.Error())
	}
	if len(block) == 0 && len(q.applied) == 0 {
		return
	}
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := q.cfg.Block(cctx, block); err != nil {
		q.cfg.Logger.Debug("exit quota block not applied", "error", err.Error())
		return
	}
	if !slices.Equal(block, q.applied) {
		q.cfg.Logger.Info("exit quota blocks applied", "addresses", len(block))
	}
	q.applied = block
}
