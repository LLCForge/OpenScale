package coordinator

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"time"
)

// No-metadata mode (#630, ADR-0182). Connection times, source addresses and
// who relays to whom are never written to disk and stay in memory for at
// most the retention period:
//   - the monthly relay usage file (ops.go, #482) is neither read nor
//     written;
//   - the logger drops debug records (they carry endpoints) and blanks
//     address, endpoint and device name attributes of every other record;
//   - a sweep every minute forgets clone samples and alerts, relay
//     statistics, relay peer pairs, SPA sources and candidates that are
//     older than the retention.
// The mode is auditable: admin devices fetch the attestation (TypeNoLog),
// `openscale server audit` checks that journald keeps nothing on disk and
// that no usage file exists (srvaudit). An attestation is a statement of
// the coordinator's own configuration, not a proof: a modified binary can
// claim anything (ADR-0109).

// Message type of the attestation (admin devices only).
const (
	TypeNoLog    = "nolog"
	FeatureNoLog = "nolog"
)

// redactedKeys are the log attribute keys blanked in the no-metadata mode.
var redactedKeys = []string{"address", "addr", "endpoint", "remote", "ip", "source", "src", "from", "to", "device", "name", "peer", "target"}

const redactedValue = "[gizlendi]"

// redactHandler blanks metadata attributes and drops debug records.
type redactHandler struct {
	next slog.Handler
}

func newRedactHandler(next slog.Handler) slog.Handler { return &redactHandler{next: next} }

func (h *redactHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return l > slog.LevelDebug && h.next.Enabled(ctx, l)
}

func (h *redactHandler) Handle(ctx context.Context, r slog.Record) error {
	if r.Level <= slog.LevelDebug {
		return nil
	}
	out := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	r.Attrs(func(a slog.Attr) bool {
		out.AddAttrs(redactAttr(a))
		return true
	})
	return h.next.Handle(ctx, out)
}

func (h *redactHandler) WithAttrs(as []slog.Attr) slog.Handler {
	red := make([]slog.Attr, len(as))
	for i, a := range as {
		red[i] = redactAttr(a)
	}
	return &redactHandler{next: h.next.WithAttrs(red)}
}

func (h *redactHandler) WithGroup(name string) slog.Handler {
	return &redactHandler{next: h.next.WithGroup(name)}
}

func redactAttr(a slog.Attr) slog.Attr {
	if a.Value.Kind() == slog.KindGroup {
		g := a.Value.Group()
		red := make([]any, len(g))
		for i, x := range g {
			red[i] = redactAttr(x)
		}
		return slog.Group(a.Key, red...)
	}
	k := strings.ToLower(a.Key)
	for _, r := range redactedKeys {
		if k == r || strings.HasSuffix(k, "_"+r) {
			return slog.String(a.Key, redactedValue)
		}
	}
	return a
}

// NoLogAttestation describes what this coordinator keeps (TypeNoLog).
type NoLogAttestation struct {
	Schema           int      `json:"schema"`
	NoMetadata       bool     `json:"no_metadata"`
	RetentionMinutes int      `json:"retention_minutes,omitempty"`
	UsageFile        bool     `json:"usage_file"`
	DebugLogs        bool     `json:"debug_logs"`
	RAMOnly          bool     `json:"ram_only"`
	StateFS          string   `json:"state_fs,omitempty"`
	SPA              bool     `json:"spa"`
	Blind            bool     `json:"blind"`
	CoreDumps        string   `json:"core_dumps"`
	Notes            []string `json:"notes,omitempty"`
}

// Attestation returns the coordinator's statement of what it keeps.
func (s *Server) Attestation() NoLogAttestation {
	h := s.g2.hard
	a := NoLogAttestation{Schema: 1, NoMetadata: h.NoMetadata, UsageFile: s.ops != nil && s.ops.usage != nil,
		DebugLogs: !h.NoMetadata, RAMOnly: h.RAMOnly, StateFS: s.g2.stateFS, SPA: h.SPA, Blind: h.Blind, CoreDumps: s.g2.coreDumps}
	if h.NoMetadata {
		a.RetentionMinutes = h.Retention()
	}
	if !h.RAMOnly {
		a.Notes = append(a.Notes, "Durum klasörü diskte; belge ve anahtar kalıcı.")
	}
	if s.g2.swap {
		a.Notes = append(a.Notes, "Sistemde takas alanı açık; bellek diske yazılabilir.")
	}
	a.Notes = append(a.Notes, "Bu beyan koordinatörün kendi yapılandırmasıdır, kanıt değildir (ADR-0109).")
	return a
}

// noLog answers TypeNoLog for admin devices.
func (s *Server) noLogData() ([]byte, error) {
	return json.Marshal(s.Attestation())
}

// metadataSweep forgets connection metadata older than the retention.
func (s *Server) metadataSweep() {
	h := s.g2.hard
	if !h.NoMetadata {
		return
	}
	keep := time.Duration(h.Retention()) * time.Minute
	now := s.cfg.Now()
	m := s.memberState()
	m.mu.Lock()
	for id, t := range m.clones {
		if now.Sub(t.sampled) > keep {
			delete(m.clones, id)
		}
	}
	for id, a := range m.alerts {
		if now.Sub(a.Last) > keep {
			delete(m.alerts, id)
		}
	}
	m.mu.Unlock()
	s.ext.mu.Lock()
	for id, e := range s.ext.cands {
		if now.Sub(e.at) > keep {
			delete(s.ext.cands, id)
		}
	}
	s.ext.mu.Unlock()
	s.relay.mu.Lock()
	for id, st := range s.relay.stats {
		if now.Sub(st.LastSeen) > keep {
			delete(s.relay.stats, id)
		}
	}
	s.relay.mu.Unlock()
	if s.p15 != nil {
		s.p15.mu.Lock()
		for from, to := range s.p15.peers {
			for id, at := range to {
				if now.Sub(at) > keep {
					delete(to, id)
				}
			}
			if len(to) == 0 {
				delete(s.p15.peers, from)
			}
		}
		s.p15.mu.Unlock()
	}
	if s.g2.spa != nil {
		s.g2.spa.forgetOlder(keep)
	}
}
