package coordinator

import (
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/control"
	"github.com/openscale/openscale/internal/privacy"
)

// Audit of refused registrations (#187). The coordinator answers a refused
// enrollment, an invite used twice, a request from an address it does not
// know, a document whose signature does not verify and a refused root
// transition with a short error; the owner also wants to see them later.
// Each one is handed to Config.Rejections, which writes it to the local
// hash-chained audit log (internal/audit) of the computer running the
// coordinator.
//
// What is written: the kind, the masked source address (privacy.MaskAddr:
// the first two octets only) and the error code. No device name, invite id
// or key is written. A peer that keeps failing cannot flood the log: each
// kind and source is written at most once per rejectEvery, and at most
// rejectBudget records are written per rejectWindow in all; what was held
// back is counted in the next record of that kind.

// RejectionSink receives one audit record.
type RejectionSink func(kind, severity, message string)

// Kinds of the rejection records (audit kinds, snake_case).
const (
	RejectEnrollment  = "coord_enroll_rejected"
	RejectInviteUsed  = "coord_invite_reused"
	RejectUnknown     = "coord_unknown_source"
	RejectDocument    = "coord_document_rejected"
	RejectTransition  = "coord_transition_rejected"
	RejectLeave       = "coord_leave_rejected"
	rejectSevWarning  = "warning"
	rejectSevCritical = "critical"
	rejectSevInfo     = "info"
)

// Limits of the rejection audit.
const (
	rejectEvery  = time.Minute
	rejectWindow = 10 * time.Minute
	rejectBudget = 60
	// rejectMaxKeys bounds the per-source table; past it the table is
	// cleared (the per-window budget still holds).
	rejectMaxKeys = 4096
)

type rejectState struct {
	mu          sync.Mutex
	last        map[string]time.Time
	held        map[string]int
	windowStart time.Time
	written     int
}

func (s *Server) rejectState() *rejectState {
	st := &s.rej
	st.mu.Lock()
	if st.last == nil {
		st.last, st.held = map[string]time.Time{}, map[string]int{}
	}
	st.mu.Unlock()
	return st
}

// rejectText is the Turkish text of each kind.
var rejectText = map[string]string{
	RejectEnrollment: "Koordinatör bir katılım isteğini reddetti (davet veya imza doğrulanamadı ya da sahip reddetmişti)",
	RejectInviteUsed: "Koordinatör kullanılmış bir davetle gelen katılım isteğini reddetti",
	RejectUnknown:    "Koordinatör ağda olmayan bir adresten gelen isteği reddetti",
	RejectDocument:   "Koordinatör yüklenen ağ belgesini reddetti (imza veya sürüm doğrulanamadı)",
	RejectTransition: "Koordinatör bir kök anahtar geçişini reddetti (imza doğrulanamadı)",
	RejectLeave:      "Koordinatör bir ayrılma isteğini reddetti (imza doğrulanamadı)",
}

var rejectSeverity = map[string]string{
	RejectEnrollment: rejectSevWarning,
	RejectInviteUsed: rejectSevWarning,
	RejectUnknown:    rejectSevInfo,
	RejectDocument:   rejectSevWarning,
	RejectTransition: rejectSevCritical,
	RejectLeave:      rejectSevWarning,
}

// rejected records one refusal, rate limited. err may be nil.
func (s *Server) rejected(kind string, src netip.Addr, err error) {
	sink := s.cfg.Rejections
	if sink == nil {
		return
	}
	text, ok := rejectText[kind]
	if !ok {
		return
	}
	now := s.cfg.Now()
	masked := privacy.MaskAddr(src)
	// The table is keyed by the full address (memory only, never written).
	key := kind + "|" + src.String()
	st := s.rejectState()
	st.mu.Lock()
	if st.windowStart.IsZero() || now.Sub(st.windowStart) >= rejectWindow {
		st.windowStart, st.written = now, 0
	}
	if len(st.last) >= rejectMaxKeys {
		clear(st.last)
	}
	if last, seen := st.last[key]; (seen && now.Sub(last) < rejectEvery) || st.written >= rejectBudget {
		st.held[kind]++
		st.mu.Unlock()
		return
	}
	st.last[key] = now
	st.written++
	held := st.held[kind]
	delete(st.held, kind)
	st.mu.Unlock()

	msg := text
	if masked != "" {
		msg += "; kaynak " + masked
	}
	if code := classifyError(err); code != "" {
		msg += "; kod " + code
	}
	if held > 0 {
		msg += fmt.Sprintf("; ayrıca %d benzer olay sınır nedeniyle yazılmadı", held)
	}
	sink(kind, rejectSeverity[kind], msg+".")
}

// auditEnroll records a refused enrollment answer and passes it on.
func (s *Server) auditEnroll(resp control.Message, src netip.Addr) control.Message {
	switch resp.Error {
	case "invite already used":
		s.rejected(RejectInviteUsed, src, nil)
	case "enrollment rejected":
		s.rejected(RejectEnrollment, src, nil)
	}
	return resp
}

// ErrorCode maps an error to its stable code (internal/errcode.Classify).
// It is set by the program; the coordinator does not import errcode, which
// depends on the device engine.
var ErrorCode func(error) string

func classifyError(err error) string {
	if err == nil || ErrorCode == nil {
		return ""
	}
	return ErrorCode(err)
}
