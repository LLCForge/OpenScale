package coordinator

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/openscale/openscale/internal/audit"
	"github.com/openscale/openscale/internal/control"
	"github.com/openscale/openscale/internal/errcode"
	"github.com/openscale/openscale/internal/trust"
)

// The program wires the classifier (internal/cli); tests do the same.
func init() { ErrorCode = errcode.Classify }

type rejectRecord struct{ kind, severity, message string }

func rejectServer(now *time.Time, out *[]rejectRecord) *Server {
	return &Server{cfg: Config{Now: func() time.Time { return *now }, Rejections: func(kind, severity, message string) {
		*out = append(*out, rejectRecord{kind, severity, message})
	}}}
}

func TestRejectionAuditMasksAndLimits(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	var got []rejectRecord
	s := rejectServer(&now, &got)
	src := netip.MustParseAddr("100.64.12.34")
	s.rejected(RejectEnrollment, src, nil)
	s.rejected(RejectEnrollment, src, nil) // same source within a minute: held back
	s.rejected(RejectEnrollment, src, nil)
	if len(got) != 1 {
		t.Fatalf("records = %d, want 1", len(got))
	}
	if strings.Contains(got[0].message, "12.34") || !strings.Contains(got[0].message, "100.64.*.*") || got[0].severity != audit.SeverityWarning {
		t.Fatalf("record = %+v", got[0])
	}
	now = now.Add(rejectEvery)
	s.rejected(RejectEnrollment, src, nil)
	if len(got) != 2 || !strings.Contains(got[1].message, "2 benzer olay") {
		t.Fatalf("held-back count missing: %+v", got)
	}
	// Signature failure of an uploaded document carries the error code.
	s.rejected(RejectDocument, src, trust.ErrBadSignature)
	if last := got[len(got)-1]; last.kind != RejectDocument || !strings.Contains(last.message, "OS-1002") {
		t.Fatalf("document record = %+v", last)
	}
	s.rejected(RejectTransition, src, errors.New("bad"))
	if last := got[len(got)-1]; last.severity != audit.SeverityCritical {
		t.Fatalf("transition record = %+v", last)
	}
	// Every kind is a valid audit kind and has a text.
	dir := t.TempDir()
	l, err := audit.Open(dir, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range got {
		if err := l.Append(r.kind, r.severity, r.message); err != nil {
			t.Fatalf("append %+v: %v", r, err)
		}
	}
	if rep, err := audit.Verify(dir); err != nil || !rep.OK {
		t.Fatalf("verify: %+v %v", rep, err)
	}
}

func TestRejectionAuditBudget(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	var got []rejectRecord
	s := rejectServer(&now, &got)
	for i := range rejectBudget * 2 {
		s.rejected(RejectUnknown, netip.AddrFrom4([4]byte{100, byte(64 + i/250), byte(i), 1}), nil)
	}
	if len(got) > rejectBudget {
		t.Fatalf("budget not kept: %d records", len(got))
	}
	now = now.Add(rejectWindow)
	s.rejected(RejectUnknown, netip.MustParseAddr("100.99.0.1"), nil)
	if len(got) != rejectBudget+1 {
		t.Fatalf("new window refused: %d", len(got))
	}
	// Without a sink nothing happens.
	(&Server{cfg: Config{Now: time.Now}}).rejected(RejectUnknown, netip.Addr{}, nil)
}

func TestAuditEnrollPassesReply(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	var got []rejectRecord
	s := rejectServer(&now, &got)
	src := netip.MustParseAddr("100.64.0.9")
	ok := control.Message{T: control.TypeEnroll, Complete: true}
	if r := s.auditEnroll(ok, src); r.T != control.TypeEnroll || len(got) != 0 {
		t.Fatalf("accepted enrollment audited: %+v", got)
	}
	s.auditEnroll(control.Message{T: control.TypeError, Error: "invite already used"}, src)
	if len(got) != 1 || got[0].kind != RejectInviteUsed {
		t.Fatalf("got %+v", got)
	}
}
