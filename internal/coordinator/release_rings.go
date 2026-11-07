package coordinator

import (
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/openscale/openscale/internal/control"
	"github.com/openscale/openscale/internal/rollout"
	"github.com/openscale/openscale/internal/trust"
)

// Update rings (#827, ADR-0235). A device's TypeRelease request may carry
// its rollout report in Data (the version it runs, its health, a rollback);
// the reply carries the progress of the announced release in Data. Both
// use an existing field, so old devices and old coordinators are not
// affected: an old coordinator ignores the request's Data, an old device
// the reply's. The ring of a device comes from its tags in the signed
// document; what a device reports only moves the progress, and every
// device keeps its own floor (internal/rollout).

func newRingTracker(mirrorDir string, logger *slog.Logger, now func() time.Time) *rollout.Tracker {
	dir := ""
	if mirrorDir != "" {
		dir = filepath.Dir(mirrorDir)
	}
	t := rollout.NewTracker(dir, now)
	t.Logf = func(format string, args ...any) {
		logger.Info("release rings", "event", fmt.Sprintf(format, args...))
	}
	return t
}

// ringMembers lists the devices of doc with their rings.
func ringMembers(doc *trust.Document) []rollout.Member {
	out := make([]rollout.Member, 0, len(doc.Devices))
	for i := range doc.Devices {
		d := &doc.Devices[i]
		out = append(out, rollout.Member{ID: d.ID, Ring: rollout.RingOf(d.Tags)})
	}
	return out
}

// releaseRings records req's report and adds the progress to resp.
func (s *Server) releaseRings(req control.Message, resp *control.Message, doc *trust.Document, self *trust.Device) {
	if s.rings == nil || resp.Release == "" || doc == nil {
		return
	}
	var rep *rollout.Report
	if len(req.Data) > 0 {
		if r, err := rollout.DecodeReport(req.Data); err == nil {
			rep = &r
		}
	}
	id := ""
	if self != nil {
		id = self.ID
	}
	a := s.rings.Observe(resp.Digest, resp.Release, ringMembers(doc), id, rep)
	data, err := a.Encode()
	if err != nil {
		return
	}
	resp.Data = data
	if control.EncodedSize(*resp) > control.MaxDatagram {
		// A long source name leaves no room: devices fall back to their
		// local floor, as with an older coordinator.
		resp.Data = nil
	}
}

// ReleaseRingsHandler answers TypeRelease (with update rings) and
// TypeReleaseFile requests from dir like a running coordinator, for the
// device given with each request (tests of the device side).
func ReleaseRingsHandler(dir string, doc func() *trust.Document, now func() time.Time, logger *slog.Logger) (handle func(deviceID string, req control.Message) control.Message, reload func()) {
	if logger == nil {
		logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	if now == nil {
		now = time.Now
	}
	s := &Server{rel: newReleaseMirror(dir, logger), rings: newRingTracker(dir, logger, now)}
	return func(deviceID string, req control.Message) control.Message {
		d := doc()
		var self *trust.Device
		for i := range d.Devices {
			if d.Devices[i].ID == deviceID {
				self = &d.Devices[i]
			}
		}
		switch req.T {
		case control.TypeRelease:
			resp := s.releaseAnnounce()
			s.releaseRings(req, &resp, d, self)
			return resp
		case control.TypeReleaseFile:
			return s.releaseChunk(req)
		}
		return control.Message{T: control.TypeError, Error: "unknown message type"}
	}, s.rel.reload
}
