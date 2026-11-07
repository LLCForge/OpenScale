package flightrec

import (
	"context"
	"log/slog"
)

// Handler returns a slog.Handler that sends every record, debug included,
// to the ring and passes the records next accepts on to next. It is meant
// to wrap the service's own handler, so the ring sees debug detail while
// the service log keeps its configured level.
func (r *Recorder) Handler(next slog.Handler) slog.Handler {
	return &teeHandler{rec: r, next: next}
}

type teeHandler struct {
	rec    *Recorder
	next   slog.Handler
	attrs  []slog.Attr // bound with WithAttrs, already prefixed by groups
	groups []string
}

func (h *teeHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *teeHandler) Handle(ctx context.Context, rec slog.Record) error {
	attrs := make([]slog.Attr, 0, len(h.attrs)+rec.NumAttrs())
	attrs = append(attrs, h.attrs...)
	rec.Attrs(func(a slog.Attr) bool {
		attrs = append(attrs, h.grouped(a))
		return true
	})
	h.rec.Add(rec.Time, rec.Level, rec.Message, attrs)
	if h.next != nil && h.next.Enabled(ctx, rec.Level) {
		return h.next.Handle(ctx, rec)
	}
	return nil
}

// grouped nests a in the open groups.
func (h *teeHandler) grouped(a slog.Attr) slog.Attr {
	for i := len(h.groups) - 1; i >= 0; i-- {
		a = slog.Group(h.groups[i], a)
	}
	return a
}

func (h *teeHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	out := &teeHandler{rec: h.rec, groups: h.groups, attrs: append([]slog.Attr(nil), h.attrs...)}
	for _, a := range attrs {
		out.attrs = append(out.attrs, h.grouped(a))
	}
	if h.next != nil {
		out.next = h.next.WithAttrs(attrs)
	}
	return out
}

func (h *teeHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	out := &teeHandler{rec: h.rec, attrs: h.attrs, groups: append(append([]string(nil), h.groups...), name)}
	if h.next != nil {
		out.next = h.next.WithGroup(name)
	}
	return out
}
