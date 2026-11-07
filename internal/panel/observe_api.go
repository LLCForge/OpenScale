package panel

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// The observability handlers (ADR-0105). The panel's "Tanı" page gets the
// read-only views and the switches; the command line (app token and the
// caller check of ADR-0050) also gets metrics, the bundle, the capture
// and profiling. None of them exists on a listener other than loopback.

const (
	// streamWait is one long poll's wait; streamLife ends an event stream
	// so a forgotten tab does not hold a connection forever (the browser
	// reconnects with Last-Event-ID).
	streamWait = 25 * time.Second
	streamLife = 10 * time.Minute
	// maxPollWait bounds the wait a client may ask for.
	maxPollWait = 30 * time.Second
	// maxAuditList bounds one audit listing.
	maxAuditList = 500
)

// observeRoutes registers the observability handlers next to the
// diagnostics ones (diagAPI.routes).
func (a *diagAPI) observeRoutes(mux *http.ServeMux, prefix string, read, write func(http.HandlerFunc) http.HandlerFunc, full bool) {
	mux.HandleFunc("GET "+prefix+"/denied", read(a.obs(a.denied)))
	mux.HandleFunc("GET "+prefix+"/audit", read(a.obs(a.auditList)))
	mux.HandleFunc("GET "+prefix+"/stream", read(a.obs(a.stream)))
	mux.HandleFunc("GET "+prefix+"/observe", read(a.obs(a.observePrefs)))
	mux.HandleFunc("POST "+prefix+"/observe", write(a.obs(a.setObservePrefs)))
	mux.HandleFunc("POST "+prefix+"/denied/clear", write(a.obs(a.clearDenied)))
	a.p12ObserveRoutes(mux, prefix, read) // #505, #516 (p12_api.go)
	if !full {
		return
	}
	mux.HandleFunc("GET "+prefix+"/events/poll", read(a.obs(a.poll)))
	mux.HandleFunc("GET "+prefix+"/audit/verify", read(a.obs(a.auditVerify)))
	mux.HandleFunc("GET "+prefix+"/metrics", read(a.obs(a.metrics)))
	mux.HandleFunc("GET "+prefix+"/bundle", read(a.obs(a.bundle)))
	mux.HandleFunc("POST "+prefix+"/capture", write(a.obs(a.capture)))
	mux.HandleFunc("POST "+prefix+"/pprof", write(a.obs(a.profile)))
}

// obs resolves the Observability source or answers 404.
func (a *diagAPI) obs(h func(http.ResponseWriter, *http.Request, Observability)) http.HandlerFunc {
	return a.with(func(w http.ResponseWriter, r *http.Request, d Diagnostics) {
		src, ok := d.(ObservabilitySource)
		var o Observability
		if ok {
			o = src.Observability()
		}
		if o == nil {
			writeError(w, http.StatusNotFound, "Bu işlem bu tünelde yok; masaüstü servisini veya güncel 'openscale up' sürümünü kullanın.")
			return
		}
		h(w, r, o)
	})
}

func (a *diagAPI) denied(w http.ResponseWriter, _ *http.Request, o Observability) {
	rep, err := o.Denied()
	if err != nil {
		diagFailed(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

func (a *diagAPI) clearDenied(w http.ResponseWriter, _ *http.Request, o Observability) {
	if err := o.ClearDenied(); err != nil {
		diagFailed(w, err)
		return
	}
	writeJSON(w, http.StatusOK, okReply{Schema: DiagSchema, OK: true})
}

func queryInt(r *http.Request, name string, def, lo, hi int) (int, bool) {
	s := r.URL.Query().Get(name)
	if s == "" {
		return def, true
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < lo || n > hi {
		return 0, false
	}
	return n, true
}

func (a *diagAPI) auditList(w http.ResponseWriter, r *http.Request, o Observability) {
	n, ok := queryInt(r, "n", 100, 1, maxAuditList)
	if !ok {
		writeError(w, http.StatusBadRequest, "n 1-500 arasında olmalı.")
		return
	}
	rep, err := o.AuditTail(n)
	if err != nil {
		diagFailed(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

func (a *diagAPI) auditVerify(w http.ResponseWriter, _ *http.Request, o Observability) {
	rep, err := o.AuditVerify()
	if err != nil {
		diagFailed(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

func (a *diagAPI) observePrefs(w http.ResponseWriter, _ *http.Request, o Observability) {
	writeJSON(w, http.StatusOK, o.ObservePrefs())
}

func (a *diagAPI) setObservePrefs(w http.ResponseWriter, r *http.Request, o Observability) {
	var req ObservePrefsChange
	if !decodeBody(w, r, &req) {
		return
	}
	if req.Metrics == nil && req.Notifications == nil && req.Profiling == nil {
		writeError(w, http.StatusBadRequest, "Değiştirilecek ayar gönderilmeli.")
		return
	}
	p, err := o.SetObservePrefs(req)
	if err != nil {
		diagFailed(w, err)
		return
	}
	a.logger.Info("observability switches changed", "metrics", p.Metrics, "notifications", p.Notifications, "profiling", p.Profiling)
	writeJSON(w, http.StatusOK, p)
}

// sinceOf reads the position to continue from: Last-Event-ID (browser
// reconnects) or ?since=.
func sinceOf(r *http.Request) (uint64, bool) {
	s := r.Header.Get("Last-Event-ID")
	if s == "" {
		s = r.URL.Query().Get("since")
	}
	if s == "" {
		return 0, true
	}
	n, err := strconv.ParseUint(s, 10, 64)
	return n, err == nil
}

func (a *diagAPI) poll(w http.ResponseWriter, r *http.Request, o Observability) {
	since, ok := sinceOf(r)
	wait, ok2 := queryInt(r, "wait", 0, 0, int(maxPollWait/time.Second))
	if !ok || !ok2 {
		writeError(w, http.StatusBadRequest, "since veya wait geçersiz.")
		return
	}
	writeJSON(w, http.StatusOK, o.EventsSince(r.Context(), since, time.Duration(wait)*time.Second))
}

// stream serves the events as Server-Sent Events (F-182).
func (a *diagAPI) stream(w http.ResponseWriter, r *http.Request, o Observability) {
	since, ok := sinceOf(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "since geçersiz.")
		return
	}
	rc := http.NewResponseController(w)
	h := w.Header()
	h.Set("Content-Type", "text/event-stream; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	bw := bufio.NewWriter(w)
	ctx, cancel := context.WithTimeout(r.Context(), streamLife)
	defer cancel()
	// The first answer comes at once so the client knows where it is.
	wait := time.Duration(0)
	for ctx.Err() == nil {
		_ = rc.SetWriteDeadline(time.Now().Add(streamWait + 30*time.Second))
		rep := o.EventsSince(ctx, since, wait)
		wait = streamWait
		if len(rep.Events) == 0 {
			fmt.Fprintf(bw, ": %d\n\n", rep.Next)
		}
		for _, ev := range rep.Events {
			data, err := json.Marshal(ev)
			if err != nil {
				continue
			}
			fmt.Fprintf(bw, "id: %d\ndata: %s\n\n", ev.Seq, data)
		}
		since = rep.Next
		if bw.Flush() != nil || rc.Flush() != nil {
			return
		}
	}
}

func (a *diagAPI) metrics(w http.ResponseWriter, _ *http.Request, o Observability) {
	var buf bytes.Buffer
	if err := o.WriteMetrics(&buf); err != nil {
		if errors.Is(err, ErrMetricsOff) {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		diagFailed(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf.Bytes())
}

func (a *diagAPI) bundle(w http.ResponseWriter, r *http.Request, o Observability) {
	// The system commands may take a while; the server's write timeout is
	// shorter.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(3 * time.Minute))
	rep, err := o.Bundle(r.Context())
	if err != nil {
		diagFailed(w, err)
		return
	}
	a.logger.Info("diagnostics bundle prepared", "files", len(rep.Files))
	writeJSON(w, http.StatusOK, rep)
}

// validCapture checks a capture request at the boundary.
func validCapture(req *CaptureRequest) error {
	if req.Peer != "" && !validDiagQuery(req.Peer) {
		return errors.New("cihaz adı geçersiz")
	}
	switch req.Proto {
	case "", "tcp", "udp", "icmp":
	default:
		if n, err := strconv.Atoi(req.Proto); err != nil || n < 0 || n > 255 {
			return errors.New("protokol tcp, udp, icmp veya 0-255 bir sayı olmalı")
		}
	}
	switch req.Direction {
	case "", "in", "out", "both":
	default:
		return errors.New("yön in, out veya both olmalı")
	}
	if req.Port < 0 || req.Port > 65535 {
		return errors.New("port 0-65535 olmalı")
	}
	if req.Seconds < 1 || req.Seconds > MaxCaptureSeconds {
		return fmt.Errorf("süre 1-%d saniye olmalı", MaxCaptureSeconds)
	}
	if req.MaxBytes < MinCaptureBytes || req.MaxBytes > MaxCaptureBytes {
		return fmt.Errorf("boyut sınırı %d bayt ile %d MiB arasında olmalı", MinCaptureBytes, MaxCaptureBytes>>20)
	}
	if req.Snap < 0 || req.Snap > 65535 {
		return errors.New("paket başına bayt 0-65535 olmalı")
	}
	return nil
}

// capture streams a pcap file; the totals follow as trailers.
func (a *diagAPI) capture(w http.ResponseWriter, r *http.Request, o Observability) {
	var req CaptureRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if err := validCapture(&req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	a.logger.Info("packet capture started", "seconds", req.Seconds, "max_bytes", req.MaxBytes, "full_packets", req.Snap > 0)
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Now().Add(time.Duration(req.Seconds)*time.Second + time.Minute))
	h := w.Header()
	h.Set("Trailer", "X-Capture-Packets, X-Capture-Dropped")
	sw := &startWriter{w: w, rc: rc, contentType: "application/vnd.tcpdump.pcap"}
	sum, err := o.Capture(r.Context(), req, sw)
	if err != nil && !sw.started {
		diagFailed(w, err)
		return
	}
	h.Set("X-Capture-Packets", strconv.FormatUint(sum.Packets, 10))
	h.Set("X-Capture-Dropped", strconv.FormatUint(sum.Dropped, 10))
	a.logger.Info("packet capture finished", "packets", sum.Packets, "dropped", sum.Dropped)
}

// startWriter sends the pcap header and status on the first write and
// flushes each write so the client sees progress.
type startWriter struct {
	w           http.ResponseWriter
	rc          *http.ResponseController
	contentType string
	started     bool
}

func (s *startWriter) Write(p []byte) (int, error) {
	if !s.started {
		s.started = true
		s.w.Header().Set("Content-Type", s.contentType)
		s.w.WriteHeader(http.StatusOK)
	}
	n, err := s.w.Write(p)
	if err == nil {
		_ = s.rc.Flush()
	}
	return n, err
}

var profileKinds = map[string]bool{"cpu": true, "heap": true, "allocs": true, "goroutine": true, "block": true, "mutex": true, "threadcreate": true}

func (a *diagAPI) profile(w http.ResponseWriter, r *http.Request, o Observability) {
	var req ProfileRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if !profileKinds[req.Kind] {
		writeError(w, http.StatusBadRequest, "Profil türü cpu, heap, allocs, goroutine, block, mutex veya threadcreate olmalı.")
		return
	}
	if req.Kind == "cpu" && (req.Seconds < 1 || req.Seconds > MaxProfileSeconds) {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("CPU profili için süre 1-%d saniye olmalı.", MaxProfileSeconds))
		return
	}
	if req.Debug < 0 || req.Debug > 2 {
		writeError(w, http.StatusBadRequest, "debug 0, 1 veya 2 olmalı.")
		return
	}
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Now().Add(time.Duration(req.Seconds)*time.Second + time.Minute))
	sw := &startWriter{w: w, rc: rc, contentType: "application/octet-stream"}
	if req.Debug > 0 {
		sw.contentType = "text/plain; charset=utf-8"
	}
	if err := o.Profile(r.Context(), req, sw); err != nil && !sw.started {
		if errors.Is(err, ErrProfilingOff) {
			writeError(w, http.StatusForbidden, err.Error())
			return
		}
		diagFailed(w, err)
		return
	}
	a.logger.Info("profile taken", "kind", req.Kind)
}
