package panel

import (
	"net/http"
	"time"

	"github.com/openscale/openscale/internal/node"
)

// Exit node resolver controls of the local API (P05): timed block list
// exceptions (#418) and the memory-only query log (#419). Only the full
// local API (token, same user) serves them: the log holds names asked.

// ExitDNSReply is "openscale exit-dns status".
type ExitDNSReply struct {
	Schema     int                     `json:"schema"`
	Stats      node.ExitDNSGuardStats  `json:"stats"`
	Exceptions []node.ExitDNSException `json:"exceptions"`
	LogUntil   *time.Time              `json:"log_until,omitempty"`
}

// ExitDNSLogReply is "openscale exit-dns log".
type ExitDNSLogReply struct {
	Schema  int                    `json:"schema"`
	Until   *time.Time             `json:"until,omitempty"`
	Entries []node.ExitDNSLogEntry `json:"entries"`
}

// ExitDNSDiagnostics is implemented by the service and "openscale up".
type ExitDNSDiagnostics interface {
	DiagExitDNS() (ExitDNSReply, error)
	DiagExitDNSAllow(name string, d time.Duration) (node.ExitDNSException, error)
	DiagExitDNSRevoke(name string) error
	DiagExitDNSLog() (ExitDNSLogReply, error)
	DiagExitDNSSetLog(d time.Duration) (ExitDNSLogReply, error)
}

type exitDNSAllowRequest struct {
	Name    string `json:"name"`
	Seconds int64  `json:"seconds"`
}

type exitDNSLogRequest struct {
	Seconds int64 `json:"seconds"`
}

const maxExitDNSNameParam = 253

func (a *diagAPI) exitDNSRoutes(mux *http.ServeMux, prefix string, read, write func(http.HandlerFunc) http.HandlerFunc) {
	mux.HandleFunc("GET "+prefix+"/exit-dns", read(a.with(a.exitDNS)))
	mux.HandleFunc("POST "+prefix+"/exit-dns/allow", write(a.with(a.exitDNSAllow)))
	mux.HandleFunc("POST "+prefix+"/exit-dns/revoke", write(a.with(a.exitDNSRevoke)))
	mux.HandleFunc("GET "+prefix+"/exit-dns/log", read(a.with(a.exitDNSLog)))
	mux.HandleFunc("POST "+prefix+"/exit-dns/log", write(a.with(a.exitDNSSetLog)))
}

func exitDNSDiag(w http.ResponseWriter, d Diagnostics) (ExitDNSDiagnostics, bool) {
	x, ok := d.(ExitDNSDiagnostics)
	if !ok {
		diagFailed(w, ErrNeedsService)
	}
	return x, ok
}

func (a *diagAPI) exitDNS(w http.ResponseWriter, _ *http.Request, d Diagnostics) {
	x, ok := exitDNSDiag(w, d)
	if !ok {
		return
	}
	rep, err := x.DiagExitDNS()
	if err != nil {
		diagFailed(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

func (a *diagAPI) exitDNSAllow(w http.ResponseWriter, r *http.Request, d Diagnostics) {
	x, ok := exitDNSDiag(w, d)
	if !ok {
		return
	}
	var req exitDNSAllowRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if req.Name == "" || len(req.Name) > maxExitDNSNameParam {
		writeError(w, http.StatusBadRequest, "Geçersiz alan adı.")
		return
	}
	if req.Seconds < int64(node.MinExitDNSException/time.Second) || req.Seconds > int64(node.MaxExitDNSException/time.Second) {
		writeError(w, http.StatusBadRequest, "Süre 1 dakika ile 24 saat arasında olmalı.")
		return
	}
	ex, err := x.DiagExitDNSAllow(req.Name, time.Duration(req.Seconds)*time.Second)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, ex)
}

func (a *diagAPI) exitDNSRevoke(w http.ResponseWriter, r *http.Request, d Diagnostics) {
	x, ok := exitDNSDiag(w, d)
	if !ok {
		return
	}
	var req exitDNSAllowRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if req.Name == "" || len(req.Name) > maxExitDNSNameParam {
		writeError(w, http.StatusBadRequest, "Geçersiz alan adı.")
		return
	}
	if err := x.DiagExitDNSRevoke(req.Name); err != nil {
		diagFailed(w, err)
		return
	}
	writeJSON(w, http.StatusOK, okReply{Schema: DiagSchema, OK: true})
}

func (a *diagAPI) exitDNSLog(w http.ResponseWriter, _ *http.Request, d Diagnostics) {
	x, ok := exitDNSDiag(w, d)
	if !ok {
		return
	}
	rep, err := x.DiagExitDNSLog()
	if err != nil {
		diagFailed(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

func (a *diagAPI) exitDNSSetLog(w http.ResponseWriter, r *http.Request, d Diagnostics) {
	x, ok := exitDNSDiag(w, d)
	if !ok {
		return
	}
	var req exitDNSLogRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if req.Seconds < 0 || req.Seconds > int64(node.MaxExitDNSQueryLog/time.Second) {
		writeError(w, http.StatusBadRequest, "Süre 0 (kapalı) ile 1 saat arasında olmalı.")
		return
	}
	rep, err := x.DiagExitDNSSetLog(time.Duration(req.Seconds) * time.Second)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

// ExitDNSStatus builds the status reply from the process state; the
// service and "openscale up" share it.
func ExitDNSStatus(now time.Time) ExitDNSReply {
	rep := ExitDNSReply{Schema: DiagSchema, Stats: node.ExitDNSStats(), Exceptions: node.ExitDNSExceptions(now)}
	if _, until := node.ExitDNSQueryLog(now); !until.IsZero() {
		rep.LogUntil = &until
	}
	return rep
}

// ExitDNSLogNow builds the log reply.
func ExitDNSLogNow(now time.Time) ExitDNSLogReply {
	entries, until := node.ExitDNSQueryLog(now)
	rep := ExitDNSLogReply{Schema: DiagSchema, Entries: entries}
	if !until.IsZero() {
		rep.Until = &until
	}
	return rep
}
