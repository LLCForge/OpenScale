package service

import (
	"context"
	"crypto/ecdh"
	"errors"
	"log/slog"
	"path/filepath"
	"sync"
	"time"

	"github.com/openscale/openscale/internal/flightrec"
	"github.com/openscale/openscale/internal/panel"
	"github.com/openscale/openscale/internal/version"
)

// The connection flight recorder (#836). The service log is teed into a
// bounded ring at debug level (flightrec); a dropout (the tunnel or the
// coordinator lost) freezes the ring into a sealed recording in the data
// directory, at most once per flightAutoEvery, and the owner can freeze
// it by hand ("Son kopmayı kaydet" in the panel, "openscale debug freeze").

const (
	// FlightRecDir holds the sealed recordings and the recorder key.
	FlightRecDir = "flightrec"
	// flightAutoEvery thins out automatic freezes.
	flightAutoEvery = 15 * time.Minute
	// flightAfterDrop waits after a dropout so the recording also holds
	// the reconnect attempts that follow it.
	flightAfterDrop = 20 * time.Second
	// flightNamesEvery refreshes the device names masked in the ring.
	flightNamesEvery = time.Minute
	// flightWait is one long poll of the event bus.
	flightWait = 30 * time.Second
)

// flightState is the Runtime's recorder (Runtime.fr).
type flightState struct {
	rec   *flightrec.Recorder
	th    flightrec.Throttle
	mu    sync.Mutex
	store *flightrec.Store
	err   string
}

var _ panel.FlightRecorderControl = (*Runtime)(nil)

// startFlightRecorder tees the service log into the ring and starts the
// automatic freezes. It runs first in Run, before anything copies the
// logger.
func (r *Runtime) startFlightRecorder(ctx context.Context) {
	r.fr.rec = flightrec.New(flightrec.Config{Now: r.cfg.Now, Random: r.cfg.Random})
	r.fr.th.Every = flightAutoEvery
	r.logger = slog.New(r.fr.rec.Handler(r.logger.Handler()))
	r.spawn(func() { r.flightLoop(ctx) })
}

// flightStore opens the store on first use.
func (r *Runtime) flightStore() (*flightrec.Store, error) {
	r.fr.mu.Lock()
	defer r.fr.mu.Unlock()
	if r.fr.store != nil {
		return r.fr.store, nil
	}
	st, err := flightrec.OpenStore(filepath.Join(r.cfg.DataDir, FlightRecDir), flightrec.DefaultKeep, r.cfg.Random)
	if err != nil {
		r.fr.err = err.Error()
		return nil, err
	}
	r.fr.store, r.fr.err = st, ""
	return st, nil
}

// flightLoop freezes the ring after a dropout and keeps the masked names
// current.
func (r *Runtime) flightLoop(ctx context.Context) {
	bus := r.observer().Bus()
	since := bus.Seq()
	var namesAt time.Time
	for ctx.Err() == nil {
		if now := r.cfg.Now(); now.Sub(namesAt) >= flightNamesEvery {
			namesAt = now
			r.refreshFlightNames()
		}
		evs, next := bus.Since(ctx, since, flightWait)
		since = next
		for _, ev := range evs {
			reason := ""
			switch ev.Kind {
			case panel.EventTunnelDown:
				reason = flightrec.ReasonTunnelDown
			case panel.EventSyncLost:
				reason = flightrec.ReasonCoordinatorLost
			}
			if reason == "" || !r.fr.th.Allow(r.cfg.Now()) {
				continue
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(flightAfterDrop):
			}
			if _, err := r.flightFreeze(reason); err != nil {
				r.logger.Warn("flight recording not saved", "reason", reason, "error", err.Error())
			} else {
				r.logger.Info("flight recording saved after a dropout", "reason", reason)
			}
		}
	}
}

// refreshFlightNames gives the ring this network's device names to mask.
func (r *Runtime) refreshFlightNames() {
	st, err := r.DiagStatus()
	if err != nil {
		return
	}
	names := make([]string, 0, len(st.Peers)+1)
	if st.Self != nil {
		names = append(names, st.Self.Name, st.Self.FQDN)
	}
	for _, p := range st.Peers {
		names = append(names, p.Name, p.FQDN)
	}
	if h, err := r.cfg.Hostname(); err == nil {
		names = append(names, h)
	}
	r.fr.rec.SetNames(names)
}

func (r *Runtime) flightRecorder() (*flightrec.Recorder, error) {
	if r.fr.rec == nil {
		return nil, errors.New("uçuş kaydedici çalışmıyor")
	}
	return r.fr.rec, nil
}

func (r *Runtime) flightFreeze(reason string) (flightrec.Info, error) {
	rec, err := r.flightRecorder()
	if err != nil {
		return flightrec.Info{}, err
	}
	snap, err := rec.Freeze(reason, version.String())
	if err != nil {
		return flightrec.Info{}, err
	}
	st, err := r.flightStore()
	if err != nil {
		return flightrec.Info{}, err
	}
	return st.Save(snap)
}

// FlightRecStatus implements panel.FlightRecorderControl.
func (r *Runtime) FlightRecStatus() panel.FlightRecStatus {
	out := panel.FlightRecStatus{Schema: panel.DiagSchema, Stored: []flightrec.Info{}, AutoFreeze: true, AutoEvery: int(flightAutoEvery / time.Second)}
	rec, err := r.flightRecorder()
	if err != nil {
		out.Error = err.Error()
		return out
	}
	out.Enabled, out.Stats = true, rec.Stats()
	st, err := r.flightStore()
	if err != nil {
		out.Error = err.Error()
		return out
	}
	if list, err := st.List(); err == nil {
		out.Stored = list
	} else {
		out.Error = err.Error()
	}
	return out
}

// FlightRecFreeze implements panel.FlightRecorderControl.
func (r *Runtime) FlightRecFreeze(reason string) (flightrec.Info, error) {
	info, err := r.flightFreeze(reason)
	if err == nil {
		r.auditLocal("flight_recording_saved", "Uçuş kaydı elle donduruldu.")
	}
	return info, err
}

// FlightRecExport implements panel.FlightRecorderControl: a stored
// recording, or the ring now when id is empty, sealed to a helper's key.
func (r *Runtime) FlightRecExport(id string, to *ecdh.PublicKey) ([]byte, error) {
	var sealed []byte
	if id == "" {
		rec, err := r.flightRecorder()
		if err != nil {
			return nil, err
		}
		snap, err := rec.Freeze(flightrec.ReasonManual, version.String())
		if err != nil {
			return nil, err
		}
		if sealed, err = snap.Seal(r.cfg.Random, to); err != nil {
			return nil, err
		}
	} else {
		st, err := r.flightStore()
		if err != nil {
			return nil, err
		}
		if sealed, err = st.Export(id, to); err != nil {
			return nil, err
		}
	}
	r.auditLocal("flight_recording_exported", "Uçuş kaydı yardımcının anahtarına şifrelenip dışa verildi.")
	return sealed, nil
}
